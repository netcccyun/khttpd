/*
 * KPoolableSocketContainer.cpp
 *
 *  Created on: 2010-8-18
 *      Author: keengo
 */

#include "KPoolableSocketContainer.h"
#include "klog.h"
#include "kselector_manager.h"
#include "KRequest.h"
#include "KSink.h"
#include "KTsUpstream.h"
#include "kfiber.h"
#include "KHttpServer.h"
#include "KTcpUpstream.h"
#include "KHttpUpstream.h"
#include "KSockPoolHelper.h"

using namespace std;
struct KUpstreamSelectableList {
	kgl_list queue;
	KUpstream *st;
};
kev_result next_destroy(KOPAQUE data, void *arg, int got)
{
	KUpstream *st = (KUpstream *)arg;
	st->Destroy();
	return kev_destroy;
}
int kfiber_next_destroy(void* arg, int got)
{
	KUpstream* st = (KUpstream*)arg;
	st->Destroy();
	return 0;
}
int KPoolableSocketContainer::kfiber_unbind_upstream(void* arg, int got)
{
	KUpstream* st = (KUpstream*)arg;
	st->unbind_selector();
	return 0;
}
void SafeDestroyUpstream(KUpstream *st)
{
	kselector *selector = st->get_connection()->st.base.selector;
	if (selector != NULL && selector != kgl_get_tls_selector()) {
		kfiber_create2(selector, kfiber_next_destroy, st, 0, http_config.fiber_stack_size, NULL);
	} else {
		st->Destroy();
	}
}
void KPoolableSocketContainerImp::refreshList(kgl_list *l,bool clean)
{
	for (;;) {
		kgl_list *n = l->prev;
		if (n == l) {
			break;
		}
		KUpstreamSelectableList *socket_list = kgl_list_data(n, KUpstreamSelectableList, queue);
		if (!clean && socket_list->st->expire_time > kgl_current_sec) {
			break;
		}
		size--;
		klist_remove(n);
		assert(socket_list->st->container == NULL);
		KUpstream *st = socket_list->st;
		delete socket_list;	
		SafeDestroyUpstream(st);
	}
}
KPoolableSocketContainerImp::KPoolableSocketContainerImp()
{
	//assert(is_selector_manager_init());
	size = 0;
	list_count = 1;
#ifndef _WIN32
	/* worker threads added later use list 0, as before */
	list_count += KGL_MAX(get_selector_count(), 0);
#endif
	lists = new kgl_list[list_count];
	for (int i = 0; i < list_count; i++) {
		klist_init(&lists[i]);
	}
}
KPoolableSocketContainerImp::~KPoolableSocketContainerImp()
{
	for (int i = 0; i < list_count; i++) {
		kassert(klist_empty(&lists[i]));
	}
	delete[] lists;
}
void KPoolableSocketContainerImp::refresh(bool clean)
{
	for (int i = 0; i < list_count; i++) {
		refreshList(&lists[i], clean);
	}
}
KPoolableSocketContainer::KPoolableSocketContainer() {
	flags = 0;
	imp = NULL;
	param = NULL;
}
KPoolableSocketContainer::~KPoolableSocketContainer() {
	if (imp) {
		imp->refresh(true);
		delete imp;
	}
	if (param) {
		kstring_release(param);
	}
}

void KPoolableSocketContainer::unbind(KUpstream *st) {
	release();
}
void KPoolableSocketContainer::gcSocket(KUpstream *st,int life_time) {
	if (this->life_time <= 0 || life_time < 0) {
		//printf("sorry the lifeTime is zero.we must close it us=[%p]\n",st);
		st->Destroy();
		return;
	}
	if (life_time == 0 || life_time>this->life_time) {
		life_time = this->life_time;
	}
	time_t now_time = kgl_current_sec;
	if (st->read_header_time > now_time) {
		st->Destroy();
		return;
	}
	st->expire_time = st->read_header_time + life_time;
	if (st->expire_time < now_time) {
		st->Destroy();
		return;
	}
	PutPoolSocket(st);
}
void KPoolableSocketContainer::PutPoolSocket(KUpstream *st)
{
	kselector *selector = kgl_get_tls_selector();
	bool keep_bound = !st->IsMultiStream() && selector != NULL && st->get_connection() &&
		st->get_connection()->st.base.selector == selector;
	if (!keep_bound) {
		st->unbind_selector();
	}
	lock.Lock();
	if (imp == NULL) {
		imp = new KPoolableSocketContainerImp;
	}
	kgl_list *l = keep_bound ? imp->GetSelectorList(selector) : NULL;
	if (l == NULL) {
		if (keep_bound) {
			st->unbind_selector();
		}
		l = imp->GetList();
	}
	imp->size++;
	assert(st->container);
	st->container = NULL;
	KUpstreamSelectableList *st_list = new KUpstreamSelectableList;
	st_list->st = st;
	l = l->next;
	klist_insert(l, &st_list->queue);
	lock.Unlock();
	unbind(st);
}
KUpstream *KPoolableSocketContainer::internalGetPoolSocket(uint32_t flags) {
	if (imp == NULL) {
		imp = new KPoolableSocketContainerImp;
	}
	/* connections this worker thread kept bound: reuse them without epoll_ctl */
	kgl_list *own_head = imp->GetSelectorList(kgl_get_tls_selector());
	KUpstream *socket = NULL;
	if (own_head) {
		socket = imp->TakeBound(own_head, flags, true);
		if (socket) {
			bind(socket);
			return socket;
		}
	}
	socket = internalGetUnboundSocket(flags);
	if (socket) {
		return socket;
	}
	/*
	 * Then connections idle in other worker threads, so threads still share
	 * them (a backend may accept only a few connections). get_pool_socket
	 * moves the connection to this thread.
	 */
	for (int i = 1; i < imp->GetListCount(); i++) {
		kgl_list *head = imp->GetListAt(i);
		if (head == own_head) {
			continue;
		}
		socket = imp->TakeBound(head, flags, false);
		if (socket) {
			bind(socket);
			return socket;
		}
	}
	return NULL;
}
KUpstream *KPoolableSocketContainerImp::TakeBound(kgl_list *head, uint32_t flags, bool own_selector) {
	refreshList(head, false);
	kgl_list *n = klist_head(head);
	while (n != head) {
		KUpstreamSelectableList *st_list = kgl_list_data(n, KUpstreamSelectableList, queue);
		KUpstream *socket = st_list->st;
		if (KBIT_TEST(flags, KSOCKET_FLAGS_WEBSOCKET) && !socket->support_websocket()) {
			return NULL;
		}
		kgl_list *next = n->next;
		size--;
		klist_remove(n);
		delete st_list;
		kconnection *cn = socket->get_connection();
		/* another thread's flags are only safe to read after moving it */
		if (own_selector && cn && KBIT_TEST(cn->st.base.st_flags, STF_ERR)) {
			/* epoll saw the peer close it while idle */
			SafeDestroyUpstream(socket);
			n = next;
			continue;
		}
		return socket;
	}
	return NULL;
}
KUpstream *KPoolableSocketContainer::internalGetUnboundSocket(uint32_t flags) {
	kgl_list *list_head = imp->GetList();
	imp->refreshList(list_head, false);
	KUpstream *socket = NULL;
	kgl_list *n = klist_head(list_head);
	while (n!=list_head) {
		KUpstreamSelectableList *st_list = kgl_list_data(n, KUpstreamSelectableList, queue);
		socket = st_list->st;
		if (KBIT_TEST(flags, KSOCKET_FLAGS_WEBSOCKET) && !socket->support_websocket()) {
			return NULL;
		}
		if (socket->IsMultiStream()) {
			KUpstream *us = socket->NewStream();
			if (us==NULL) {
				imp->size--;
				kgl_list *next = n->next;
				klist_remove(n);
				delete st_list;
				SafeDestroyUpstream(socket);
				n = next;
				continue;
			}
			bind(us);
			return us;
		}
		imp->size--;
		klist_remove(n);
		delete st_list;	
		bind(socket);
		return socket;
	}
	return NULL;
}
void KPoolableSocketContainer::bind(KUpstream *st) {
	kassert(st->container==NULL);
	st->container = this;
	addRef();
}
void KPoolableSocketContainer::setLifeTime(int life_time) {
	this->life_time = life_time;
	if (life_time <= 0) {
		clean();
	}
}
void KPoolableSocketContainer::refresh(time_t nowTime) {
	lock.Lock();
	if (imp) {
		imp->refresh(nowTime==0);
	}
	lock.Unlock();
}
KUpstream* KPoolableSocketContainer::new_upstream(kconnection *cn)
{
	KUpstream* us;
	if (tcp) {
		us = new KTcpUpstream(cn);
	} else {
		us = new KHttpUpstream(cn);
	}
	return us;
}
KUpstream *KPoolableSocketContainer::get_pool_socket(uint32_t flags) {
	lock.Lock();
	KUpstream *socket = internalGetPoolSocket(flags);
	lock.Unlock();
	if (socket==NULL) {
		return NULL;
	}
	socket->read_header_time = kgl_current_sec;
	kselector *selector = socket->get_connection()->st.base.selector;
	kselector *current = kgl_get_tls_selector();
	if (selector!=NULL && selector!=current) {
#ifndef _WIN32
		if (!socket->IsMultiStream() && current && kfiber_self2()) {
			/* idle in another worker thread: that thread takes it out of its epoll */
			kfiber *fiber = NULL;
			if (kfiber_create2(selector, kfiber_unbind_upstream, socket, 0, http_config.fiber_stack_size, &fiber) == 0) {
				int ret = 0;
				kfiber_join(fiber, &ret);
				if (KBIT_TEST(socket->get_connection()->st.base.st_flags, STF_ERR)) {
					/* the peer closed it while idle */
					socket->Destroy();
					return NULL;
				}
				socket->bind_selector(current);
				return socket;
			}
		}
#endif
		//连接和当前selector不一致,一般发生在windows上，多线程情况上.
		//因为windows中socket一但绑定了iocp，无法解绑。
		return new KTsUpstream(socket);
	}
	socket->bind_selector(current);
	return socket;
}
void KPoolableSocketContainer::clean()
{
	lock.Lock();
	if (imp) {
		imp->refresh(true);
		assert(imp->size == 0);
	}
	lock.Unlock();
}

void KPoolableSocketContainer::SetParam(const char* param)
{
	lock.Lock();
	kstring_release(this->param);
	this->param = kstring_from(param);
	lock.Unlock();
}
kgl_refs_string* KPoolableSocketContainer::GetParam()
{
	lock.Lock();
	kgl_refs_string* result = kstring_refs(param);
	lock.Unlock();
	return result;
}
