#include <stdio.h>
#include "KTsUpstream.h"
#include "kselectable.h"
#include "kconnection.h"
#include "kfiber.h"
#include "KHttpServer.h"

struct KTsUpstreamParam {
	KUpstream* us;
	union {
		const kbuf* bufs;
		char* buf;
		KTsUpstream* ts;
	};
	union {
		int bc;
		int len;
		int life_time;
	};
};

static bool ts_header_callback(KUpstream *us, void *arg, const char *attr, int attr_len, const char *val, int val_len,bool request_line)
{
	KTsUpstream *ts = (KTsUpstream *)arg;
	kgl_pool_t *pool = ts->us->GetPool();
	KHttpHeader* header = nullptr;
	if (!attr) {
		header = new_pool_http_know_header(pool, (kgl_header_type)attr_len, val, val_len);
	} else {
		header = new_pool_http_header(pool, attr, attr_len, val, val_len);
	}
	if (header == nullptr) {
		return false;
	}
	if (ts->header) {
		ts->last_header->next = header;
		ts->last_header = header;
	} else {
		ts->header = header;
		ts->last_header = header;
	}
	return true;
}
static int ts_send_header_complete(void* arg, int len)
{
	KUpstream* us = (KUpstream*)arg;
	return (int)us->send_header_complete();
}
static int ts_shutdown(void* arg, int len)
{
	KUpstream* us = (KUpstream*)arg;
	us->shutdown();
	return 0;
}
static int ts_write_end(void* arg, int len)
{
	KUpstream* us = (KUpstream*)arg;
	us->write_end();
	return 0;
}
static int ts_gc(void* arg, int len)
{
	KTsUpstreamParam* param = (KTsUpstreamParam*)arg;
	param->us->gc(param->life_time);
	return 0;
}
static int ts_read(void* arg, int len)
{
	KTsUpstreamParam* param = (KTsUpstreamParam*)arg;
	return param->us->read(param->buf, param->len);
}
static int ts_write_str(void* arg, int len)
{
	KTsUpstreamParam* param = (KTsUpstreamParam*)arg;
	return param->us->write_all(param->buf, param->len);
}
static int ts_write_buf(void* arg, int len) {
	KTsUpstreamParam* param = (KTsUpstreamParam*)arg;
	return param->us->write_all(param->bufs, param->len);
}
static int ts_read_http_header(void* arg, int len)
{
	return (int)((KUpstream*)arg)->read_header();
}
static kev_result next_ts_destroy(KOPAQUE data, void *arg, int got)
{
	KUpstream *us = (KUpstream *)arg;
	us->Destroy();
	return kev_ok;
}

static int ts_set_http2_parser(void* arg, int len)
{
	KTsUpstreamParam* param = (KTsUpstreamParam*)arg;
	param->us->set_header_callback(param->ts, ts_header_callback);
	return 0;
}
KGL_RESULT KTsUpstream::read_header()
{
	kfiber* fiber = NULL;
	if (kfiber_create2(us->get_selector(), ts_read_http_header, us, 0, http_config.fiber_stack_size, &fiber) != 0) {
		return KGL_ESYSCALL;
	}
	int ret;
	kfiber_join(fiber, &ret);
	bool is_first = true;
	while (header) {
		if (!stack.header(us, stack.arg, (header->name_is_know?NULL:header->buf), header->name_len, header->buf + header->val_offset, header->val_len, is_first)) {
			return KGL_EDATA_FORMAT;
		}
		is_first = false;
		header = header->next;
	}
	return (KGL_RESULT)ret;
}
int KTsUpstream::write_all(const char * buf, int bc)
{
	KTsUpstreamParam param;
	param.us = us;
	param.buf = (char *)buf;
	param.len = bc;
	kfiber* fiber = NULL;
	if (kfiber_create2(us->get_selector(), ts_write_str, &param, 0, 0, &fiber) != 0) {
		return -1;
	}
	int ret;
	kfiber_join(fiber, &ret);
	return ret;
}
int KTsUpstream::write_all(const kbuf* buf, int bc) {
	KTsUpstreamParam param;
	param.us = us;
	param.bufs = buf;
	param.len = bc;
	kfiber* fiber = NULL;
	if (kfiber_create2(us->get_selector(), ts_write_buf, &param, 0, 0, &fiber) != 0) {
		return -1;
	}
	int ret;
	kfiber_join(fiber, &ret);
	return ret;
}
int KTsUpstream::read(char* buf, int len)
{
	KTsUpstreamParam param;
	param.us = us;
	param.buf = buf;
	param.len = len;
	kfiber* fiber = NULL;
	if (kfiber_create2(us->get_selector(), ts_read, &param, 0, 0, &fiber) != 0) {
		return -1;
	}
	int ret;
	kfiber_join(fiber, &ret);
	return ret;
}
void KTsUpstream::write_end()
{
	if (!us->IsMultiStream()) {
		us->write_end();
		return;
	}
	kfiber* fiber = NULL;
	kfiber_create2(us->get_selector(), ts_write_end, us, 0, http_config.fiber_stack_size, &fiber);
	int ret;
	kfiber_join(fiber, &ret);
}
void KTsUpstream::shutdown()
{
	if (!us->IsMultiStream()) {
		us->shutdown();
		return;
	}
	kfiber* fiber = NULL;
	kfiber_create2(us->get_selector(), ts_shutdown, us, 0, http_config.fiber_stack_size, &fiber);
	int ret;
	kfiber_join(fiber, &ret);
}
KGL_RESULT KTsUpstream::send_header_complete()
{
	if (us->IsMultiStream()) {
		return us->send_header_complete();
	}
	kfiber* fiber = NULL;
	kfiber_create2(us->get_selector(), ts_send_header_complete, us, 0, http_config.fiber_stack_size, &fiber);
	int ret = KGL_EUNKNOW;
	kfiber_join(fiber, &ret);
	return (KGL_RESULT)ret;
}
void KTsUpstream::Destroy()
{
	fprintf(stderr, "never goto here.\n");
	kassert(false);
	if (us) {
		selectable_next(&us->get_connection()->st, next_ts_destroy, us, 0);
		us = NULL;
	}
	delete this;
}
void KTsUpstream::gc(int life_time)
{
	KTsUpstreamParam param;
	param.life_time = life_time;
	param.us = us;
	kfiber* fiber = NULL;
	kfiber_create2(us->get_selector(), ts_gc, &param, 0, http_config.fiber_stack_size, &fiber);
	int ret;
	kfiber_join(fiber, &ret);
	us = NULL;
	delete this;
}

bool KTsUpstream::set_header_callback(void* arg, kgl_header_callback header)
{
	stack.arg = arg;
	stack.header = header;
	KTsUpstreamParam param;
	param.us = us;
	param.ts = this;

	kfiber* fiber = NULL;
	if (kfiber_create2(us->get_selector(), ts_set_http2_parser, &param, 0, http_config.fiber_stack_size, &fiber) != 0) {
		return false;
	}
	int ret;
	kfiber_join(fiber, &ret);
	return true;
}
