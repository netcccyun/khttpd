#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "khttp.h"
#ifdef ENABLE_HTTP3
#include "klog.h"
#include "KHttp3.h"
#include "KHttp3Sink.h"


#include "KHttpKeyValue.h"
#include "lsxpack_header.h"
#include "kselector_manager.h"
#include "kstring.h"
#include "kudp.h"
#include "KRequest.h"
#include "kfiber.h"
#include "openssl/rand.h"
#define MAX_SELECTOR_COUNT 256

#define  CW_SENDADDR  (1 << 0)
#if ECN_SUPPORTED
#define  CW_ECN       (1 << 1)
#endif
struct kgl_quic_package
{
	sockaddr_i local_addr;
	sockaddr_i* peer_addr;
	char* buffer;
};
kev_result h3_result_udp_recv(KOPAQUE data, void* arg, int got);
int h3_process_package_in(KHttp3ServerEngine* h3_engine, kconnection* uc, int got);
static lsquic_stream_ctx_t* http_server_on_new_stream(void* stream_if_ctx, lsquic_stream_t* stream) {
	auto lsquic_cn = lsquic_stream_conn(stream);
	if (lsquic_cn == NULL) {
		return NULL;
	}
	KHttp3Connection* cn = (KHttp3Connection*)lsquic_conn_get_ctx(lsquic_cn);
	if (cn == NULL) {
		return NULL;
	}
	KHttp3Sink* sink = new KHttp3Sink(cn);
	lsquic_stream_wantread(stream, 1);
	lsquic_stream_wantwrite(stream, 0);
	return (lsquic_stream_ctx_t*)sink;
}

static lsquic_conn_ctx_t* http_server_on_new_conn(void* stream_if_ctx, lsquic_conn_t* conn) {
	KHttp3Connection* cn = new KHttp3Connection(conn, (KHttp3ServerEngine*)stream_if_ctx);
	return (lsquic_conn_ctx_t*)cn;
}
static void http_server_on_conn_closed(lsquic_conn_t* conn) {
	KHttp3Connection* cn = (KHttp3Connection*)lsquic_conn_get_ctx(conn);
	lsquic_conn_set_ctx(conn, NULL);
	cn->detach_connection();
	cn->release();
}
static void http_server_on_read(struct lsquic_stream* stream, lsquic_stream_ctx_t* st_h) {
	assert(st_h);
	KHttp3Sink* sink = (KHttp3Sink*)st_h;
	sink->on_read(stream);
}
static void http_server_on_write(lsquic_stream_t* stream, lsquic_stream_ctx_t* st_h) {
	assert(st_h);
	KHttp3Sink* sink = (KHttp3Sink*)st_h;
	sink->on_write(stream);
}
static void http_server_on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* st_h) {
	if (st_h) {
		KHttp3Sink* sink = (KHttp3Sink*)st_h;
		lsquic_stream_set_ctx(stream, NULL);
		if (sink->is_processing()) {
			sink->detach_stream();
		} else {
			delete sink;
		}
	}
}
static void
http_server_on_goaway(lsquic_conn_t* conn) {
	lsquic_conn_ctx_t* conn_h = lsquic_conn_get_ctx(conn);
	//conn_h->flags |= RECEIVED_GOAWAY;
}
static struct lsquic_stream_if http_server_if;
static struct lsquic_hset_if header_bypass_api;
inline kev_result h3_recv_package(KHttp3ServerEngine* h3_engine, kconnection* uc) {
	return selectable_read(&uc->st, h3_result_udp_recv, h3_engine->iov_buf, uc);
}
static void
setup_control_msg(
#ifndef WIN32
	struct msghdr
#else
	WSAMSG
#endif
	* msg, int cw,
	const struct lsquic_out_spec* spec, unsigned char* buf, size_t bufsz) {
	struct cmsghdr* cmsg;
	struct sockaddr_in* local_sa;
	struct sockaddr_in6* local_sa6;
#if __linux__ || __APPLE__ || WIN32
	struct in_pktinfo info;
#endif
	struct in6_pktinfo info6;
	size_t ctl_len;

#ifndef WIN32
	msg->msg_control = buf;
	msg->msg_controllen = bufsz;
#else
	msg->Control.buf = (char*)buf;
	msg->Control.len = bufsz;
#endif

	/* Need to zero the buffer due to a bug(?) in CMSG_NXTHDR.  See
	 * https://stackoverflow.com/questions/27601849/cmsg-nxthdr-returns-null-even-though-there-are-more-cmsghdr-objects
	 */
	memset(buf, 0, bufsz);

	ctl_len = 0;
	for (cmsg = CMSG_FIRSTHDR(msg); cw && cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cw & CW_SENDADDR) {
			if (AF_INET == spec->dest_sa->sa_family) {
				local_sa = (struct sockaddr_in*)spec->local_sa;
#if defined(LINUX) || defined(__APPLE__)
				memset(&info, 0, sizeof(info));
				info.ipi_spec_dst = local_sa->sin_addr;
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_PKTINFO;
				cmsg->cmsg_len = CMSG_LEN(sizeof(info));
				ctl_len += CMSG_SPACE(sizeof(info));
				memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
#elif WIN32
				memset(&info, 0, sizeof(info));
				info.ipi_addr = local_sa->sin_addr;
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_PKTINFO;
				cmsg->cmsg_len = CMSG_LEN(sizeof(info));
				ctl_len += CMSG_SPACE(sizeof(info));
				memcpy(WSA_CMSG_DATA(cmsg), &info, sizeof(info));
#else
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_SENDSRCADDR;
				cmsg->cmsg_len = CMSG_LEN(sizeof(local_sa->sin_addr));
				ctl_len += CMSG_SPACE(sizeof(local_sa->sin_addr));
				memcpy(CMSG_DATA(cmsg), &local_sa->sin_addr,
					sizeof(local_sa->sin_addr));
#endif
			} else {
				local_sa6 = (struct sockaddr_in6*)spec->local_sa;
				memset(&info6, 0, sizeof(info6));
				info6.ipi6_addr = local_sa6->sin6_addr;
				cmsg->cmsg_level = IPPROTO_IPV6;
				cmsg->cmsg_type = IPV6_PKTINFO;
				cmsg->cmsg_len = CMSG_LEN(sizeof(info6));
#ifndef WIN32
				memcpy(CMSG_DATA(cmsg), &info6, sizeof(info6));
#else
				memcpy(WSA_CMSG_DATA(cmsg), &info6, sizeof(info6));
#endif
				ctl_len += CMSG_SPACE(sizeof(info6));
			}
			cw &= ~CW_SENDADDR;
		}
#if ECN_SUPPORTED
		else if (cw & CW_ECN) {
			if (AF_INET == spec->dest_sa->sa_family) {
				const
#if defined(__FreeBSD__)
					unsigned char
#else
					int
#endif
					tos = spec->ecn;
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_TOS;
				cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
				memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
				ctl_len += CMSG_SPACE(sizeof(tos));
			} else {
				const int tos = spec->ecn;
				cmsg->cmsg_level = IPPROTO_IPV6;
				cmsg->cmsg_type = IPV6_TCLASS;
				cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
				memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
				ctl_len += CMSG_SPACE(sizeof(tos));
			}
			cw &= ~CW_ECN;
		}
#endif
		else
			assert(0);
	}

#ifndef WIN32
	msg->msg_controllen = ctl_len;
#else
	msg->Control.len = ctl_len;
#endif
}


int send_packets_out(
	void* packets_out_ctx,
	const struct lsquic_out_spec* specs,
	unsigned                       count
) {
	KHttp3ServerEngine* h3_engine;
	unsigned n;
	int s = 0;
#ifndef _WIN32
	struct msghdr msg;
#else
	DWORD bytes;
	WSAMSG msg;
#endif
	union
	{
		/* cmsg(3) recommends union for proper alignment */
#if defined(LINUX) || defined(_WIN32)
#	define SIZE1 sizeof(struct in_pktinfo)
#else
#	define SIZE1 sizeof(struct in_addr)
#endif
		unsigned char buf[
			CMSG_SPACE(KGL_MAX(SIZE1, sizeof(struct in6_pktinfo)))
#if ECN_SUPPORTED
				+ CMSG_SPACE(sizeof(int))
#endif
		];
		struct cmsghdr cmsg;
	} ancil;
	uintptr_t ancil_key, prev_ancil_key = 0;
	if (0 == count)
		return 0;
	//printf("out package count=[%d]\n", count);
	const unsigned orig_count = count;
#if 0
	const unsigned out_limit = packet_out_limit();
	if (out_limit && count > out_limit)
		count = out_limit;
#endif
	n = 0;
	int cw;
	do {
		h3_engine = (KHttp3ServerEngine*)specs[n].peer_ctx;
		kconnection* uc = h3_engine->uc;
#ifndef _WIN32
		msg.msg_name = (void*)specs[n].dest_sa;
		msg.msg_namelen = (AF_INET == specs[n].dest_sa->sa_family ?
			sizeof(struct sockaddr_in) :
			sizeof(struct sockaddr_in6));
		msg.msg_iov = specs[n].iov;
		msg.msg_iovlen = specs[n].iovlen;
		msg.msg_flags = 0;
#else
		msg.name = (sockaddr*)specs[n].dest_sa;
		msg.namelen = (AF_INET == specs[n].dest_sa->sa_family ?
			sizeof(struct sockaddr_in) :
			sizeof(struct sockaddr_in6));
		msg.dwBufferCount = specs[n].iovlen;
		msg.lpBuffers = specs[n].iov;
		msg.dwFlags = 0;
#endif        
		if (h3_engine->allow_src_ip() && specs[n].local_sa->sa_family) {
			cw = CW_SENDADDR;
			ancil_key = (uintptr_t)specs[n].local_sa;
			assert(0 == (ancil_key & 3));
		} else {
			cw = 0;
			ancil_key = 0;
		}
#if ECN_SUPPORTED
		if (specs[n].ecn) {
			cw |= CW_ECN;
			ancil_key |= specs[n].ecn;
		}
#endif
		if (cw && prev_ancil_key == ancil_key) {
			/* Reuse previous ancillary message */
			;
		} else if (cw) {
			prev_ancil_key = ancil_key;
			setup_control_msg(&msg, cw, &specs[n], ancil.buf, sizeof(ancil.buf));
		} else {
			prev_ancil_key = 0;
#ifndef WIN32
			msg.msg_control = NULL;
			msg.msg_controllen = 0;
#else
			msg.Control.buf = NULL;
			msg.Control.len = 0;
#endif
		}
#ifndef WIN32
		s = sendmsg(uc->st.fd, &msg, 0);
#else
		s = lpfnWsaSendMsg(uc->st.fd, &msg, 0, &bytes, NULL, NULL);
#endif
		if (s < 0) {
			break;
		}
		++n;
	} while (n < count);


	if (n < orig_count) {
		//prog_sport_cant_send(sport->sp_prog, sport->fd);
	}


	if (n > 0) {
		if (n < orig_count)
			errno = EAGAIN;
		return n;
	}
	assert(s < 0);
	return -1;
}
static int parse_local_addr(kgl_quic_package* package, kconnection* uc) {
	package->local_addr.v4.sin_family = package->peer_addr->v4.sin_family;
	package->local_addr.v4.sin_port = uc->addr.v4.sin_port;
	return kudp_get_recvaddr(uc, (struct sockaddr*)&package->local_addr);
}
inline int  kgl_quic_package_in(KHttp3ServerEngine* h3_engine, kgl_quic_package* package, int got) {
	return lsquic_engine_packet_in(h3_engine->engine, (unsigned char*)package->buffer, got, (sockaddr*)&package->local_addr, (sockaddr*)package->peer_addr, h3_engine, 0);
}
static struct lsquic_engine_settings engine_settings = { 0 };

static kev_result next_quic_package_in(KOPAQUE data, void* arg, int got) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)data;
	kgl_quic_package* package = (kgl_quic_package*)arg;
	kgl_quic_package_in(h3_engine, package, got);
	h3_engine->release();
	xfree(package->peer_addr);
	xfree(package->buffer);
	xfree(package);
	return kev_ok;
}
int h3_process_package_in(KHttp3ServerEngine* h3_engine, kconnection* uc, int got) {
	if (h3_engine->is_multi()) {
		lsquic_cid_t cid;
		cid.len = 0;
		if (0 != lsquic_cid_from_packet((unsigned char*)h3_engine->get_udp_buffer(), got, &cid) || cid.len < sizeof(kgl_h3_cid_header)) {
			return -1;

		}
		int index = h3_engine->server->get_engine_index((kgl_h3_cid_header*)cid.idbuf);
		//printf("package index=[%d] current selector=[%p] sid=[%d]\n", index, kgl_get_tls_selector(), kgl_get_tls_selector()->sid);
		if (index != kgl_get_tls_selector()->sid) {
			kselector* selector = get_selector_by_index(index);
			KHttp3ServerEngine* next_engine = h3_engine->server->refs_engine(index);
			kgl_quic_package* package = (kgl_quic_package*)xmalloc(sizeof(kgl_quic_package));
			package->buffer = h3_engine->realloc_buffer();
			package->peer_addr = (sockaddr_i*)xmalloc(sizeof(sockaddr_i));
			memcpy(package->peer_addr, &uc->addr, sizeof(sockaddr_i));
			parse_local_addr(package, uc);
			kgl_selector_module.next(selector, next_engine, next_quic_package_in, package, got);
			return 0;
		}
	}

	kgl_quic_package package;
	package.buffer = (char*)h3_engine->iov_buf[1].iov_base;
	package.peer_addr = &uc->addr;
	parse_local_addr(&package, uc);
	return kgl_quic_package_in(h3_engine, &package, got);
}
kev_result h3_result_udp_recv(KOPAQUE data, void* arg, int got) {
	kconnection* uc = (kconnection*)arg;
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)data;
	if (got == ST_ERR_TIME_OUT) {
		return kev_ok;
	}
	if (got > 0) {
		h3_process_package_in(h3_engine, uc, got);
	}
	if (h3_engine->server->is_shutdown()) {
		h3_engine->release();
		return kev_destroy;
	}
	return h3_recv_package(h3_engine, uc);
}
SSL_CTX* h3_lookup_cert(void* lsquic_cert_lookup_ctx, const struct sockaddr* local, const char* hostname) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)lsquic_cert_lookup_ctx;
	SSL_CTX* ssl_ctx = nullptr;
	void* sni = kgl_ssl_create_sni(h3_engine->server->get_data(), hostname, &ssl_ctx);
	if (sni) {
		h3_engine->cache_sni(hostname, sni);
	}
	if (ssl_ctx) {
		return ssl_ctx;
	}
	return kgl_get_ssl_ctx(h3_engine->server->ssl_ctx);
}
SSL_CTX* ea_get_ssl_ctx(void* peer_ctx, const struct sockaddr* local) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)peer_ctx;
	return kgl_get_ssl_ctx(h3_engine->server->ssl_ctx);
}
static void*
interop_server_hset_create(void* hsi_ctx, lsquic_stream_t* stream, int is_push_promise) {
	struct header_decoder* req = (struct header_decoder*)malloc(sizeof(struct header_decoder));
	if (req == NULL) {
		return NULL;
	}
	memset(req, 0, sizeof(struct header_decoder));
	req->sink = (KHttp3Sink*)lsquic_stream_get_ctx(stream);
	req->is_first = true;
	return req;
}
static struct lsxpack_header*
interop_server_hset_prepare_decode(void* hset_p, struct lsxpack_header* xhdr,
	size_t req_space) {
	struct header_decoder* req = (struct header_decoder*)hset_p;
	if (xhdr) {
		//LSQ_WARN("we don't reallocate headers: can't give more");
		return NULL;
	}

	if (req->have_xhdr) {
		if (req->decode_off + lsxpack_header_get_dec_size(&req->xhdr)
			>= sizeof(req->decode_buf)) {
			//LSQ_WARN("Not enough room in header");
			return NULL;
		}
		req->decode_off += lsxpack_header_get_dec_size(&req->xhdr);
	} else
		req->have_xhdr = true;

	lsxpack_header_prepare_decode(&req->xhdr, req->decode_buf,
		req->decode_off, sizeof(req->decode_buf) - req->decode_off);
	return &req->xhdr;
}
static int
interop_server_hset_add_header(void* hset_p, struct lsxpack_header* xhdr) {
	struct header_decoder* req = (struct header_decoder*)hset_p;
	const char* name, * value;
	int name_len, value_len;
	if (!xhdr) {
		if (req->sink->data.raw_url.is_bad()) {
			return 1;
		}
		return 0;
	}
	name = lsxpack_header_get_name(xhdr);
	value = lsxpack_header_get_value(xhdr);
	name_len = xhdr->name_len;
	value_len = xhdr->val_len;
	bool result = req->sink->parse_header<const char*>(name, name_len, (char*)value, value_len, req->is_first);
	req->is_first = false;
	if (result) {
		return 0;
	}
	return -1;
}
static void
interop_server_hset_destroy(void* hset_p) {
	struct header_decoder* req = (struct header_decoder*)hset_p;
	free_header_decoder(req);
}
static int h3_log_buf(void* ctx, const char* buf, size_t len) {
	FILE* out = (FILE*)ctx;
	fwrite(buf, 1, len, out);
	fflush(out);
	return 0;
}
static const struct lsquic_logger_if logger_if = { h3_log_buf, };

void kgl_shutdown_khttp3() {
	lsquic_global_cleanup();
}
bool kgl_init_khttp3() {
	lsquic_global_init(LSQUIC_GLOBAL_SERVER | LSQUIC_GLOBAL_CLIENT);
	//lsquic_logger_init(&logger_if, stdout, LLTS_HHMMSSUS);
	//lsquic_set_log_level("debug");
	memset(&http_server_if, 0, sizeof(http_server_if));
	http_server_if.on_new_conn = http_server_on_new_conn;
	http_server_if.on_conn_closed = http_server_on_conn_closed;
	http_server_if.on_new_stream = http_server_on_new_stream;
	http_server_if.on_read = http_server_on_read;
	http_server_if.on_write = http_server_on_write;
	http_server_if.on_close = http_server_on_close;
	http_server_if.on_goaway_received = http_server_on_goaway;
	lsquic_engine_init_settings(&engine_settings, LSENG_SERVER);
	engine_settings.es_rw_once = 1;
	engine_settings.es_send_prst = 1;
	//engine_settings.es_proc_time_thresh = LSQUIC_DF_PROC_TIME_THRESH;
	//engine_settings.es_cc_rtt_thresh = 0;
	//engine_settings.es_cc_algo = 2; //BBRv1

	memset(&header_bypass_api, 0, sizeof(header_bypass_api));
	header_bypass_api.hsi_create_header_set = interop_server_hset_create;
	header_bypass_api.hsi_prepare_decode = interop_server_hset_prepare_decode;
	header_bypass_api.hsi_process_header = interop_server_hset_add_header;
	header_bypass_api.hsi_discard_header_set = interop_server_hset_destroy;
	header_bypass_api.hsi_flags = (lsquic_hsi_flag)(LSQUIC_HSI_HTTP1X | LSQUIC_HSI_HASH_NAME | LSQUIC_HSI_HASH_NAMEVAL);

	return true;

}
void kgl_h3_generate_scid(void* ctx, lsquic_conn_t* cn, uint8_t*buf, unsigned len) {
	if (buf == NULL) {
		return;
	}
	if (len < sizeof(kgl_h3_cid_header)) {
		memset(buf, 0, len);
		return;
	}
//}
//void kgl_h3_generate_scid(void* ctx, lsquic_conn_t* cn, lsquic_cid_t* cid, unsigned len) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)ctx;
	kselector* selector = kgl_get_tls_selector();
	kgl_h3_cid_header* header = (kgl_h3_cid_header*)buf;
	header->port_id = (uint8_t)selector->sid;
	header->seq = h3_engine->seq++;
	if (RAND_bytes(buf + sizeof(kgl_h3_cid_header), (int)(len - sizeof(kgl_h3_cid_header))) != 1) {
		memset(buf + sizeof(kgl_h3_cid_header), 0, len - sizeof(kgl_h3_cid_header));
	}
	//cid->len = len;
}

int h3_start_server_engine(void* arg, int got) {
	assert(kgl_get_tls_selector()->sid == got);
	KHttp3Server* server = (KHttp3Server*)arg;
	return server->start_engine(got);
}
int h3_shutdown_engine(void* arg, int got) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)arg;
	return h3_engine->shutdown();
}
int kgl_h3_engine_tick(void* arg, int event_count) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)arg;
	assert(h3_engine->selector_tick);
	h3_engine->ticked();
	int next_time = h3_engine->next_event_time();

	if (h3_engine->server->is_shutdown() && next_time < 0) {
		kselector_close_tick(h3_engine->selector_tick);
		h3_engine->selector_tick = NULL;
		h3_engine->release();
		return 0;
	}
	return next_time;
}
KHttp3Server* kgl_h3_new_server(const char* ip, uint16_t port, int sock_flags, kgl_ssl_ctx* ssl_ctx, uint32_t model) {
	assert(is_selector_manager_init());
	auto selector_count = get_selector_count();
	assert(selector_count > 0);
	if (selector_count > MAX_SELECTOR_COUNT) {
		selector_count = MAX_SELECTOR_COUNT;
	}
	KHttp3Server* server = new KHttp3Server(selector_count);
	if (0 != server->init(ip, port, sock_flags, ssl_ctx, model)) {
		server->release();
		return nullptr;
	}
	return server;
}
int KHttp3Server::shutdown() {
	if (!KBIT_TEST(flags, KGL_SERVER_START)) {
		return false;
	}
	KBIT_CLR(flags, KGL_SERVER_START);
	for (int i = 0; i < engine_count; i++) {
		auto selector = get_selector_by_index(i);
		kfiber* fiber = NULL;
		kfiber_create2(selector, h3_shutdown_engine, engines[i], 0, 0, &fiber);
		int retval = -1;
		kfiber_join(fiber, &retval);
	}
	return 0;
}
int KHttp3Server::init(const char* ip, uint16_t port, int sock_flags, kgl_ssl_ctx* ssl_ctx, uint32_t model) {
	if (!ssl_ctx) {
		return -1;
	}
	if (this->ssl_ctx) {
		return -1;
	}
	if (!ksocket_getaddr(ip, port, PF_UNSPEC, AI_NUMERICHOST, &addr)) {
		return -1;
	}
	allow_src_ip = 0;
	if (addr.v4.sin_family == PF_INET) {
		if (addr.v4.sin_addr.s_addr == INADDR_ANY) {
			allow_src_ip = 1;
		}
#ifdef KSOCKET_IPV6
	} else {
		if (memcmp(&addr.v6.sin6_addr, &in6addr_any, sizeof(addr.v6.sin6_addr)) == 0) {
			allow_src_ip = 1;
		}
#endif
	}
	kgl_add_ref_ssl_ctx(ssl_ctx);
	this->ssl_ctx = ssl_ctx;
	this->flags = model;
	for (int i = 0; i < engine_count; i++) {
		int ret = engines[i]->init(get_selector_by_index(i), sock_flags);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}
bool KHttp3Server::start() {
	if (KBIT_TEST(flags, KGL_SERVER_START)) {
		return false;
	}
	if (this->ssl_ctx == nullptr) {
		return false;
	}
	KBIT_SET(flags, KGL_SERVER_START);
	for (int i = 0; i < engine_count; i++) {
		auto selector = get_selector_by_index(i);
		assert(selector->sid == i);
		addRef();
		kfiber_create2(selector, h3_start_server_engine, this, i, 0, NULL);
	}
	return true;
}
int KHttp3Server::start_engine(int index) {
	auto engine = engines[index];
	return engine->start();
}
int KHttp3ServerEngine::start() {
	if (engine == nullptr || uc == nullptr) {
		//not init engine
		release();
		return -1;
	}

	if (selector_tick == nullptr) {
		selector_tick = kselector_new_tick(kgl_h3_engine_tick, this);
		if (selector_tick) {
			if (kselector_register_tick(selector_tick)) {
				server->addRef();
			} else {
				kselector_close_tick(selector_tick);
				selector_tick = nullptr;
			}
		}
	}
	h3_recv_package(this, uc);
	return 0;
}
int KHttp3ServerEngine::init(kselector* selector, int udp_flag) {
	KBIT_SET(udp_flag, KSOCKET_IP_PKTINFO);
	lsquic_engine_api engine_api = { 0 };
	engine_api.ea_packets_out = send_packets_out;
	engine_api.ea_packets_out_ctx = (void*)this;
	engine_api.ea_get_ssl_ctx = ea_get_ssl_ctx;
	engine_api.ea_stream_if = &http_server_if;
	engine_api.ea_stream_if_ctx = (void*)this;

	engine_api.ea_settings = &engine_settings;
	engine_api.ea_hsi_if = &header_bypass_api;
	if (kgl_ssl_create_sni) {
		engine_api.ea_lookup_cert = h3_lookup_cert;
		engine_api.ea_cert_lu_ctx = (void*)this;
	}
	if (is_multi()) {
		engine_api.ea_gen_scid_ctx = (void*)this;
		engine_api.ea_generate_scid = kgl_h3_generate_scid;
		udp_flag |= KSOCKET_REUSEPORT;
	}
	if (engine != nullptr) {
		return -1;
	}
	engine = lsquic_engine_new(LSENG_SERVER | LSENG_HTTP, &engine_api);
	if (!engine) {
		return -1;
	}
	if (uc == nullptr) {
		uc = kudp_new2(udp_flag, selector);
	}
	if (!kudp_bind(uc, &server->addr)) {
		return -1;
	}
	KBIT_SET(uc->st.base.st_flags, STF_RTIME_OUT);
	selectable_bind_opaque(&uc->st, this);
	return 0;
}
int KHttp3ServerEngine::add_refs() {
	return server->addRef();
}
void KHttp3ServerEngine::release() {
	server->release();
}
bool KHttp3ServerEngine::is_multi() {
	return server->engine_count > 1;
}
bool KHttp3ServerEngine::allow_src_ip() {
	return server->allow_src_ip;
}
int KHttp3ServerEngine::shutdown() {
	if (uc == nullptr) {
		return -1;
	}
	lsquic_engine_cooldown(engine);
	selectable_shutdown(&uc->st);
	return 0;
}
#endif
