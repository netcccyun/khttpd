#include "KHttp2Upstream.h"
#include "KStringBuf.h"
#include "khttp.h"
#include "KHttpKeyValue.h"

#ifdef ENABLE_UPSTREAM_HTTP2
bool KHttp2Upstream::parse_header(const char* attr, int attr_len, const char* val, int val_len) {
	int status_code;
	if (kgl_mem_same(attr, attr_len, _KS(":status"))) {
		status_code = (int)kgl_atol((u_char *)val, val_len);
		attr = NULL;
		attr_len = (int)kgl_header_status;
		val = (char*)&status_code;
		val_len = KGL_HEADER_VALUE_INT;
		if (status_code == 100) {
			//next headers is not trailer header
			ctx->is_100_continue = 1;
			assert(ctx->parsed_header == 0);
			goto skip_trailer;
		}
	}
	if (ctx->parsed_header) {
		if (attr) {
			return ctx->get_trailer_header()->add_header(attr, attr_len, val, val_len) != nullptr;
		}
		return ctx->get_trailer_header()->add_header((kgl_header_type)attr_len, val, val_len) != nullptr;
	}
skip_trailer:
	kgl_http2_event* re = ctx->read_wait;
	if (re) {
		//client模式中在等待读header的过程中，有可能就会被客户端connection broken而导致shutdown.
		kassert(re->header);
		return re->header(this, re->header_arg, attr, attr_len, val, val_len, false);
	}
	return true;
}
bool KHttp2Upstream::set_header_callback(void* arg, kgl_header_callback header) {
	assert(kselector_is_same_thread(http2->c->st.base.selector));
	assert(!ctx->in_closed);
	assert(ctx->read_wait == NULL);
	kgl_http2_event* e = new kgl_http2_event;
	e->header_arg = arg;
	e->header = header;
	ctx->read_wait = e;
	return true;
}
KGL_RESULT KHttp2Upstream::read_header() {
	read_header_time = kgl_current_sec;
	if (ctx->send_header) {
		http2->send_header(ctx, ctx->content_left == 0);
	}
	if (0 == http2->ReadHeader(ctx)) {
		return KGL_OK;
	}
	return KGL_EUNKNOW;
}
KUpstream* KHttp2Upstream::NewStream() {
	kassert(this->ctx->admin_stream);
	return http2->connect();
}
bool KHttp2Upstream::send_trailer(const char* name, hlen_t name_len, const char* val, hlen_t val_len) {
	if (!ctx->write_trailer) {
		assert(ctx->content_left == -1);
		if (ctx->send_header) {
			http2->send_header(ctx, false);
		}
		ctx->write_trailer = 1;
	}
	return http2->add_header(ctx, name, name_len, val, val_len);
}
bool KHttp2Upstream::send_header(kgl_header_type name, const char* val, hlen_t val_len) {
	switch (name) {
	case kgl_header_expect:
		ctx->has_expect = 1;
		return KUpstream::send_header(name, val, val_len);
	case kgl_header_upgrade:
		if (ctx->has_upgrade) {
			return http2->add_header(ctx, _KS(":protocol"), val, val_len);
		}
		return KUpstream::send_header(name, val, val_len);
	default:
		return KUpstream::send_header(name, val, val_len);
	}
}
bool KHttp2Upstream::send_header(const char* attr, hlen_t attr_len, const char* val, hlen_t val_len) {
	return http2->add_header(ctx, attr, attr_len, val, val_len);
}
bool KHttp2Upstream::send_method_path(uint16_t meth, const char* path, hlen_t path_len) {
	if (!http2->add_method(ctx, (uint8_t)meth)) {
		return false;
	}
	if (meth == METH_CONNECT) {
		ctx->has_upgrade = 1;
		ctx->set_content_length(-1);
	}
	return http2->add_header(ctx, kgl_expand_string(":path"), path, path_len);
}
bool KHttp2Upstream::send_host(const char* host, hlen_t host_len) {
	return http2->add_header(ctx, kgl_expand_string(":authority"), host, host_len);
}
void KHttp2Upstream::set_content_length(int64_t content_length) {
	if (ctx->has_upgrade) {
		return;
	}
	ctx->set_content_length(content_length);
}
KGL_RESULT KHttp2Upstream::send_header_complete() {
	return KGL_OK;
}
#endif
