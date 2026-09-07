#include "KHttpUpstream.h"
#include "KHttpKeyValue.h"
#include "KHttpParser.h"
#include "KTcpServerSink.h"

bool KHttpUpstream::send_connection(const char* val, hlen_t val_len)
{
	return send_header(kgl_expand_string("Connection"), val, val_len);
}
bool KHttpUpstream::send_method_path(uint16_t meth, const char* path, hlen_t path_len)
{
	assert(this->ctx.send_header_buffer == NULL);
	if (this->ctx.send_header_buffer == NULL) {
		ctx.send_header_buffer = krw_buffer_new(4096);
	}
	kgl_str_t *meth_str = KHttpKeyValue::get_method(meth);
	krw_write_str(ctx.send_header_buffer, meth_str->data, (int)meth_str->len);
	krw_write_str(ctx.send_header_buffer, kgl_expand_string(" "));
	krw_write_str(ctx.send_header_buffer, path, path_len);
	krw_write_str(ctx.send_header_buffer, kgl_expand_string(" HTTP/1.1\r\n"));
	return true;
}
bool KHttpUpstream::send_header(const char* attr, hlen_t attr_len, const char* val, hlen_t val_len)
{
	if (this->ctx.send_header_buffer == NULL) {
		return false;
	}
	//printf("%.*s: %.*s\n", attr_len, attr, val_len, val);
	krw_write_str(ctx.send_header_buffer, attr, attr_len);
	krw_write_str(ctx.send_header_buffer, kgl_expand_string(": "));
	krw_write_str(ctx.send_header_buffer, val, val_len);
	krw_write_str(ctx.send_header_buffer, kgl_expand_string("\r\n"));
	return true;
}
bool KHttpUpstream::send_host(const char* host, hlen_t host_len)
{
	return send_header(kgl_expand_string("Host"), host, host_len);
}
void KHttpUpstream::set_content_length(int64_t content_length)
{
	if (content_length == -1) {
		//unknow
		send_header(kgl_expand_string("Transfer-Encoding"), kgl_expand_string("chunked"));
	}
	return;
}
KGL_RESULT KHttpUpstream::send_header_complete()
{
	if (this->ctx.send_header_buffer == NULL) {
		return KGL_ENOT_READY;
	}
	kgl_iovec header_end;
	header_end.iov_base = (char*)"\r\n";
	header_end.iov_len = 2;
	int left = kangle::write_buf(cn, ctx.send_header_buffer->head, ctx.send_header_buffer->total_len, &header_end);
	krw_buffer_destroy(ctx.send_header_buffer);
	ctx.send_header_buffer = NULL;
	return left == 0 ? KGL_OK : KGL_ECAN_RETRY_SOCKET_BROKEN;
}
KGL_RESULT KHttpUpstream::read_header()
{
	read_header_time = kgl_current_sec;
	assert(ctx.read_buffer == NULL || ctx.read_buffer->used==0);
	if (ctx.read_buffer != NULL && ctx.read_buffer->used>0) {
		return KGL_EUNKNOW;
	}
	assert(stack.header);
	KGL_RESULT result = KGL_OK;
	khttp_parser parser;
	memset(&parser, 0, sizeof(parser));
	if (ctx.read_buffer == nullptr) {
		ctx.read_buffer = ks_buffer_new(8192);
	}
	int64_t begin_time_msec = kgl_current_msec;
	for (;;) {
	continue_read:
		int write_len;
		char* write_buf = ks_get_write_buffer(ctx.read_buffer, &write_len);
		int got = kfiber_net_read(cn, write_buf, write_len);
		if (got <= 0) {
			return KGL_EDATA_FORMAT;
		}
		ks_write_success(ctx.read_buffer, got);
		khttp_parse_result rs;
		char* hot = ctx.read_buffer->buf;
		char* end = ctx.read_buffer->buf + ctx.read_buffer->used;
		for (;;) {
			memset(&rs, 0, sizeof(rs));
			kgl_parse_result parse_result = khttp_parse(&parser, &hot, end, &rs);
			if (parser.header_len > MAX_HTTP_HEAD_SIZE) {
				result = KGL_EDATA_FORMAT;
				goto out;
			}
			switch (parse_result) {
			case kgl_parse_continue:
			{
				if (kgl_current_msec - begin_time_msec > 60000) {
					result = KGL_EIO;
					goto out;
				}
				if ((size_t)parser.header_len + (size_t)(end - hot) >= MAX_HTTP_HEAD_SIZE) {
					result = KGL_EDATA_FORMAT;
					goto out;
				}
				ks_save_point(ctx.read_buffer, hot);
				goto continue_read;
			}
			case kgl_parse_success:
			{
				if (!stack.header(this, stack.arg, rs.attr, rs.attr_len, rs.val, rs.val_len, rs.is_first)) {
					result = KGL_EDATA_FORMAT;
					goto out;
				}
				break;
			}
			case kgl_parse_finished:
				ks_save_point(ctx.read_buffer, hot);
				goto out;
			default:
				result = KGL_EDATA_FORMAT;
				goto out;
			}
		}
	}
out:
	return result;
}
int KHttpUpstream::read(char* buf, int len)
{
	if (ctx.read_buffer) {
		if (ctx.read_buffer->used > 0) {
			len = KGL_MIN((int)len, (int)ctx.read_buffer->used);
			kgl_memcpy(buf, ctx.read_buffer->buf, len);
			ks_save_point(ctx.read_buffer, ctx.read_buffer->buf + len);
			//assert(len <= ctx.left);
			//ctx.left -= len;
			return len;
		}
		ks_buffer_destroy(ctx.read_buffer);
		ctx.read_buffer = NULL;
	}
	return KTcpUpstream::read(buf, len);
}
void KHttpUpstream::clean()
{
	KTcpUpstream::clean();
	if (ctx.send_header_buffer) {
		krw_buffer_destroy(ctx.send_header_buffer);
	}
	//if (ctx.dechunk_ctx) {
	//	delete ctx.dechunk_ctx;
	//}
	if (ctx.read_buffer) {
		ks_buffer_destroy(ctx.read_buffer);
	}
	memset(&ctx, 0, sizeof(ctx));
}
