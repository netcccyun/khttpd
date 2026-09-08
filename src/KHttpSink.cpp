#include "KHttpSink.h"
#include "KRequest.h"
#include "kbuf.h"
#include "kfiber.h"
#include "kfeature.h"
#include "khttp.h"
#include "KHttpKeyValue.h"
#include "KHttpServer.h"
#include "KHttp2.h"
#include "klog.h"

#define MAX_HTTP_CHUNK_SIZE 8192
#ifdef KSOCKET_SSL
static int handle_http2https_error(void* arg, int got) {
	KSink* sink = (KSink*)arg;
	KBIT_SET(sink->data.flags, RQ_CONNECTION_CLOSE);
	if (http2https_error) {
		http2https_error(sink, 0);
		return 0;
	}
	const char* body = "send http to https port";
	int body_len = (int)strlen(body);
	sink->response_status(STATUS_HTTP_TO_HTTPS);
	//sink->response_content_length(body_len);
	sink->response_header(kgl_expand_string("Cache-Control"), kgl_expand_string("no-cache,no-store"));
	sink->start_response_body(body_len);
	if (sink->data.meth != METH_HEAD) {
		sink->write_all(body, body_len);
	} else {
		// start_response_body() buffers HTTP/1 response headers until the first
		// write.  HEAD has no body, so explicitly finish the response or the
		// client receives an empty connection instead of the 497 headers.
		sink->end_request();
	}
	return 0;
}
#endif
KHttpSink::KHttpSink(kconnection* c, kgl_pool_t* pool) : KSingleConnectionSink(c, pool) {
	ks_buffer_init(&buffer, MAX_HTTP_CHUNK_SIZE);
	parserd_hot = buffer.buf;
	dechunk = NULL;
}
KHttpSink::~KHttpSink() {
	//printf("~KHttpSink\n");
	if (dechunk) {
		delete dechunk;
	}
	if (buffer.buf) {
		xfree(buffer.buf);
	}
}
bool KHttpSink::internal_response_status(uint16_t status_code) {
	kgl_str_t request_line;
	KHttpKeyValue::get_request_line(pool, status_code, &request_line);
	rc.head_insert_const(pool, request_line.data, (uint16_t)request_line.len);
	return true;
}
#ifdef ENABLE_HTTP2
static kev_result h2c_process(KOPAQUE data, void* arg, int got) {
	KHttp2* http2 = (KHttp2*)arg;
	http2->server_h2c(got);
	return kev_ok;
}
bool KHttpSink::switch_h2c() {
	KHttp2* http2 = new KHttp2();
	selectable_bind_opaque(&cn->st, http2);
	if (!http2->init_h2c(cn, buffer.buf, buffer.used)) {
		return false;
	}
	selectable_next(&cn->st, h2c_process, http2, buffer.used);
	//cn is handle by http2
	cn = nullptr;
	return true;
}
#endif

int KHttpSink::internal_start_response_body(int64_t body_size, bool is_100_continue) {
	if (likely(!is_100_continue)) {
		response_connection();
	}
	if (rc.empty()) {
		return 0;
	}
	this->response_left = body_size;
	send_alt_svc_header();
	rc.head_append(pool, _KS("\r\n\r\n"));
	int header_len = rc.get_len();
	assert(!kfiber_is_main());
	if (KBIT_TEST(data.flags, RQ_CONNECTION_UPGRADE)) {
		if (0 != KSingleConnectionSink::write_buf(rc.get_buf(), header_len, nullptr)) {
			return -1;
		}
		rc.clean();
		return header_len;
	}
	if (is_100_continue) {
		if (0 != KSingleConnectionSink::write_buf(rc.get_buf(), header_len, nullptr)) {
			return -1;
		}
		rc.clean();
	}
	return header_len;
}
int KHttpSink::internal_read(char* buf, int len) {
	if (dechunk) {
		return dechunk->read(cn, buf, len);
	}
	size_t parsed_len = parserd_hot - buffer.buf;
	int buffer_left = buffer.used - (int)parsed_len;
	if (buffer_left > 0) {
		len = KGL_MIN((int)len, buffer_left);
		kgl_memcpy(buf, parserd_hot, len);
		parserd_hot += len;
		return len;
	}
	return kfiber_net_read(cn, buf, len);
}
int KHttpSink::sendfile(kfiber_file* fp, int len) {
	if (!rc.empty()) {
		int left = KSingleConnectionSink::write_buf(rc.get_buf(), rc.get_len(), nullptr);
		rc.clean();
		if (left != 0) {
			return 0;
		}
	}
	if (!KBIT_TEST(data.flags, RQ_TE_CHUNKED)) {
		return KSingleConnectionSink::sendfile(fp, len);
	}
	char header[32];
	int size = sprintf(header, "%x\r\n", len);
	if (!kfiber_net_write_full(cn, header, &size)) {
		return -1;
	}
	int size2 = len;
	bool result = kfiber_sendfile_full(cn, fp, &size2);
	add_down_flow(nullptr, len - size2 + size + 2);
	if (!result) {
		return -1;
	}
	size2 = 2;
	if (!kfiber_net_write_full(cn, "\r\n", &size2)) {
		return -1;
	}
	on_success_response(len + size + 2);
	return len;
}
int KHttpSink::write_all(const char* str, int len) {
	if (KBIT_TEST(data.flags, RQ_TE_CHUNKED)) {
		char header[32];
		kbuf buf[2];
		buf[0].used = sprintf(header, "%x\r\n", len);
		buf[0].next = &buf[1];
		buf[0].data = (char*)header;
		buf[1].used = len;
		buf[1].data = (char*)str;
		kgl_iovec chunked_end;
		chunked_end.iov_base = (char*)"\r\n";
		chunked_end.iov_len = 2;
		return internal_write(buf, len + buf[0].used, &chunked_end);
	}
	if (!rc.empty()) {
		kbuf buf{ 0 };
		buf.data = (char*)str;
		buf.used = len;
		return internal_write(&buf, len, nullptr);
	}
	return KSingleConnectionSink::write_all(str, len);
}
int KHttpSink::write_all(const kbuf* buf, int len) {
	if (KBIT_TEST(data.flags, RQ_TE_CHUNKED)) {
		char header[32];
		kbuf chunked_buf;
		chunked_buf.used = sprintf(header, "%x\r\n", len);
		chunked_buf.next = (kbuf*)buf;
		chunked_buf.data = (char*)header;
		kgl_iovec chunked_end;
		chunked_end.iov_base = (char*)"\r\n";
		chunked_end.iov_len = 2;
		return internal_write(&chunked_buf, len + chunked_buf.used, &chunked_end);
	}
	return internal_write(buf, len, nullptr);
}
void KHttpSink::end_request() {

	if (!rc.empty()) {
		//has header to send.
		if (KSingleConnectionSink::write_buf(rc.get_buf(), rc.get_len(), nullptr) != 0) {
			KBIT_SET(data.flags, RQ_CONNECTION_CLOSE);
			return;
		}
	}
	if (response_left > 0) {
		KBIT_SET(data.flags, RQ_CONNECTION_CLOSE);
		return;
	}
	rc.clean();
	if (KBIT_TEST(data.flags, RQ_TE_CHUNKED) && response_left == -1) {
		//has chunked but body is complete successful.
		WSABUF bufs;
		int bc = 1;
		if (!KBIT_TEST(data.flags, RQ_HAS_SEND_CHUNK_0)) {
			KBIT_SET(data.flags, RQ_HAS_SEND_CHUNK_0);
			bufs.iov_base = (char*)"0\r\n\r\n";
			bufs.iov_len = 5;
		} else {
			bufs.iov_base = (char*)"\r\n";
			bufs.iov_len = 2;
		}
		kfiber_net_writev_full(cn, &bufs, &bc);
		if (bc > 0) {
			KBIT_SET(data.flags, RQ_CONNECTION_CLOSE);
		}
	}
	return;
}
bool KHttpSink::skip_post() {
	kassert(data.left_read != 0);
	char buf[4096];
	if (dechunk) {
		for (;;) {
			int got = dechunk->read(cn, buf, sizeof(buf));
			if (got < 0) {
				break;
			}
			if (got == 0) {
				data.left_read = 0;
				return true;
			}
			add_up_flow((INT64)got);
		}
		return false;
	}

	while (data.left_read > 0) {
		int len = internal_read(buf, (int)KGL_MIN(sizeof(buf), data.left_read));
		if (len <= 0) {
			return false;
		}
		add_up_flow((INT64)len);
		data.left_read -= len;
	}
	return true;
}
bool KHttpSink::response_trailer(const char* name, int name_len, const char* val, int val_len) {
	if (!KBIT_TEST(data.flags, RQ_TE_CHUNKED)) {
		return true;
	}
	WSABUF bufs[5];
	int bc = 0;
	if (!KBIT_TEST(data.flags, RQ_HAS_SEND_CHUNK_0)) {
		KBIT_SET(data.flags, RQ_HAS_SEND_CHUNK_0);
		bufs[bc].iov_base = (char*)"0\r\n";
		bufs[bc].iov_len = 3;
		bc++;
	}
	bufs[bc].iov_base = (char*)name;
	bufs[bc].iov_len = name_len;
	bc++;
	bufs[bc].iov_base = (char*)": ";
	bufs[bc].iov_len = 2;
	bc++;
	bufs[bc].iov_base = (char*)val;
	bufs[bc].iov_len = val_len;
	bc++;
	bufs[bc].iov_base = (char*)"\r\n";
	bufs[bc].iov_len = 2;
	bc++;
	kfiber_net_writev_full(cn, bufs, &bc);
	return bc == 0;
}
void KHttpSink::start(int header_len) {
	assert(header_len == 0);
	khttp_parser parser{ 0 };
	for (;;) {
		int len;
		char* hot = get_read_buffer(&len);
		if (hot == nullptr || len <= 0) {
			return;
		}
		//printf("hot=[%p] len=[%d]\n", hot, len);
		int got = kfiber_net_read(cn, hot, len);
		if (got <= 0) {
			return;
		}
		//printf("got=[%d][",got);
		//fwrite(hot, 1, got, stdout);
		//printf("]\n");

		ks_write_success(&buffer, got);
	parse_header:
		switch (parse(&parser)) {
		case kgl_parse_continue:
			break;
		case kgl_parse_finished:
#ifdef KSOCKET_SSL
			if (kconnection_is_ssl_not_handshake(cn)) {
				handle_http2https_error((KSink*)this, 0);
				return;
			}
#endif
#ifdef KGL_DEBUG_TIME
			reset_start_time();
#endif
			khttp_server_new_request((KSink*)this, parser.header_len);
#ifdef KGL_DEBUG_TIME
			log_passed_time("+end_request");
#endif
			if (!start_pipe_line()) {
				return;
			}
			parser = { 0 };
			{
				if (dechunk) {
					if (dechunk->buffer.used > 0) {
						begin_request();
						dechunk->swap(&buffer);
						parserd_hot = buffer.buf;
						delete dechunk;
						dechunk = nullptr;
						goto parse_header;
					}
					delete dechunk;
					dechunk = nullptr;
				} else {
					if (parserd_hot < buffer.buf + buffer.used) {
						//have data
						begin_request();
						save_point();
						goto parse_header;
					}
				}
				char* new_buf = (char*)xmalloc(buffer.buf_size);
				int got = kfiber_net_read(cn, new_buf, buffer.buf_size);
				if (got <= 0) {
					xfree(new_buf);
					return;
				}
				data.free_lazy_memory();
				data.free_header();
				if (pool) {
					kgl_reset_pool(pool);
				}
				data.begin_request();
				xfree(buffer.buf);
				buffer.buf = new_buf;
				buffer.used = got;
				parserd_hot = buffer.buf;
				goto parse_header;
			}
			break;
		default:
			return;
		}
	}
}
