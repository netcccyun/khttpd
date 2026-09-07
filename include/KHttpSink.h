#ifndef KHTTPSINK_H_99
#define KHTTPSINK_H_99
#include "KTcpServerSink.h"
#include "kconnection.h"
#include "KHttpParser.h"
#include "KResponseContext.h"
#include "KHttpHeader.h"
#include "KDechunkContext.h"
#include "KHttpServer.h"
#include "klog.h"
//handle http/1.x protocol
class KHttpSink final : public KSingleConnectionSink
{
public:
	KHttpSink(kconnection* c, kgl_pool_t* pool);
	~KHttpSink();
	virtual bool is_locked() override {
		return KBIT_TEST(cn->st.base.st_flags, STF_LOCK);
	}
	virtual bool response_header(kgl_header_type know_header, const char* val, int val_len, bool lock_value) override {
		assert(know_header < kgl_header_unknow);
		rc.head_append(pool, kgl_header_type_string[know_header].http11.data, (uint16_t)kgl_header_type_string[know_header].http11.len);
		if (lock_value) {
			rc.head_append(pool, val, val_len);
		} else {
			char* buf = (char*)kgl_pnalloc(pool, val_len);
			memcpy(buf, val, val_len);
			rc.head_append(pool, buf, (uint16_t)val_len);
		}
		return true;
	}
	virtual bool response_header(const char* name, int name_len, const char* val, int val_len) override {
		int len = name_len + val_len + 4;
		char* buf = (char*)kgl_pnalloc(pool, len);
		char* hot = buf;
		kgl_memcpy(hot, "\r\n", 2);
		hot += 2;
		kgl_memcpy(hot, name, name_len);
		hot += name_len;
		kgl_memcpy(hot, ": ", 2);
		hot += 2;
		kgl_memcpy(hot, val, val_len);
		hot += val_len;
		rc.head_append(pool, buf, len);
		return true;
	}
	inline bool response_connection() {
#ifdef HTTP_PROXY
		if (data.meth == METH_CONNECT) {
			return false;
		}
#endif
		if (KBIT_TEST(data.flags, RQ_CONNECTION_UPGRADE)) {
			return response_header(kgl_header_connection, kgl_expand_string("upgrade"), true);
		} else if (KBIT_TEST(data.flags, RQ_CONNECTION_CLOSE) || !KBIT_TEST(data.flags, RQ_HAS_KEEP_CONNECTION)) {
			return response_header(kgl_header_connection, kgl_expand_string("close"), true);
		}
		if (data.http_version > 0x100) {
			//HTTP/1.1 default keep-alive
			return true;
		}
		return response_header(kgl_header_connection, kgl_expand_string("keep-alive"), true);
	}
	bool readhup(void* arg, result_callback result) override {
		return selectable_readhup(&cn->st, result, arg);
	}
	void remove_readhup() override {
		selectable_remove_readhup(&cn->st);
	}
	void set_delay() override {
		ksocket_delay(cn->st.fd);
	}
	void set_no_delay(bool forever) override {
		ksocket_no_delay(cn->st.fd, forever);
	}
	void shutdown() override {
		selectable_shutdown(&cn->st);
	}
	void set_time_out(int tmo) override {
		cn->st.base.tmo = tmo;
		cn->st.base.tmo_left = tmo;
	}
	int get_time_out() override {
		return cn->st.base.tmo;
	}
	/* return true will use pipe_line */
	void end_request() override;
	ks_buffer buffer;
	char* parserd_hot;
	char* get_read_buffer(int* size) {
		assert(parserd_hot - buffer.buf >= 0 && parserd_hot - buffer.buf <= buffer.used);
		assert(buffer.used <= buffer.buf_size);
	retry:
		*size = buffer.buf_size - (int)buffer.used;
		if (*size > 0) {
			return buffer.buf + buffer.used;
		}
		{
			if (buffer.buf_size >= MAX_HTTP_HEAD_SIZE) {
				*size = 0;
				return nullptr;
			}
			int new_size = KGL_MIN(buffer.buf_size * 2, MAX_HTTP_HEAD_SIZE);
			char* nb = (char*)xmalloc(new_size);
			kgl_memcpy(nb, buffer.buf, buffer.used);
			ptrdiff_t delta_point = nb - buffer.buf;
			data.adjust_buffer_offset(delta_point);
			xfree(buffer.buf);
			buffer.buf = nb;
			buffer.buf_size = new_size;
			parserd_hot += delta_point;
			goto retry;
		}
	}
	KResponseContext rc;
	kconnection* get_connection() override {
		return cn;
	}
	KDechunkContext* GetDechunkContext() {
		return dechunk;
	}
	KHttpHeader* get_trailer() override {
		if (!dechunk || !dechunk->trailer) {
			return nullptr;
		}
		return dechunk->trailer->header;
	}
	virtual bool response_headers(const KHttpHeader* header) override {
		return khttpd::response_headers<KHttpSink>(this, header);
	}
	bool response_trailer(const char* name, int name_len, const char* val, int val_len) override;
	void start(int header_len) override;
	bool skip_post();
	bool start_pipe_line() {
		if (KBIT_TEST(data.flags, RQ_CONNECTION_CLOSE | RQ_CONNECTION_UPGRADE) || !KBIT_TEST(data.flags, RQ_HAS_KEEP_CONNECTION)) {
			return false;
		}
		assert(rc.empty());
		ksocket_no_delay(cn->st.fd, false);
		kassert(buffer.buf_size > 0);
		kassert(data.left_read >= 0 || dechunk != NULL);

		if (data.left_read != 0 && !KBIT_TEST(data.flags, RQ_HAVE_EXPECT)) {
			//still have data to read
			if (!skip_post()) {
				return false;
			}
		}
		kassert(data.left_read == 0 || KBIT_TEST(data.flags, RQ_HAVE_EXPECT));
		reset_pipeline();
		return true;
	}
	int sendfile(kfiber_file* fp, int len) override;
	int write_all(const char* buf, int len) override;
	int write_all(const kbuf* buf, int len) override;
protected:
	bool response_altsvc_header(const char* val, int val_len) override {
		return response_header(kgl_header_alt_svc, val, val_len, false);
	}
	int internal_start_response_body(int64_t body_size, bool is_100_continue) override;
	int internal_read(char* buf, int len) override;
	int internal_write(const kbuf* buf, int len, const kgl_iovec* suffix) {
		if (!rc.empty()) {
			rc.attach(buf, len);
			int left = KSingleConnectionSink::write_buf(rc.get_buf(), rc.get_len(), suffix);
			rc.clean();
			on_success_response(len - left);
			return left;
		}
		int left = KSingleConnectionSink::write_buf(buf, len, suffix);
		on_success_response(len - left);
		return left;
	}
protected:
#ifdef ENABLE_HTTP2
	bool switch_h2c();
#endif
	bool internal_response_status(uint16_t status_code) override;
	KDechunkContext* dechunk;
private:
	void reset_pipeline() {
		data.clean();
		data.init();
		set_state(STATE_IDLE);
	}
	void begin_request() {
		data.free_lazy_memory();
		data.free_header();
		if (pool) {
			kgl_reset_pool(pool);
		}
		data.begin_request();
	}
	void save_point() {
		ks_save_point(&buffer, parserd_hot);
		parserd_hot = buffer.buf;
	}
	kgl_parse_result parse(khttp_parser* parser) {
		khttp_parse_result rs;
		char* end = buffer.buf + buffer.used;
		assert(parserd_hot >= buffer.buf && parserd_hot <= end);
		for (;;) {
			memset(&rs, 0, sizeof(rs));
			kgl_parse_result result = khttp_parse(parser, &parserd_hot, end, &rs);
			if (parser->header_len > MAX_HTTP_HEAD_SIZE) {
				return kgl_parse_error;
			}
			assert(parserd_hot >= buffer.buf && parserd_hot <= end);
			//printf("len=[%d],result=[%d]\n", len,result);
			switch (result) {
			case kgl_parse_continue:
			{
				if (kgl_current_msec - data.begin_time_msec > 60000) {
					return kgl_parse_error;
				}
				if ((size_t)parser->header_len + (size_t)(end - parserd_hot) >= MAX_HTTP_HEAD_SIZE) {
					return kgl_parse_error;
				}
				//ks_save_point(&buffer, hot);
				return kgl_parse_continue;
			}
			case kgl_parse_success:
				if (!parse_header<char*>(rs.attr, rs.attr_len, rs.val, rs.val_len, rs.is_first)) {
					return kgl_parse_error;
				}
				if (rs.is_first && data.meth == METH_PRI && KBIT_TEST(cn->server->flags, KGL_SERVER_H2)) {
#ifdef ENABLE_HTTP2
					save_point();
					if (!switch_h2c()) {
						klog(KLOG_ERR, "cann't switch to h2c, buffer size=[%d] may greater than http2 buffer\n", buffer.used);
					}
#endif
					return kgl_parse_error;
				}
				break;
			case kgl_parse_finished:
				kassert(rc.get_buf() == nullptr);
				ksocket_delay(cn->st.fd);
				if (KBIT_TEST(data.flags, RQ_INPUT_CHUNKED)) {
					kassert(dechunk == NULL);
					dechunk = new KDechunkContext(parserd_hot, (int)(buffer.used - (parserd_hot - buffer.buf)));
				}
				//printf("***************body_len=[%d]\n", parser.body_len);
				return kgl_parse_finished;

			default:
				return kgl_parse_error;
			}
		}
	}
};
#endif
