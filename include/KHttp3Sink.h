#ifndef KGL_HTTP3_INCLUDED_H_
#define KGL_HTTP3_INCLUDED_H_
#include "KSink.h"
#include "KHttp3.h"
#ifdef ENABLE_HTTP3
#include "lsxpack_header.h"
#include "kfiber_sync.h"
#include "KHttp3Connection.h"
#include "KObjArray.h"
#include "kfiber.h"

#define  H3_STATUS_SENT    (1<<17)
#define  H3_HEADER_SENT    (1<<18)
#define  H3_IS_PROCESSING  (1<<19)
extern "C" {
	void lsquic_stream_maybe_reset(struct lsquic_stream*, uint64_t error_code, int);
}
struct kgl_fiber_event
{
	kfiber_cond* cd;
	WSABUF* buf;
	int bc;
	int result;
};
class KHttp3Sink final: public KSink
{
public:
	KHttp3Sink(KHttp3Connection* cn) : KSink(NULL), response_headers(16), content_left{ 0 } {
		cn->addRef();
		this->cn = cn;
		this->st = NULL;
		data.set_http_version(3, 0);
		st_flags = 0;
		for (int i = 0; i < 2; i++) {
			ev[i].cd = kfiber_cond_init(true);
		}
		response_headers.new_first();
	}
	~KHttp3Sink() {
		if (is_processing()) {
			if (st) {
				lsquic_stream_set_ctx(st, NULL);
				if (content_left > 0) {
					lsquic_stream_maybe_reset(st, 0, 0);
				}
				lsquic_stream_close(st);
			}
			KBIT_CLR(st_flags, H3_IS_PROCESSING);
		}
		for (int i = 0; i < 2; i++) {
			ev[i].cd->f->release(ev[i].cd);
		}
		assert(cn);
		cn->release();
	}
	void detach_stream() {
		assert(is_processing());
		st = NULL;
	}
	bool is_processing() {
		return KBIT_TEST(st_flags, H3_IS_PROCESSING) > 0;
	}
	bool set_transfer_chunked() override {
		return false;
	}
	bool internal_response_status(uint16_t status_code) override {
		char buf[4];
		snprintf(buf, sizeof(buf), "%03d", status_code);
		auto header = response_headers[0];
		build_header(header, kgl_expand_string(":status"), buf, 3);
		return true;
	}
	bool response_header(const char* name, int name_len, const char* val, int val_len) override {
		auto header = response_headers.get_new();
		if (header == NULL) {
			return false;
		}
		build_header(header, name, name_len, val, val_len);
		return true;
	}
	//返回头长度,-1表示出错
	int internal_start_response_body(int64_t body_size,bool is_100_continue) override {
		if (st == NULL) {
			return -1;
		}
		assert(!KBIT_TEST(st_flags, H3_HEADER_SENT));
		if (KBIT_TEST(st_flags, H3_HEADER_SENT)) {
			return -1;
		}
		assert(!KBIT_TEST(st_flags, STF_WRITE));
		this->content_left = body_size;
		if (lsquic_stream_wantwrite(st, 1) < 0) {
			//printf("internal_start_response_body call wantwrite failed.\n");
			return -1;
		}
		KBIT_SET(st_flags, STF_WRITE);
		int got;
		ev[OP_WRITE].cd->f->wait(ev[OP_WRITE].cd,&got);
		assert(got == ev[OP_WRITE].result);
		return ev[OP_WRITE].result;
	}
	bool is_locked() override {
		return KBIT_TEST(st_flags, STF_READ | STF_WRITE) > 0;
	}
	bool readhup(void* arg, result_callback result) override {
		//http2->read_hup(ctx, result, arg);
		return false;
	}
	void remove_readhup() override {
		//http2->remove_read_hup(ctx);
	}
	int internal_read(char* buf, int len) override {
		assert(!KBIT_TEST(st_flags, STF_READ));
		if (st == NULL) {
			return -1;
		}
		WSABUF bufs;
		bufs.iov_base = buf;
		bufs.iov_len = len;
		ev[OP_READ].buf = &bufs;
		ev[OP_READ].bc = 1;
		if (KBIT_TEST(st_flags, STF_RREADY)) {
			on_read(st);
		} else {
			if (lsquic_stream_wantread(st, 1) < 0) {
				return -1;
			}
		}
		KBIT_SET(st_flags, STF_READ);
		int got;
		ev[OP_READ].cd->f->wait(ev[OP_READ].cd,&got);
		assert(!KBIT_TEST(st_flags, STF_READ));
		assert(got == ev[OP_READ].result);
		//printf("http3 read result=[%d]\n", ev[OP_READ].result);
		return ev[OP_READ].result;
	}
	int write_all(const kbuf* buf, int length) override {
#define KGL_RQ_WRITE_BUF_COUNT 64
		kgl_iovec iovec_buf[KGL_RQ_WRITE_BUF_COUNT];
		int left = length;
		while (left > 0 && buf) {
			/* prepare iovec_buf */
			int packed = 0;
			int bc = 0;
			for (; bc < KGL_RQ_WRITE_BUF_COUNT && left > 0 && buf; ++bc) {
				while (buf && buf->used == 0) {
					buf = buf->next;
				}
				if (buf == nullptr || buf->used < 0) {
					break;
				}
				iovec_buf[bc].iov_len = KGL_MIN(left, buf->used);
				iovec_buf[bc].iov_base = buf->data;
				packed += (int)iovec_buf[bc].iov_len;
				left -= (int)iovec_buf[bc].iov_len;
				buf = buf->next;
			}
			if (packed == 0) {
				return left;
			}
			kgl_iovec* hot_buf = iovec_buf;
			int remain = packed;
			while (bc > 0) {
				/* write iovec_buf */
				int got = internal_write(hot_buf, bc);
				if (got <= 0) {
					return left + remain;
				}
				if (got > remain) {
					return left + remain;
				}
				remain -= got;
				/* see iovec_buf left data */
				while (got > 0) {
					if ((int)hot_buf->iov_len > got) {
						hot_buf->iov_len -= got;
						hot_buf->iov_base = (char*)(hot_buf->iov_base) + got;
						break;
					}
					got -= (int)hot_buf->iov_len;
					hot_buf++;
					bc--;
				}
			}
		}
		return left;
	}
	int write_all(const char* str, int length) override {
		while (length > 0) {
			kgl_iovec buf;
			buf.iov_base = (char*)str;
			buf.iov_len = length;
			int got = internal_write(&buf, 1);
			if (got <= 0) {
				break;
			}
			length -= got;
			str += got;
		}
		return length;
	}
	int internal_write(WSABUF* buf, int bc)  {
		assert(!KBIT_TEST(st_flags, STF_WRITE));
		if (st == NULL) {
			return -1;
		}
		ev[OP_WRITE].buf = buf;
		ev[OP_WRITE].bc = bc;
		if (lsquic_stream_wantwrite(st, 1) < 0) {
			//printf("internal_write call wantwrite failed.\n");
			return -1;
		}
		KBIT_SET(st_flags, STF_WRITE);
		int got;
		ev[OP_WRITE].cd->f->wait(ev[OP_WRITE].cd, &got);
		assert(!KBIT_TEST(st_flags, STF_WRITE));
		assert(got == ev[OP_WRITE].result);
		int result = ev[OP_WRITE].result;
		if (result > 0) {
			if (content_left > 0) {
				content_left -= result;
			}
			add_down_flow(nullptr, result);
		}
		return result;
	}
	void on_read(lsquic_stream_t* st);
	void on_write(lsquic_stream_t* st);
	void start(int got) override;
	
	kgl_pool_t* get_connection_pool() override {
		return cn->get_pool();
	}
	void* get_sni() override {
		return cn->get_sni();
	}
	bool get_self_addr(sockaddr_i* addr) override {
		if (cn->c && cn->local_addr) {
			memcpy(addr, cn->local_addr, ksocket_addr_len((sockaddr_i*)cn->local_addr));
			return true;
		}
		return false;
	}
	void shutdown() override {
		//lsquic_stream_shutdown(st,SHUT_RDWR);
	}
	sockaddr_i* get_peer_addr() override {
		if (cn->c) {
			return (sockaddr_i*)cn->peer_addr;
		}
		return nullptr;
	}
	kselector* get_selector() override {
		return cn->engine->uc->st.base.selector;
	}
	void set_time_out(int tmo_count) override {

	}
	int get_time_out() override {
		return 30;
	}
	void flush() override {
		if (st) {
			lsquic_stream_flush(st);
		}
	}
	uint32_t get_server_model() override {
		return cn->engine->server->flags;
	}
	KOPAQUE get_server_opaque() override {
		return cn->engine->server->get_data();
	}
	int64_t get_response_left() override {
		return content_left;
	}
private:
	void build_header(lsxpack_header* header, const char* name, int name_len, const char* val, int val_len) {
		memset(header, 0, sizeof(lsxpack_header));
		size_t buf_len = name_len + val_len + 2;
		header->buf = (char*)kgl_pnalloc(pool, buf_len);
		memset(header->buf, 0, buf_len);
		kgl_strlow((u_char*)header->buf, (u_char*)name, name_len);
		header->name_len = name_len;
		header->val_len = val_len;
		header->val_offset = name_len + 1;
		kgl_memcpy(header->buf + header->val_offset, val, val_len);
	}
	KObjArray<lsxpack_header> response_headers;
	uint32_t st_flags;
	lsquic_stream_t* st;
	KHttp3Connection* cn;
	int64_t content_left;
	kgl_fiber_event ev[2];
};
struct header_decoder
{
	bool have_xhdr;
	bool is_first;
	struct lsxpack_header xhdr;
	size_t       decode_off;
	KHttp3Sink* sink;
	char         decode_buf[KGL_MIN(LSXPACK_MAX_STRLEN + 1, 64 * 1024)];
};

inline void free_header_decoder(struct header_decoder* r) {
	free(r);
}
#endif
#endif
