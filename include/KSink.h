#ifndef KSINK_H_99
#define KSINK_H_99
#include "kselector.h"
#include "kserver.h"
#include "kmalloc.h"
#include "KResponseContext.h"
#include "kgl_ssl.h"
#include "kstring.h"
#include "KRequest.h"
#include "kfiber.h"
#include "KHttpServer.h"
#include "KHttpFieldValue.h"
#define KGL_FLAG_PRECONDITION_MASK  7
//#define KGL_DEBUG_TIME
#ifdef KGL_DEBUG_TIME
void kgl_log_total_timespec();
#endif
struct kgl_request_ts
{
	kgl_list sinks;
};
namespace khttpd {
	template<typename T>
	inline bool response_headers(T* sink, const KHttpHeader* header) {
		while (header) {
			if (header->name_is_know) {
				if (!sink->response_header((kgl_header_type)header->know_header, header->buf + header->val_offset, header->val_len, !header->buf_cannot_lock)) {
					return false;
				}
			} else {
				if (!sink->response_header(header->buf, header->name_len, header->buf + header->val_offset, header->val_len)) {
					return false;
				}
			}
			header = header->next;
		}
		return true;
	}
}
extern krequest_start_func server_on_new_request;
extern pthread_key_t kgl_request_key;
class KSink
{
public:
#ifdef KGL_DEBUG_TIME
	void log_passed_time(const char* tip);
	void reset_start_time() {
		clock_gettime(CLOCK_REALTIME, &start_time);
	}
	struct timespec start_time;
#endif
	KSink(kgl_pool_t* pool) {
		init_pool(pool);
		kgl_request_ts* ts = (kgl_request_ts*)pthread_getspecific(kgl_request_key);
		assert(ts);
		klist_append(&ts->sinks, &queue);
#ifdef KGL_DEBUG_TIME
		reset_start_time();
#endif
	}
	virtual ~KSink() {
		data.free_header();
		if (pool) {
			kgl_destroy_pool(pool);
		}
		klist_remove(&queue);
	}
	template<typename T>
	T* alloc() {
		T* t = (T*)kgl_pnalloc(pool, sizeof(T));
		memset(t, 0, sizeof(T));
		return t;
	}
	void push_flow_info(KFlowInfo* fi) {
		KFlowInfoHelper* helper = new KFlowInfoHelper(fi);
		helper->next = data.fh;
		data.fh = helper;
	}
	void add_up_flow(int flow) {
		KFlowInfoHelper* helper = data.fh;
		while (helper) {
			helper->fi->AddUpFlow((INT64)flow);
			helper = helper->next;
		}
	}
	virtual void start(int header_len) = 0;
	bool adjust_range(int64_t* len) {
		assert(data.range);
		return kgl_adjust_range(data.range, len);
	}
	void add_down_flow(const kgl_iovec* suffix, int flow) {
		if (flow <= 0) {
			return;
		}
		if (suffix) {
			flow += (int)suffix->iov_len;
		}
		KFlowInfoHelper* helper = data.fh;
		while (helper) {
			helper->fi->AddDownFlow((INT64)flow, KBIT_TEST(data.flags, RQ_CACHE_HIT));
			helper = helper->next;
		}
	}
	bool response_header(kgl_header_type attr, int64_t value) {
		char* tmpbuf = (char*)kgl_pnalloc(pool, INT2STRING_LEN);
		int len = int2string2(value, tmpbuf);
		return response_header(attr, tmpbuf, len, true);
	}
	bool response_status(uint16_t status_code) {
		if (data.status_code > 0) {
			//status_code只能发送一次
			return false;
		}
		set_state(STATE_SEND);
		data.first_response_time_msec = kgl_current_msec;
		data.status_code = status_code;
		return internal_response_status(status_code);
	}
	virtual bool response_headers(const KHttpHeader* header) {
		return khttpd::response_headers<KSink>(this, header);
	}
	virtual bool response_header(kgl_header_type know_header, const char* val, int val_len, bool lock_value) {
		assert(know_header < kgl_header_unknow);
		return response_header(kgl_header_type_string[(int)know_header].value.data, (int)kgl_header_type_string[(int)know_header].value.len, val, val_len);
	}
	virtual bool readhup(void* arg, result_callback result) = 0;
	virtual void remove_readhup() = 0;
	virtual bool set_transfer_chunked() {
		return response_header(kgl_header_transfer_encoding, _KS("chunked"), true);
	}
	virtual bool response_trailer(const char* name, int name_len, const char* val, int val_len) {
		return true;
	}
	virtual bool response_header(const char* name, int name_len, const char* val, int val_len) = 0;
	virtual sockaddr_i* get_peer_addr() = 0;
	virtual int64_t get_response_left() {
		return -1;
	}
	bool get_peer_ip(char* ips, int ips_len) {
		sockaddr_i* addr = get_peer_addr();
		if (addr == nullptr) {
			return false;
		}
		return ksocket_sockaddr_ip(addr, ips, ips_len);
	}
	uint16_t get_self_port() {
		if (data.self_port > 0) {
			return data.self_port;
		}
		sockaddr_i addr;
		if (!get_self_addr(&addr)) {
			return 0;
		}
		data.self_port = ksocket_addr_port(&addr);
		return data.self_port;
	}
	void set_self_port(uint16_t port, bool ssl) {
		if (port > 0) {
			data.self_port = port;
		}
		if (ssl) {
			KBIT_SET(data.raw_url.flags, KGL_URL_SSL);
			if (data.raw_url.port == 80) {
				data.raw_url.port = 443;
			}
		} else {
			KBIT_CLR(data.raw_url.flags, KGL_URL_SSL);
			if (data.raw_url.port == 443) {
				data.raw_url.port = 80;
			}
		}
	}
	uint16_t get_self_ip(char* ips, int ips_len) {
		sockaddr_i addr;
		if (!get_self_addr(&addr)) {
			return 0;
		}
		if (!ksocket_sockaddr_ip(&addr, ips, ips_len)) {
			return 0;
		}
		if (data.self_port > 0) {
			return data.self_port;
		}
		data.self_port = ksocket_addr_port(&addr);
		return data.self_port;
	}
	const char* get_state();
	void set_state(uint8_t state) {
#ifdef ENABLE_STAT_STUB
		if (data.state == state) {
			return;
		}
		switch (data.state) {
		case STATE_IDLE:
			katom_dec((void*)&kgl_waiting);
			break;
		case STATE_RECV:
			katom_dec((void*)&kgl_reading);
			break;
		case STATE_SEND:
			katom_dec((void*)&kgl_writing);
			break;
		}
#endif
		data.state = state;
#ifdef ENABLE_STAT_STUB
		switch (state) {
		case STATE_IDLE:
			katom_inc((void*)&kgl_waiting);
			break;
		case STATE_RECV:
			katom_inc((void*)&kgl_reading);
			break;
		case STATE_SEND:
			katom_inc((void*)&kgl_writing);
			break;
		}
#endif

	}
	virtual kselector* get_selector() = 0;
	virtual void shutdown() = 0;
	virtual uint32_t get_server_model() = 0;
	virtual KOPAQUE get_server_opaque() = 0;
	virtual KHttpHeader* get_trailer() {
		return nullptr;
	}
	virtual void set_time_out(int tmo_count) = 0;
	virtual kgl_pool_t* get_connection_pool() = 0;
	virtual int get_time_out() = 0;
	virtual void set_delay() {}
	virtual void set_no_delay(bool forever) {}
	virtual void flush() {
		set_no_delay(false);
		set_delay();
	}
	virtual kssl_session* get_ssl() {
		return nullptr;
	}
	const char* get_client_ip() {
		if (data.client_ip) {
			return data.client_ip;
		}
		data.client_ip = (char*)xmalloc(MAXIPLEN);
		if (get_peer_ip(data.client_ip, MAXIPLEN)) {
			return data.client_ip;
		}
		return "";
	}
	virtual void end_request() {

	}
	void set_client_ip(const char* ip) {
		if (data.client_ip) {
			xfree(data.client_ip);
		}
		data.client_ip = strdup(ip);
	}
	bool start_response_body(INT64 body_len) {
		assert(!KBIT_TEST(data.flags, RQ_HAS_SEND_HEADER));
		if (KBIT_TEST(data.flags, RQ_HAS_SEND_HEADER)) {
			return true;
		}
		KBIT_SET(data.flags, RQ_HAS_SEND_HEADER);
		if (likely(!is_status_code_no_body(data.status_code))) {
			if (body_len >= 0) {
				/* know content-length and response header */
				response_header(kgl_header_content_length, body_len);
			} else {
				/* unknow content-length */
				if (data.http_version == 0x100) {
					//HTTP/1.0 client not support transfer-encoding
					//The connection MUST close
					KBIT_SET(data.flags, RQ_CONNECTION_CLOSE);
				} else if (!KBIT_TEST(data.flags, RQ_CONNECTION_UPGRADE) && set_transfer_chunked()) {
					KBIT_SET(data.flags, RQ_TE_CHUNKED);
				}
			}
		} else {
			/* status_code is no body not need send content-length */
			body_len = 0;
		}
		if (data.meth == METH_HEAD) {
			/* request is HEAD method so do not send any body */
			body_len = 0;
		}
		int header_len = internal_start_response_body(body_len, false);
		add_down_flow(nullptr, header_len);
		return header_len >= 0;
	}
	int read(char* buf, int len);
	/*
	* write_all will send data until all success or failed.
	* if failed return left byte to send.
	* if return 0 will all success.
	* notice: left byte may be greater than len.
	*/
	virtual int write_all(const char* buf, int len) = 0;
	virtual int write_all(const kbuf* buf, int len) {
		while (len > 0) {
			int got = KGL_MIN(len, buf->used);
			len -= got;
			int left = write_all(buf->data, got);
			if (left > 0) {
				return len + left;
			}
			buf = buf->next;
		}
		return len;
	}
	template<typename T>
	bool parse_header(T attr, int attr_len, T val, int val_len, bool is_first) {
		//printf("%.*s%s%.*s\n",attr_len, attr, (is_first?" ":": "),val_len, val);
		if (is_first) {
			start_parse();
			assert(!data.header);
		}
#if defined(ENABLE_HTTP2) || defined(ENABLE_HTTP3)
		if (data.http_version > 0x100 && *attr == ':') {
			//pseudo header
			if (kgl_mem_same(attr, attr_len, kgl_expand_string(":method"))) {
				if (!data.parse_method(val, val_len)) {
					return false;
				}
				if (data.meth == METH_CONNECT) {
					data.meth = METH_GET;
					KBIT_SET(data.flags, RQ_HAS_CONNECTION_UPGRADE);
				}
				return true;
			}
			if (kgl_mem_same(attr, attr_len, kgl_expand_string(":version"))) {
				return data.parse_http_version((u_char*)val, val_len);
			}
			if (kgl_mem_same(attr, attr_len, kgl_expand_string(":path"))) {
				return parse_url(val, val_len, &data.raw_url);
			}
			if (kgl_mem_same(attr, attr_len, kgl_expand_string(":authority"))) {
				return data.parse_host(val, val_len);
			}
			if (kgl_mem_same(attr, attr_len, _KS(":protocol"))) {
				return data.add_header(pool, kgl_header_upgrade, val, val_len);
			}
			return true;
		}
#endif
		if (is_first && data.http_version < 0x200) {
			if (!data.parse_method(attr, attr_len)) {
				//klog(KLOG_DEBUG, "httpparse:cann't parse meth=[%s]\n", attr);
				return false;
			}
			u_char* val_end = (u_char*)val + val_len;
			u_char* space = (u_char*)memchr(val, ' ', val_len);
			if (space == NULL) {
				//klog(KLOG_DEBUG, "httpparse:cann't get space seperator to parse HTTP/1.1 [%s]\n", val);
				return false;
			}
			size_t url_len = space - (u_char*)val;
			u_char* version = space;
			while (version < val_end && IS_SPACE(*version)) {
				version++;
			}
			*space = 0;
			switch (data.meth) {
			case METH_CONNECT:
				if (!data.parse_connect_url((u_char*)val, url_len)) {
					return false;
				}
			case METH_PRI:
				return true;
			default:
				if (!parse_url(val, url_len, &data.raw_url)) {
					return false;
				}
			}
			if (!data.parse_http_version(version, (size_t)(val_end - version))) {
				//klog(KLOG_DEBUG, "httpparse:cann't parse http version [%s]\n", space);
				return false;
			}
			if (data.http_version > 0x100) {//data.http_major > 1 || (data.http_major == 1 && data.http_minor == 1)) {
				KBIT_SET(data.flags, RQ_HAS_KEEP_CONNECTION);
			}
			return true;
		}
		switch (*attr) {
		case 'A':
		case 'a':
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("Accept-Encoding"))) {
				KHttpFieldValue field(val, val + val_len);
				int64_t q;
				for (;;) {
					const char* field_end = field.get_field_end();
					if (field.get_double_param(_KS("q"), field_end, 3, &q)) {
						if (q == 0) {
							goto next_field;
						}
					}
					if (field.is(kgl_expand_string("gzip"))) {
						KBIT_SET(data.raw_url.accept_encoding, KGL_ENCODING_GZIP);
					} else if (field.is(kgl_expand_string("deflate"))) {
						KBIT_SET(data.raw_url.accept_encoding, KGL_ENCODING_DEFLATE);
					} else if (field.is(kgl_expand_string("compress"))) {
						KBIT_SET(data.raw_url.accept_encoding, KGL_ENCODING_COMPRESS);
					} else if (field.is(kgl_expand_string("br"))) {
						KBIT_SET(data.raw_url.accept_encoding, KGL_ENCODING_BR);
					} else if (field.is(kgl_expand_string("zstd"))) {
						KBIT_SET(data.raw_url.accept_encoding, KGL_ENCODING_ZSTD);
					} else if (!field.is(kgl_expand_string("identity"))) {
						KBIT_SET(data.raw_url.accept_encoding, KGL_ENCODING_UNKNOW);
					}
				next_field:
					if (!field.next(field_end)) {
						break;
					}
				}
				return data.add_header(pool, kgl_header_accept_encoding, val, val_len);
			}
			break;
		case 'C':
		case 'c':
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("Connection"))
#ifdef HTTP_PROXY
				|| kgl_mem_case_same(attr, attr_len, kgl_expand_string("proxy-connection"))
#endif
				) {
				KHttpFieldValue field(val, val + val_len);
				do {
					if (field.is(_KS("keep-alive"))) {
						data.flags |= RQ_HAS_KEEP_CONNECTION;
					} else if (field.is(_KS("upgrade"))) {
						data.flags |= RQ_HAS_CONNECTION_UPGRADE;
					} else if (field.is(_KS("close"))) {
						KBIT_CLR(data.flags, RQ_HAS_KEEP_CONNECTION);
					}
				} while (field.next());
				return data.add_header(pool, kgl_header_connection, val, val_len);
			}
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("Content-length"))) {
				return data.parse_content_length(val, val_len);
			}
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("Cache-Control"))) {
				KHttpFieldValue field(val, val + val_len);
				do {
					if (field.is(_KS("no-store")) || field.is(_KS("no-cache"))) {
						data.flags |= RQ_HAS_NO_CACHE;
					} else if (field.is(_KS("only-if-cached"))) {
						data.flags |= RQ_HAS_ONLY_IF_CACHED;
					}
				} while (field.next());
				return data.add_header(pool, kgl_header_cache_control, val, val_len);
			}
			break;
		case 'E':
		case 'e':
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("Expect"))) {
				if (kgl_memstr(val, val_len, kgl_expand_string("100-continue")) != NULL) {
					data.flags |= RQ_HAVE_EXPECT;
					return data.add_header(pool, kgl_header_expect, val, val_len);
				}
				//unknow expect header.
				return true;
			}
			break;
		case 'H':
		case 'h':
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("Host"))) {
				return data.parse_host(val, val_len);
			}
			break;
		case 'I':
		case 'i':
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("If-Range"))) {
				time_t try_time = kgl_parse_http_time((u_char*)val, val_len);
				if (try_time == -1) {
					alloc_request_range()->if_range_entity = alloc_entity(val, val_len);
					KBIT_CLR(data.flags, RQ_IF_RANGE_DATE);
				} else {
					alloc_request_range()->if_range_date = try_time;
					KBIT_SET(data.flags, RQ_IF_RANGE_DATE);
				}
				return true;
			}
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("If-Modified-Since"))) {
				if (data.precondition.time == 0) {
					data.precondition.time = kgl_parse_http_time((u_char*)val, val_len);
					KBIT_SET(data.flags, RQ_IF_TIME);
				}
				return true;
			}
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("If-None-Match"))) {
				data.precondition.entity = alloc_entity(val, val_len);
				KBIT_CLR(data.flags, RQ_IF_TIME | RQ_IF_MATCH_UNMODIFIED);
				return true;
			}
			break;
		case 'P':
		case 'p':
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("Pragma"))) {
				if (kgl_memstr(val, val_len, kgl_expand_string("no-cache"))) {
					data.flags |= RQ_HAS_NO_CACHE;
				}
				return data.add_header(pool, kgl_header_pragma, val, val_len);
			}
			break;
		case 'R':
		case 'r':
			if (kgl_mem_case_same(attr, attr_len, _KS("Referer"))) {
				return data.add_header(pool, kgl_header_referer, val, val_len);
			}
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("Range"))) {
				if (val_len > 6 && !strncasecmp(val, kgl_expand_string("bytes="))) {
					u_char* end = (u_char*)val + val_len;
					u_char* hot = (u_char*)val + 6;
					kgl_request_range* range = alloc_request_range();
					if (*hot == '-') {
						/* last range model */
						range->from = -kgl_atol(hot + 1, end - hot - 1);
						return true;
					}
					range->from = kgl_atol(hot, end - hot);
					hot = (u_char*)memchr(hot, '-', end - hot);
					if (hot && hot < end - 1) {
						hot++;
						range->to = kgl_atol(hot, end - hot);
					} else {
						/* to end */
						range->to = -1;
					}
					/*
					u_char* next_range = (u_char*)memchr(hot, ',', end - hot);
					if (next_range) {
						//we do not support multi range
						end = next_range;
						return data.add_header(pool, kgl_header_range, val, (int)(end - (u_char*)val), true);
					}
					*/
					return true;
				}
				return data.add_header(pool, kgl_header_range, val, val_len);
			}
			break;
		case 'T':
		case 't':
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("Transfer-Encoding"))) {
				if (!kgl_mem_case_same(val, val_len, kgl_expand_string("chunked")) ||
					KBIT_TEST(data.flags, RQ_HAS_CONTENT_LEN)) {
					return false;
				}
				KBIT_SET(data.flags, RQ_INPUT_CHUNKED);
				data.left_read = -1;
				return true;
			}
			break;
		case 'U':
		case 'u':
			if (kgl_mem_case_same(attr, attr_len, _KS("User-Agent"))) {
				return data.add_header(pool, kgl_header_user_agent, val, val_len);
			}
			if (kgl_mem_case_same(attr, attr_len, _KS("Upgrade"))) {
				return data.add_header(pool, kgl_header_upgrade, val, val_len);
			}
			break;
		case 'X':
		case 'x':
			if (kgl_mem_case_same(attr, attr_len, kgl_expand_string("X-Forwarded-Proto"))) {
				if (kgl_mem_case_same(val, val_len, kgl_expand_string("https"))) {
					KBIT_SET(data.raw_url.flags, KGL_URL_ORIG_SSL);
				} else {
					KBIT_CLR(data.raw_url.flags, KGL_URL_ORIG_SSL);
				}
				return true;
			}
			break;
		default:
			break;
		}
		return data.add_header(pool, attr, attr_len, val, val_len);
	}
	bool begin_request() {
		katom_inc64((void*)&kgl_total_requests);
		set_state(STATE_RECV);
		assert(data.url == NULL);
		if (!data.raw_url.host) {
			return false;
		}
		data.url = new KUrl(true);
		if (data.raw_url.host) {
			data.url->host = xstrdup(data.raw_url.host);
		}
		if (data.raw_url.param) {
			data.url->param = strdup(data.raw_url.param);
		}
		data.url->flag_encoding = data.raw_url.flag_encoding;
		data.url->port = data.raw_url.port;
		if (data.raw_url.path) {
			data.url->path = xstrdup(data.raw_url.path);
			url_decode(data.url->path, 0, data.url, false);
		}
		return true;
	}
	virtual bool is_locked() = 0;
	kgl_precondition_flag get_precondition_flag() {
		return (kgl_precondition_flag)(data.flags & KGL_FLAG_PRECONDITION_MASK);
	}
	kgl_precondition* get_precondition(kgl_precondition_flag* flag) {
		*flag = get_precondition_flag();
		if (data.precondition.entity) {
			return &data.precondition;
		}
		return NULL;
	}
	virtual kgl_proxy_protocol* get_proxy_info() {
		return nullptr;
	}
	virtual void* get_sni() {
		return nullptr;
	}
	virtual bool support_sendfile() {
		return false;
	}
	virtual int sendfile(kasync_file* fp, int len) {
		return -1;
	}
	virtual bool get_self_addr(sockaddr_i* addr) = 0;
	kgl_len_str_t* alloc_entity(const char* entity_value, int len) {
		kgl_len_str_t* entity = (kgl_len_str_t*)kgl_pnalloc(pool, kgl_len_str_size(len));
		entity->len = len;
		kgl_memcpy(entity->data, entity_value, len);
		entity->data[len] = '\0';
		return entity;
	}
	kgl_list queue;
	kgl_pool_t* pool;
	KRequestData data;
	friend class KHttp2;
protected:
	void start_parse() {
		if (KBIT_TEST(get_server_model(), WORK_MODEL_SSL)) {
			KBIT_SET(data.raw_url.flags, KGL_URL_SSL | KGL_URL_ORIG_SSL);
		}
	}

	void init_pool(kgl_pool_t* pool) {
		this->pool = pool;
		if (this->pool == NULL) {
			this->pool = kgl_create_pool(KGL_REQUEST_POOL_SIZE);
		}
	}
	virtual int internal_read(char* buf, int len) = 0;
	virtual bool internal_response_status(uint16_t status_code) = 0;
	virtual int internal_start_response_body(int64_t body_size, bool is_100_continue) = 0;
private:
	bool response_100_continue();

	kgl_request_range* alloc_request_range() {
		if (data.range) {
			return data.range;
		}
		data.range = (kgl_request_range*)kgl_pnalloc(pool, sizeof(kgl_request_range));
		*data.range = { 0 };
		return data.range;
	}
};
bool kgl_init_sink_queue();
typedef bool (*kgl_sink_iterator)(void* ctx, KSink* sink);
void kgl_iterator_sink(kgl_sink_iterator it, void* ctx);
inline void khttp_server_new_request(KSink* sink, int got) {
	if (!sink->begin_request()) {
		KBIT_SET(sink->data.flags, RQ_CONNECTION_CLOSE);
		return;
	}
	server_on_new_request(sink, got);
}
#endif
