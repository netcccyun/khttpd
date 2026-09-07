#include "KHttp2.h"
#include "kselector.h"
#include "kconnection.h"
#include "KRequest.h"
#include "KHttp2Sink.h"
#include "KHttp2Upstream.h"
#include "kfiber.h"
#include "KHttpServer.h"
#include "KHttpKeyValue.h"
#include "klog.h"
#include "KPreRequest.h"

#ifdef ENABLE_HTTP2
http2_buff* KHttp2::get_frame(uint32_t sid, size_t length, uint8_t type, u_char flags) {
	if (write_buffer.getCountedFrames() >= KGL_HTTP_V2_MAX_FRAMES) {
		klog(KLOG_WARNING, "http2 flood detected, outstanding frames=%d\n", write_buffer.getCountedFrames());
		return NULL;
	}
	http2_buff* buf = new http2_buff;
	http2_frame_header* h = (http2_frame_header*)malloc(length + sizeof(http2_frame_header));
	if (h == NULL) {
		delete buf;
		return NULL;
	}
	buf->used = (int)(length + sizeof(http2_frame_header));
	buf->counted = 1;
	memset(h, 0, buf->used);
	buf->data = (char*)h;
	h->set_length_type((int)length, (int)type);
	h->flags = (uint8_t)flags;
	h->stream_id = htonl(sid);
	return buf;
}
kgl_http_v2_handler_pt KHttp2::kgl_http_v2_frame_states[] = {
	&KHttp2::state_data,
	&KHttp2::state_headers,
	&KHttp2::state_priority,
	&KHttp2::state_rst_stream,
	&KHttp2::state_settings,
	&KHttp2::state_push_promise,
	&KHttp2::state_ping,
	&KHttp2::state_goaway,
	&KHttp2::state_window_update,
	&KHttp2::state_continuation,
	&KHttp2::state_altsvc
};
#define KGL_HTTP_V2_FRAME_STATES                                              \
    (sizeof(kgl_http_v2_frame_states) / sizeof(kgl_http_v2_handler_pt))
#define MAX_FRAME_BODY  65536
void dump_hex(void* d, int len) {
	unsigned char* s = (unsigned char*)d;
	for (int i = 0; i < len; i++) {
		printf("%02x ", s[i]);
	}
	printf("\n");
}

void kgl_init_header_string() {
#ifdef ENABLE_HTTP2
	for (int i = 0; i < kgl_header_unknow; ++i) {
		kgl_header_type_string[i].http2_index = kgl_find_http2_static_table(&kgl_header_type_string[i].low_case);
		//printf("[%s] index=[%d]\n", kgl_header_type_string[i].low_case.data, kgl_header_type_string[i].http2_index);
	}
#endif
}
kev_result resultHttp2Read(KOPAQUE data, void* arg, int got) {
	KHttp2* http2 = (KHttp2*)data;
	return http2->on_read_result(arg, got);
}
kev_result resultHttp2Write(KOPAQUE data, void* arg, int got) {
	KHttp2* http2 = (KHttp2*)data;
	return http2->on_write_result(arg, got);
}
kev_result http2_next_write(KOPAQUE data, void* arg, int got) {
	kassert(got <= 0);
	KHttp2* http2 = (KHttp2*)data;
	return http2->NextWrite(got);
}
kev_result http2_next_read(KOPAQUE data, void* arg, int got) {
	KHttp2* http2 = (KHttp2*)data;
	return http2->NextRead(got);
}

static bool construct_cookie_header(KHttp2Context* ctx, KHttp2Sink* r) {
	char* buf, * p, * end;
	size_t                      len;
	kgl_str_t* vals;
	size_t                  i;
	kgl_array_t* cookies;
	kgl_http_v2_header_t h;
	kgl_str_set(&h.name, "cookie");

	cookies = ctx->cookies;

	if (cookies == NULL) {
		return true;
	}

	vals = (kgl_str_t*)cookies->elts;

	i = 0;
	len = 0;

	do {
		len += vals[i].len + 2;
	} while (++i != cookies->nelts);

	len -= 2;

	buf = (char*)kgl_pnalloc(r->pool, len + 1);
	if (buf == NULL) {
		return false;
	}
	p = buf;
	end = buf + len;

	for (i = 0; /* void */; i++) {

		p = (char*)kgl_cpymem(p, vals[i].data, vals[i].len);

		if (p == end) {
			*p = '\0';
			break;
		}

		*p++ = ';'; *p++ = ' ';
	}

	h.value.len = len;
	h.value.data = buf;
#if 0
	if (ctx->read_trailer) {
		ctx->get_trailer_header()->add_header(h.name.data, (int)h.name.len, h.value.data, (int)h.value.len);
	}
#endif
	r->parse_header(h.name.data, (int)h.name.len, h.value.data, (int)h.value.len);
	return true;
}
KHttp2::KHttp2() {
	//printf("new http2=[%p]\n", this);
	memset(this, 0, sizeof(*this));
	hpack.size = KGL_HTTP_V2_TABLE_SIZE;
	hpack.free = KGL_HTTP_V2_TABLE_SIZE;
	streams_index = (KHttp2Node**)malloc(sizeof(KHttp2Node*) * kgl_http_v2_index_size());
	memset(streams_index, 0, sizeof(KHttp2Node*) * kgl_http_v2_index_size());
	klist_init(&active_queue);
	read_buffer[0].iov_base = (char*)&read_buffer[1];
	read_buffer[0].iov_len = 1;
}
KHttp2::~KHttp2() {
	//printf("~KHttp2 called [%p]\n",this);
	assert(!destroyed);
	kassert(write_processing == 0 && read_processing == 0 && processing == 0);
	kconnection_destroy(c);
	ReleaseStateStream();
#ifndef NDEBUG
	destroyed = 1;
	for (int i = 0; i < kgl_http_v2_index_size(); i++) {
		KHttp2Node* node = streams_index[i];
		kassert(node == NULL);
	}
#endif
	if (!state.keep_pool && state.pool) {
		kgl_destroy_pool(state.pool);
#ifndef NDEBUG
		state.pool = NULL;
#endif
	}
	xfree(streams_index);
	kassert(klist_empty(&active_queue));
}
bool KHttp2::send_settings_ack() {
	http2_buff* buf = get_frame(0, 0, KGL_HTTP_V2_SETTINGS_FRAME, KGL_HTTP_V2_ACK_FLAG);
	if (buf == NULL) {
		return false;
	}
	write_buffer.push(buf);
	start_write();
	return true;
}
bool KHttp2::send_settings() {
	int setting_frame_count = 3;
	if (KGL_HTTP_V2_STREAM_RECV_WINDOW != KGL_HTTP_V2_DEFAULT_WINDOW) {
		setting_frame_count++;
	}
	int len = (sizeof(http2_frame_setting)) * setting_frame_count;
	http2_buff* buf = get_frame(0, len, KGL_HTTP_V2_SETTINGS_FRAME, 0);
	if (buf == NULL) {
		return false;
	}
	http2_frame_setting* setting = (http2_frame_setting*)(buf->data + sizeof(http2_frame_header));
	setting->id = htons(KGL_HTTP_V2_MAX_STREAMS_SETTING);
	setting->value = htonl((uint32_t)max_stream);
	if (KGL_HTTP_V2_STREAM_RECV_WINDOW != KGL_HTTP_V2_DEFAULT_WINDOW) {
		setting++;
		setting->id = htons(KGL_HTTP_V2_INIT_WINDOW_SIZE_SETTING);
		setting->value = (uint32_t)htonl(KGL_HTTP_V2_STREAM_RECV_WINDOW);
	}
	setting++;
	setting->id = (uint16_t)htons(KGL_HTTP_V2_MAX_FRAME_SIZE_SETTING);
	setting->value = (uint32_t)htonl(KGL_HTTP_V2_MAX_FRAME_SIZE);

	setting++;
	setting->id = (uint16_t)htons(KGL_HTTP_V2_ENABLE_CONNECT_SETTING);
	setting->value = (uint32_t)htonl(1);

	write_buffer.push(buf);
	start_write();
	return true;
}
bool KHttp2::send_window_update(uint32_t sid, size_t window) {
	if (window == 0) {
		return false;
	}
	//printf("stream id=[%d] send windows update [%d]\n", sid, window);
	http2_buff* buf = get_frame(sid, sizeof(http2_frame_window_update), KGL_HTTP_V2_WINDOW_UPDATE_FRAME, 0);
	if (buf == NULL) {
		return false;
	}
	http2_frame_window_update* b = (http2_frame_window_update*)(buf->data + sizeof(http2_frame_header));
	b->inc_size = htonl((uint32_t)window);
	buf->tcp_nodelay = 1;
	write_buffer.push(buf);
	return true;
}
u_char* KHttp2::close(bool read, int status) {
	kassert(kselector_is_same_thread(c->st.base.selector));
	//printf("%lld http2 [%p] close read=[%d] status=[%d]\n", kgl_current_sec,this,read,status);
	http2_buff* buf = NULL;
	if (!read && write_buffer.getBufferSize() > 0) {
		//write出错，清理正在写的buffer
		buf = write_buffer.clean();
	}
	KHttp2Node* node;
	KHttp2Context* stream;
	int size = kgl_http_v2_index_size();
	kgl_http2_event* read_event, * write_event;
	//clean wait event
	for (int i = 0; i < size; i++) {
		node = streams_index[i];
		while (node) {
			stream = node->stream;
			assert(stream == NULL || stream->node == node);
			node = node->index;
			if (stream == NULL) {
				continue;
			}
			stream->in_closed = 1;
			stream->out_closed = 1;
			stream->rst = 1;
			read_event = stream->read_wait;
			stream->read_wait = NULL;
			if (stream->write_wait && !IS_WRITE_WAIT_FOR_WRITING(stream->write_wait)) {
				//WAIT_FOR_WRITING的由remove_buff清理
				write_event = stream->write_wait;
				stream->write_wait = NULL;
			} else {
				write_event = NULL;
			}
			stream->RemoveQueue();
			if (read_event) {
				read_event->on_read(-1);
				delete read_event;
			}
			if (write_event) {
				write_event->on_write(-1);
				delete write_event;
			}
		}
	}
	if (buf) {
		KHttp2WriteBuffer::remove_buff(buf, true);
	}
	//read_processing/write_processing  要最后置0。
	closed = 1;
	KBIT_SET(c->st.base.st_flags, STF_ERR);
	if (read) {
		assert(read_processing == 1);
		read_processing = 0;
		self_goaway = 1;
	} else {
		assert(write_processing == 1);
		write_processing = 0;
	}
	if (can_destroy()) {
		delete this;
	}
	return NULL;
}
kev_result KHttp2::on_read_result(void* arg, int got) {
	assert(arg == c);
	assert(read_processing);
	//printf("http2=[%p] got=[%d]\n",this,got);
	if (got == ST_ERR_TIME_OUT) {
		if (pinged) {
			selectable_shutdown(&c->st);
			return kev_ok;
		}
		ping();
		return kev_ok;
	}
	if (got <= 0) {
		close(true, KGL_HTTP_V2_CONNECT_ERROR);
		return kev_ok;
	}
	pinged = 0;
	u_char* p = state.buffer;
	u_char* end = p + state.buffer_used + got;
	state.buffer_used = 0;
	state.incomplete = 0;
	do {
		p = (this->*state.handler)(p, end);
		if (p == NULL) {
			return kev_err;
		}
	} while (p != end);

	return start_read();
}
u_char* KHttp2::handle_continuation(u_char* pos, u_char* end, kgl_http_v2_handler_pt handler) {
	u_char* p;
	size_t     len, skip;
	uint32_t   head;

	len = state.length;
	if (state.padding && (size_t)(end - pos) > len) {
		skip = KGL_MIN(state.padding, (end - pos) - len);

		state.padding -= (uint8_t)skip;

		p = pos;
		pos += skip;
		memmove(pos, p, len);
	}

	if ((size_t)(end - pos) < len + KGL_HTTP_V2_FRAME_HEADER_SIZE) {
		return state_save(pos, end, handler);
	}

	p = pos + len;

	head = kgl_http_v2_parse_uint32(p);

	if (kgl_http_v2_parse_type(head) != KGL_HTTP_V2_CONTINUATION_FRAME) {
		klog(KLOG_WARNING, "client sent inappropriate frame while CONTINUATION was expected\n");
		return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
	}

	state.length += kgl_http_v2_parse_length(head);
	state.flags |= p[4];

	if (state.sid != kgl_http_v2_parse_sid(&p[5])) {
		klog(KLOG_WARNING,
			"client sent CONTINUATION frame with incorrect identifier\n");

		return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
	}

	p = pos;
	pos += KGL_HTTP_V2_FRAME_HEADER_SIZE;

	memmove(pos, p, len);
	state.handler = handler;
	return pos;
}
bool KHttp2::add_cookie(kgl_http_v2_header_t* header) {
	kgl_str_t* val;
	kgl_array_t* cookies;
	KSink* r = state.stream->sink;
	cookies = state.stream->cookies;

	if (cookies == NULL) {
		cookies = kgl_array_create(r->pool, 2, sizeof(kgl_str_t));
		if (cookies == NULL) {
			return false;
		}

		state.stream->cookies = cookies;
	}

	val = (kgl_str_t*)kgl_array_push(cookies);
	if (val == NULL) {
		return false;
	}

	val->len = header->value.len;
	val->data = header->value.data;

	return true;
}


u_char* KHttp2::state_process_header(u_char* pos, u_char* end) {
	size_t                      len;
	//intptr_t                   rc;
	//kgl_table_elt_t            *h;
	KHttp2Sink* r;
	kgl_http_v2_header_t* header;

	static kgl_str_t cookie = kgl_string("cookie");

	header = &state.header;

	if (state.parse_name) {
		state.parse_name = 0;

		header->name.len = state.field_end - state.field_start;
		header->name.data = (char*)state.field_start;
		if (header->name.len == 0) {
			klog(KLOG_ERR, "client sent zero header name length\n");
			return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
		}
		return state_field_len(pos, end);
	}

	if (state.parse_value) {
		state.parse_value = 0;
		header->value.len = state.field_end - state.field_start;
		header->value.data = (char*)state.field_start;
	}

	len = header->name.len + header->value.len;

	state.header_length += (uint32_t)len;
	if (state.header_length > 1048576) {
		klog(KLOG_ERR, "client exceeded http2_max_header_size limit\n");
		return this->close(true, KGL_HTTP_V2_ENHANCE_YOUR_CALM);
	}

	if (state.index) {
		if (!add_header(header)) {
			klog(KLOG_ERR, "http2 cann't add_header\n");
			return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
		}
		state.index = 0;
	}
	KHttp2Context* stream = state.stream;
	if (stream == NULL || !stream->is_available()) {
		return state_header_complete(pos, end);
	}
	if (header->name.data == NULL || header->value.data == NULL) {
		return state_header_complete(pos, end);
	}
	if (!client_model &&
		header->name.len == cookie.len &&
		memcmp(header->name.data, cookie.data, cookie.len) == 0) {
		if (!add_cookie(header)) {
			return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
		}
		return state_header_complete(pos, end);
	}
#if 0
	if (stream->read_trailer) {
		stream->get_trailer_header()->add_header(header->name.data, (int)header->name.len, header->value.data, (int)header->value.len);
		return state_header_complete(pos, end);
	}
#endif

	//printf("request name=[%s][%d %d] val=[%s][%d]\n", header->name.data, header->name.len, strlen(header->name.data), header->value.data, header->value.len);
#ifdef ENABLE_UPSTREAM_HTTP2
	if (client_model) {
		kassert(state.stream->node);
		stream->us->parse_header(header->name.data, (int)header->name.len, header->value.data, (int)header->value.len);
		return state_header_complete(pos, end);
	}
#endif	
	r = state.stream->sink;
	if (!r->parse_header(header->name.data, (int)header->name.len,
		header->value.data, (int)header->value.len)) {
		terminate_stream(stream, KGL_HTTP_V2_PROTOCOL_ERROR);
	}
	return state_header_complete(pos, end);
}


u_char* KHttp2::state_header_block(u_char* pos, u_char* end) {
	u_char      ch;
	intptr_t   value;
	uintptr_t  indexed, size_update, prefix;

	if (end - pos < 1) {
		return state_save(pos, end, &KHttp2::state_header_block);
	}
	if (!(state.flags & KGL_HTTP_V2_END_HEADERS_FLAG)
		&& state.length < KGL_HTTP_V2_INT_OCTETS) {
		return handle_continuation(pos, end, &KHttp2::state_header_block);
	}

	size_update = 0;
	indexed = 0;

	ch = *pos;

	if (ch >= (1 << 7)) {
		/* indexed header field */
		indexed = 1;
		prefix = kgl_http_v2_prefix(7);

	} else if (ch >= (1 << 6)) {
		/* literal header field with incremental indexing */
		state.index = 1;
		prefix = kgl_http_v2_prefix(6);

	} else if (ch >= (1 << 5)) {
		/* dynamic table size update */
		size_update = 1;
		prefix = kgl_http_v2_prefix(5);

	} else if (ch >= (1 << 4)) {
		/* literal header field never indexed */
		prefix = kgl_http_v2_prefix(4);

	} else {
		/* literal header field without indexing */
		prefix = kgl_http_v2_prefix(4);
	}

	value = parse_int(&pos, end, prefix);
	if (value < 0) {
		if (value == KGL_AGAIN) {
			return state_save(pos, end, &KHttp2::state_header_block);
		}
		if (value == KGL_DECLINED) {
			klog(KLOG_WARNING, "client sent header block with too long %s value\n",
				size_update ? "size update" : "header index");

			return this->close(true, KGL_HTTP_V2_COMP_ERROR);
		}
		klog(KLOG_WARNING, "client sent header block with incorrect length\n");
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}

	if (indexed) {
		if (!get_indexed_header(value, false)) {
			klog(KLOG_ERR, "http2 cann't get indexed header [%d] name_only=false\n", value);
			return this->close(true, KGL_HTTP_V2_COMP_ERROR);
		}
		return state_process_header(pos, end);
	}
	if (size_update) {
		if (!table_size(value)) {
			return this->close(true, KGL_HTTP_V2_COMP_ERROR);
		}
		return state_header_complete(pos, end);
	}

	if (value == 0) {
		state.parse_name = 1;
	} else if (!get_indexed_header(value, true)) {
		klog(KLOG_ERR, "http2 cann't get indexed header [%d] name_only=true\n", value);
		return this->close(true, KGL_HTTP_V2_COMP_ERROR);
	}
	state.parse_value = 1;
	return state_field_len(pos, end);
}

u_char* KHttp2::state_skip_padded(u_char* pos, u_char* end) {
	state.length += state.padding;
	state.padding = 0;
	return state_skip(pos, end);
}

bool KHttp2::on_header_success(KHttp2Context* stream) {

#ifdef ENABLE_UPSTREAM_HTTP2
	if (client_model) {
		if (stream->has_upgrade) {
			kgl_http2_event* re = stream->read_wait;
			if (re) {
				re->header(stream->us, re->header_arg, _KS("Connection"), _KS("Upgrade"), false);
			}
		}
		if (stream->is_100_continue) {
			stream->is_100_continue = 0;
			if (stream->read_wait) {
				//不能删除read_wait,因为还要继续读.
				stream->read_wait->on_read(0);
			}
			return true;
		}
		stream->parsed_header = 1;
	}
#endif
	if (!stream->is_available()) {
		return true;
	}
	if (!client_model) {
		if (!construct_cookie_header(stream, stream->sink)) {
			return false;
		}
	}
	//printf("%lld http2=[%p] stream=[%d] header complete\n", kgl_current_sec,this, stream->node->id);
	//client模式中在等待读header的过程中，有可能就会被客户端connection broken而导致shutdown.
	//而发生stream已经被释放时，stream->request会变成无效
	if (client_model || stream->parsed_header) {
		state.stream = NULL;
		kgl_http2_event* read_wait = stream->read_wait;
		if (read_wait) {
			stream->read_wait = NULL;
			kassert(stream->queue.next == NULL);
			read_wait->on_read(0);
			delete read_wait;
		}
		return true;
	}
	if (!KBIT_TEST(stream->sink->data.flags, RQ_HAS_CONTENT_LEN) && !stream->in_closed) {
		stream->sink->data.left_read = -1;
	}
	//server模式，调用了parsed_header，就要调用handleStartRequest
	//否则会早成stream泄漏
	stream->parsed_header = 1;
	assert(processing >= 0);
	katom_inc((void*)&processing);
	state.stream = NULL;
	kfiber_create(kgl_sink_start_fiber, stream->sink, (int)state.header_length, http_config.fiber_stack_size, NULL);
	return true;
}
u_char* KHttp2::state_header_complete(u_char* pos, u_char* end) {
	KHttp2Context* stream;
	if (state.length) {
		state.handler = &KHttp2::state_header_block;
		return pos;
	}
	if (!(state.flags & KGL_HTTP_V2_END_HEADERS_FLAG)) {
		return handle_continuation(pos, end, &KHttp2::state_header_complete);
	}
	stream = state.stream;
	if (stream) {
		if (!on_header_success(stream)) {
			return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
		}
	}
	if (!state.keep_pool && state.pool) {
		kgl_destroy_pool(state.pool);
	}
	state.pool = NULL;
	state.keep_pool = 0;
	if (state.padding) {
		return state_skip_padded(pos, end);
	}
	return state_complete(pos, end);
}

intptr_t KHttp2::parse_int(u_char** pos, u_char* end, uintptr_t prefix) {
	u_char* start, * p;
	uintptr_t   value, octet, shift;

	start = *pos;
	p = start;

	value = *p++ & prefix;

	if (value != prefix) {
		if (state.length == 0) {
			return KGL_ERROR;
		}

		state.length--;

		*pos = p;
		return value;
	}

	if (end - start > KGL_HTTP_V2_INT_OCTETS) {
		end = start + KGL_HTTP_V2_INT_OCTETS;
	}

	for (shift = 0; p != end; shift += 7) {
		octet = *p++;

		value += (octet & 0x7f) << shift;

		if (octet < 128) {
			if ((uint32_t)(p - start) > state.length) {
				return KGL_ERROR;
			}

			state.length -= (uint32_t)(p - start);

			*pos = p;
			return value;
		}
	}

	if ((uint32_t)(end - start) >= state.length) {
		return KGL_ERROR;
	}

	if (end == start + KGL_HTTP_V2_INT_OCTETS) {
		return KGL_DECLINED;
	}

	return KGL_AGAIN;

}
KHttp2Context* KHttp2::create_stream() {
	KHttp2Context* stream = new KHttp2Context;
	stream->Init((int)init_window);
#ifdef ENABLE_UPSTREAM_HTTP2
	if (client_model) {
		return stream;
	}
#endif
	kassert(kselector_is_same_thread(c->st.base.selector));
	state.keep_pool = 1;
	KHttp2Sink* sink = new KHttp2Sink(this, stream, state.pool);
	sink->data.set_http_version(2, 0);
	stream->sink = sink;
#ifdef KSOCKET_SSL
	if (kconnection_is_ssl(c)) {
		KBIT_SET(stream->sink->data.raw_url.flags, KGL_URL_SSL);
	}
#endif
	return stream;
}
void KHttp2::set_dependency(KHttp2Node* node, uint32_t depend, bool exclusive) {

}
kev_result KHttp2::CloseWrite() {
	kassert(write_processing == 1);
	if (read_processing == 0 && katom_get((void*)&processing) == 0) {
		close(false, KGL_HTTP_V2_NO_ERROR);
		return kev_destroy;
	}
	write_processing = 0;
	return kev_err;
}
kev_result KHttp2::NextRead(int got) {
	assert(read_processing == 1);
	return start_read();
}
kev_result KHttp2::NextWrite(int got) {
	if (got < 0) {
		close(false, KGL_HTTP_V2_CONNECT_ERROR);
		return kev_destroy;
	}
	return try_write();
}
kev_result KHttp2::try_write() {
	assert(write_processing == 1);
	if (write_buffer.getBufferSize() > 0) {
		if (write_buffer.is_sendfile()) {
			return selectable_sendfile(&c->st, resultHttp2Write, get_write_buffer(), this);
		}
		return selectable_write(&c->st, resultHttp2Write, get_write_buffer(), this);
	}
	return CloseWrite();
}
kev_result KHttp2::on_write_result(void* arg, int got) {
	kgl_iovec* buf = (kgl_iovec*)arg;
	if (got <= 0) {
		close(false, KGL_HTTP_V2_CONNECT_ERROR);
		return kev_destroy;
	}
	http2_buff* remove_list = write_buffer.readSuccess(c->st.fd, got);
	KHttp2WriteBuffer::remove_buff(remove_list, false);
	return try_write();
}
kev_result KHttp2::start_read() {
	int32_t pc = katom_get((void*)&processing);
	if (pc == 0 &&
		self_goaway == 0 &&
		kgl_current_msec - last_stream_msec > (http_config.time_out + 30) * 1000) {
		goaway(0);
	}
	if (pc == 0 && write_processing == 0 && peer_goaway) {
		close(true, KGL_HTTP_V2_NO_ERROR);
		return kev_destroy;
	}
	return selectable_read(&c->st, resultHttp2Read, get_read_buffer(), c);
}
void KHttp2::goaway(int error_code) {
	//printf("self_goaway\n");
	self_goaway = 1;
	http2_buff* buf = get_frame(0, sizeof(http2_frame_goaway), KGL_HTTP_V2_GOAWAY_FRAME, 0);
	if (buf == NULL) {
		selectable_shutdown(&c->st);
		return;
	}
	http2_frame_goaway* b = (http2_frame_goaway*)(buf->data + sizeof(http2_frame_header));
	b->last_stream_id = htonl(last_peer_sid);
	b->error_code = htonl(error_code);
	buf->tcp_nodelay = 1;
	write_buffer.push(buf);
	start_write();
}
void KHttp2::ping() {
	if (self_goaway && (katom_get((void*)&processing) == 0 && write_processing == 0)) {
		//printf("shutdown socket\n");
		selectable_shutdown(&c->st);
		return;
	}
	check_stream_timeout();
	//printf("ping\n");
	pinged = 1;
	http2_buff* buf = get_frame(0, sizeof(http2_frame_ping), KGL_HTTP_V2_PING_FRAME, 0);
	if (buf == NULL) {
		selectable_shutdown(&c->st);
		return;
	}
	http2_frame_ping* b = (http2_frame_ping*)(buf->data + sizeof(http2_frame_header));
	b->opaque = time(NULL);
	buf->tcp_nodelay = 1;
	write_buffer.push(buf);
	start_write();
}
kev_result KHttp2::start_write() {
	kassert(kselector_is_same_thread(c->st.base.selector));
	kassert(read_processing);
	if (write_processing || closed || write_buffer.getBufferSize() == 0) {
		return kev_err;
	}
	write_processing = 1;
	selectable_next_write(&c->st, http2_next_write, this);
	return kev_ok;
}
void KHttp2::write_end(KHttp2Context* ctx) {
	kassert(kselector_is_same_thread(c->st.base.selector));
	if (IsWriteClosed(ctx)) {
		return;
	}
	if (ctx->send_header && !ctx->write_trailer) {
		//try to send header
		ctx->set_content_length(0);
		send_header(ctx, true);
		return;
	}
	//只有不明长度，才需要调用write_end
	assert(ctx->content_left == -1);
	//printf("ctx id=[%d] out_closed\n", ctx->node->id);	
	http2_buff* new_buf = get_frame(ctx->node->id, 0, KGL_HTTP_V2_DATA_FRAME, (ctx->send_header ? 0 : KGL_HTTP_V2_END_STREAM_FLAG));
	if (new_buf == NULL) {
		return;
	}
	new_buf->tcp_nodelay = 1;
	write_buffer.push(new_buf);
	if (ctx->send_header) {
		assert(ctx->write_trailer);
		send_header(ctx, true);
		assert(ctx->out_closed);
		//send_header 里面会调用start_write,以及设置out_closed=1
		return;
	}
	ctx->out_closed = 1;
	start_write();
}
void KHttp2::destroy_node(KHttp2Node* node) {
	uint8_t index = kgl_http_v2_index(node->id);
	KHttp2Node* last = NULL;
	KHttp2Node* n = streams_index[index];
	while (n) {
		if (n->id == node->id) {
			if (last == NULL) {
				streams_index[index] = n->index;
			} else {
				last->index = n->index;
			}
			break;
		}
		last = n;
		n = n->index;
		assert(n);
	}
	delete node;
}
void KHttp2::release_stream(KHttp2Context* ctx) {
	kassert(kselector_is_same_thread(c->st.base.selector));
	kassert(ctx->queue.next == NULL);
	kassert(ctx->read_wait == NULL || ctx->read_wait->fiber == NULL);
	kassert(ctx->write_wait == NULL);
	last_stream_msec = kgl_current_msec;
	if (ctx->read_wait) {
		delete ctx->read_wait;
		ctx->read_wait = NULL;
	}
	if (ctx->write_wait) {
		delete ctx->write_wait;
		ctx->write_wait = NULL;
	}
	if (!ctx->out_closed || !ctx->in_closed) {
		ctx->out_closed = 1;
		ctx->in_closed = 1;
		ctx->rst = 1;
		if (ctx->node) {
			send_rst_stream(ctx->node->id, KGL_HTTP_V2_INTERNAL_ERROR);
		}
	}
	if (ctx->node) {
		destroy_node(ctx->node);
		ctx->node = NULL;
	}
}
void KHttp2::release_admin(KHttp2Context* ctx) {
	kassert(kselector_is_same_thread(c->st.base.selector));
	//{{ent
#ifdef ENABLE_UPSTREAM_HTTP2
	if (ctx->admin_stream) {
		assert(has_admin_stream == 1);
		has_admin_stream = 0;
	}
#endif//}}
	if (state.stream == ctx) {
		//the ctx is current using by state
		ctx->destroy_by_http2 = 1;
	} else {
		ctx->Destroy();
	}
	katom_dec((void*)&processing);
	assert(processing >= 0);
	if (can_destroy()) {
		delete this;
	}
}
void KHttp2::release(KHttp2Context* ctx) {
	release_stream(ctx);
	release_admin(ctx);
}
kselector* KHttp2::getSelector() {
	return c->st.base.selector;
}
int KHttp2::copy_read_buffer(KHttp2Context* ctx, char* buf, int length) {
	//WSABUF vc[MAX_HTTP2_BUFFER_SIZE];
	int total_send = 0;
	assert(ctx->read_buffer->getHeader());
	if (ctx->read_buffer->getHeader() == NULL) {
		return 0;
	}
	while (length > 0) {
		int this_len;
		char* data = ctx->read_buffer->getReadBuffer(this_len);
		this_len = KGL_MIN(this_len, length);
		kgl_memcpy(buf, data, this_len);
		total_send += this_len;
		length -= this_len;
		buf += this_len;
		if (!ctx->read_buffer->readSuccess(this_len)) {
			break;
		}
	}
#if 0
	//int bufferCount = buffer(ctx->data, arg,vc, MAX_HTTP2_BUFFER_SIZE);
	for (int i = 0; i < bc; i++) {
		while (buf[i].iov_len > 0) {
			int this_len;
			char* data = ctx->read_buffer->getReadBuffer(this_len);
			this_len = KGL_MIN(this_len, (int)buf[i].iov_len);
			kgl_memcpy(buf[i].iov_base, data, this_len);
			total_send += this_len;
			buf[i].iov_len -= this_len;
			buf[i].iov_base = (char*)buf[i].iov_base + this_len;
			if (!ctx->read_buffer->readSuccess(this_len)) {
				goto done;
			}
		}
	}
#endif
	return total_send;
}
int KHttp2::ReadHeader(KHttp2Context* http2_ctx) {
	//{{ent
#ifdef ENABLE_UPSTREAM_HTTP2
	kassert(IsClientModel());
#endif//}}
	kassert(kselector_is_same_thread(c->st.base.selector));
	if (http2_ctx->rst) {
		return -1;
		//return result(http2_ctx->data, arg, -1);
	}
	if (http2_ctx->parsed_header) {
		kassert(http2_ctx->read_wait == NULL);
		//return result(http2_ctx->data, arg, 0);
		return 0;
	}
	auto fiber = kfiber_self(&c->st.base);
	assert(http2_ctx);
	assert(http2_ctx->read_wait);
	assert(http2_ctx->read_wait->fiber == NULL);
	http2_ctx->read_wait->fiber = fiber;
	AddQueue(http2_ctx);
	return __kfiber_wait(fiber, http2_ctx->read_wait);
}
bool KHttp2::check_recv_window(KHttp2Context* http2_ctx) {
	if (http2_ctx->in_closed) {
		return false;
	}
	size_t recv_window = http2_ctx->recv_window;
	if (http2_ctx->read_buffer) {
		recv_window += http2_ctx->read_buffer->getLength();
	}
	if (recv_window < KGL_HTTP_V2_STREAM_RECV_WINDOW / 4) {
		//printf("stream [%d] recv_window is too small stream_recv_window=[%d],add_read_buffer size=[%d]\n", http2_ctx->node->id, http2_ctx->recv_window, recv_window);
		bool send_window_flag = send_window_update(http2_ctx->node->id, KGL_HTTP_V2_STREAM_RECV_WINDOW - http2_ctx->recv_window);
		http2_ctx->recv_window = KGL_HTTP_V2_STREAM_RECV_WINDOW;
		return send_window_flag;
	}
	return false;
}
bool KHttp2::terminate_stream(KHttp2Context* ctx, uint32_t status) {
	kassert(kselector_is_same_thread(c->st.base.selector));
	kgl_http2_event* re = NULL, * we = NULL;
	bool send_flag = false;
	if (ctx->read_wait) {
		re = ctx->read_wait;
		ctx->read_wait = NULL;
	}
	if (ctx->write_wait && !IS_WRITE_WAIT_FOR_WRITING(ctx->write_wait)) {
		/**
		* write_wait is hold on by http2_buff when status is wait_for_writing
		* released by http2_buff::clean
		*/
		we = ctx->write_wait;
		ctx->write_wait = NULL;
	}
	if (ctx->in_closed && ctx->out_closed) {
		ctx->rst = 1;
	} else {
		ctx->in_closed = 1;
		ctx->out_closed = 1;
		ctx->rst = 1;
		if (ctx->node && read_processing) {
			//在http2的client模式中，有可能ctx->node还未初始化。
			//因为ctx->node是实际write或read时，进行初始化。
			send_flag = send_rst_stream(ctx->node->id, status);
		}
	}
	ctx->RemoveQueue();
	if (re) {
		re->on_read(-1);
		delete re;
	}
	if (we) {
		we->on_write(-1);
	}
	return send_flag;
}
void KHttp2::shutdown(KHttp2Context* ctx) {
	if (ctx->rst) {
		//already shutdown.
		kassert(ctx->in_closed);
		kassert(ctx->out_closed);
		return;
	}
	//printf("****************http2 shutdown....\n");
	terminate_stream(ctx, KGL_HTTP_V2_CANCEL);
}
void KHttp2::remove_readhup(KHttp2Context* http2_ctx) {
	if (http2_ctx->write_wait && IS_WRITE_WAIT_FOR_HUP(http2_ctx->write_wait)) {
		delete http2_ctx->write_wait;
		http2_ctx->write_wait = NULL;
	}
}
bool KHttp2::readhup(KHttp2Context* http2_ctx, result_callback result, void* arg) {
	kassert(kselector_is_same_thread(c->st.base.selector));
	if (http2_ctx->write_wait && !IS_WRITE_WAIT_FOR_HUP(http2_ctx->write_wait)) {
		//write wait is setting not for hup
		return false;
	}
	if (http2_ctx->read_wait) {
		//read wait is setting
		return false;
	}
	if (http2_ctx->write_wait == NULL) {
		http2_ctx->write_wait = new kgl_http2_event;
		memset(http2_ctx->write_wait, 0, sizeof(kgl_http2_event));
	}
	http2_ctx->write_wait->buf = NULL;
	http2_ctx->write_wait->readhup_result = result;
	http2_ctx->write_wait->readhup_arg = arg;
	//http2_ctx->write_wait->len = -1;
	kassert(IS_WRITE_WAIT_FOR_HUP(http2_ctx->write_wait));
	return true;
}
bool KHttp2::send_altsvc(KHttp2Context* ctx, const char* val, int val_len) {
	if (read_processing == 0) {
		return false;
	}
	http2_buff* buf = get_frame(ctx->node->id, sizeof(http2_frame_altsvc) + val_len, KGL_HTTP_V2_ALTSVC_FRAME, KGL_HTTP_V2_NO_FLAG);
	if (buf == NULL) {
		return false;
	}
	http2_frame_altsvc* b = (http2_frame_altsvc*)(buf->data + sizeof(http2_frame_header));
	b->origin_length = 0;
	b += 1;
	memcpy(b, val, val_len);
	write_buffer.push(buf);
	start_write();
	return true;
}
int KHttp2::send_header(KHttp2Context* http2_ctx, bool body_end) {
	kassert(http2_ctx->send_header);
	kassert(kselector_is_same_thread(c->st.base.selector));
	if (read_processing == 0) {
		return 0;
	}
#ifdef ENABLE_UPSTREAM_HTTP2
	if (client_model) {
		kassert(http2_ctx->node == NULL || http2_ctx->write_trailer);
		if (http2_ctx->node == NULL) {
			assert(http2_ctx->us);
			last_self_sid += 2;
			KHttp2Node* node = get_node(last_self_sid, true);
			node->stream = http2_ctx;
			http2_ctx->node = node;
		}
	}
#endif
	http2_buff* buf = http2_ctx->send_header->create(http2_ctx->node->id, body_end, frame_size);
	if (body_end) {
		//printf("ctx id=[%d] no_body out_closed\n", http2_ctx->node->id);
		http2_ctx->out_closed = 1;
	}
	delete http2_ctx->send_header;
	http2_ctx->send_header = NULL;
	//http2_ctx->setContentLength(body_len);
	write_buffer.push(buf);
	int header_len = 0;
	while (buf) {
		header_len += buf->used;
		if (buf->next == NULL && body_end) {
			buf->tcp_nodelay = 1;
		}
		buf = buf->next;
	}
	start_write();
	return header_len;
}

bool KHttp2::add_method(KHttp2Context* ctx, u_char meth) {
	assert(ctx->send_header == NULL);
	if (ctx->send_header == NULL) {
		ctx->send_header = new KHttp2HeaderFrame;
	}
	switch (meth) {
	case METH_GET:
		ctx->send_header->write(kgl_http_v2_indexed(KGL_HTTP_V2_METHOD_GET_INDEX));
		return true;
	case METH_POST:
		ctx->send_header->write(kgl_http_v2_indexed(KGL_HTTP_V2_METHOD_POST_INDEX));
		return true;
	default:
	{
		ctx->send_header->write(kgl_http_v2_inc_indexed(KGL_HTTP_V2_METHOD_INDEX));
		auto method = KHttpKeyValue::get_method(meth);
		ctx->send_header->write_int(KGL_HTTP_V2_ENCODE_RAW, kgl_http_v2_prefix(7), method->len);
		ctx->send_header->write(method->data, (hlen_t)method->len);
		return true;
	}
	}
	//
	//return add_header(ctx,kgl_header_method)
	//add_header(ctx, kgl_expand_string(":method"), method->data, (hlen_t)method->len);
	//return true;
}
bool KHttp2::add_status(KHttp2Context* ctx, uint16_t status_code) {
	u_char  status;
	u_char buf[8];
	u_char* hot = buf;
	switch (status_code) {
	case STATUS_OK:
		status = kgl_http_v2_indexed(KGL_HTTP_V2_STATUS_200_INDEX);
		break;
	case STATUS_NO_CONTENT:
		status = kgl_http_v2_indexed(KGL_HTTP_V2_STATUS_204_INDEX);
		break;
	case STATUS_CONTENT_PARTIAL:
		status = kgl_http_v2_indexed(KGL_HTTP_V2_STATUS_206_INDEX);
		break;
	case STATUS_NOT_MODIFIED:
		status = kgl_http_v2_indexed(KGL_HTTP_V2_STATUS_304_INDEX);
		break;
	case STATUS_BAD_REQUEST:
		status = kgl_http_v2_indexed(KGL_HTTP_V2_STATUS_400_INDEX);
		break;
	case STATUS_NOT_FOUND:
		status = kgl_http_v2_indexed(KGL_HTTP_V2_STATUS_404_INDEX);
		break;
	case STATUS_SERVER_ERROR:
		status = kgl_http_v2_indexed(KGL_HTTP_V2_STATUS_500_INDEX);
		break;
	default:
		status = 0;
	}
	if (status) {
		*hot++ = status;
	} else {
		*hot++ = kgl_http_v2_inc_indexed(KGL_HTTP_V2_STATUS_INDEX);
		*hot++ = (KGL_HTTP_V2_ENCODE_RAW | 3);
		sprintf((char*)hot, "%03u", status_code);
		hot += 3;
	}
	if (ctx->send_header == NULL) {
		ctx->send_header = new KHttp2HeaderFrame;
	}
	ctx->send_header->insert((char*)buf, (int)(hot - buf));
	return true;
}
bool KHttp2::add_header(KHttp2Context* ctx, kgl_header_type name, const char* val, hlen_t val_len) {
	if (ctx->send_header == NULL) {
		ctx->send_header = new KHttp2HeaderFrame;
	}
	if (name == kgl_header_cookie) {
		return add_header_cookie(ctx, val, val_len);
	}
	if (kgl_header_type_string[name].http2_index == 0) {
		ctx->send_header->write(0);/* not indexed */
		ctx->send_header->write_int(KGL_HTTP_V2_ENCODE_RAW, kgl_http_v2_prefix(7), kgl_header_type_string[name].low_case.len);
		ctx->send_header->write(kgl_header_type_string[name].low_case.data, (int)kgl_header_type_string[name].low_case.len);
		ctx->send_header->write_int(KGL_HTTP_V2_ENCODE_RAW, kgl_http_v2_prefix(7), val_len);
		ctx->send_header->write(val, val_len);
		return true;
	}
	ctx->send_header->write(kgl_http_v2_inc_indexed(kgl_header_type_string[name].http2_index));
	ctx->send_header->write_int(KGL_HTTP_V2_ENCODE_RAW, kgl_http_v2_prefix(7), val_len);
	ctx->send_header->write(val, val_len);
	return true;
}
bool KHttp2::add_header_cookie(KHttp2Context* ctx, const char* val, hlen_t val_len) {
	//TODO: split cookie
	ctx->send_header->write(kgl_http_v2_inc_indexed(KGL_HTTP_V2_COOKIE_INDEX));
	ctx->send_header->write_int(KGL_HTTP_V2_ENCODE_RAW, kgl_http_v2_prefix(7), val_len);
	ctx->send_header->write(val, val_len);
	return true;
}
bool KHttp2::add_header(KHttp2Context* ctx, const char* name, hlen_t name_len, const char* val, hlen_t val_len) {
	if (ctx->send_header == NULL) {
		ctx->send_header = new KHttp2HeaderFrame;
	}
	switch (name_len) {
	case 6:
		if (strcasecmp(name, "cookie") == 0) {
			return add_header_cookie(ctx, val, val_len);
		}
		break;
	case 7:
		if (strcasecmp(name, "upgrade") == 0) {
			if ((val_len == 2 && strncasecmp(val, "h2", val_len) == 0) || (val_len == 3 && strncasecmp(val, "h2c", val_len) == 0)) {
				//in http2 skip upgrade: h2/h2c header
				return true;
			}
		}
		break;
	default:
		break;
	}
	ctx->send_header->write(0);/* not indexed */
	ctx->send_header->write_int(KGL_HTTP_V2_ENCODE_RAW, kgl_http_v2_prefix(7), name_len);
	ctx->send_header->write_lower_string(name, name_len);
	ctx->send_header->write_int(KGL_HTTP_V2_ENCODE_RAW, kgl_http_v2_prefix(7), val_len);
	ctx->send_header->write(val, val_len);
#if 0
	fwrite(name, 1, name_len, stdout);
	fwrite(": ", 1, 2, stdout);
	fwrite(val, 1, val_len, stdout);
	fwrite("\r\n", 1, 2, stdout);
#endif
	return true;
}
void KHttp2::init(kconnection* c) {
	//printf("Http2 init [%p]\n", this);
	this->c = c;
	KBIT_SET(c->st.base.st_flags, STF_RTIME_OUT);
	read_processing = 1;
	send_window = KGL_HTTP_V2_DEFAULT_WINDOW;
	recv_window = KGL_HTTP_V2_CONNECTION_RECV_WINDOW;
	init_window = KGL_HTTP_V2_DEFAULT_WINDOW;
	frame_size = KGL_HTTP_V2_DEFAULT_FRAME_SIZE;
	max_stream = KGL_HTTP_V2_DEFAULT_MAX_STREAM;
	last_stream_msec = kgl_current_msec;
}
#ifdef ENABLE_UPSTREAM_HTTP2
KHttp2Upstream* KHttp2::get_admin_stream() {
	kassert(kselector_is_same_thread(c->st.base.selector));
	if (has_admin_stream || self_goaway || peer_goaway || !client_model) {
		return NULL;
	}
	has_admin_stream = 1;
	katom_inc((void*)&processing);
	KHttp2Context* http2_ctx = new KHttp2Context;
	http2_ctx->Init((int)init_window);
	http2_ctx->admin_stream = 1;
	KHttp2Upstream* us = new KHttp2Upstream(this, http2_ctx);
	return us;
}
KHttp2Upstream* KHttp2::connect() {
	if (peer_goaway || self_goaway || last_self_sid > 655360) {
#ifndef NDEBUG
		klog(KLOG_ERR, "peer_goaway=[%d] self_goaway=[%d] last_self_sid=[%d]\n", (int)peer_goaway, (int)self_goaway, last_self_sid);
#endif
		return NULL;
	}
	if (katom_inc((void*)&processing) >= max_stream + 1) {
#ifndef NDEBUG
		klog(KLOG_ERR, "processing is too big.\n", processing);
#endif
		katom_dec((void*)&processing);
		return NULL;
	}
	return NewClientStream(false);
}
KHttp2Upstream* KHttp2::client(kconnection* us) {
	//printf("http2 client=[%p] us=[%p]\n", this, us);
	//assert(us->selector->is_same_thread());
	static const u_char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	init(us);
	client_model = 1;
	has_admin_stream = 1;
	last_self_sid = 1;

	katom_inc((void*)&processing);
	state.handler = &KHttp2::state_head;
	http2_buff* buf = new http2_buff;
	buf->data = (char*)malloc(sizeof(preface) - 1);
	buf->used = sizeof(preface) - 1;
	kgl_memcpy(buf->data, preface, buf->used);
	write_buffer.push(buf);
	send_settings();
	if (send_window_update(0, KGL_HTTP_V2_CONNECTION_RECV_WINDOW - KGL_HTTP_V2_DEFAULT_WINDOW)) {
		start_write();
	}
	selectable_next_read(&c->st, http2_next_read, this);
	return NewClientStream(true);
}
KHttp2Upstream* KHttp2::NewClientStream(bool admin) {
	KHttp2Context* stream = create_stream();
	stream->admin_stream = admin;
	return new KHttp2Upstream(this, stream);
}
#endif
void KHttp2::server_h2c(int got) {
	send_settings();
	if (send_window_update(0, KGL_HTTP_V2_CONNECTION_RECV_WINDOW - KGL_HTTP_V2_DEFAULT_WINDOW)) {
		start_write();
	}
	if (got > 0) {
		resultHttp2Read(this, c, got);
		return;
	}
	start_read();
}
bool KHttp2::init_h2c(kconnection* c, const char* buf, int len) {
	if (len > sizeof(state.buffer)) {
		return false;
	}
	init(c);
	state.handler = &KHttp2::state_preface_end;
	if (len > 0) {
		memcpy(state.buffer, buf, len);
		return true;
	}
	return true;

	send_settings();
	if (send_window_update(0, KGL_HTTP_V2_CONNECTION_RECV_WINDOW - KGL_HTTP_V2_DEFAULT_WINDOW)) {
		start_write();
	}
	if (len > 0) {
		memcpy(state.buffer, buf, len);
		resultHttp2Read(this, c, len);
		return true;
	}
	start_read();
	return true;
}
void KHttp2::server(kconnection* c) {
	init(c);
	state.handler = &KHttp2::state_preface;
	send_settings();
	if (send_window_update(0, KGL_HTTP_V2_CONNECTION_RECV_WINDOW - KGL_HTTP_V2_DEFAULT_WINDOW)) {
		start_write();
	}
	start_read();
}
int KHttp2::read(KHttp2Context* http2_ctx, char* buf, int len) {
	kassert(kselector_is_same_thread(c->st.base.selector));
	assert(http2_ctx);
	assert(http2_ctx->parsed_header);
	if (http2_ctx->write_wait && IS_WRITE_WAIT_FOR_HUP(http2_ctx->write_wait)) {
		//remove read_hup
		delete http2_ctx->write_wait;
		http2_ctx->write_wait = NULL;
	}
	kassert(http2_ctx->read_wait == NULL);
	if (http2_ctx->read_wait) {
		delete http2_ctx->read_wait;
		http2_ctx->read_wait = NULL;
		FlushQueue(http2_ctx);
	}
#ifdef ENABLE_UPSTREAM_HTTP2
	if (client_model) {
#ifndef NDEBUG
		if (http2_ctx->content_left >= 0 && !http2_ctx->has_expect) {
			assert(http2_ctx->content_left == 0);
			assert(http2_ctx->out_closed);
		}
#endif
		if (http2_ctx->out_closed == 0 && (!http2_ctx->has_upgrade || http2_ctx->has_expect)) {
			http2_ctx->out_closed = 1;
			http2_buff* new_buf = get_frame(http2_ctx->node->id, 0, KGL_HTTP_V2_DATA_FRAME, KGL_HTTP_V2_END_STREAM_FLAG);
			if (new_buf) {
				new_buf->tcp_nodelay = 1;
				write_buffer.push(new_buf);
			}
		}
	}
#endif
	//printf("stream_recv_window=[%d],recv_window=[%d]\n", http2_ctx->recv_window, recv_window);
	bool recv_window_result = check_recv_window(http2_ctx);
	if (recv_window_result) {
		start_write();
	}
	if (http2_ctx->read_buffer && http2_ctx->read_buffer->getHeader() != NULL) {
		return copy_read_buffer(http2_ctx, buf, len);
	}
	if (http2_ctx->rst) {
		return -1;
	}
	if (http2_ctx->in_closed) {
		return 0;
	}
	http2_ctx->read_wait = new kgl_http2_event;
	http2_ctx->read_wait->rbuf = buf;
	http2_ctx->read_wait->buf_len = len;
	http2_ctx->read_wait->fiber = kfiber_self2();
	AddQueue(http2_ctx);
	return kfiber_wait(&http2_ctx->read_wait->fiber->base, http2_ctx->read_wait);
}
int KHttp2::on_write_window_ready(KHttp2Context* http2_ctx) {
	assert(http2_ctx->write_wait && IS_WRITE_WAIT_FOR_WINDOW(http2_ctx->write_wait));
	assert(!IsWriteClosed(http2_ctx));
	int len = KGL_MIN((int)frame_size, http2_ctx->send_window);
	len = KGL_MIN(len, (int)send_window);
	if (len <= 0) {
		AddQueue(http2_ctx);
		return len;
	}
	http2_buff* new_buf = http2_ctx->build_write_buffer(http2_ctx->write_wait, len);
	kassert(IS_WRITE_WAIT_FOR_WRITING(http2_ctx->write_wait));
	http2_ctx->send_window -= len;
	send_window -= len;
	write_buffer.push(new_buf);
	FlushQueue(http2_ctx);
	if (write_processing == 0) {
		write_processing = 1;
		selectable_next_write(&c->st, http2_next_write, this);
	}
	return len;
}
int KHttp2::sendfile(KHttp2Context* ctx, kasync_file* file, int length) {
	if (ctx->write_wait) {
		kassert(IS_WRITE_WAIT_FOR_HUP(ctx->write_wait));
		delete ctx->write_wait;
		ctx->write_wait = NULL;
	}
	kassert(kselector_is_same_thread(c->st.base.selector));
	if (IsWriteClosed(ctx)) {
		return -1;
	}
	if (ctx->send_header) {
		//try to send header
		assert(!ctx->write_trailer);
		send_header(ctx, ctx->content_left == 0);
	}
	auto fiber = kfiber_self(&file->st.base);
	ctx->sendfile = 1;
	ctx->CreateWriteWaitWindow(fiber, (kbuf*)file, length);
	on_write_window_ready(ctx);
	return __kfiber_wait(fiber, ctx->write_wait);
}
int KHttp2::write(KHttp2Context* ctx, const kbuf* buf, int bc) {
	if (ctx->write_wait) {
		kassert(IS_WRITE_WAIT_FOR_HUP(ctx->write_wait));
		delete ctx->write_wait;
		ctx->write_wait = NULL;
	}
	kassert(kselector_is_same_thread(c->st.base.selector));
	if (IsWriteClosed(ctx)) {
		return -1;
	}
	if (ctx->send_header) {
		//try to send header
		assert(!ctx->write_trailer);
		send_header(ctx, ctx->content_left == 0);
	}
	auto fiber = kfiber_self(&c->st.base);
	ctx->sendfile = 0;
	ctx->CreateWriteWaitWindow(fiber, buf, bc);
	on_write_window_ready(ctx);
	return __kfiber_wait(fiber, ctx->write_wait);
}

KHttp2Node* KHttp2::get_node(uint32_t sid, bool alloc) {
	uint8_t               index;
	KHttp2Node* node;
	index = kgl_http_v2_index(sid);

	for (node = this->streams_index[index]; node; node = node->index) {
		if (node->id == sid) {
			return node;
		}
	}

	if (!alloc) {
		return NULL;
	}
	node = new KHttp2Node();
	if (node == NULL) {
		return NULL;
	}
	node->id = sid;
	node->index = this->streams_index[index];
	this->streams_index[index] = node;
	return node;
}
u_char* KHttp2::state_preface(u_char* pos, u_char* end) {
	static const u_char preface[] = "PRI * HTTP/2.0\r\n";
	if (end - pos < (int)sizeof(preface)) {
		return state_save(pos, end, &KHttp2::state_preface);
	}
	if (memcmp(pos, preface, sizeof(preface) - 1) != 0) {
		this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
		return NULL;
	}
	return state_preface_end(pos + sizeof(preface) - 1, end);
}
u_char* KHttp2::state_preface_end(u_char* pos, u_char* end) {
	static const u_char preface[] = "\r\nSM\r\n\r\n";
	if (end - pos < (int)sizeof(preface)) {
		return state_save(pos, end, &KHttp2::state_preface_end);
	}
	if (memcmp(pos, preface, sizeof(preface) - 1) != 0) {
		this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
		return NULL;
	}
	return state_head(pos + sizeof(preface) - 1, end);
}
u_char* KHttp2::state_save(u_char* pos, u_char* end, kgl_http_v2_handler_pt handler) {
	size_t size = end - pos;
	if (size > KGL_HTTP_V2_STATE_BUFFER_SIZE) {
		klog(KLOG_WARNING, "state buffer overflow: %d bytes required\n", size);
		this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
		return NULL;
	}
	memmove(this->state.buffer, pos, size);
	state.buffer_used = (uint32_t)size;
	state.handler = handler;
	state.incomplete = 1;
	return end;
}
void KHttp2::check_stream_timeout() {
	for (;;) {
		kgl_list* l = klist_head(&active_queue);
		if (l == &active_queue) {
			break;
		}
		KHttp2Context* ctx = kgl_list_data(l, KHttp2Context, queue);
		if ((kgl_current_msec - ctx->active_msec) < (time_t)http_config.time_out * 1000 + 2000) {
			break;
		}
		klist_remove(l);
		memset(l, 0, sizeof(kgl_list));
		if (ctx->tmo_left > 0) {
			ctx->tmo_left--;
			ctx->active_msec = kgl_current_msec;
			klist_append(&active_queue, l);
			continue;
		}
#ifndef NDEBUG
		ctx->timeout = 1;
#endif
		shutdown(ctx);
	}
}
u_char* KHttp2::state_head(u_char* pos, u_char* end) {
	uint32_t    head;
	int  type;
	if (end - pos < (int)sizeof(http2_frame_header)) {
		return state_save(pos, end, &KHttp2::state_head);
	}
	head = kgl_http_v2_parse_uint32(pos);
	state.length = kgl_http_v2_parse_length(head);
	state.flags = pos[4];
	state.sid = kgl_http_v2_parse_sid(&pos[5]);
	pos += sizeof(http2_frame_header);
	type = kgl_http_v2_parse_type(head);
	//printf("%lld http2=[%p] recv frame sid=[%d] type=[%d] flag=[%d] length=[%d]\n",kgl_current_sec, this,state.sid,type,state.flags,state.length);
	if (type >= (int)KGL_HTTP_V2_FRAME_STATES) {
		return state_skip(pos, end);
	}
	check_stream_timeout();
	return (this->*kgl_http_v2_frame_states[type])(pos, end);
}
u_char* KHttp2::state_data(u_char* pos, u_char* end) {
	KHttp2Node* node;
	KHttp2Context* stream;
	if (state.sid == 0) {
		klog(KLOG_WARNING, "client sent DATA frame with stream identifier 0\n");
		return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
	}

	if (state.flags & KGL_HTTP_V2_PADDED_FLAG) {
		if (state.length == 0) {
			klog(KLOG_WARNING, "client sent padded DATA frame "
				"with incorrect length: %u\n", state.length);
			return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
		}

		if (end - pos == 0) {
			return state_save(pos, end, &KHttp2::state_data);
		}

		state.padding = *pos++;
		state.length--;

		if (state.padding > state.length) {
			klog(KLOG_WARNING,
				"client sent padded DATA frame "
				"with incorrect length: %u, padding: %u\n",
				state.length, state.padding);

			return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
		}

		state.length -= state.padding;
	}


	if (state.length > recv_window) {
		klog(KLOG_WARNING,
			"client violated connection flow control: "
			"received DATA frame length %u, available window %u\n",
			state.length, recv_window);
		return this->close(true, KGL_HTTP_V2_FLOW_CTRL_ERROR);
	}
	bool send_window_flag = false;
	recv_window -= state.length;
	if (recv_window < KGL_HTTP_V2_CONNECTION_RECV_WINDOW / 4) {
		send_window_flag = send_window_update(0, KGL_HTTP_V2_CONNECTION_RECV_WINDOW - recv_window);
		recv_window = KGL_HTTP_V2_CONNECTION_RECV_WINDOW;
	}

	node = get_node(state.sid, false);
	if (node == NULL || node->stream == NULL) {
		klog(KLOG_WARNING, "unknown http2 stream [%u] for data frame.\n", state.sid);
		if (send_window_flag) {
			start_write();
		}
		return state_skip_padded(pos, end);
	}
	stream = node->stream;
	if (!stream->parsed_header) {
		klog(KLOG_DEBUG, "must parsed header first.\n");
		terminate_stream(stream, KGL_HTTP_V2_PROTOCOL_ERROR);
		return state_skip_padded(pos, end);
	}
	if (state.length > stream->recv_window) {
		klog(KLOG_INFO, "client violated flow control for stream %u: "
			"received DATA frame length %u, available window %u",
			node->id, state.length, stream->recv_window);
		terminate_stream(stream, KGL_HTTP_V2_FLOW_CTRL_ERROR);
		return state_skip_padded(pos, end);
	}

	stream->recv_window -= state.length;
	if (stream->in_closed) {
		klog(KLOG_INFO, "client sent DATA frame for half-closed stream %u\n", node->id);
		if (!terminate_stream(stream, KGL_HTTP_V2_STREAM_CLOSED) && send_window_flag) {
			start_write();
		}
		return state_skip_padded(pos, end);
	}
	assert(state.stream == NULL);
	state.stream = stream;
	if (send_window_flag) {
		start_write();
	}
	return state_read_data(pos, end);

}
u_char* KHttp2::state_read_data(u_char* pos, u_char* end) {
	size_t                     size;
	//int                    n;
	KHttp2Context* stream;


	stream = state.stream;

	if (stream == NULL) {
		return state_skip_padded(pos, end);
	}

	if (stream->skip_data) {
		klog(KLOG_DEBUG, "skipping http2 DATA frame, reason: %d", stream->skip_data);
		if (state.flags & KGL_HTTP_V2_END_STREAM_FLAG) {
			stream->in_closed = 1;
			kgl_http2_event* read_wait = stream->read_wait;
			if (read_wait) {
				stream->read_wait = NULL;
				FlushQueue(stream);
				read_wait->on_read(0);
				delete read_wait;
			}
		}
		return state_skip_padded(pos, end);
	}

	size = end - pos;

	if (size > state.length) {
		size = state.length;
	}

	if (size) {
		//TODO: read size data
		//printf("read data length=[%d]\n", size);
		if (stream->read_buffer == NULL) {
			stream->read_buffer = new KSendBuffer();
		}
		stream->read_buffer->append((char*)pos, (uint16_t)size);
		kgl_http2_event* read_wait = stream->read_wait;
		if (read_wait) {
			assert(read_wait->fiber);
			stream->read_wait = NULL;
			FlushQueue(stream);
			int got = copy_read_buffer(stream, read_wait->rbuf, read_wait->buf_len);
			read_wait->on_read(got);
			delete read_wait;
		}
		state.length -= (uint32_t)size;
		pos += size;
	}

	if (state.length) {
		return state_save(pos, end, &KHttp2::state_read_data);
	}

	if (state.flags & KGL_HTTP_V2_END_STREAM_FLAG) {
		stream->in_closed = 1;
		kgl_http2_event* read_wait = stream->read_wait;
		if (read_wait) {
			assert(read_wait->fiber);
			stream->read_wait = NULL;
			FlushQueue(stream);
			read_wait->on_read(0);
			delete read_wait;
		}
	}

	if (state.padding) {
		return state_skip_padded(pos, end);
	}

	return state_complete(pos, end);

}
u_char* KHttp2::state_headers(u_char* pos, u_char* end) {
	size_t                   size;
	uintptr_t               padded, priority, depend, dependency, excl, weight;
	KHttp2Node* node;
	KHttp2Context* stream;
	state.header_length = 0;
	padded = state.flags & KGL_HTTP_V2_PADDED_FLAG;
	priority = state.flags & KGL_HTTP_V2_PRIORITY_FLAG;

	size = 0;

	if (padded) {
		size++;
	}

	if (priority) {
		size += sizeof(uint32_t) + 1;
	}

	if (state.length < size) {
		klog(KLOG_WARNING, "http2 client sent HEADERS frame with incorrect length %u\n", state.length);
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}
	if (state.length == size) {
		klog(KLOG_WARNING, "http2 client sent HEADERS frame with empty header block\n");
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}

	if ((size_t)(end - pos) < size) {
		return state_save(pos, end, &KHttp2::state_headers);
	}

	state.length -= (uint32_t)size;

	if (padded) {
		state.padding = *pos++;
		if (state.padding > state.length) {
			klog(KLOG_WARNING,
				"http2 client sent padded HEADERS frame "
				"with incorrect length: %uz, padding: %u\n",
				state.length, state.padding);

			return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
		}
		state.length -= state.padding;
	}

	depend = 0;
	excl = 0;
	weight = 16;

	if (priority) {
		dependency = kgl_http_v2_parse_uint32(pos);

		depend = dependency & 0x7fffffff;
		excl = dependency >> 31;
		weight = pos[4] + 1;

		pos += sizeof(uint32_t) + 1;
	}

	klog(KLOG_DEBUG, "http2 HEADERS frame sid:%ui on %ui excl:%ui weight:%ui", state.sid, depend, excl, weight);
#ifdef ENABLE_UPSTREAM_HTTP2
	if (client_model) {
		node = get_node(state.sid, false);
		if (node == NULL) {
			klog(KLOG_WARNING, "http2 cann't find node [%d]\n", state.sid);
			return state_skip(pos, end);
		}
		stream = node->stream;
		kassert(stream);
		kassert(state.pool == NULL);
		stream->RemoveQueue();
		if (!stream->is_available() || stream->in_closed) {
			klog(KLOG_WARNING, "http2 stream in is not available [%d]\n", state.sid);
			return state_skip(pos, end);
		}
		//assert(stream->read_wait || stream->read_trailer);
		assert(stream->us);
		state.pool = stream->us->GetPool();
		state.keep_pool = 1;
		kassert(state.pool);
		kassert(state.stream == NULL);
		state.stream = stream;
		stream->in_closed = state.flags & KGL_HTTP_V2_END_STREAM_FLAG;
		return state_header_block(pos, end);
	}
#endif
	if (state.sid == 0 || state.sid % 2 == 0) {
		klog(KLOG_WARNING, "http2 client sent HEADERS frame with incorrect identifier "
			"%u, the last was %u\n", state.sid, last_peer_sid);
		return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
	}
	if (depend == state.sid) {
		klog(KLOG_WARNING,
			"client sent HEADERS frame for stream %u "
			"with incorrect dependency\n", state.sid);

		if (!send_rst_stream(state.sid, KGL_HTTP_V2_PROTOCOL_ERROR)) {
			return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
		}
		return state_skip_headers(pos, end);
	}
	node = get_node(state.sid, false);
	if (node != NULL && node->stream != NULL) {
		stream = node->stream;
		if (!(state.flags & KGL_HTTP_V2_END_STREAM_FLAG)) {
			klog(KLOG_WARNING, "client sent trailer without END_STREAM for stream %u\n", state.sid);
			if (!send_rst_stream(state.sid, KGL_HTTP_V2_PROTOCOL_ERROR)) {
				return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
			}
			return state_skip_headers(pos, end);
		}
		kassert(state.pool == NULL);
		stream->RemoveQueue();
		if (!stream->is_available() || stream->in_closed) {
			klog(KLOG_WARNING, "http2 stream is not available [%d]\n", state.sid);
			return state_skip_headers(pos, end);
		}
		state.pool = stream->sink->pool;
		state.keep_pool = 1;
		kassert(state.pool);
		kassert(state.stream == NULL);
		state.stream = stream;
		stream->in_closed = 1;
		return state_header_block(pos, end);
	}
	if (state.sid <= last_peer_sid) {
		klog(KLOG_WARNING, "http2 client tried to reopen stream %u, the last was %u\n",
			state.sid, last_peer_sid);
		return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
	}
	if (self_goaway) {
		if (!send_rst_stream(state.sid, KGL_HTTP_V2_NO_ERROR)) {
			return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
		}
		return state_skip_headers(pos, end);
	}
	last_peer_sid = state.sid;
	node = get_node(state.sid, true);
	if (node == NULL) {
		return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
	}
	assert(state.pool == NULL);
	state.pool = kgl_create_pool(KGL_REQUEST_POOL_SIZE);
	assert(node->stream == NULL);
	stream = create_stream();
	if (stream == NULL) {
		return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
	}
	stream->in_closed = state.flags & KGL_HTTP_V2_END_STREAM_FLAG;
	stream->node = node;
	node->stream = stream;
	assert(state.stream == NULL);
	state.stream = stream;
	assert(state.pool == stream->sink->pool);
	/*
	if (priority || node->parent == NULL) {
		node->weight = weight;
		lock.Lock();
		this->setDependency(node, depend, excl>0);
		lock.Unlock();
	}
	*/
	return state_header_block(pos, end);
}
u_char* KHttp2::state_priority(u_char* pos, u_char* end) {
	uintptr_t           depend, dependency, excl, weight;
	if (state.length != KGL_HTTP_V2_PRIORITY_SIZE) {
		klog(KLOG_WARNING, "client sent PRIORITY frame with incorrect length %d\n", state.length);
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}

	if (end - pos < KGL_HTTP_V2_PRIORITY_SIZE) {
		return state_save(pos, end, &KHttp2::state_priority);
	}

	dependency = kgl_http_v2_parse_uint32(pos);
	depend = dependency & 0x7fffffff;
	excl = dependency >> 31;
	weight = pos[4] + 1;
	pos += KGL_HTTP_V2_PRIORITY_SIZE;
	if (state.sid == 0) {
		klog(KLOG_WARNING, "client sent PRIORITY frame with incorrect identifier\n");
		return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
	}

	if (depend == state.sid) {
		klog(KLOG_WARNING, "client sent PRIORITY frame for stream %u "
			"with incorrect dependency\n", state.sid);

		if (!send_rst_stream(state.sid, KGL_HTTP_V2_PROTOCOL_ERROR)) {
			return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
		}
		return state_complete(pos, end);
	}
	return state_complete(pos, end);
}
u_char* KHttp2::state_rst_stream(u_char* pos, u_char* end) {
	uint32_t		status;
	KHttp2Node* node;
	KHttp2Context* stream;
	if (state.length != KGL_HTTP_V2_RST_STREAM_SIZE) {
		klog(KLOG_WARNING, "client sent RST_STREAM frame with incorrect length %u\n", state.length);
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}

	if (end - pos < KGL_HTTP_V2_RST_STREAM_SIZE) {
		return state_save(pos, end, &KHttp2::state_rst_stream);
	}

	status = kgl_http_v2_parse_uint32(pos);

	pos += KGL_HTTP_V2_RST_STREAM_SIZE;

	klog(KLOG_DEBUG, "http2 RST_STREAM frame, sid:%ui status:%ui", state.sid, status);

	if (state.sid == 0) {
		klog(KLOG_WARNING, "client sent RST_STREAM frame with incorrect identifier\n");
		return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
	}
	node = this->get_node(state.sid, false);

	if (node == NULL || node->stream == NULL) {
		//klog(KLOG_WARNING,"unknown http2 stream [%d]\n",state.sid);
		return state_complete(pos, end);
	}
	stream = node->stream;

	switch (status) {

	case KGL_HTTP_V2_CANCEL:
		klog(KLOG_INFO, "client canceled stream %u\n", state.sid);
		break;

	case KGL_HTTP_V2_INTERNAL_ERROR:
		klog(KLOG_INFO, "client terminated stream %u due to internal error\n", state.sid);
		break;

	default:
		klog(KLOG_INFO, "client terminated stream %u with status %u\n", state.sid, status);
		break;
	}
	kgl_http2_event* re = stream->read_wait;
	stream->read_wait = NULL;

	kgl_http2_event* we = NULL;
	if (stream->write_wait && !IS_WRITE_WAIT_FOR_WRITING(stream->write_wait)) {
		/**
		* write_wait is hold on by http2_buff when status is wait_for_writing
		* released by http2_buff::clean
		*/
		we = stream->write_wait;
		stream->write_wait = NULL;
	}
	stream->in_closed = 1;
	stream->out_closed = 1;
	stream->rst = 1;
	stream->RemoveQueue();
	if (stream->read_buffer) {
		stream->read_buffer->clean();
	}
	if (re) {
		re->on_read(-1);
		delete re;
	}
	if (we) {
		we->on_write(-1);
		delete we;
	}
	return state_complete(pos, end);
}
u_char* KHttp2::state_settings(u_char* pos, u_char* end) {
	if (state.sid != 0) {
		klog(KLOG_WARNING, "client sent SETTINGS frame with nonzero stream identifier\n");
		return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
	}
	if (state.flags & KGL_HTTP_V2_ACK_FLAG) {
		if (state.length != 0) {
			klog(KLOG_WARNING, "client sent SETTINGS frame with the ACK flag and nonzero length\n");
			return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
		}

		/* TODO settings acknowledged */

		return state_complete(pos, end);
	}

	if (state.length % KGL_HTTP_V2_SETTINGS_PARAM_SIZE) {
		klog(KLOG_WARNING, "client sent SETTINGS frame with incorrect length %u\n", state.length);
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}

	return state_settings_params(pos, end);
}
void KHttp2::check_write_wait() {
	KHttp2Node* node;
	KHttp2Context* stream;
	int size = kgl_http_v2_index_size();
	bool buffer_writed = false;
	kassert(kselector_is_same_thread(c->st.base.selector));
	for (int i = 0; i < size; i++) {
		for (node = streams_index[i]; node; node = node->index) {
			if (send_window <= 0) {
				//connection send_window limit
				return;
			}
			stream = node->stream;
			if (stream == NULL || stream->send_window <= 0) {
				continue;
			}
			if (stream->write_wait == NULL || !IS_WRITE_WAIT_FOR_WINDOW(stream->write_wait)) {
				continue;
			}
			kassert(stream->queue.next);
			on_write_window_ready(stream);
		}
	}
}
void KHttp2::adjust_windows(size_t window) {
	KHttp2Node* node;
	KHttp2Context* stream;
	int size = kgl_http_v2_index_size();

	int delta = (int)(window - init_window);
	init_window = (uint32_t)window;
	for (int i = 0; i < size; i++) {
		for (node = streams_index[i]; node; node = node->index) {
			stream = node->stream;
			if (stream == NULL) {
				continue;
			}
			if (delta > 0 && stream->send_window > (int)(KGL_HTTP_V2_MAX_WINDOW - delta)) {
				klog(KLOG_WARNING, "adjust_windows failed window [%d] delta [%d] stream send_window=[%d]\n", window, delta, stream->send_window);
				//terminate_stream(stream, KGL_HTTP_V2_FLOW_CTRL_ERROR);
				continue;
			}
			stream->send_window += delta;
		}
	}
	check_write_wait();
}
u_char* KHttp2::state_settings_params(u_char* pos, u_char* end) {
	uintptr_t  id, value;

	while (state.length) {
		if (end - pos < KGL_HTTP_V2_SETTINGS_PARAM_SIZE) {
			return state_save(pos, end, &KHttp2::state_settings_params);
		}

		state.length -= KGL_HTTP_V2_SETTINGS_PARAM_SIZE;

		id = kgl_http_v2_parse_uint16(pos);
		value = kgl_http_v2_parse_uint32(&pos[2]);
		//printf("setting params id=[%d] value=[%d]\n", id, value);
		switch (id) {

		case KGL_HTTP_V2_INIT_WINDOW_SIZE_SETTING:
			if (value > KGL_HTTP_V2_MAX_WINDOW) {
				klog(KLOG_WARNING, "client sent SETTINGS frame with incorrect "
					"INITIAL_WINDOW_SIZE value %u\n", value);

				return this->close(true, KGL_HTTP_V2_FLOW_CTRL_ERROR);
			}
			adjust_windows(value);
			break;
		case KGL_HTTP_V2_MAX_FRAME_SIZE_SETTING:
			if (value > KGL_HTTP_V2_MAX_FRAME_SIZE
				|| value < KGL_HTTP_V2_DEFAULT_FRAME_SIZE) {
				klog(KLOG_WARNING, "client sent SETTINGS frame with incorrect "
					"MAX_FRAME_SIZE value %u\n", value);

				return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
			}
			frame_size = (uint32_t)value;
			break;
		case KGL_HTTP_V2_ENABLE_PUSH_SETTING:
			if (value > 1) {
				klog(KLOG_WARNING, "client sent invalid ENABLE_PUSH value %u\n", value);
				return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
			}
			break;
		case KGL_HTTP_V2_ENABLE_CONNECT_SETTING:
			if (value > 1) {
				klog(KLOG_WARNING, "client sent invalid ENABLE_CONNECT_PROTOCOL value %u\n", value);
				return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
			}
			enable_connect = !!value;
			break;
		default:
			break;
		}
		pos += KGL_HTTP_V2_SETTINGS_PARAM_SIZE;
	}
	if (!send_settings_ack()) {
		return this->close(true, KGL_HTTP_V2_ENHANCE_YOUR_CALM);
	}
	return state_complete(pos, end);
}

u_char* KHttp2::state_push_promise(u_char* pos, u_char* end) {
	klog(KLOG_WARNING, "client sent unsupport push_promise frame\n");
	return state_skip(pos, end);
}
u_char* KHttp2::state_ping(u_char* pos, u_char* end) {
	if (state.sid != 0) {
		klog(KLOG_WARNING, "client sent PING frame with nonzero stream identifier\n");
		return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
	}

	if (state.length != KGL_HTTP_V2_PING_SIZE) {
		klog(KLOG_WARNING, "client sent PING frame with incorrect length %u\n", state.length);
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}

	if (end - pos < KGL_HTTP_V2_PING_SIZE) {
		return state_save(pos, end, &KHttp2::state_ping);
	}
	if (state.flags & KGL_HTTP_V2_ACK_FLAG) {
		return state_skip(pos, end);
	}
	http2_buff* frame = get_frame(0, KGL_HTTP_V2_PING_SIZE, KGL_HTTP_V2_PING_FRAME, KGL_HTTP_V2_ACK_FLAG);
	if (frame == NULL) {
		return this->close(true, KGL_HTTP_V2_ENHANCE_YOUR_CALM);
	}
	memcpy(frame->data + sizeof(http2_frame_header), pos, KGL_HTTP_V2_PING_SIZE);
	frame->tcp_nodelay = 1;
	write_buffer.push(frame);
	start_write();
	return state_complete(pos + KGL_HTTP_V2_PING_SIZE, end);
}
u_char* KHttp2::state_goaway(u_char* pos, u_char* end) {
	if (state.sid != 0) {
		klog(KLOG_WARNING, "client sent GOAWAY frame with nonzero stream identifier\n");
		return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
	}
	if (state.length < KGL_HTTP_V2_GOAWAY_SIZE) {
		klog(KLOG_WARNING, "client sent GOAWAY frame with incorrect length %u\n", state.length);
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}
	if (end - pos < KGL_HTTP_V2_GOAWAY_SIZE) {
		return state_save(pos, end, &KHttp2::state_goaway);
	}
	peer_goaway = 1;
	return state_skip(pos, end);
}
u_char* KHttp2::state_window_update(u_char* pos, u_char* end) {
	size_t                 window;
	KHttp2Node* node;
	KHttp2Context* stream;

	if (state.length != KGL_HTTP_V2_WINDOW_UPDATE_SIZE) {
		klog(KLOG_WARNING,
			"client sent WINDOW_UPDATE frame "
			"with incorrect length %u\n", state.length);
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}

	if (end - pos < KGL_HTTP_V2_WINDOW_UPDATE_SIZE) {
		return state_save(pos, end,
			&KHttp2::state_window_update);
	}

	window = kgl_http_v2_parse_window(pos);

	pos += KGL_HTTP_V2_WINDOW_UPDATE_SIZE;
	if (window == 0) {
		klog(KLOG_WARNING, "client sent WINDOW_UPDATE frame with zero increment\n");
		if (state.sid == 0) {
			return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
		}
		if (!send_rst_stream(state.sid, KGL_HTTP_V2_PROTOCOL_ERROR)) {
			return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
		}
		return state_complete(pos, end);
	}

	//printf("http2 WINDOW_UPDATE frame sid:%u window:%u\n",state.sid, window);

	if (state.sid) {
		node = this->get_node(state.sid, false);
		if (node == NULL || node->stream == NULL) {
			//klog(KLOG_WARNING,"unknown http2 stream id=[%d]\n",state.sid);
			return state_complete(pos, end);
		}
		stream = node->stream;

		if ((int64_t)stream->send_window + (int64_t)window > KGL_HTTP_V2_MAX_WINDOW) {
			klog(KLOG_WARNING,
				"client violated flow control for stream %ui: "
				"received WINDOW_UPDATE frame "
				"with window increment %u "
				"not allowed for window %u\n",
				state.sid, window, stream->send_window);
			terminate_stream(stream, KGL_HTTP_V2_FLOW_CTRL_ERROR);
			return state_complete(pos, end);
		}
		stream->send_window += (int)window;
		if (stream->write_wait && IS_WRITE_WAIT_FOR_WINDOW(stream->write_wait)) {
			kassert(stream->queue.next);
			on_write_window_ready(stream);
		}
		//printf("stream [%d] window=[%d] send_window=[%d]\n", node->id, window, stream->send_window);
		return state_complete(pos, end);
	}

	if ((int64_t)send_window + (int64_t)window > KGL_HTTP_V2_MAX_WINDOW) {
		klog(KLOG_WARNING,
			"client violated connection flow control: "
			"received WINDOW_UPDATE frame "
			"with window increment %u "
			"not allowed for window %u\n",
			window, send_window);

		return this->close(true, KGL_HTTP_V2_FLOW_CTRL_ERROR);
	}
	if (send_window <= 0) {
		send_window += (int)window;
		check_write_wait();
	} else {
		send_window += (int)window;
	}
	return state_complete(pos, end);
}
u_char* KHttp2::state_continuation(u_char* pos, u_char* end) {
	klog(KLOG_ERR, "client sent unexpected CONTINUATION frame\n");
	return this->close(true, KGL_HTTP_V2_PROTOCOL_ERROR);
}
u_char* KHttp2::state_altsvc(u_char* pos, u_char* end) {
	if (state.length < KGL_HTTP_V2_ALTSVC_SIZE) {
		klog(KLOG_WARNING, "client sent GOAWAY frame with incorrect length %u\n", state.length);
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}
	if (end - pos < KGL_HTTP_V2_ALTSVC_SIZE) {
		return state_save(pos, end, &KHttp2::state_altsvc);
	}
	//NOW skip altsvc FRAME
	return state_skip(pos, end);
}
bool KHttp2::send_rst_stream(uint32_t sid, uint32_t status) {
	http2_buff* buf = get_frame(sid, sizeof(http2_frame_rst_stream), KGL_HTTP_V2_RST_STREAM_FRAME, KGL_HTTP_V2_NO_FLAG);
	if (buf == NULL) {
		return false;
	}
	buf->tcp_nodelay = 1;
	http2_frame_rst_stream* b = (http2_frame_rst_stream*)(buf->data + sizeof(http2_frame_header));
	b->status = htonl(status);
	write_buffer.push(buf);
	start_write();
	return true;
}
u_char* KHttp2::state_skip(u_char* pos, u_char* end) {
	size_t  size;
	size = end - pos;
	if (size < state.length) {
		state.length -= (uint32_t)size;
		return state_save(end, end, &KHttp2::state_skip);
	}
	return state_complete(pos + state.length, end);
}
void KHttp2::ReleaseStateStream() {
	if (state.stream == NULL) {
		return;
	}
	if (!state.stream->parsed_header
		//{{ent
#ifdef ENABLE_UPSTREAM_HTTP2
		&& !client_model
#endif//}}
		) {
		//incomplete stream
		kassert(state.stream->sink);
		if (state.stream->sink) {
			KSink* rq = state.stream->sink;
#ifndef NDEBUG
			//调试模式时，~KHttp2Sink里面会对ctx有检查。
			KHttp2Sink* sink = static_cast<KHttp2Sink*>(rq);
			sink->ctx = NULL;
#endif
			delete rq;
		}
		destroy_node(state.stream->node);
		state.stream->Destroy();
	} else if (state.stream->destroy_by_http2) {
		//must destroy by http2
		state.stream->Destroy();
	}
	state.stream = NULL;
}
u_char* KHttp2::state_complete(u_char* pos, u_char* end) {
	if (pos > end) {
		klog(KLOG_WARNING, "receive buffer overrun\n");
		return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
	}
	ReleaseStateStream();
	state.handler = &KHttp2::state_head;
	return pos;
}
u_char* KHttp2::skip_padded(u_char* pos, u_char* end) {
	state.length += state.padding;
	state.padding = 0;
	return state_skip(pos, end);
}
u_char* KHttp2::state_skip_headers(u_char* pos, u_char* end) {
	return state_header_block(pos, end);
}
u_char* KHttp2::state_field_len(u_char* pos, u_char* end) {
	size_t                   alloc;
	intptr_t                len;
	uintptr_t               huff;

	if (!(state.flags & KGL_HTTP_V2_END_HEADERS_FLAG)
		&& state.length < KGL_HTTP_V2_INT_OCTETS) {
		return handle_continuation(pos, end, &KHttp2::state_field_len);
	}

	if (state.length < 1) {
		klog(KLOG_WARNING, "client sent header block with incorrect length\n");
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}

	if (end - pos < 1) {
		return state_save(pos, end, &KHttp2::state_field_len);
	}

	huff = *pos >> 7;
	len = parse_int(&pos, end, kgl_http_v2_prefix(7));

	if (len < 0) {
		if (len == KGL_AGAIN) {
			return state_save(pos, end, &KHttp2::state_field_len);
		}

		if (len == KGL_DECLINED) {
			klog(KLOG_WARNING, "client sent header field with too long length value\n");
			return this->close(true, KGL_HTTP_V2_COMP_ERROR);
		}

		klog(KLOG_WARNING, "client sent header block with incorrect length\n");
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}

	klog(KLOG_DEBUG, "http2 hpack %s string length: %i\n", huff ? "encoded" : "raw", len);
	state.field_rest = (uint32_t)len;
	if ((int)len > 4096) {
		klog(KLOG_WARNING, "client exceeded http2_max_field_size limit len=[%d]\n", len);
		return state_field_skip(pos, end);
	}
	if (state.stream == NULL || state.stream->destroy_by_http2) {
		return state_field_skip(pos, end);
	}
	/*
	if (state.stream == NULL && !state.index) {
		return state_field_skip(pos, end);
	}
	*/

	alloc = (huff ? len * 8 / 5 : len) + 1;

	state.field_start = (u_char*)kgl_pnalloc(state.pool, alloc);
	if (state.field_start == NULL) {
		return this->close(true, KGL_HTTP_V2_INTERNAL_ERROR);
	}

	state.field_end = state.field_start;

	if (huff) {
		return state_field_huff(pos, end);
	}

	return state_field_raw(pos, end);
}
u_char* KHttp2::state_field_huff(u_char* pos, u_char* end) {
	size_t  size;
	size = end - pos;

	if (size > state.field_rest) {
		size = state.field_rest;
	}
	if (size > state.length) {
		size = state.length;
	}
	state.length -= (uint32_t)size;
	state.field_rest -= (uint32_t)size;
	if (!kgl_http_v2_huff_decode(&state.field_state, pos, size,
		&state.field_end,
		state.field_rest == 0)) {
		klog(KLOG_WARNING, "client sent invalid encoded header field\n");
		return this->close(true, KGL_HTTP_V2_COMP_ERROR);
	}
	pos += size;
	if (state.field_rest == 0) {
		*state.field_end = '\0';
		return state_process_header(pos, end);
	}

	if (state.length) {
		return state_save(pos, end, &KHttp2::state_field_huff);
	}
	if (state.flags & KGL_HTTP_V2_END_HEADERS_FLAG) {
		klog(KLOG_WARNING, "client sent header field with incorrect length\n");
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}
	return handle_continuation(pos, end, &KHttp2::state_field_huff);
}
u_char* KHttp2::state_field_raw(u_char* pos, u_char* end) {
	size_t  size;

	size = end - pos;

	if (size > state.field_rest) {
		size = state.field_rest;
	}

	if (size > state.length) {
		size = state.length;
	}

	state.length -= (uint32_t)size;
	state.field_rest -= (uint32_t)size;

	state.field_end = (u_char*)kgl_cpymem(state.field_end, pos, size);

	pos += size;

	if (state.field_rest == 0) {
		*state.field_end = '\0';
		return state_process_header(pos, end);
	}

	if (state.length) {
		return state_save(pos, end, &KHttp2::state_field_raw);
	}

	if (state.flags & KGL_HTTP_V2_END_HEADERS_FLAG) {
		klog(KLOG_WARNING, "client sent header field with incorrect length\n");
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}
	return handle_continuation(pos, end, &KHttp2::state_field_raw);
}
u_char* KHttp2::state_field_skip(u_char* pos, u_char* end) {
	size_t  size;

	size = end - pos;

	if (size > state.field_rest) {
		size = state.field_rest;
	}

	if (size > state.length) {
		size = state.length;
	}

	state.length -= (uint32_t)size;
	state.field_rest -= (uint32_t)size;

	pos += size;

	if (state.field_rest == 0) {
		return state_process_header(pos, end);
	}

	if (state.length) {
		return state_save(pos, end, &KHttp2::state_field_skip);
	}

	if (state.flags & KGL_HTTP_V2_END_HEADERS_FLAG) {
		klog(KLOG_WARNING, "client sent header field with incorrect length\n");
		return this->close(true, KGL_HTTP_V2_SIZE_ERROR);
	}

	return handle_continuation(pos, end, &KHttp2::state_field_skip);
}
#endif
