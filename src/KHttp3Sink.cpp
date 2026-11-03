#include "KHttp3Sink.h"
#include "KHttpServer.h"
#include "KPreRequest.h"
#include <errno.h>
#ifdef ENABLE_HTTP3
static int h3_sink_tick(void* arg, int) { return ((KHttp3Sink*)arg)->check_timeout(); }
static kev_result h3_start_request(KOPAQUE, void* arg, int) {
    kfiber_create(kgl_sink_start_fiber, (KSink*)arg, 0, http_config.fiber_stack_size, nullptr);
    return kev_ok;
}
KHttp3Sink::KHttp3Sink(KHttp3Connection* conn, lsquic_stream_t* stream) : KSink(nullptr), st(stream), cn(conn) {
    cn->addRef();
    data.set_http_version(3, 0);
    for (auto& e : ev) e.cd = kfiber_cond_init(true);
    response_fields.resize(1);
    timeout_tick = kselector_new_tick(h3_sink_tick, this);
    if (timeout_tick && !kselector_register_tick(timeout_tick)) {
        kselector_close_tick(timeout_tick);
        timeout_tick = nullptr;
    }
}
KHttp3Sink::~KHttp3Sink() {
    remove_readhup();
    if (st) {
        if (processing && !aborted) end_request();
        if (st) {
            lsquic_stream_set_ctx(st, nullptr);
            lsquic_stream_close(st);
        }
    }
    if (timeout_tick) kselector_close_tick(timeout_tick);
    free_header_list(request_trailers.header);
    for (auto& e : ev) e.cd->f->release(e.cd);
    cn->release();
}
void KHttp3Sink::complete(int op, int result) {
    auto& e = ev[op];
    if (!e.waiting) return;
    e.waiting = false;
    e.result = result;
    // Fiber notices switch synchronously. Queue the wakeup so LSQUIC callbacks
    // can finish before a resumed request destroys this sink or its stream.
    auto waiter = e.cd->waiter;
    e.cd->waiter = nullptr;
    assert(waiter && waiter->st_flags == STF_FIBER && !waiter->next);
    auto fiber = kgl_list_data(waiter, kfiber, base);
    kgl_selector_module.next(waiter->selector, waiter->wait_obj, kfiber_result_callback, fiber, result);
}
int KHttp3Sink::wait(int op) {
    auto& e = ev[op];
    e.waiting = true;
    e.active = kgl_current_msec;
    int got;
    e.cd->f->wait(e.cd, &got);
    return e.result;
}
void KHttp3Sink::notify_hup(int result) {
    auto cb = hup_result;
    auto arg = hup_arg;
    remove_readhup();
    if (cb) cb(nullptr, arg, result);
}
void KHttp3Sink::abort_stream(uint64_t error, int result) {
    if (aborted) return;
    aborted = true;
    if (st) {
        lsquic_stream_wantread(st, 0);
        lsquic_stream_wantwrite(st, 0);
        lsquic_stream_maybe_reset(st, error, 1);
    }
    complete(OP_READ, result);
    complete(OP_WRITE, result);
    notify_hup(result);
}
void KHttp3Sink::shutdown() { abort_stream(0x10c); /* H3_REQUEST_CANCELLED */ }
void KHttp3Sink::detach_stream() {
    st = nullptr;
    abort_stream(0x10c);
}
void KHttp3Sink::on_reset(int how) {
    if (how == 0 && read_canceled) return;
    // RESET_STREAM or STOP_SENDING must also cancel work at the upstream.
    abort_stream(0x10c);
}
void KHttp3Sink::cancel_read() {
    if (read_canceled) return;
    read_canceled = true;
    if (st) lsquic_stream_shutdown(st, 0);
    complete(OP_READ, -1);
}
bool KHttp3Sink::readhup(void* arg, result_callback result) {
    if (!st || aborted || hup_result) return false;
    hup_arg = arg;
    hup_result = result;
    hup_active = kgl_current_msec;
    return true;
}
void KHttp3Sink::set_time_out(int count) {
    timeout_count = KGL_MAX(0, KGL_MIN(count, 255));
    for (auto& e : ev) e.active = kgl_current_msec;
    hup_active = kgl_current_msec;
}
int KHttp3Sink::check_timeout() {
    if (aborted || !st) return -1;
    // Match the timeout mark's multiplier used by HTTP/1 and HTTP/2.
    int64_t interval = (int64_t)KGL_MAX(1, http_config.time_out) * (timeout_count + 1) * 1000;
    int64_t remaining = interval;
    bool active = false;
    for (const auto& e : ev) if (e.waiting) {
        active = true;
        remaining = KGL_MIN(remaining, interval - (kgl_current_msec - e.active));
    }
    if (hup_result) {
        active = true;
        remaining = KGL_MIN(remaining, interval - (kgl_current_msec - hup_active));
    }
    if (!active) return -1;
    if (remaining <= 0) {
        abort_stream(0x10c, ST_ERR_TIME_OUT);
        return -1;
    }
    return (int)KGL_MIN(remaining, 1000);
}
void KHttp3Sink::on_headers(lsquic_stream_t* stream) {
    auto hset = (header_decoder*)lsquic_stream_get_hset(stream);
    if (!hset) return;
    bool good = !hset->invalid && !aborted && !trailer_received;
    if (header_received) {
        KHttpHeaderValidation validation{};
        for (auto h = hset->fields.header; good && h; h = h->next)
            good = validation.field(h->buf, h->name_len, h->buf + h->val_offset, h->val_len, true, true, true);
        if (good) {
            request_trailers.header = hset->fields.steal_header();
            trailer_received = true;
        }
    } else {
        bool first = true;
        for (auto h = hset->fields.header; good && h; h = h->next) {
            // Extended CONNECT requires a setting this adapter does not advertise.
            if (h->buf[0] == ':' && khttp_field_equal(h->buf, h->name_len, ":protocol")) good = false;
            else good = KSink::parse_header<const char*>(h->buf, h->name_len, h->buf + h->val_offset, h->val_len, first);
            first = false;
        }
        good = good && input_headers.complete(true) && !data.raw_url.is_bad();
        if (good) {
            request_length = KBIT_TEST(data.flags, RQ_HAS_CONTENT_LEN) ? data.left_read : -1;
            data.left_read = request_length;
            header_received = true;
        }
    }
    free_header_decoder(hset);
    if (!good) abort_stream(0x10e); /* H3_MESSAGE_ERROR */
    else if (!processing) {
        // Claiming the header set removes LSQUIC's read notification when no
        // DATA or FIN has arrived yet. Start header-only requests immediately,
        // outside the decoder callback, including Expect: 100-continue.
        processing = true;
        lsquic_stream_wantread(stream, 0);
        kgl_selector_module.next(get_selector(), nullptr, h3_start_request, this, 0);
    }
}
void KHttp3Sink::start(int) {
    if (!aborted && header_received) khttp_server_new_request(this, 0);
}
void KHttp3Sink::on_read(lsquic_stream_t* stream) {
    if (aborted || read_canceled) { lsquic_stream_wantread(stream, 0); return; }
    if (!processing) {
        if (!header_received) on_headers(stream);
        lsquic_stream_wantread(stream, 0);
        return;
    }
    if (!ev[OP_READ].waiting) { lsquic_stream_wantread(stream, 0); return; }
    int got = (int)lsquic_stream_readv(stream, ev[OP_READ].buf, ev[OP_READ].bc);
    if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
    lsquic_stream_wantread(stream, 0);
    if (got > 0) {
        body_read += got;
        if (request_length >= 0 && body_read > request_length) { abort_stream(0x10e); return; }
    } else if (got == 0) {
        if (request_length >= 0 && body_read != request_length) { abort_stream(0x10e); return; }
        input_eof = true;
    }
    if (got >= 0) hup_active = kgl_current_msec;
    complete(OP_READ, got);
}
int KHttp3Sink::internal_read(char* buf, int len) {
    if (!st || aborted || read_canceled) return -1;
    if (len <= 0 || input_eof) return 0;
    assert(!ev[OP_READ].waiting);
    WSABUF buffer;
    buffer.iov_base = buf;
    buffer.iov_len = len;
    ev[OP_READ].buf = &buffer;
    ev[OP_READ].bc = 1;
    if (lsquic_stream_wantread(st, 1) < 0) return -1;
    return wait(OP_READ);
}
bool KHttp3Sink::finish_read_body() {
    if (data.left_read != 0 || aborted || read_canceled) return false;
    char extra;
    return internal_read(&extra, 1) == 0;
}
bool KHttp3Sink::add_header(std::vector<lsxpack_header>& headers, const char* name, int nlen, const char* value, int vlen) {
    while (vlen > 0 && (value[0] == ' ' || value[0] == '\t')) { ++value; --vlen; }
    while (vlen > 0 && (value[vlen-1] == ' ' || value[vlen-1] == '\t')) --vlen;
    if (nlen <= 0 || nlen > MAX_HEADER_ATTR_VAL_SIZE || vlen < 0 || vlen > MAX_HEADER_ATTR_VAL_SIZE || headers.size() >= KHTTP_MAX_FIELD_COUNT) return false;
    size_t bytes = nlen + vlen + 32;
    for (const auto& field : headers) bytes += field.name_len + field.val_len + 32;
    if (bytes > 64 * 1024) return false;
    lsxpack_header h{};
    h.buf = (char*)kgl_pnalloc(pool, nlen + vlen + 2);
    kgl_strlow((u_char*)h.buf, (u_char*)name, nlen);
    h.name_len = nlen;
    h.val_len = vlen;
    h.val_offset = nlen + 1;
    h.buf[nlen] = 0;
    memcpy(h.buf + h.val_offset, value, vlen);
    h.buf[h.val_offset + vlen] = 0;
    headers.push_back(h);
    return true;
}
bool KHttp3Sink::internal_response_status(uint16_t status) {
    if (final_sent || status == 101 || status < 100 || status > 599) return false;
    char value[4];
    snprintf(value, sizeof(value), "%03u", status);
    std::vector<lsxpack_header> status_field;
    if (!add_header(status_field, ":status", 7, value, 3)) return false;
    response_fields[0] = status_field[0];
    return true;
}
bool KHttp3Sink::response_header(const char* name, int nlen, const char* value, int vlen) {
    if (final_sent || !khttp_valid_field(name, nlen, value, vlen)) return false;
    if (khttp_field_equal(name,nlen,"connection") || khttp_field_equal(name,nlen,"keep-alive") ||
        khttp_field_equal(name,nlen,"proxy-connection") || khttp_field_equal(name,nlen,"transfer-encoding") ||
        khttp_field_equal(name,nlen,"upgrade") || khttp_field_equal(name,nlen,"te")) return true;
    return add_header(response_fields, name, nlen, value, vlen);
}
bool KHttp3Sink::send_headers(std::vector<lsxpack_header>& headers) {
    if (!st || aborted || headers.empty()) return false;
    assert(!ev[OP_WRITE].waiting && pending_headers == nullptr);
    pending_headers = &headers;
    if (lsquic_stream_wantwrite(st, 1) < 0) { pending_headers = nullptr; return false; }
    int result = wait(OP_WRITE);
    pending_headers = nullptr;
    return result >= 0;
}
int KHttp3Sink::internal_start_response_body(int64_t size, bool interim) {
    if (final_sent) return -1;
    if (interim) {
        std::vector<lsxpack_header> info(1, response_fields[0]);
        if (!send_headers(info)) return -1;
        response_fields[0] = lsxpack_header{};
        flush();
    } else {
        if (!send_headers(response_fields)) return -1;
        final_sent = true;
        content_left = size;
    }
    return 0;
}
bool KHttp3Sink::response_early_hints(const KHttpHeader* headers) {
    if (final_sent || data.status_code || KBIT_TEST(data.flags, RQ_HAS_SEND_HEADER)) return false;
    std::vector<lsxpack_header> hints;
    if (!add_header(hints, ":status", 7, "103", 3)) return false;
    for (auto h = headers; h; h = h->next) {
        kgl_str_t name;
        kgl_get_header_name((KHttpHeader*)h, &name);
        if (!add_header(hints, name.data, (int)name.len, h->buf + h->val_offset, h->val_len)) return false;
    }
    if (!send_headers(hints)) return false;
    flush();
    return true;
}
bool KHttp3Sink::response_trailer(const char* name, int nlen, const char* value, int vlen) {
    if (!final_sent || ended || aborted || content_left > 0 || !khttp_valid_trailer(name, nlen, value, vlen)) return false;
    return add_header(response_trailers, name, nlen, value, vlen);
}
void KHttp3Sink::end_request() {
    if (ended || !st || aborted) return;
    if (!final_sent || content_left > 0) { shutdown(); return; }
    if (!response_trailers.empty() && !send_headers(response_trailers)) { shutdown(); return; }
    ended = true;
    // Finish the response independently, then stop an unused request body.
    lsquic_stream_shutdown(st, 1);
    if (!input_eof) cancel_read();
    flush();
}
void KHttp3Sink::on_write(lsquic_stream_t* stream) {
    if (!ev[OP_WRITE].waiting || aborted) { lsquic_stream_wantwrite(stream, 0); return; }
    int got;
    if (pending_headers) {
        lsquic_http_headers_t headers;
        headers.headers = pending_headers->data();
        headers.count = pending_headers->size();
        got = lsquic_stream_send_headers(stream, &headers, 0);
    } else got = (int)lsquic_stream_writev(stream, ev[OP_WRITE].buf, ev[OP_WRITE].bc);
    if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
    // Zero body bytes is temporary backpressure, not a closed stream. Keep the
    // fiber and write interest until LSQUIC has connection/stream credit again.
    // Header sending uses zero to report success and must still wake its fiber.
    if (!pending_headers && got == 0) return;
    lsquic_stream_wantwrite(stream, 0);
    if (got >= 0) hup_active = kgl_current_msec;
    complete(OP_WRITE, got);
}
int KHttp3Sink::internal_write(WSABUF* buf, int count) {
    if (!st || aborted || ended || !final_sent || !response_trailers.empty()) return -1;
    int64_t size = 0;
    for (int i = 0; i < count; i++) size += buf[i].iov_len;
    if (content_left >= 0 && size > content_left) { abort_stream(0x10e); return -1; }
    ev[OP_WRITE].buf = buf;
    ev[OP_WRITE].bc = count;
    if (lsquic_stream_wantwrite(st, 1) < 0) return -1;
    int result = wait(OP_WRITE);
    if (result > 0) {
        if (content_left >= 0) content_left -= result;
        add_down_flow(nullptr, result);
    }
    return result;
}
#define KGL_H3_WRITE_BUF_COUNT 64
int KHttp3Sink::write_all(const kbuf* buf, int length) {
    // Hand several buffers to one internal_write: each call waits for an
    // engine write callback, so one buffer per call made big bodies slow.
    int left = length;
    int offset = 0; // bytes of buf already written
    while (left > 0 && buf) {
        WSABUF bufs[KGL_H3_WRITE_BUF_COUNT];
        int bc = 0;
        int size = 0;
        int b_offset = offset;
        for (const kbuf* b = buf; b && bc < KGL_H3_WRITE_BUF_COUNT && size < left; b = b->next) {
            if (b->used < 0) return left;
            int amount = KGL_MIN(left - size, b->used - b_offset);
            if (amount > 0) {
                bufs[bc].iov_base = b->data + b_offset;
                bufs[bc].iov_len = amount;
                bc++;
                size += amount;
            }
            b_offset = 0;
        }
        if (bc == 0) break;
        int got = internal_write(bufs, bc);
        if (got <= 0) break;
        left -= got;
        while (got > 0 && buf) {
            int avail = buf->used - offset;
            if (got < avail) {
                offset += got;
                break;
            }
            got -= avail;
            buf = buf->next;
            offset = 0;
        }
    }
    return left;
}
int KHttp3Sink::write_all(const char* str, int length) {
    while (length > 0) {
        WSABUF buf;
        buf.iov_base = (char*)str;
        buf.iov_len = length;
        int got = internal_write(&buf, 1);
        if (got <= 0) break;
        length -= got;
        str += got;
    }
    return length;
}
#endif
