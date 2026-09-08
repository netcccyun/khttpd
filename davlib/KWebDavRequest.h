#ifndef KHTTPD_KWEBDAVREQUEST_H
#define KHTTPD_KWEBDAVREQUEST_H
#include "KUpstream.h"
#include "KHttpHeaderManager.h"
#include "KXmlDocument.h"
#include "kbuf.h"
#include "KDechunkEngine.h"
#include "KHttpLib.h"

class KWebDavLockToken;
struct KWebDavAuth;
class KWebDavClient;
bool webdav_header_callback(KUpstream* us, void* arg, const char* attr, int attr_len, const char* val, int val_len, bool is_first);
class KResponseData : public KHttpHeaderManager
{
public:
	KResponseData()
	{
		memset(this, 0, sizeof(*this));
	}
	~KResponseData()
	{
		free_header_list(header);
		if (dechunk) {
			delete dechunk;
		}
		if (us) {
			us->gc(left == 0 ? 10 : -1);
		}
	}
	bool parse_header(KUpstream *us, const char* attr, int attr_len, const char* val, int val_len, bool is_first)
	{
		if (is_first) {
			status_code = atoi(val);
			if (is_status_code_no_body(status_code)) {
				left = 0;
			}
			return true;
		}
		if (strcasecmp(attr, "Transfer-Encoding") == 0) {
			if (strcasecmp(val, "chunked") == 0 && dechunk == nullptr) {
				left = -1;
				dechunk = new KDechunkReader();
			}
			return true;
		}
		if (!strcasecmp(attr, "Content-length")) {
			left = string2int(val);
			if (dechunk) {
				delete dechunk;
				dechunk = nullptr;
			}
			return true;
		}
		return add_header(attr, attr_len, val, val_len);
	}
	int read(char* buf, int len)
	{
		if (left == 0) {
			return 0;
		}
		if (left > 0) {
			assert(dechunk == nullptr);
			len = (int)(KGL_MIN(left, len));
			int got = us->read(buf, len);
			if (got <= 0) {
				return -1;
			}
			left -= got;
			return got;
		}
		if (dechunk) {
			int got = dechunk->read<KUpstream>(us,buf, len);
			if (got == 0) {
				left = 0;
			}
			return got;
		}
		return us->read(buf, len);
	}
	int read_all(char* buf, int len)
	{
		int total_len = 0;
		while (len > 0) {
			int got = read(buf, len);
			if (got == 0) {
				return total_len;
			}
			if (got < 0) {
				return -1;
			}
			buf += got;
			len -= got;
			total_len += got;
		}
		return total_len;
	}
	ks_buffer* read_body(KGL_RESULT &result, int max_body_len) {
		int64_t body_len = left;
		if (body_len == 0) {
			result = KGL_OK;
			return nullptr;
		}
		if (body_len > max_body_len) {
			result = KGL_EINSUFFICIENT_BUFFER;
			return nullptr;
		}
		if (body_len > 0) {
			ks_buffer* buffer = ks_buffer_new((int)(body_len + 1));
			if (read_all(buffer->buf, (int)body_len) != body_len) {
				ks_buffer_destroy(buffer);
				result = KGL_ESOCKET_BROKEN;
				return nullptr;
			}
			buffer->buf[body_len] = '\0';
			//ks_write_success(buffer, body_len);
			//ks_write_str(buffer, "\0", 1);
			result = KGL_OK;
			return buffer;
		}
		ks_buffer* buffer = ks_buffer_new(4096);
		for (;;) {
			int len;
			char* buf = ks_get_write_buffer(buffer, &len);
			//printf("before us_read buf=[%p] len=[%d]\n",buf, len);
			int got = read(buf, len);
			assert(got <= len);
			//printf("got=[%d]\n", got);
			if (got < 0) {
				ks_buffer_destroy(buffer);
				result = KGL_ESOCKET_BROKEN;
				return nullptr;
			}
			if (got == 0) {
				ks_write_str(buffer, "\0", 1);
				result = KGL_OK;
				return buffer;
			}
			if (buffer->used > max_body_len - got) {
				ks_buffer_destroy(buffer);
				result = KGL_EINSUFFICIENT_BUFFER;
				return nullptr;
			}
			ks_write_success(buffer, got);
		}
		return nullptr;
	}
	uint16_t status_code;
	int64_t left;
	KUpstream* us;
	KDechunkReader* dechunk;
};
class KWebDavRequest
{
public:
	KWebDavRequest(KWebDavClient *client,KUpstream *us);
	~KWebDavRequest();
	bool send_header(const char* attr, hlen_t attr_len, const char* val, hlen_t val_len)
	{
		return resp.us->send_header(attr, attr_len, val, val_len);
	}
	KGL_RESULT send_header_complete()
	{
		return resp.us->send_header_complete();
		
	}
	KGL_RESULT read_header()
	{
		resp.us->set_no_delay(false);
		return resp.us->read_header();
	}
	bool send_http_auth(KWebDavAuth* auth);
	bool send_if_lock_token(KWebDavLockToken* token, bool send_resource=false);
	bool send_lock_token(KWebDavLockToken* token);
	KGL_RESULT write_all(const char* buf, int len)
	{
		return resp.us->write_all(buf, len)==0?KGL_OK:KGL_EIO;
	}
	int read(char* buf, int len)
	{
		return resp.read(buf, len);
	}
	int read_all(char* buf, int len) 
	{
		return resp.read_all(buf, len);
	}
	int64_t get_left()
	{
		return resp.left;
	}
	KGL_RESULT skip_body();
	ks_buffer *read_body(KGL_RESULT &result);
	KGL_RESULT read_body(khttpd::KXmlDocument &body);
	KResponseData resp;
private:
	
	KWebDavClient* client;
};
#endif
