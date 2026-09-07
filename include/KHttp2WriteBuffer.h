#ifndef KSPDYWRITEBUFFER_H
#define KSPDYWRITEBUFFER_H
#include <string.h>
#include <assert.h>
#include <ctype.h>
#ifndef _WIN32
#include <stdint.h>
#include <sys/uio.h>
#endif
#include "khttp.h"
#include "kforwin32.h"
#include "KMutex.h"
#include "kselector.h"
#include "ksocket.h"
#include "KUpstream.h"
#include "kfiber.h"

#ifdef ENABLE_HTTP2

#define IS_WRITE_WAIT_FOR_WINDOW(we)	(we->len<0 && we->buf!=NULL)
#define IS_WRITE_WAIT_FOR_HUP(we)		(we->buf==NULL)
#define IS_WRITE_WAIT_FOR_WRITING(we)	(we->len>=0 && we->buf!=NULL)

#define ENABLE_HTTP2_TCP_CORK 1
class KHttp2Context;
class KHttp2;
class http2_buff;


class kgl_http2_event
{
public:
	kgl_http2_event()
	{
		memset(this, 0, sizeof(kgl_http2_event));
	}
	~kgl_http2_event();
	void on_read(int got) {
		if (fiber) {
			kfiber* f = fiber;
			fiber = nullptr;
			kfiber_wakeup(f, this, got);
		}
	}
	void on_write(int got) {
		if (IS_WRITE_WAIT_FOR_HUP(this)) {
			readhup_result(NULL, readhup_arg, got);
		} else {
			kfiber_wakeup(fiber, this, got);
		}
	}
	union
	{
		/**
		* write_event use readhup_result or fiber to wait result.
		* when use readhup_result the buf must be NULL otherwise buf must not NULL.
		*/
		kfiber* fiber;
		result_callback readhup_result;
	};
	union {
		/**
		* on client model before complete read header. 
		* read_event will use header callback and the fiber can be NULL(no wait header) or NOT NULL(wait the header).
		*/
		const kbuf* buf;
		kgl_header_callback header;
		kasync_file* file;
		char* rbuf;
	};
	union {
		struct {
			int buf_len;
			int len;
		};
		void* header_arg;
		void* readhup_arg;
	};
};
class http2_buff
{
public:
	http2_buff()
	{
		memset(this,0,sizeof(*this));
	}
	~http2_buff();
	void clean(bool fin);
	union
	{
		char* data;
		kasync_file* file;
	};
	int used;
	int skip_data_free:1;
	int sendfile : 1;
	int tcp_nodelay : 1;
	int counted : 1;
	KHttp2Context *ctx;
	http2_buff *next;
};
#define KGL_HEADER_FRAME_CHUNK_SIZE 4096
class KHttp2HeaderFrame
{
public:
	KHttp2HeaderFrame()
	{
		memset(this, 0, sizeof(KHttp2HeaderFrame));
	}
	~KHttp2HeaderFrame()
	{
		while (head) {
			last = head->next;			
			delete head;
			head = last;
		}
	}
	http2_buff *create(uint32_t stream_id,bool no_body, size_t frame_size);
	void write_lower_string(const char *str, int len)
	{
		while (len) {
			int chunk_len = len;
			char *buf = alloc_buffer(chunk_len);
			len -= chunk_len;
			while (chunk_len) {
				*buf = tolower(*str);
				buf++;
				str++;
				chunk_len--;
			}
		}
	}
	void write_int(u_char type,uintptr_t prefix, uintptr_t value)
	{
		char buf[32];
		u_char *pos = (u_char *)buf;
		*pos = type;
		if (value < prefix) {
			*pos |= value;
			write(buf, 1);
			return;
		}

		*pos++ |= prefix;
		value -= prefix;

		while (value >= 128) {
			*pos++ = value % 128 + 128;
			value /= 128;
		}
		*pos++ = (u_char)value;
		assert(pos - (u_char *)buf <= (int)sizeof(buf));
		write(buf, (int)(pos - (u_char *)buf));
		return;
	}
	void write(const u_char data)
	{
		write((char *)&data, 1);
	}
	void write(const char *str, int len)
	{
		while (len) {
			int chunk_len = len;
			char *buf = alloc_buffer(chunk_len);
			len -= chunk_len;
			kgl_memcpy(buf, str, chunk_len);
			str += chunk_len;
		}
	}
	void insert(const char *str, int len)
	{
		if (head == NULL) {
			write(str, len);
			return;
		}
		http2_buff *buf = new http2_buff;
		buf->data = (char *)xmalloc(len);
		buf->used = len;
		kgl_memcpy(buf->data, str, len);
		buf->next = head;
		head = buf;
	}
private:
	char *alloc_buffer(int &len)
	{
		if (last == NULL || last->used == KGL_HEADER_FRAME_CHUNK_SIZE) {
			http2_buff *buf = new http2_buff;
			buf->data = (char *)xmalloc(KGL_HEADER_FRAME_CHUNK_SIZE);
			hot = buf->data;
			if (head == NULL) {
				head = buf;
			}
			if (last) {
				last->next = buf;
			}
			last = buf;
		}
		assert(last->used < KGL_HEADER_FRAME_CHUNK_SIZE);
		int left = KGL_HEADER_FRAME_CHUNK_SIZE - last->used;
		len = KGL_MIN(len, left);
		last->used += len;
		char *ret = hot;
		hot += len;
		return ret;
	}
	http2_buff *head;
	http2_buff *last;
	char *hot;
};
class KHttp2WriteBuffer
{
public:
	KHttp2WriteBuffer()
	{
		memset(this,0,sizeof(*this));
	}
	~KHttp2WriteBuffer()
	{
		http2_buff *buf = clean();
		KHttp2WriteBuffer::remove_buff(buf,true);
	}
	kgl_iovec* get_read_buffer(SOCKET fd) {
#ifdef ENABLE_HTTP2_TCP_CORK
		if (!tcp_cork) {
			tcp_cork = 1;
			ksocket_delay(fd);
		}
#endif
#ifndef NDEBUG
		if (hot == NULL) {
			//it is a bug.
			kassert(false);
		}
#endif
		if (header->sendfile) {
			iovec_buf[0].iov_base = (char*)header->file;
			iovec_buf[0].iov_len = header->used;
		} else {
			iovec_buf[0].iov_base = (char*)(iovec_buf+1);
			iovec_buf[0].iov_len = get_read_buffer(iovec_buf + 1, MAX_IOVECT_COUNT - 1);
		}
		return iovec_buf;
	}
	http2_buff *readSuccess(SOCKET fd,int got)
	{
		http2_buff *remove_list = NULL;
		left -= got;
		while (got>0) {
			bool header_is_empty;
			if (header->sendfile) {
				header->file->st.offset += got;
				int this_len = KGL_MIN(got, header->used);
				header->used -= this_len;
				got -= this_len;
				header_is_empty = (header->used == 0);
			} else {
				int hot_left = header->used - (int)(hot - header->data);
				int this_len = KGL_MIN(got, hot_left);
				hot += this_len;
				got -= this_len;
				header_is_empty = (header->used == hot - header->data);
			}
			if (header_is_empty) {
#ifdef ENABLE_HTTP2_TCP_CORK
				if (header->tcp_nodelay) {
					tcp_no_cork_at_empty = 1;
				}
#endif
				if (header->counted) {
					assert(counted_frames > 0);
					counted_frames--;
				}
				http2_buff *next = header->next;
				header->next = remove_list;
				remove_list = header;
				header = next;
				if (header==NULL) {
					reset();
#ifdef ENABLE_HTTP2_TCP_CORK
					check_tcp_cork(fd);
#endif
					return remove_list;
				}
				hot = header->data;
			}
		}
		if (left==0) {
			reset();
#ifdef ENABLE_HTTP2_TCP_CORK
			check_tcp_cork(fd);	
#endif
		}
		return remove_list;
	}
	void push(http2_buff *buf)
	{
		while (buf) {
			add(buf);
			buf = buf->next;
		}
	}
	int getBufferSize()
	{		
		return left;
	}
	int getCountedFrames()
	{
		return counted_frames;
	}
	bool is_sendfile() {
		assert(header);
		return header->sendfile;
	}
	http2_buff *clean();
	/* return fin */
	static void remove_buff(http2_buff *remove_list,bool fin)
	{
		 while (remove_list) {
			http2_buff *next = remove_list->next;
			remove_list->clean(fin);
			delete remove_list;
			remove_list = next;
		}
		return;
	}
private:
	int get_read_buffer(WSABUF* buffer, int bc) {
		assert(hot);
		int got = left;
		assert(header);
		http2_buff* tmp = header;
		buffer[0].iov_base = hot;
		int hot_left = header->used - (int)(hot - header->data);
		hot_left = KGL_MIN(hot_left, got);
		buffer[0].iov_len = hot_left;
		got -= hot_left;
		int i;
		for (i = 1; i < bc; i++) {
			tmp = tmp->next;
			if (tmp == NULL || got <= 0 || tmp->sendfile) {
				break;
			}
			buffer[i].iov_base = tmp->data;
			buffer[i].iov_len = KGL_MIN(got, tmp->used);
			got -= buffer[i].iov_len;
		}
		return i;
	}
	void reset()
	{
#ifndef NDEBUG
		if (left != 0 || header!=NULL) {
			//it is a bug.
			kassert(false);
		}
#endif
		assert(header == NULL);
		assert(left == 0);
		assert(counted_frames == 0);
		last = NULL;
		hot = NULL;
	}
#ifdef ENABLE_HTTP2_TCP_CORK
	void check_tcp_cork(SOCKET fd)
	{
		if (tcp_no_cork_at_empty) {
			tcp_no_cork_at_empty = 0;
			if (!tcp_cork) {
				return;
			}
			tcp_cork = 0;
			ksocket_no_delay(fd,false);
		}
	}
#endif
	void add(http2_buff *buf)
	{
		left += buf->used;
		if (buf->counted) {
			counted_frames++;
		}
		if (last==NULL) {
			assert(header==NULL);
			last = header = buf;
			hot = header->data;
		} else {
			last->next = buf;
			last = buf;
		}
	}
	kgl_iovec  iovec_buf[MAX_IOVECT_COUNT];
	http2_buff *last;
	http2_buff *header;
	char *hot;
	int left;
	int counted_frames;
#ifdef ENABLE_HTTP2_TCP_CORK
	uint16_t tcp_cork : 1;
	uint16_t tcp_no_cork_at_empty : 1;
#endif
};
#endif
#endif
