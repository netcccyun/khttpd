/*
 * KPoolableStream.h
 *
 *  Created on: 2010-8-18
 *      Author: keengo
 */

#ifndef KUPSTREAM_H
#define KUPSTREAM_H
#include <time.h>
#include "kselector.h"
#include "ksocket.h"
#include "kconnection.h"
#include "kmalloc.h"
#include "kstring.h"
#include "KHttpHeader.h"
enum class HealthStatus
{
	//this only detect socket on tcp level(write success)
	Err,
	Success
};


class KPoolableSocketContainer;
class KWriteStream;
class KUpstream;
//when attr is NULL, and attr_len treated as kgl_header_type
typedef bool (*kgl_header_callback)(KUpstream* us, void* arg, const char* attr, int attr_len, const char* val, int val_len, bool request_line);

class KUpstreamCallBack
{
public:
	KUpstreamCallBack() {
		memset(this, 0, sizeof(KUpstreamCallBack));
	}
	kgl_header_callback header;
	void* arg;
};

class KUpstream
{
public:
	KUpstream() {
		expire_time = 0;
		container = NULL;
	}
	virtual void set_delay() {}
	virtual void set_no_delay(bool forever) {}
	virtual KOPAQUE GetOpaque() {
		return get_connection()->st.data;
	}
	kselector* get_selector() {
		return get_connection()->st.base.selector;
	}
	virtual bool support_websocket() {
		return false;
	}
	virtual KHttpHeader* get_trailer() {
		return nullptr;
	}
	virtual bool send_connection(const char* val, hlen_t val_len) = 0;
	virtual bool send_header(kgl_header_type attr, const char* val, hlen_t val_len) {
		return send_header(kgl_header_type_string[attr].value.data, (hlen_t)kgl_header_type_string[attr].value.len, val, val_len);
	}
	virtual bool send_header(const char* attr, hlen_t attr_len, const char* val, hlen_t val_len) = 0;
	virtual bool send_trailer(const char* name, hlen_t name_len, const char* val, hlen_t val_len) = 0;
	virtual bool send_method_path(uint16_t meth, const char* path, hlen_t path_len) = 0;
	virtual bool send_host(const char* host, hlen_t host_len) = 0;
	virtual void set_content_length(int64_t content_length) = 0;
	virtual KGL_RESULT send_header_complete() = 0;
	virtual void BindOpaque(KOPAQUE data) = 0;
	virtual bool set_header_callback(void* arg, kgl_header_callback header_callback) = 0;
	virtual KGL_RESULT read_header() = 0;
	virtual kgl_pool_t* GetPool() = 0;
	virtual kconnection* get_connection() = 0;
	virtual void write_end() {
	}
	virtual int read(char* buf, int len) = 0;
	/*
	* write_all will send data until all success or failed.
	* if failed return left byte.
	* if return 0 will all success.
	*/
	virtual int write_all(const kbuf* buf, int len) = 0;
	virtual int write_all(const char* buf, int len) {
		kbuf bufs{ 0 };
		bufs.data = (char*)buf;
		bufs.used = len;
		return write_all(&bufs, len);
	}
	virtual void shutdown() = 0;
	virtual void Destroy() = 0;
	virtual bool IsMultiStream() {
		return false;
	}
	virtual void set_time_out(int tmo) {
	}


	virtual KUpstream* NewStream() {
		return NULL;
	}
	virtual bool IsNew() {
		return expire_time == 0;
	}
	virtual int GetLifeTime();
	virtual void health(HealthStatus stage);
	virtual sockaddr_i* GetAddr() = 0;
	bool GetSelfAddr(sockaddr_i* addr) {
		kconnection* cn = get_connection();
		if (cn == NULL) {
			return false;
		}
		return 0 == kconnection_self_addr(cn, addr);
	}
	uint16_t GetSelfPort() {
		sockaddr_i addr;
		if (!GetSelfAddr(&addr)) {
			return 0;
		}
		return ksocket_addr_port(&addr);
	}
	virtual kgl_ref_str_t* get_param();
	virtual void gc(int life_time) = 0;
	virtual KPoolableSocketContainer* get_container() {
		return container;
	}
	friend class KPoolableSocketContainer;
	union
	{
		time_t expire_time;
		//记录开始读的时间，用于长连接计算超时用的。
		time_t read_header_time;
	};
	KPoolableSocketContainer* container;
protected:
	virtual void unbind_selector() {
	}
	virtual void bind_selector(kselector* selector) {
	}
	virtual void clean() {

	}
	virtual ~KUpstream();
};
#endif
