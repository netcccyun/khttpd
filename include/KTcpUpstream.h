#ifndef KTCPUPSTREAM_H
#define KTCPUPSTREAM_H
#include "KUpstream.h"
#include "kconnection.h"
#include "kfiber.h"

class KTcpUpstream : public KUpstream {
public:
	KTcpUpstream(kconnection* cn)
	{
		this->cn = cn;
		pool = NULL;
		assert(cn);
		bind_selector(kgl_get_tls_selector());
	}
	void BindOpaque(KOPAQUE data) override
	{
		selectable_bind_opaque(&cn->st, data);
	}
	sockaddr_i *GetAddr() override
	{
		if (cn) {
			return &cn->addr;
		}
		return NULL;
	}
	kconnection *get_connection() override
	{
		return this->cn;
	}
#ifdef LINUX
	/* pooled connections are reused for many requests: skip setsockopt calls that change nothing */
	void set_delay() override {
		if (!corked) {
			ksocket_delay(cn->st.fd);
			corked = 1;
		}
	}
	void set_no_delay(bool forever) override {
		if (forever) {
			if (!no_delay) {
				ksocket_no_delay(cn->st.fd, true);
				no_delay = 1;
			}
			return;
		}
		/* on Linux this only removes TCP_CORK */
		if (corked) {
			ksocket_no_delay(cn->st.fd, false);
			corked = 0;
		}
	}
#else
	void set_delay() override {
		ksocket_delay(cn->st.fd);
	}
	void set_no_delay(bool forever) override {
		ksocket_no_delay(cn->st.fd, forever);
	}
#endif
	void shutdown() override
	{
		selectable_shutdown(&cn->st);
	}
	void set_time_out(int tmo) override
	{
		cn->st.base.tmo = tmo;
		cn->st.base.tmo_left = tmo;
	}
	bool send_connection(const char* val, hlen_t val_len) override
	{
		return true;
	}
	bool send_trailer(const char* name, hlen_t name_len, const char* val, hlen_t val_len) override;
	bool send_header(const char* attr, hlen_t attr_len, const char* val, hlen_t val_len) override;
	bool send_method_path(uint16_t meth, const char* path, hlen_t path_len) override;
	bool send_host(const char* host, hlen_t host_len) override;
	void set_content_length(int64_t content_length) override
	{

	}
	KGL_RESULT send_header_complete() override;
	bool set_header_callback(void* arg, kgl_header_callback cb) override;
	virtual KGL_RESULT read_header() override;
	int read(char* buf, int len) override;
	int write_all(const kbuf* buf,int bc) override;
	int write_all(const char* buf, int bc) override;
	void bind_selector(kselector *selector) override;
	virtual void gc(int life_time) override;
	void unbind_selector() override;
	void Destroy() override
	{
		delete this;
	}
	void clean() override
	{
		if (pool) {
			kgl_destroy_pool(pool);
			pool = NULL;
		}
		memset(&stack, 0, sizeof(stack));
	}
	kgl_pool_t* GetPool() override
	{
		if (pool == NULL) {
			pool = kgl_create_pool(8192);
		}
		return pool;
	}
	friend class KPoolableSocketContainer;
protected:

	~KTcpUpstream()
	{
		if (cn) {
			kfiber_net_close(cn);
		}
		assert(pool == NULL);
	}
	kconnection *cn;
	KUpstreamCallBack stack;
	kgl_pool_t* pool;
	uint8_t corked = 0;
	uint8_t no_delay = 0;
};
#endif
