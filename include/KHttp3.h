#ifndef KGL_HTTP3_H
#define KGL_HTTP3_H
#include "ksocket.h"
#include "khttp.h"
#include "KAtomCountable.h"
#include "kconnection.h"
#include "kserver.h"
#include "kselector_manager.h"
#ifdef ENABLE_HTTP3
#include "lsquic.h"
#define MAX_QUIC_UDP_SIZE 4096
#pragma pack(push,1)
struct kgl_h3_cid_header
{
    uint8_t port_id;
    uint32_t seq;
};
#pragma pack(pop)

bool kgl_init_khttp3();
/* scratch buffers for batched UDP send and receive */
struct kgl_h3_udp_batch;
void kgl_h3_free_udp_batch(kgl_h3_udp_batch* batch);
void kgl_shutdown_khttp3();

class KHttp3Server;
class KHttp3CachedSni
{
public:
	KHttp3CachedSni(const char* hostname, void* sni)
	{
		this->hostname = strdup(hostname);
		this->sni = sni;
	}
	~KHttp3CachedSni()
	{
		xfree(hostname);
		if (sni && kgl_ssl_free_sni) {
			kgl_ssl_free_sni(sni);
		}
	}
	void* get_sni()
	{
		void* data = sni;
		sni = nullptr;
		return data;
	}
	char* hostname;
	void* sni;
};
class KHttp3ServerEngine
{
public:
	KHttp3ServerEngine(KHttp3Server *server)
	{
		uc = nullptr;
		engine = nullptr;
		selector_tick = NULL;
		seq = rand();
		this->server = server;
		iov_buf[0].iov_base = (char*)(iov_buf + 1);
		iov_buf[0].iov_len = 1;
		iov_buf[1].iov_base = (char *)xmalloc(MAX_QUIC_UDP_SIZE);
		iov_buf[1].iov_len = MAX_QUIC_UDP_SIZE;
	}
	bool allow_src_ip();
	void ticked()
	{
		if (lsquic_engine_has_unsent_packets(engine)) {
			lsquic_engine_send_unsent_packets(engine);
		}
		lsquic_engine_process_conns(engine);
	}
	int next_event_time()
	{
		int diff;
		if (lsquic_engine_earliest_adv_tick(engine, &diff)) {
			if (diff >= 1000) {
				return (diff + 500) / 1000;
			} else if (diff >= 0) {
				return diff > 0;
			}
		}
		return -1;
	}
	bool is_multi();
	char* realloc_buffer()
	{
		char* old_buffer = (char *)iov_buf[1].iov_base;
		iov_buf[1].iov_base = (char*)xmalloc(MAX_QUIC_UDP_SIZE);
		return old_buffer;
	}
	char* get_udp_buffer() {
		return (char *)iov_buf[1].iov_base;
	}
	int start();
	int init(kselector *selector, int udp_flag);
	void release();
	int add_refs();
	int shutdown();
	void* get_cache_sni(const char* hostname)
	{
		if (last_sni == nullptr || hostname == nullptr) {
			return nullptr;
		}
		if (strcasecmp(last_sni->hostname, hostname) == 0) {
			void* sni = last_sni->get_sni();
			delete last_sni;
			last_sni = nullptr;
			return sni;
		}
		return nullptr;
	}
	void cache_sni(const char *hostname, void* sni)
	{
		if (last_sni != nullptr) {
			delete last_sni;
		}
		last_sni = new KHttp3CachedSni(hostname, sni);
	}
	kgl_iovec iov_buf[2];
	kconnection* uc;
	lsquic_engine* engine;
	uint32_t seq;
	KHttp3Server* server;
	kselector_tick* selector_tick;
	KHttp3CachedSni* last_sni = nullptr;
	kgl_ssl_ctx* ssl_ctx = nullptr;
	kgl_h3_udp_batch* udp_batch = nullptr;
	/* the kernel can split one large send into many datagrams (UDP GSO) */
	bool udp_gso = false;
	friend class KHttp3Server;
protected:
	~KHttp3ServerEngine()
	{
		if (uc) {
			kconnection_destroy(uc);
		}
		if (engine) {
			lsquic_engine_destroy(engine);
		}
		if (ssl_ctx) kgl_release_ssl_ctx(ssl_ctx);
		xfree(iov_buf[1].iov_base);
		if (udp_batch) {
			kgl_h3_free_udp_batch(udp_batch);
		}
		assert(selector_tick == NULL);
		if (last_sni) {
			delete last_sni;
		}
	}
};
class KHttp3Server : public KAtomCountable
{
public:
	KHttp3Server(uint16_t count)
	{
		flags = 0;
		ssl_ctx = nullptr;
		free_opaque = nullptr;
		data = NULL;
		count_flags = 0;
		engine_count = count;
		engines = (KHttp3ServerEngine **)malloc(sizeof(KHttp3ServerEngine*)*count);
		for (int i = 0; i < (int)count; i++) {
			engines[i] = new KHttp3ServerEngine(this);
		}
	}
	void bind_data(kserver_free_opaque free_opaque, KOPAQUE data) {
		try_free_data();
		this->data = data;
		this->free_opaque = free_opaque;
	}
	KOPAQUE get_data()
	{
		return data;
	}
	void update_ssl_ctx(kgl_ssl_ctx* ssl_ctx);
	int init(const char *ip,uint16_t port,int sock_flags, kgl_ssl_ctx* ssl_ctx,uint32_t model);
	bool start();
	int shutdown();
	bool is_shutdown()
	{
		return KBIT_TEST(flags,KGL_SERVER_START)==0;
	}
	int start_engine(int index);
	int get_engine_index(kgl_h3_cid_header *header)
	{
		return (int)header->port_id % (int)engine_count;
	}
	KHttp3ServerEngine* refs_engine(int index)
	{
		assert(index < engine_count);
		addRef();
		return engines[index];
	}
	friend class KHttp3ServerEngine;
	sockaddr_i addr;
	kgl_ssl_ctx* ssl_ctx;
	uint32_t flags;
protected:
	union {
		struct {
			uint16_t allow_src_ip : 1;
			uint16_t engine_count;
		};
		uint32_t count_flags;
	};
	kserver_free_opaque free_opaque;
	KOPAQUE data;
	void try_free_data()
	{
		if (data && free_opaque) {
			free_opaque(data);
		}
	}
	~KHttp3Server()
	{
		if (engines) {
			for (int i = 0; i < engine_count; i++) {
				delete engines[i];
			}
			free(engines);
		}
		if (ssl_ctx) {
			kgl_release_ssl_ctx(ssl_ctx);
		}
		try_free_data();
	}
	KHttp3ServerEngine** engines;
};
KHttp3Server* kgl_h3_new_server(const char *ip, uint16_t port, int sock_flags, kgl_ssl_ctx* ssl_ctx, uint32_t model);
#endif
#endif
