#ifndef KSOCKPOOLHELPER_H_
#define KSOCKPOOLHELPER_H_
#include <map>
#include <string>
#include <list>
#include "ksocket.h"
#include "KAtomCountable.h"
#include "KPoolableSocketContainer.h"
#include "KTcpUpstream.h"
#include "KXmlAttribute.h"
#include "serializable.h"

#define KSOCKET_FLAGS_SKIP_POOL 1
#define KSOCKET_FLAGS_WEBSOCKET (1<<1)

#define ERROR_RECONNECT_TIME	600
class KSockPoolHelper : public KPoolableSocketContainer
{
public:
	KSockPoolHelper();
	virtual ~KSockPoolHelper();
	void health(KUpstream* st, HealthStatus stage) override {
		switch (stage) {
		case HealthStatus::Err:
			katom_inc64((void*)&this->total_error);
			if (katom_inc16((void*)&error_count) >= max_error_count) {
				disable();
			}
			break;
		case HealthStatus::Success:
			enable();
			break;
		default:
			break;
		}
	}
	bool isChanged(KSockPoolHelper* sh) {
		if (host != sh->host) {
			return true;
		}
		if (port != sh->port) {
			return true;
		}
#ifdef ENABLE_UPSTREAM_SSL
		if (ssl != sh->ssl) {
			return true;
		}
		if (no_sni != sh->no_sni) {
			return true;
		}
#endif
		if (weight != sh->weight) {
			return true;
		}
		if (is_unix != sh->is_unix) {
			return true;
		}
		if (ip != sh->ip || (ip && strcmp(ip, sh->ip) != 0)) {
			return true;
		}
		if (life_time != sh->life_time) {
			return true;
		}
		if (sign != sh->sign) {
			return true;
		}
		return false;
	}
	void start_monitor_call_back();
	void setErrorTryTime(int max_error_count, int error_try_time) {
		lock.Lock();
		this->max_error_count = max_error_count;
		this->error_try_time = error_try_time;
		if (max_error_count > 0) {
			internalStopMonitor();
		} else {
			startMonitor();
		}
		lock.Unlock();
	}
	void shutdown() override;
	bool parse(const KXmlAttribute& attr);
	void build(std::map<KString, KString>& attr);
	void dump(kgl::serializable* s, bool as_mserver=false);
	KUpstream* get_upstream(uint32_t flags, const char* sni_host = NULL);
	KString get_port();
	bool setHostPort(KString host, const char* port);
	bool setHostPort(KString host, int port, const char* s);
	void disable();
	void enable();
	bool is_enabled();
	void setIp(const char* ip) {
		lock.Lock();
		if (this->ip) {
			free(this->ip);
			this->ip = NULL;
		}
		if (ip && *ip) {
			this->ip = strdup(ip);
		}
		lock.Unlock();
	}
	const char* getIp() {
		return this->ip;
	}
#ifdef HTTP_PROXY
	KHttpHeader* get_proxy_header(kgl_pool_t* pool) override;
	KString auth_user;
	KString auth_passwd;
#endif
	KString host;
	volatile uint64_t total_hit = 0;
	volatile uint64_t total_error = 0;
	volatile uint64_t total_connect = 0;
	int avg_monitor_tick = 0;
	int error_try_time;
	/*
	 * 连续错误连接次数，如果超过MAX_ERROR_COUNT次，就会认为是问题的。
	 * 下次试连接时间会从当前时间加ERROR_RECONNECT_TIME秒。
	 */
	volatile uint16_t error_count;
	uint16_t max_error_count;
	uint16_t weight;
	uint16_t port;
#ifdef ENABLE_UPSTREAM_SSL
#ifdef ENABLE_UPSTREAM_HTTP2
	u_char alpn;
#endif
	bool need_verify() {
		return ssl == "S";
	}
	KString ssl;
#endif
	void stopMonitor() {
		lock.Lock();
		internalStopMonitor();
		lock.Unlock();
	}
	int get_error_try_time() {
		if (error_try_time <= 0) {
			return ERROR_RECONNECT_TIME;
		}
		return error_try_time;
	}
	KSockPoolHelper* next = nullptr;
	KSockPoolHelper* prev = nullptr;
private:
	void startMonitor();
	void internalStopMonitor() {
		monitor = 0;
	}
	char* ip;
#ifdef ENABLE_UPSTREAM_SSL
	SSL_CTX* ssl_ctx;
#endif
};

#endif /* KSOCKPOOLHELPER_H_ */
