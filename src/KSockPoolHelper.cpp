#include "KSockPoolHelper.h"
#include "kthread.h"
#include "kaddr.h"
#include "kselector_manager.h"
#include "KHttp2Upstream.h"
#include "KTsUpstream.h"
#include "KHttpUpstream.h"
#include "KHttpServer.h"
#include "klog.h"
#include <sstream>

using namespace std;
#ifdef ENABLE_UPSTREAM_SSL
static int kgl_ssl_verify_callback(int ok, X509_STORE_CTX* x509_store) {
#ifndef NDEBUG
	char* subject, * issuer;
	int                err, depth;
	X509* cert;
	X509_NAME* sname, * iname;


	cert = X509_STORE_CTX_get_current_cert(x509_store);
	err = X509_STORE_CTX_get_error(x509_store);
	depth = X509_STORE_CTX_get_error_depth(x509_store);

	sname = X509_get_subject_name(cert);

	if (sname) {
		subject = X509_NAME_oneline(sname, NULL, 0);
		if (subject == NULL) {
			klog(KLOG_DEBUG, "X509_NAME_oneline() failed\n");
		}

	} else {
		subject = NULL;
	}

	iname = X509_get_issuer_name(cert);

	if (iname) {
		issuer = X509_NAME_oneline(iname, NULL, 0);
		if (issuer == NULL) {
			klog(KLOG_DEBUG, "X509_NAME_oneline() failed\n");
		}

	} else {
		issuer = NULL;
	}

	klog(KLOG_DEBUG, "verify:%d, error:%d %s, depth:%d, "
		"subject:\"%s\", issuer:\"%s\"\n",
		ok, err, X509_verify_cert_error_string(err), depth,
		subject ? subject : "(none)",
		issuer ? issuer : "(none)");
	if (subject) {
		OPENSSL_free(subject);
	}
	if (issuer) {
		OPENSSL_free(issuer);
	}
#endif
	return 1;
}
#endif
static int monitor_fiber(void* arg, int got) {
	KSockPoolHelper* sock_pool = (KSockPoolHelper*)arg;
	sock_pool->start_monitor_call_back();
	sock_pool->release();
	return 0;
}
void KSockPoolHelper::start_monitor_call_back() {
	//10 seconds rand sleep
	kfiber_msleep(rand() % 10000);
	for (;;) {
#ifdef MALLOCDEBUG
		if (kgl_get_tls_selector()->shutdown) {
			break;
		}
#endif
		if (!monitor) {
			//monitor is stoped
			break;
		}
		auto monitor_start_time = kgl_current_msec;
		auto us = get_upstream(KSOCKET_FLAGS_SKIP_POOL, NULL);
		if (!us) {
			disable();
			kfiber_msleep(get_error_try_time() * 1000);
			continue;
		}
		//caculate monitor tick time
		int monitor_tick = (int)(kgl_current_msec - monitor_start_time);
		if (monitor_tick <= 0) {
			monitor_tick = 1;
		}
		if (monitor_tick > 30000) {
			monitor_tick = 30000;
		}
		if (avg_monitor_tick == 0) {
			avg_monitor_tick = monitor_tick;
		} else {
			avg_monitor_tick = (int)(0.9 * float(avg_monitor_tick) + 0.1 * float(monitor_tick));
		}
		us->Destroy();
		enable();
		kfiber_msleep(get_error_try_time() * 1000);
	}
	monitor = 0;
}
KSockPoolHelper::KSockPoolHelper() {
	ip = NULL;
	error_count = 0;
	flags = 0;
	max_error_count = 5;
	weight = 1;
#ifdef ENABLE_UPSTREAM_SSL
#ifdef ENABLE_UPSTREAM_HTTP2
	alpn = 0;
#endif
	ssl_ctx = NULL;
#endif
}
KSockPoolHelper::~KSockPoolHelper() {
#ifdef ENABLE_UPSTREAM_SSL
	if (ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
	}
#endif
	if (ip) {
		free(ip);
	}
}
void KSockPoolHelper::startMonitor() {
	if (monitor) {
		return;
	}
	monitor = 1;
	addRef();
	if (kfiber_create2(get_perfect_selector(), monitor_fiber, this, 0, 0, NULL) != 0) {
		monitor = 0;
		release();
	}
}
KUpstream* KSockPoolHelper::get_upstream(uint32_t flags, const char* sni_host) {
	katom_inc64((void*)&total_hit);
	KUpstream* socket = NULL;
	if (!KBIT_TEST(flags, KSOCKET_FLAGS_SKIP_POOL)) {
		//如果是发生错误重连或upgrade的连接，则排除连接池
		socket = get_pool_socket(flags);
		if (socket) {
			return socket;
		}
	}
	sockaddr_i* bind_addr = NULL;
	sockaddr_i tmp_addr;
	const char* bind_ip = ip;
	if (bind_ip) {
		bind_addr = &tmp_addr;
		if (!ksocket_getaddr(bind_ip, 0, AF_UNSPEC, AI_NUMERICHOST, bind_addr)) {
			return NULL;
		}
	}
	katom_inc64((void*)&total_connect);
	kgl_addr* addr = NULL;
	if (kfiber_net_getaddr(host.c_str(), &addr) != 0) {
		assert(addr == NULL);
		health(NULL, HealthStatus::Err);
		return NULL;
	}
	auto ai_addr = addr->addr;
	int tproxy_mask = 0;
	kconnection* cn = nullptr;
	while (ai_addr) {
		cn = kfiber_net_open2(ai_addr, port);
		if (kfiber_net_connect(cn, bind_addr, tproxy_mask) == 0) {
			break;
		}
		kfiber_net_close(cn);
		cn = nullptr;
		ai_addr = ai_addr->ai_next;
	}
	kgl_addr_release(addr);
	if (!cn) {
		health(NULL, HealthStatus::Err);
		return NULL;
	}
#ifdef ENABLE_UPSTREAM_SSL
	if (this->ssl_ctx) {
		if (this->no_sni) {
			sni_host = NULL;
		}
		if (sni_host && ksocket_getaddr(sni_host, 0, AF_UNSPEC, AI_NUMERICHOST, &tmp_addr)) {
			/* sni_host is ip address, then do not send sni to remote. */
			sni_host = NULL;
		}
		if (!kconnection_ssl_connect(cn, ssl_ctx, sni_host)) {
			klog(KLOG_ERR, "cann't bind_fd for ssl socket.\n");
			kfiber_net_close(cn);
			health(NULL, HealthStatus::Err);
			return NULL;
		}
#ifdef ENABLE_UPSTREAM_HTTP2
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
		if (alpn > 0 && cn->st.ssl && KBIT_TEST(flags, KSOCKET_FLAGS_WEBSOCKET)) {
			//websocket will turn off http2
			SSL_set_alpn_protos(cn->st.ssl->ssl, (unsigned char*)KGL_HTTP_NPN_ADVERTISE, sizeof(KGL_HTTP_NPN_ADVERTISE) - 1);
		}
#endif
#endif
		if (kfiber_ssl_handshake(cn) != 0) {
			kfiber_net_close(cn);
			health(NULL, HealthStatus::Err);
			return NULL;
		}
		if (need_verify()) {
			if (X509_V_OK != SSL_get_verify_result(cn->st.ssl->ssl)) {
				klog(KLOG_ERR, "cann't verify [%s:%d] ssl certificate.\n", host.c_str(), port);
				kfiber_net_close(cn);
				health(NULL, HealthStatus::Err);
				return NULL;
			}
		}
#ifdef ENABLE_UPSTREAM_HTTP2
		const unsigned char* protocol_data = NULL;
		unsigned len = 0;
		assert(cn->st.ssl);
		kgl_ssl_get_next_proto_negotiated(cn->st.ssl->ssl, &protocol_data, &len);
		if (len == sizeof(KGL_HTTP_V2_NPN_NEGOTIATED) - 1 &&
			memcmp(protocol_data, KGL_HTTP_V2_NPN_NEGOTIATED, len) == 0) {
			KHttp2* http2 = new KHttp2();
			selectable_bind_opaque(&cn->st, http2);
			KHttp2Upstream* http2_us = http2->client(cn);
			bind(http2_us);
			return http2_us;
		}
#endif
	}
#endif
#ifdef ENABLE_UPSTREAM_HTTP2
	if (h2 && !KBIT_TEST(flags, KSOCKET_FLAGS_WEBSOCKET)) {
		KHttp2* http2 = new KHttp2();
		selectable_bind_opaque(&cn->st, http2);
		KHttp2Upstream* http2_us = http2->client(cn);
		bind(http2_us);
		return http2_us;
	}
#endif
	socket = new_upstream(cn);
	bind(socket);
	return socket;
}
bool KSockPoolHelper::setHostPort(KString host, int port, const char* s) {
	bool destChanged = false;
#ifdef KSOCKET_UNIX
	bool new_is_unix = false;
	if (strncasecmp(host.c_str(), "unix:", 5) == 0) {
		new_is_unix = true;
		host = host.substr(5);
	}
	if (!host.empty() && host[0] == '/') {
		new_is_unix = true;
	}
#endif
	lock.Lock();
	if (s && *s == 'h') {
		h2 = 1;
		s = NULL;
	} else {
		h2 = 0;
	}
	if (s && (*s != 's' && *s != 'S')) {
		s = NULL;
	}
	if (this->host != host || this->port != port || this->ssl!=s
#ifdef KSOCKET_UNIX
		|| this->is_unix != new_is_unix
#endif
		) {
		destChanged = true;
	}
	this->host = host;
	this->port = port;
#ifdef ENABLE_UPSTREAM_SSL
	char* ssl_buf = NULL;
	char* protocols = NULL;
	char* chiper = NULL;
	if (s) {
		this->ssl = s;
		ssl_buf = strdup(s);
		protocols = strchr(ssl_buf, '/');
		if (protocols) {
			*protocols = '\0';
			protocols++;
			chiper = strchr(protocols, '/');
			if (chiper) {
				*chiper = '\0';
				chiper++;
			}
		}
	} else {
		this->ssl.clear();
	}
#ifdef ENABLE_UPSTREAM_HTTP2
	this->alpn = KGL_ALPN_HTTP1;
	if (ssl_buf && strchr(ssl_buf, 'p')) {
		this->alpn = KGL_ALPN_HTTP2;
	}
#endif
	this->no_sni = 0;
	if (ssl_buf && strchr(ssl_buf, 'n')) {
		this->no_sni = 1;
	}
	if (ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}
	if (s) {
		void* ssl_ctx_data = NULL;
#ifdef ENABLE_UPSTREAM_HTTP2
		ssl_ctx_data = &alpn;
#endif
		kgl_refs_string* ssl_client_chiper;
		kgl_refs_string* ssl_client_protocols;
		kgl_refs_string* ca_path;
		khttp_server_refs_ssl_config(&ca_path, &ssl_client_chiper, &ssl_client_protocols);
		ssl_ctx = kgl_ssl_ctx_new_client(ca_path ? ca_path->data : NULL, NULL, ssl_ctx_data);
		if (ssl_ctx) {
			if (need_verify()) {
				SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, kgl_ssl_verify_callback);
				if (!ca_path) {
					SSL_CTX_set_default_verify_paths(ssl_ctx);
				}
			}
			kgl_ssl_ctx_set_protocols(ssl_ctx, protocols);
			if (chiper) {
				kgl_ssl_ctx_set_cipher_list(ssl_ctx, chiper);
			}
			if (chiper == NULL || protocols == NULL) {
				if (chiper == NULL && ssl_client_chiper) {
					SSL_CTX_set_cipher_list(ssl_ctx, ssl_client_chiper->data);
				}
				if (protocols == NULL && ssl_client_protocols) {
					kgl_ssl_ctx_set_protocols(ssl_ctx, ssl_client_protocols->data);
				}
			}
		}
		kstring_release(ca_path);
		kstring_release(ssl_client_chiper);
		kstring_release(ssl_client_protocols);
	}
#endif
#ifdef KSOCKET_UNIX
	is_unix = new_is_unix;
#endif
	lock.Unlock();
#ifdef ENABLE_UPSTREAM_SSL
	if (ssl_buf) {
		free(ssl_buf);
	}
#endif
	if (destChanged) {
		clean();
	}
	return true;
}
bool KSockPoolHelper::setHostPort(KString host, const char* port) {
	const char* s = port;
	while (*s && IS_DIGIT(*s)) {
		s++;
	}
	return setHostPort(host, atoi(port), s);
}
void KSockPoolHelper::disable() {
	disable_flag = 1;

}
bool KSockPoolHelper::is_enabled() {
	if (disable_flag) {
		return false;
	}
	return true;
}
void KSockPoolHelper::shutdown() {
	monitor = 0;
	refresh(0);
}
void KSockPoolHelper::enable() {
	disable_flag = 0;
	katom_set16((void*)&error_count, 0);
}

bool KSockPoolHelper::parse(const KXmlAttribute& attr) {
	setHostPort(attr("host"), attr("port"));
	setLifeTime(atoi(attr("life_time")));
	SetParam(attr["param"].c_str());
	lock.Lock();
#ifdef HTTP_PROXY
	auth_user = attr["auth_user"];
	auth_passwd = attr["auth_passwd"];
#endif
	sign = (attr["sign"] == "1");
	weight = atoi(attr["weight"].c_str());
	lock.Unlock();
	setIp(attr["self_ip"].c_str());
	return true;
}
KString KSockPoolHelper::get_port() {
	KStringBuf s;
	if (is_unix) {
		s << "-";
		return s.str();
	}
	s << (int)port;
#ifdef ENABLE_UPSTREAM_SSL
	if (!ssl.empty()) {
		s << ssl;
	}
#endif
	if (h2) {
		s << "h";
	}
	return s.str();
}
void KSockPoolHelper::dump(kgl::serializable* s, bool as_mserver) {
	kgl_refs_string* str = GetParam();
	lock.Lock();
	s->add("host", host);
	s->add("port", get_port());
	s->add("life_time",getLifeTime());
	if (str) {
		s->add("param", str->data);
	}
	kstring_release(str);
#ifdef HTTP_PROXY
	if (!auth_user.empty()) {
		s->add("auth_user", auth_user);
	}
	if (!auth_passwd.empty()) {
		s->add("auth_passwd", auth_passwd);
	}
#endif
	if (ip && *ip) {
		s->add("self_ip", ip);
	}
	s->add("sign", sign);
	s->add("idle_size", getSize());
	s->add("total_connect", total_connect);
	s->add("total_hit", total_hit);
	s->add("total_err", total_error);
	if (as_mserver) {	
		s->add("avg_monitor_tick", avg_monitor_tick);
		s->add("weight", weight);
		s->add("enable", is_enabled());
	}
	lock.Unlock();
}
void KSockPoolHelper::build(std::map<KString, KString>& attr) {
	kgl_refs_string* str = GetParam();
	lock.Lock();
	attr["host"] = host;
	attr["port"] = get_port();
	attr["life_time"] = std::to_string(getLifeTime());
	if (str) {
		attr["param"] = str->data;
	}
	kstring_release(str);
#ifdef HTTP_PROXY
	if (!auth_user.empty()) {
		attr["auth_user"] = auth_user;
	}
	if (!auth_passwd.empty()) {
		attr["auth_passwd"] = auth_passwd;
	}
#endif
	if (ip && *ip) {
		attr["self_ip"] = ip;
	}
	if (sign) {
		attr["sign"] = "1";
	}
	lock.Unlock();
}
#ifdef HTTP_PROXY
KHttpHeader* KSockPoolHelper::get_proxy_header(kgl_pool_t* pool) {
	KHttpHeader* header = nullptr;
	lock.Lock();
	if (!auth_user.empty() && !auth_passwd.empty()) {
		KStringBuf up;
		KStringBuf val;
		up << auth_user.c_str() << ":" << auth_passwd.c_str();
		val << "Basic " << b64encode((const unsigned char*)up.c_str(), up.size());
		header = new_pool_http_header(pool, _KS("Proxy-Authorization"), val.buf(), val.size());
	}
	lock.Unlock();
	return header;
}
#endif
