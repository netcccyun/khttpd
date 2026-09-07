#ifndef KURL_H
#define KURL_H
#ifdef _WIN32
#pragma warning(disable:4003)
#include <direct.h>
#endif
#include "khttp.h"
#include "KStringBuf.h"
#include "kforwin32.h"
#include "kmalloc.h"
#include "KHttpLib.h"
#include "katom.h"
#include "KSharedObj.h"


class KUrl : public kgl_url{

public:
	KUrl(bool support_share) {
		memset(static_cast<kgl_url*>(this), 0, sizeof(kgl_url));
		refs_count = !!support_share;
	}
	bool match_accept_encoding(u_char accept_encoding) {
		if (encoding > 0) {
			return KBIT_TEST(accept_encoding,encoding) > 0  && KBIT_TEST(this->accept_encoding,accept_encoding) == accept_encoding;
		}
		return KBIT_TEST(this->accept_encoding, accept_encoding) == accept_encoding;
	}
	void set_content_encoding(u_char content_encoding) {
		this->encoding = content_encoding;
	}
	void merge_accept_encoding(u_char accept_encoding) {
		if (encoding>0) {
			return;
		}
		KBIT_SET(this->accept_encoding, accept_encoding);
	}
	int cmpn(const KUrl *a,int n) const {
		int ret = strcasecmp(host,a->host);
		if (ret<0) {
			return -1;
		} else if (ret > 0) {
			return 1;
		}
		return strncmp(path,a->path,n);
	}
	int cmp(const KUrl *a) const {
		int ret = strcasecmp(host, a->host);
		if (ret < 0) {
			return -1;
		} else if (ret > 0) {
			return 1;
		}
		ret = strcmp(path, a->path);
		if (ret < 0) {
			return -1;
		} else if (ret > 0) {
			return 1;
		}
		if (port < a->port) {
			return -1;
		} else if(port > a->port) {
			return 1;
		}
		if (param == NULL) {
			if (a->param == NULL) {
				return 0;
			} else {
				return 1;
			}
		}
		if (a->param == NULL) {
			return -1;
		}
		return strcmp(param, a->param);
	}
	//only support share url call add_ref/release
	KUrl* add_ref() {		
		assert(refs_count > 0);
		katom_inc16((void*)&refs_count);
		return this;
	}
	void release() {
		assert(refs_count > 0);
		if (katom_dec16((void*)&refs_count) > 0) {
			return;
		}
		delete this;
	}
	bool is_bad() {
		return host == NULL || path == NULL;
	}
	kgl_auto_cstr getUrl() {
		KStringStream s(128);
		if (!GetUrl(s)) {
			return NULL;
		}
		return s.steal();
	}
	kgl_auto_cstr getUrl2(int &len) {
		KStringStream s(128);
		if (!GetUrl(s)) {
			return NULL;
		}
		len = s.size();
		return s.steal();
	}
	void GetPath(KWStream&s, bool urlEncode = false) {
		if (urlEncode) {
			size_t len = strlen(path);
			char *newPath = url_encode(path, len, &len);
			if (newPath) {
				s.write_all(newPath, (int)len);
				free(newPath);
			}
		} else {
			s << path;
		}
		if (param && *param) {
			if (urlEncode) {
				size_t len = strlen(param);
				char *newParam = url_value_encode(param, len, &len);
				if (newParam) {
					s.write_all("?", 1);
					s.write_all(newParam, (int)len);
					free(newParam);
				}
			}
			else {
				s << "?" << param;
			}
		}
	}
	bool GetSchema(KWStream& s)
	{
		if (unlikely(host == NULL || path == NULL)) {
			return false;
		}
		if (KBIT_TEST(flags, KGL_URL_SSL)) {
			s << "https://";
		} else {
			s << "http://";
		}
		return true;
	}
	bool GetUrl(KWStream&s,bool urlEncode=false) {
		if (!GetSchema(s)) {
			return false;
		}
		build_url_host_port(this, s);
		GetPath(s, urlEncode);
		return true;
	}
	void GetHost(KWStream& s)
	{
		build_url_host_port(this, s);
	}
	void clean() {
		IF_FREE(host);
		IF_FREE(path);
		IF_FREE(param);
		flag_encoding = 0;
	}
	~KUrl() {
		assert(refs_count == 0);
		clean();
	}
};
using KSafeUrl = KSharedObj<KUrl>;
#endif
