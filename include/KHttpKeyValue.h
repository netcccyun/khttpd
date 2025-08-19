/*
 * KHttpKeyValue.h
 *
 *  Created on: 2010-4-23
 *      Author: keengo
 */

#ifndef KHTTPKEYVALUE_H_
#define KHTTPKEYVALUE_H_
#include <stdio.h>
#include "KHttpHeader.h"
#include "KHttpLib.h"
#include "kmalloc.h"

#define METH_UNSET      0
#define METH_GET        1
#define METH_HEAD       2
#define METH_POST       3
#define METH_OPTIONS    4
#define METH_PUT        5
#define METH_DELETE     6
#define METH_TRACE      7
#define METH_PROPFIND   8
#define METH_PROPPATCH  9
#define METH_MKCOL      10
#define METH_COPY       11
#define METH_MOVE       12
#define METH_LOCK       13
#define METH_UNLOCK     14
#define METH_ACL        15
#define METH_REPORT	    16
#define METH_VERSION_CONTROL  17
#define METH_CHECKIN    18
#define METH_CHECKOUT   19
#define METH_UNCHECKOUT 20
#define METH_SEARCH     21
#define METH_MKWORKSPACE 22
#define METH_UPDATE     23
#define METH_LABEL      24
#define METH_MERGE      25
#define METH_BASELINE_CONTROL 26
#define METH_MKACTIVITY 27
#define METH_CONNECT    28
#define METH_PURGE      29
#define METH_PATCH      30
#define METH_SUBSCRIBE  31
#define METH_UNSUBSCRIBE 32
#define METH_PRI        33
constexpr int MAX_METHOD = 34;
inline bool kgl_is_safe_method(uint8_t meth) {
	return meth == METH_GET || meth == METH_HEAD;
}
extern kgl_str_t http_methods[MAX_METHOD];
class KHttpKeyValue
{
public:
	static kgl_str_t* get_method(int meth) {
		if (meth < 0 || meth >= MAX_METHOD) {
			meth = 0;
		}
		return &http_methods[meth];
	}
	static int get_method(const char* src, int len) {
		for (int i = 1; i < MAX_METHOD; i++) {
			if (kgl_mem_case_same(src, len, http_methods[i].data, http_methods[i].len)) {
				return i;
			}
		}
		return METH_UNSET;
	}
	static void get_request_line(kgl_pool_t* pool, int status, kgl_str_t* ret) {
		switch (status) {
		case 100:kgl_str_set(ret, "HTTP/1.1 100 Continue"); return;
		case 101:kgl_str_set(ret, "HTTP/1.1 101 Switching Protocols"); return;
		case 102:kgl_str_set(ret, "HTTP/1.1 102 Processing"); return; /* WebDAV */
		case 103:kgl_str_set(ret, "HTTP/1.1 103 Early Hints"); return;

		case 200:kgl_str_set(ret, "HTTP/1.1 200 OK"); return;
		case 201:kgl_str_set(ret, "HTTP/1.1 201 Created"); return;
		case 202:kgl_str_set(ret, "HTTP/1.1 202 Accepted"); return;
		case 203:kgl_str_set(ret, "HTTP/1.1 203 Non-Authoritative Information"); return;
		case 204:kgl_str_set(ret, "HTTP/1.1 204 No Content"); return;
		case 205:kgl_str_set(ret, "HTTP/1.1 205 Reset Content"); return;
		case 206:kgl_str_set(ret, "HTTP/1.1 206 Partial Content"); return;
		case 207:kgl_str_set(ret, "HTTP/1.1 207 Multi-status"); return; /* WebDAV */
		case 208:kgl_str_set(ret, "HTTP/1.1 208 Already Reported"); return;
		case 226:kgl_str_set(ret, "HTTP/1.1 226 IM Used"); return;

		case 300:kgl_str_set(ret, "HTTP/1.1 300 Multiple Choices"); return;
		case 301:kgl_str_set(ret, "HTTP/1.1 301 Moved Permanently"); return;
		case 302:kgl_str_set(ret, "HTTP/1.1 302 Found"); return;
		case 303:kgl_str_set(ret, "HTTP/1.1 303 See Other"); return;
		case 304:kgl_str_set(ret, "HTTP/1.1 304 Not Modified"); return;
		case 305:kgl_str_set(ret, "HTTP/1.1 305 Use Proxy"); return;
		case 306:kgl_str_set(ret, "HTTP/1.1 306 (Unused)"); return;
		case 307:kgl_str_set(ret, "HTTP/1.1 307 Temporary Redirect"); return;
		case 308:kgl_str_set(ret, "HTTP/1.1 308 Permanent Redirect"); return;

		case 400:kgl_str_set(ret, "HTTP/1.1 400 Bad Request"); return;
		case 401:kgl_str_set(ret, "HTTP/1.1 401 Unauthorized"); return;
		case 402:kgl_str_set(ret, "HTTP/1.1 402 Payment Required"); return;
		case 403:kgl_str_set(ret, "HTTP/1.1 403 Forbidden"); return;
		case 404:kgl_str_set(ret, "HTTP/1.1 404 Not Found"); return;
		case 405:kgl_str_set(ret, "HTTP/1.1 405 Method Not Allowed"); return;
		case 406:kgl_str_set(ret, "HTTP/1.1 406 Not Acceptable"); return;
		case 407:kgl_str_set(ret, "HTTP/1.1 407 Proxy Authentication Required"); return;
		case 408:kgl_str_set(ret, "HTTP/1.1 408 Request Timeout"); return;
		case 409:kgl_str_set(ret, "HTTP/1.1 409 Conflict"); return;
		case 410:kgl_str_set(ret, "HTTP/1.1 410 Gone"); return;
		case 411:kgl_str_set(ret, "HTTP/1.1 411 Length Required"); return;
		case 412:kgl_str_set(ret, "HTTP/1.1 412 Precondition Failed"); return;
		case 413:kgl_str_set(ret, "HTTP/1.1 413 Request Entity Too Large"); return;
		case 414:kgl_str_set(ret, "HTTP/1.1 414 Request-URI Too Long"); return;
		case 415:kgl_str_set(ret, "HTTP/1.1 415 Unsupported Media Type"); return;
		case 416:kgl_str_set(ret, "HTTP/1.1 416 Requested Range Not Satisfiable"); return;
		case 417:kgl_str_set(ret, "HTTP/1.1 417 Expectation Failed"); return;
		case 420:kgl_str_set(ret, "HTTP/1.1 420 Method Failure"); return;
		case 421:kgl_str_set(ret, "HTTP/1.1 421 Misdirected Request"); return;
		case 422:kgl_str_set(ret, "HTTP/1.1 422 Unprocessable Entity"); return; /* WebDAV */
		case 423:kgl_str_set(ret, "HTTP/1.1 423 Locked"); return; /* WebDAV */
		case 424:kgl_str_set(ret, "HTTP/1.1 424 Failed Dependency"); return; /* WebDAV */
		case 426:kgl_str_set(ret, "HTTP/1.1 426 Upgrade Required"); return; /* TLS */
		case 428:kgl_str_set(ret, "HTTP/1.1 428 Precondition Required"); return;
		case 429:kgl_str_set(ret, "HTTP/1.1 429 Too Many Requests"); return;
		case 431:kgl_str_set(ret, "HTTP/1.1 431 Request Header Fields Too Large"); return;
		case 451:kgl_str_set(ret, "HTTP/1.1 451 Unavailable For Legal Reasons"); return;
		case 497:kgl_str_set(ret, "HTTP/1.1 497 Http to Https"); return;
		case 498:kgl_str_set(ret, "HTTP/1.1 498 Invalid Token"); return;
		case 499:kgl_str_set(ret, "HTTP/1.1 499 Token Required"); return;

		case 500:kgl_str_set(ret, "HTTP/1.1 500 Internal Server Error"); return;
		case 501:kgl_str_set(ret, "HTTP/1.1 501 Not Implemented"); return;
		case 502:kgl_str_set(ret, "HTTP/1.1 502 Bad Gateway"); return;
		case 503:kgl_str_set(ret, "HTTP/1.1 503 Service Not Available"); return;
		case 504:kgl_str_set(ret, "HTTP/1.1 504 Gateway Timeout"); return;
		case 505:kgl_str_set(ret, "HTTP/1.1 505 HTTP Version Not Supported"); return;
		case 507:kgl_str_set(ret, "HTTP/1.1 507 Insufficient Storage"); return;
		case 508:kgl_str_set(ret, "HTTP/1.1 508 Loop Detected"); return;
		case 509:kgl_str_set(ret, "HTTP/1.1 509 Bandwidth Limit Exceeded"); return;
		case 510:kgl_str_set(ret, "HTTP/1.1 510 Not Extended"); return;
		case 511:kgl_str_set(ret, "HTTP/1.1 511 Network Authentication Required"); return;
		default:
			ret->data = (char*)kgl_pnalloc(pool, 32);
			ret->len = snprintf(ret->data, 32, "HTTP/1.1 %d unknow", status);
			return;
		}
	}

};
#endif /* KHTTPKEYVALUE_H_ */
