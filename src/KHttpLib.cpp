/*
 * Copyright (c) 2010, NanChang BangTeng Inc
 * All Rights Reserved.
 *
 * You may use the Software for free for non-commercial use
 * under the License Restrictions.
 *
 * You may modify the source code(if being provieded) or interface
 * of the Software under the License Restrictions.
 *
 * You may use the Software for commercial use after purchasing the
 * commercial license.Moreover, according to the license you purchased
 * you may get specified term, manner and content of technical
 * support from NanChang BangTeng Inc
 *
 * See COPYING file for detail.
 */
#include "kfeature.h"
#ifdef MALLOCDEBUG
#include <map>
#endif
#ifndef 	_WIN32
#include <syslog.h>
#include <unistd.h>
#endif
#ifdef FREEBSD
#define HAVE_TIMEGM 1
#endif
#include	 <time.h>
#include <ctype.h>
#include <string>
#include <sstream>
#include <stdarg.h>
#include "kforwin32.h"
#include "kmalloc.h"
#include "KHttpLib.h"
#include "klib.h"

static const char* b64alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define B64PAD '='

static const char* days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char* months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun","Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
static uint32_t  mday[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
static int timz_minutes = 0;

void init_time_zone() {
	time_t tt = time(NULL);
	struct tm t;
#if defined(HAVE_GMTOFF)
	localtime_r(&tt, &t);
	timz_minutes = (int)(t.tm_gmtoff / 60);
#else
	struct tm gmt;
	int days, hours;
	gmtime_r(&tt, &gmt);
	localtime_r(&tt, &t);
	days = t.tm_yday - gmt.tm_yday;
	hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24) + t.tm_hour - gmt.tm_hour);
	timz_minutes = hours * 60 + t.tm_min - gmt.tm_min;
#endif
}
void CTIME_R(time_t* a, char* b, size_t l) {
#if	defined(HAVE_CTIME_R)
#if	defined(CTIME_R_3)
	ctime_r(a, b, l);
#else
	ctime_r(a, b);
#endif /* SOLARIS */
#else
	struct tm tm;
	memset(b, 0, l);
	localtime_r(a, &tm);
	snprintf(b, l - 1, "%s %02d %s %02d:%02d:%02d\n", days[tm.tm_wday],
		tm.tm_mday, months[tm.tm_mon], tm.tm_hour, tm.tm_min, tm.tm_sec);
#endif
}

void make_last_modified_time(time_t* a, char* b, size_t l) {
	struct tm tm;
	memset(b, 0, l);
	localtime_r(a, &tm);
	snprintf(b, l - 1, "%02d-%s-%04d %02d:%02d", tm.tm_mday, months[tm.tm_mon],
		1900 + tm.tm_year, tm.tm_hour, tm.tm_min);

}
time_t kgl_parse_http_time(u_char* value, size_t len) {

	u_char* p, * end;
	int    month;
	uint64_t   day, year, hour, min, sec;
	uint64_t     time;
	enum
	{
		nofmt = 0,
		rfc822,   /* Tue, 10 Nov 2002 23:50:13   */
		rfc850,   /* Tuesday, 10-Dec-02 23:50:13 */
		isoc      /* Tue Dec 10 23:50:13 2002    */
	} fmt;

	fmt = nofmt;
	end = value + len;

#if (NGX_SUPPRESS_WARN)
	day = 32;
	year = 2038;
#endif

	for (p = value; p < end; p++) {
		if (*p == ',') {
			break;
		}

		if (*p == ' ') {
			fmt = isoc;
			break;
		}
	}

	for (p++; p < end; p++) {
		if (*p != ' ') {
			break;
		}
	}

	if (end - p < 18) {
		return -1;
	}

	if (fmt != isoc) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
			return -1;
		}

		day = (*p - '0') * 10 + (*(p + 1) - '0');
		p += 2;

		if (*p == ' ') {
			if (end - p < 18) {
				return -1;
			}
			fmt = rfc822;

		} else if (*p == '-') {
			fmt = rfc850;

		} else {
			return -1;
		}

		p++;
	}

	switch (*p) {

	case 'J':
		month = *(p + 1) == 'a' ? 0 : *(p + 2) == 'n' ? 5 : 6;
		break;

	case 'F':
		month = 1;
		break;

	case 'M':
		month = *(p + 2) == 'r' ? 2 : 4;
		break;

	case 'A':
		month = *(p + 1) == 'p' ? 3 : 7;
		break;

	case 'S':
		month = 8;
		break;

	case 'O':
		month = 9;
		break;

	case 'N':
		month = 10;
		break;

	case 'D':
		month = 11;
		break;

	default:
		return -1;
	}

	p += 3;

	if ((fmt == rfc822 && *p != ' ') || (fmt == rfc850 && *p != '-')) {
		return -1;
	}

	p++;

	if (fmt == rfc822) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
			|| *(p + 2) < '0' || *(p + 2) > '9'
			|| *(p + 3) < '0' || *(p + 3) > '9') {
			return -1;
		}

		year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
			+ (*(p + 2) - '0') * 10 + (*(p + 3) - '0');
		p += 4;

	} else if (fmt == rfc850) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
			return -1;
		}

		year = (*p - '0') * 10 + (*(p + 1) - '0');
		year += (year < 70) ? 2000 : 1900;
		p += 2;
	}

	if (fmt == isoc) {
		if (*p == ' ') {
			p++;
		}

		if (*p < '0' || *p > '9') {
			return -1;
		}

		day = *p++ - '0';

		if (*p != ' ') {
			if (*p < '0' || *p > '9') {
				return -1;
			}

			day = day * 10 + (*p++ - '0');
		}

		if (end - p < 14) {
			return -1;
		}
	}

	if (*p++ != ' ') {
		return -1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return -1;
	}

	hour = (*p - '0') * 10 + (*(p + 1) - '0');
	p += 2;

	if (*p++ != ':') {
		return -1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return -1;
	}

	min = (*p - '0') * 10 + (*(p + 1) - '0');
	p += 2;

	if (*p++ != ':') {
		return -1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return -1;
	}

	sec = (*p - '0') * 10 + (*(p + 1) - '0');

	if (fmt == isoc) {
		p += 2;

		if (*p++ != ' ') {
			return -1;
		}

		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
			|| *(p + 2) < '0' || *(p + 2) > '9'
			|| *(p + 3) < '0' || *(p + 3) > '9') {
			return -1;
		}

		year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
			+ (*(p + 2) - '0') * 10 + (*(p + 3) - '0');
	}

	if (hour > 23 || min > 59 || sec > 59) {
		return -1;
	}

	if (day == 29 && month == 1) {
		if ((year & 3) || ((year % 100 == 0) && (year % 400) != 0)) {
			return -1;
		}

	} else if (day > mday[month]) {
		return -1;
	}

	/*
	 * shift new year to March 1 and start months from 1 (not 0),
	 * it is needed for Gauss' formula
	 */

	if (--month <= 0) {
		month += 12;
		year -= 1;
	}

	/* Gauss' formula for Gregorian days since March 1, 1 BC */

	time = (uint64_t)(
		/* days in years including leap years since March 1, 1 BC */

		365 * year + year / 4 - year / 100 + year / 400

		/* days before the month */

		+367 * month / 12 - 30

		/* days before the day */

		+day - 1

		/*
		 * 719527 days were between March 1, 1 BC and March 1, 1970,
		 * 31 and 28 days were in January and February 1970
		 */

		-719527 + 31 + 28) * 86400 + hour * 3600 + min * 60 + sec;

	return (time_t)time;
}
char* make_http_time(time_t time, char* buf, int size) {
	struct tm tm;
	time_t holder = time;
	gmtime_r(&holder, &tm);
	return (char*)kgl_snprintf((u_char*)buf, size,
		"%s, %02d %s %d %02d:%02d:%02d GMT",
		days[tm.tm_wday],
		tm.tm_mday,
		months[tm.tm_mon],
		tm.tm_year + 1900,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec);
}
const char* mk1123time(time_t time, char* buf, int size) {
	make_http_time(time, buf, size);
	return buf;
}
#define	BU_FREE	1
#define	BU_BUSY	2
const char* log_request_time(time_t time, char* buf, size_t buf_size) {
	int timz = timz_minutes;
	struct tm t;
	localtime_r(&time, &t);
	char sign = (timz < 0 ? '-' : '+');
	if (timz < 0) {
		timz = -timz;
	}
	snprintf(buf, buf_size - 1, "[%02d/%s/%d:%02d:%02d:%02d %c%.2d%.2d]",
		t.tm_mday, months[t.tm_mon], t.tm_year + 1900, t.tm_hour, t.tm_min,
		t.tm_sec, sign, timz / 60, timz % 60);
	return buf;
}

static unsigned char hexchars[] = "0123456789ABCDEF";
char* url_value_encode(const char* s, size_t len, size_t* new_length) {
	unsigned char c;
	unsigned char* to, * start;
	unsigned char const* from, * end;
	if (len == 0) {
		//assert(false);
		return strdup("");
	}
	from = (unsigned char*)s;
	end = (unsigned char*)s + len;
	start = to = (unsigned char*)xmalloc(3 * len + 1);

	while (from < end) {
		c = *from++;
		if (c == '/') {
			*to++ = c;
		} else if (!isascii((int)c)) {
			to[0] = '%';
			to[1] = hexchars[c >> 4];
			to[2] = hexchars[c & 15];
			to += 3;
		} else {
			*to++ = c;
		}
	}
	*to = 0;
	if (new_length) {
		*new_length = to - start;
	}
	return (char*)start;
}
int64_t kgl_atol(const u_char* line, size_t n) {
	int64_t  value;
	if (n == 0) {
		return 0;
	}
	for (value = 0; n--; line++) {
		if (*line < '0' || *line > '9') {
			return value;
		}
		value = value * 10 + (*line - '0');
	}
	return value;
}
int kgl_atoi(const u_char* line, size_t n) {
	int  value;
	if (n == 0) {
		return 0;
	}
	for (value = 0; n--; line++) {
		if (*line < '0' || *line > '9') {
			return value;
		}
		value = value * 10 + (*line - '0');
	}
	return value;
}

/* parse a fixed point number, e.g., ngx_atofp("10.5", 4, 2) returns 1050 */
int64_t kgl_atofp(const char* line, size_t n, size_t point) {
	int64_t   value;
	unsigned  dot;
	if (n == 0) {
		return 0;
	}
	dot = 0;
	for (value = 0; n--; line++) {
		if (point == 0) {
			return 0;
		}
		if (*line == '.') {
			if (dot) {
				return value;
			}
			dot = 1;
			continue;
		}
		if (*line < '0' || *line > '9') {
			return value;
		}
		value = value * 10 + (*line - '0');
		point -= dot;
	}
	while (point--) {
		value = value * 10;
	}
	return value;
}

int kgl_cmp(const char* s1, size_t n1, const char* s2, size_t n2) 	{
	size_t     n;
	int  m, z;
	if (n1 <= n2) {
		n = n1;
		z = -1;
	} else {
		n = n2;
		z = 1;
	}
	m = memcmp(s1, s2, n);
	if (m || n1 == n2) {
		return m;
	}
	return z;
}
int kgl_icmp(const char* s1, size_t n1, const char* s2, size_t n2) 	{
	size_t     n;
	int  m, z;
	if (n1 <= n2) {
		n = n1;
		z = -1;
	} else {
		n = n2;
		z = 1;
	}
	m = kgl_casecmp(s1, s2, n);
	if (m || n1 == n2) {
		return m;
	}
	return z;
}
int kgl_ncmp(const char* s1, size_t n1, const char* s2, size_t n2) {
	size_t     n;
	int  m, z;
	if (n1 <= n2) {
		n = n1;
		z = -1;
	} else {
		n = n2;
		z = 1;
	}
	m = memcmp(s1, s2, n);
	if (m || n1 >= n2) {
		return m;
	}
	return z;
}
int kgl_ncasecmp(const char* s1, size_t n1, const char* s2, size_t n2) {
	size_t     n;
	int  m, z;
	if (n1 <= n2) {
		n = n1;
		z = -1;
	} else {
		n = n2;
		z = 1;
	}
	m = kgl_casecmp(s1, s2, n);
	if (m || n1 >= n2) {
		return m;
	}
	return z;
}
void kgl_strlow(u_char* dst, u_char* src, size_t n) {
	while (n) {
		*dst = kgl_tolower(*src);
		dst++;
		src++;
		n--;
	}
}
const char* kgl_memstr(const char* haystack, size_t haystacklen, const char* needle, size_t needlen) {
	const char* p;
	for (p = (char*)haystack; p <= (haystack - needlen + haystacklen); p++) {
		if (memcmp(p, needle, needlen) == 0)
			return p; /* found */
	}
	return NULL;
}
char* url_encode(const char* s, size_t len, size_t* new_length) {
	unsigned char c;
	unsigned char* to, * start;
	unsigned char const* from, * end;
	if (len == 0) {
		//assert(false);
		return strdup("");
	}
	from = (unsigned char*)s;
	end = (unsigned char*)s + len;
	start = to = (unsigned char*)xmalloc(3 * len + 1);

	while (from < end) {
		c = *from++;
		if (c == '/') {
			*to++ = c;
			/*
			} else if (c == ' ') {
				*to++ = '+';
			*/
		} else if ((c < '0' && c != '-' && c != '.') || (c < 'A' && c > '9')
			|| (c > 'Z' && c < 'a' && c != '_') || (c > 'z') || c == '\\') {
			to[0] = '%';
			to[1] = hexchars[c >> 4];
			to[2] = hexchars[c & 15];
			to += 3;
		} else {
			*to++ = c;
		}
	}
	*to = 0;
	if (new_length) {
		*new_length = to - start;
	}
	return (char*)start;
}
std::string url_encode(const char* str, size_t len_string) {
	std::string s;
	if (len_string == 0) {
		len_string = strlen(str);
	}
	char* new_string = url_encode(str, len_string, NULL);
	if (new_string) {
		s = new_string;
		xfree(new_string);
	}
	return s;
}
bool parse_url_host(kgl_url* url, const char* val, size_t len) {
	assert(url->host == NULL);
	char* port;
	if (*val == '[') {
		KBIT_SET(url->flags, KGL_URL_IPV6);
		val++;
		len--;
		char* host_end = (char*)memchr(val, ']', len);
		if (host_end == NULL) {
			return false;
		}
		size_t host_len = host_end - val;
		port = (char*)memchr(host_end, ':', len - host_len);
		if (port) {
			size_t port_len = len - host_len;
			port_len -= (port - host_end);
			url->port = (uint16_t)kgl_atoi((u_char*)port + 1, port_len - 1);
		}
		len = host_len;
	} else {
		port = (char*)memchr(val, ':', len);
		if (port) {
			size_t port_len = len;
			len = port - val;
			port_len -= len;
			url->port = (uint16_t)kgl_atoi((u_char*)port + 1, port_len - 1);
		}
	}
	url->host = kgl_strndup(val, len);
	if (port == NULL) {
		//no port
		if (KBIT_TEST(url->flags, KGL_URL_ORIG_SSL)) {
			url->port = 443;
		} else {
			url->port = 80;
		}
	} else {
		KBIT_SET(url->flags, KGL_URL_HAS_PORT);
	}
	return true;
}
bool parse_url(const char* src, size_t len, kgl_url * url) {
	const char* host, * path;
	if (len == 0) {
		return false;
	}
	size_t p_len, host_len;
	if (*src == '/' || *src=='*') {
		path = src;
		goto only_path;
	}
	host = kgl_memstr(src, len, kgl_expand_string("://"));
	if (!host) {
		return false;
	}
	p_len = (host - src);
	if (p_len == 4 && strncasecmp(src, "http", p_len) == 0) {
		KBIT_CLR(url->flags, KGL_URL_ORIG_SSL);
		//url->port = 80;
	} else if (p_len == 5 && strncasecmp(src, "https", p_len) == 0) {
		KBIT_SET(url->flags, KGL_URL_ORIG_SSL);
		//url->port = 443;
	}

	//host start
	host += 3;
	len -= (p_len + 3);
	path = (char*)memchr(host, '/', len);
	if (path == NULL) {
		return false;
	}
	host_len = path - host;
	len -= host_len;
	if (!parse_url_host(url, host, host_len)) {
		return false;
	}
only_path: const char* sp = (char*)memchr(path, '?', len);
	size_t path_len;
	if (sp) {
		path_len = sp - path;
		sp++;
		len -= (path_len + 1);
		char* param = kgl_strndup(sp, len);
		assert(url->param == NULL);
		if (*param) {
			url->param = param;
		} else {
			free(param);
		}
	} else {
		path_len = len;
	}
	assert(url->path == NULL);
	url->path = kgl_strndup(path, path_len);
	return true;
}
static int my_htoi(char* s) {
	int c = ((unsigned char*)s)[0];
	if (isupper(c)) {
		c = tolower(c);
	}
	int value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

	c = ((unsigned char*)s)[1];
	if (isupper(c)) {
		c = tolower(c);
	}
	value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

	return (value);
}
int url_decode(char* str, int len, kgl_url * url, bool space2plus) {
	char* dest = str;
	char* data = str;
	bool mem_availble = false;
	if (len == 0) {
		len = (int)strlen(str);
	}
	while (len--) {
		if (space2plus && *data == '+') {
			*dest = ' ';
			if (url) {
				KBIT_SET(url->flags, KGL_URL_ENCODE);
			}
		} else if (
			*data == '%' &&
			len >= 2 &&
			isxdigit((unsigned char)*(data + 1)) &&
			isxdigit((unsigned char)*(data + 2))) {
			mem_availble = true;
			*dest = (char)my_htoi(data + 1);
			data += 2;
			len -= 2;
			if (url) {
				KBIT_SET(url->flags, KGL_URL_ENCODE);
			}
		} else {
			*dest = *data;
		}
		data++;
		dest++;
	}
	if (mem_availble) {
		*dest = '\0';
	}
	return (int)(dest - str);
}




unsigned int str_chr(const char* s, int c) {
	char ch;
	const char* t;

	ch = c;
	t = s;
	for (;;) {
		if (!*t)
			break;
		if (*t == ch)
			break;
		++t;
		if (!*t)
			break;
		if (*t == ch)
			break;
		++t;
		if (!*t)
			break;
		if (*t == ch)
			break;
		++t;
		if (!*t)
			break;
		if (*t == ch)
			break;
		++t;
	}
	return (unsigned)(t - s);
}

char* b64decode(const unsigned char* in, int* l) {
	int i, j;
	//	int len;
	unsigned char a[4];
	unsigned char b[3];
	char* s;
	if (*l <= 0) {
		*l = (int)strlen((const char*)in);
	}
	char* out = (char*)xmalloc(2 * (*l) + 2);
	if (out == NULL) {
		return NULL;
	}
	s = out;
	for (i = 0; i < *l; i += 4) {
		for (j = 0; j < 4; j++)
			if ((i + j) < *l && in[i + j] != B64PAD) {
				a[j] = str_chr(b64alpha, in[i + j]);
				if (a[j] > 63) {
					//		printf("bad char=%c,j=%d\n",a[j],j);
					free(out);
					return NULL;
					//	return -1;
				}
			} else {
				a[j] = 0;
			}

		b[0] = (a[0] << 2) | (a[1] >> 4);
		b[1] = (a[1] << 4) | (a[2] >> 2);
		b[2] = (a[2] << 6) | (a[3]);

		*s = b[0];
		s++;

		if (in[i + 1] == B64PAD)
			break;
		*s = b[1];
		s++;

		if (in[i + 2] == B64PAD)
			break;
		*s = b[2];
		s++;
	}

	*l = (int)(s - out);
	//  printf("len=%d\n",len);
	while (*l && !out[*l - 1])
		--* l;
	out[*l] = 0;
	//	string result = out;
	//	free(out);
	return out;
	// return len;

	//  return s.str();
}

std::string b64encode(const unsigned char* in, int len)
/* not null terminated */
{
	unsigned char a, b, c;
	int i;
	// char *s;
	std::stringstream s;
	if (len == 0) {
		len = (int)strlen((const char*)in);
	}

	// if (!stralloc_ready(out,in->len / 3 * 4 + 4)) return -1;
	// s = out->s;
	for (i = 0; i < len; i += 3) {
		a = in[i];
		b = i + 1 < len ? in[i + 1] : 0;
		c = i + 2 < len ? in[i + 2] : 0;

		s << b64alpha[a >> 2];
		s << b64alpha[((a & 3) << 4) | (b >> 4)];

		if (i + 1 >= len)
			s << B64PAD;
		else
			s << b64alpha[((b & 15) << 2) | (c >> 6)];

		if (i + 2 >= len)
			s << B64PAD;
		else
			s << b64alpha[c & 63];
	}
	return s.str();
}
#define MEMPBRK_CACHE_SIZE  256
const char* kgl_mempbrk(const char* str, int n, const char* control, int control_len) {
	const char* p, * min = NULL, * control_ptr = control, * control_end = control + control_len;
	while (n > 0) {
		while (control_ptr < control_end) {
			if ((p = (const char*)memchr(str, *control_ptr,
				(n > MEMPBRK_CACHE_SIZE) ? MEMPBRK_CACHE_SIZE : n)) != NULL) {
				n = (int)(p - str);
				min = p;
			}
			++control_ptr;
		}
		if (min != NULL) {
			return min;
		}
		str += MEMPBRK_CACHE_SIZE;
		n -= MEMPBRK_CACHE_SIZE;
		control_ptr = control;
	}
	return NULL;
}

static u_char* kgl_sprintf_num(u_char* buf, u_char* last, uint64_t ui64, u_char zero,
	unsigned hexadecimal, unsigned width) {
	u_char* p, temp[KGL_INT64_LEN + 1];
	/*
	 * we need temp[KGL_INT64_LEN] only,
	 * but icc issues the warning
	 */
	size_t          len;
	uint32_t        ui32;
	static u_char   hex[] = "0123456789abcdef";
	static u_char   HEX[] = "0123456789ABCDEF";

	p = temp + KGL_INT64_LEN;

	if (hexadecimal == 0) {

		if (ui64 <= (uint64_t)KGL_MAX_UINT32_VALUE) {

			/*
			 * To divide 64-bit numbers and to find remainders
			 * on the x86 platform gcc and icc call the libc functions
			 * [u]divdi3() and [u]moddi3(), they call another function
			 * in its turn.  On FreeBSD it is the qdivrem() function,
			 * its source code is about 170 lines of the code.
			 * The glibc counterpart is about 150 lines of the code.
			 *
			 * For 32-bit numbers and some divisors gcc and icc use
			 * a inlined multiplication and shifts.  For example,
			 * unsigned "i32 / 10" is compiled to
			 *
			 *     (i32 * 0xCCCCCCCD) >> 35
			 */

			ui32 = (uint32_t)ui64;

			do {
				*--p = (u_char)(ui32 % 10 + '0');
			} while (ui32 /= 10);

		} else {
			do {
				*--p = (u_char)(ui64 % 10 + '0');
			} while (ui64 /= 10);
		}

	} else if (hexadecimal == 1) {

		do {

			/* the "(uint32_t)" cast disables the BCC's warning */
			*--p = hex[(uint32_t)(ui64 & 0xf)];

		} while (ui64 >>= 4);

	} else { /* hexadecimal == 2 */

		do {

			/* the "(uint32_t)" cast disables the BCC's warning */
			*--p = HEX[(uint32_t)(ui64 & 0xf)];

		} while (ui64 >>= 4);
	}

	/* zero or space padding */

	len = (temp + KGL_INT64_LEN) - p;

	while (len++ < width && buf < last) {
		*buf++ = zero;
	}

	/* number safe copy */

	len = (temp + KGL_INT64_LEN) - p;

	if (buf + len > last) {
		len = last - buf;
	}

	return kgl_cpymem(buf, p, len);
}


static u_char* kgl_sprintf_str(u_char* buf, u_char* last, u_char* src, size_t len, unsigned hexadecimal) {
	static u_char   hex[] = "0123456789abcdef";
	static u_char   HEX[] = "0123456789ABCDEF";

	if (hexadecimal == 0) {

		if (len == (size_t)-1) {
			while (*src && buf < last) {
				*buf++ = *src++;
			}

		} else {
			len = KGL_MIN((size_t)(last - buf), len);
			buf = kgl_cpymem(buf, src, len);
		}

	} else if (hexadecimal == 1) {

		if (len == (size_t)-1) {

			while (*src && buf < last - 1) {
				*buf++ = hex[*src >> 4];
				*buf++ = hex[*src++ & 0xf];
			}

		} else {

			while (len-- && buf < last - 1) {
				*buf++ = hex[*src >> 4];
				*buf++ = hex[*src++ & 0xf];
			}
		}

	} else { /* hexadecimal == 2 */

		if (len == (size_t)-1) {

			while (*src && buf < last - 1) {
				*buf++ = HEX[*src >> 4];
				*buf++ = HEX[*src++ & 0xf];
			}

		} else {

			while (len-- && buf < last - 1) {
				*buf++ = HEX[*src >> 4];
				*buf++ = HEX[*src++ & 0xf];
			}
		}
	}

	return buf;
}


u_char* kgl_vslprintf(u_char* buf, u_char* last, const char* fmt, va_list args) {
	u_char* p, zero;
	int                    d;
	double                 f;
	size_t                 slen;
	int64_t                i64;
	uint64_t               ui64, frac;
	unsigned             width, sign, hex, max_width, frac_width, scale, n;
	kgl_str_t* v;

	while (*fmt && buf < last) {

		/*
		 * "buf < last" means that we could copy at least one character:
		 * the plain character, "%%", "%c", and minus without the checking
		 */

		if (*fmt == '%') {

			i64 = 0;
			ui64 = 0;

			zero = (u_char)((*++fmt == '0') ? '0' : ' ');
			width = 0;
			sign = 1;
			hex = 0;
			max_width = 0;
			frac_width = 0;
			slen = (size_t)-1;

			while (*fmt >= '0' && *fmt <= '9') {
				width = width * 10 + (*fmt++ - '0');
			}


			for (;; ) {
				switch (*fmt) {

				case 'u':
					sign = 0;
					fmt++;
					continue;

				case 'm':
					max_width = 1;
					fmt++;
					continue;

				case 'X':
					hex = 2;
					sign = 0;
					fmt++;
					continue;

				case 'x':
					hex = 1;
					sign = 0;
					fmt++;
					continue;

				case '.':
					fmt++;

					while (*fmt >= '0' && *fmt <= '9') {
						frac_width = frac_width * 10 + (*fmt++ - '0');
					}

					break;

				case '*':
					slen = va_arg(args, size_t);
					fmt++;
					continue;

				default:
					break;
				}

				break;
			}


			switch (*fmt) {

			case 'V':
				v = va_arg(args, kgl_str_t*);

				buf = kgl_sprintf_str(buf, last, (u_char*)v->data, v->len, hex);
				fmt++;

				continue;

			case 's':
				p = va_arg(args, u_char*);

				buf = kgl_sprintf_str(buf, last, p, slen, hex);
				fmt++;

				continue;

			case 'O':
				i64 = (int64_t)va_arg(args, off_t);
				sign = 1;
				break;
			case 'T':
				i64 = (int64_t)va_arg(args, time_t);
				sign = 1;
				break;
			case 'z':
				if (sign) {
					i64 = (int64_t)va_arg(args, ssize_t);
				} else {
					ui64 = (uint64_t)va_arg(args, size_t);
				}
				break;

			case 'i':
				if (sign) {
					i64 = (int64_t)va_arg(args, int);
				} else {
					ui64 = (uint64_t)va_arg(args, unsigned);
				}

				if (max_width) {
					width = KGL_INT32_LEN;
				}
				break;

			case 'd':
				if (sign) {
					i64 = (int64_t)va_arg(args, int);
				} else {
					ui64 = (uint64_t)va_arg(args, u_int);
				}
				break;

			case 'l':
				if (sign) {
					i64 = (int64_t)va_arg(args, long);
				} else {
					ui64 = (uint64_t)va_arg(args, u_long);
				}
				break;

			case 'D':
				if (sign) {
					i64 = (int64_t)va_arg(args, int32_t);
				} else {
					ui64 = (uint64_t)va_arg(args, uint32_t);
				}
				break;

			case 'L':
				if (sign) {
					i64 = va_arg(args, int64_t);
				} else {
					ui64 = va_arg(args, uint64_t);
				}
				break;

			case 'f':
				f = va_arg(args, double);

				if (f < 0) {
					*buf++ = '-';
					f = -f;
				}

				ui64 = (int64_t)f;
				frac = 0;

				if (frac_width) {

					scale = 1;
					for (n = frac_width; n; n--) {
						scale *= 10;
					}

					frac = (uint64_t)((f - (double)ui64) * scale + 0.5);

					if (frac == scale) {
						ui64++;
						frac = 0;
					}
				}

				buf = kgl_sprintf_num(buf, last, ui64, zero, 0, width);

				if (frac_width) {
					if (buf < last) {
						*buf++ = '.';
					}

					buf = kgl_sprintf_num(buf, last, frac, '0', 0, frac_width);
				}

				fmt++;

				continue;

			case 'p':
				ui64 = (uintptr_t)va_arg(args, void*);
				hex = 2;
				sign = 0;
				zero = '0';
				width = 2 * sizeof(void*);
				break;

			case 'c':
				d = va_arg(args, int);
				*buf++ = (u_char)(d & 0xff);
				fmt++;

				continue;

			case 'Z':
				*buf++ = '\0';
				fmt++;

				continue;
			case '%':
				*buf++ = '%';
				fmt++;

				continue;

			default:
				*buf++ = *fmt++;

				continue;
			}

			if (sign) {
				if (i64 < 0) {
					*buf++ = '-';
					ui64 = (uint64_t)-i64;

				} else {
					ui64 = (uint64_t)i64;
				}
			}

			buf = kgl_sprintf_num(buf, last, ui64, zero, hex, width);

			fmt++;

		} else {
			*buf++ = *fmt++;
		}
	}

	return buf;
}

u_char* kgl_sprintf(u_char* buf, const char* fmt, ...) {
	u_char* p;
	va_list   args;

	va_start(args, fmt);
	p = kgl_vslprintf(buf, (u_char*)((void*)-1), fmt, args);
	va_end(args);

	return p;
}


u_char* kgl_snprintf(u_char* buf, size_t max, const char* fmt, ...) {
	u_char* p;
	va_list   args;

	va_start(args, fmt);
	p = kgl_vslprintf(buf, buf + max, fmt, args);
	va_end(args);

	return p;
}


u_char* kgl_slprintf(u_char* buf, u_char* last, const char* fmt, ...) {
	u_char* p;
	va_list   args;

	va_start(args, fmt);
	p = kgl_vslprintf(buf, last, fmt, args);
	va_end(args);

	return p;
}

bool kgl_adjust_range(kgl_request_range* range, int64_t* len) 	{
	if (range->from >= 0) {
		if (range->from >= (*len)) {
			return false;
		}
		(*len) -= range->from;
		if (range->to >= 0) {
			(*len) = KGL_MIN(range->to - range->from + 1, (*len));
			if ((*len) <= 0) {
				return false;
			}
		}
	} else {
		/* suffix-byte-range-spec: bytes=-N. RFC 7233: if N >= size, use the whole representation. */
		range->from += *len;
		if (range->from < 0) {
			range->from = 0;
		}
		(*len) -= range->from;
		if ((*len) <= 0) {
			return false;
		}
	}
	range->to = range->from + (*len) - 1;
	return true;
}

