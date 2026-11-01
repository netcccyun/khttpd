#if	!defined(_LIB_H_INCLUDED_)
#define _LIB_H_INCLUDED_
#include "kforwin32.h"
#include <string>
#include <memory>
#include <cstring>
#include "KHttpHeader.h"
#include "khttp.h"
#include "klib.h"
#include "KStream.h"

typedef unsigned char* domain_t;
struct kgl_auto_cstr_free
{
	void operator()(char* t) const noexcept {
		free(t);
	}
};
struct kgl_auto_ref_str_free
{
	void operator()(kgl_ref_str_t* t) const noexcept {
		kstring_release(t);
	}
};

using kgl_auto_cstr = std::unique_ptr<char, kgl_auto_cstr_free>;
using kgl_auto_ref_str = std::unique_ptr<kgl_ref_str_t, kgl_auto_ref_str_free>;



std::string b64encode(const unsigned char* in, int len = 0);
char* b64decode(const unsigned char* in, int* l);
char *url_encode(const char *s, size_t len, size_t *new_length);
char *url_value_encode(const char *s, size_t len, size_t *new_length);
std::string url_encode(const char *str, size_t len_string=0);

u_char* kgl_slprintf(u_char* buf, u_char* last, const char* fmt, ...);
u_char* kgl_snprintf(u_char* buf, size_t max, const char* fmt, ...);
u_char* kgl_sprintf(u_char* buf, const char* fmt, ...);
time_t kgl_parse_http_time(u_char *str,size_t len);
const char *mk1123time(time_t time, char *buf, int size);
char* make_http_time(time_t time, char* buf, int size);
void make_last_modified_time(time_t *a, char *b, size_t l);
void init_time_zone();
bool parse_url_host(kgl_url* url, const char* val, size_t len);
bool parse_url(const char* src, size_t len, kgl_url* url);
inline bool parse_url(const char* src, kgl_url* url) {
	return parse_url(src, strlen(src), url);
}
// Internal upstream configuration uses port 0 to inherit the request port.
// Keep parse_url and parse_url_host strict for client HTTP messages.
bool parse_upstream_url(const char* src, size_t len, kgl_url* url);
inline bool parse_upstream_url(const char* src, kgl_url* url) {
	return parse_upstream_url(src, strlen(src), url);
}
inline void build_url_host_port(kgl_url* url, KWStream& s) {
	if (unlikely(KBIT_TEST(url->flags, KGL_URL_IPV6))) {
		s.WSTR("[");
		s << url->host;
		s.WSTR("]");
	} else {
		s << url->host;
	}
	if (KBIT_TEST(url->flags, KGL_URL_HAS_PORT)) {
		s.WSTR(":");
		s << url->port;
	}
}
int64_t kgl_atol(const u_char* line, size_t n);
int kgl_atoi(const u_char* line, size_t n);
int64_t kgl_atofp(const char* line, size_t n, size_t point);
INLINE int64_t string2int(const char* buf) {
	return kgl_atol((u_char *)buf, strlen(buf));
}
#define kgl_memcmp memcmp

inline int kgl_casecmp(const char* s1, const char* s2, size_t attr_len) {
	u_char  c1, c2;
	while (attr_len > 0) {
		c1 = (u_char)*s1++;
		c2 = (u_char)*s2++;

		c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
		c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

		int result = c1 - c2;
		if (result != 0) {
			return result;
		}
		attr_len--;
	}
	return 0;
}
const char* kgl_memstr(const char* haystack, size_t haystacklen,const char* needle, size_t needlen);
void kgl_strlow(u_char* dst, u_char* src, size_t n);

inline bool kgl_mem_same(const char* attr, size_t attr_len, const char* val, size_t val_len)
{
	if (attr_len != val_len) {
		return false;
	}
	return kgl_memcmp(attr, val, attr_len) == 0;
}
inline bool kgl_mem_case_same(const char* s1, size_t attr_len, const char* s2, size_t val_len)
{
	if (attr_len != val_len) {
		return false;
	}
	return kgl_casecmp(s1, s2, val_len) == 0;
}
int kgl_ncasecmp(const char* s1, size_t n1, const char* s2, size_t n2);
int kgl_ncmp(const char* s1, size_t n1, const char* s2, size_t n2);
int kgl_cmp(const char* s1, size_t n1, const char* s2, size_t n2);
int kgl_icmp(const char* s1, size_t n1, const char* s2, size_t n2);

#ifdef _WIN32
#define kgl_file_cmp kgl_icmp
#else
#define kgl_file_cmp kgl_cmp
#endif

/**
 * @kgl_mempbrk
 * @brief Finds a character within a specified input buffer.
 *
 * @param[in] str - A pointer to the beginning of the buffer.
 * @param[in] n - The length of the str.
 * @param[in] control - A pointer to a list of characters to match.
 * @param[in] control_len - The length of the \e control buffer.
 * @return A pointer to the first occurance of one of the accept characters
 *   in the input buffer,
 *   else NULL if not found.
 */
const char* kgl_mempbrk(const char* str, int n, const char* control, int control_len);
inline int kgl_attr_tolower(const u_char p) {
	if (p == '-') {
		return '_';
	}
	return kgl_tolower((u_char)p);
}
inline bool kgl_is_attr(const char* s1, size_t s1_len, const char* s2, size_t s2_len)
{
	if (s1_len != s2_len) {
		return false;
	}
	while (s1_len > 0) {
		if (kgl_attr_tolower((u_char)*s1++) != kgl_attr_tolower((u_char)*s2++)) {
			return false;
		}
		s1_len--;
	}
	return true;
}
inline bool kgl_is_attr(KHttpHeader* header, const char* s2, size_t s2_len)
{
	if (header->name_is_know) {
		return kgl_is_attr(kgl_header_type_string[header->know_header].value.data, kgl_header_type_string[header->know_header].value.len, s2, s2_len);
	}
	return kgl_is_attr(header->buf, header->name_len, s2, s2_len);
}
/*
skip space or not space
*/
inline const char* kgl_skip_space(const char* start, const char* end, bool space = true)
{
	while (start < end) {
		if ((isspace((unsigned char)*start) != 0) != space) {
			return start;
		}
		start++;
	}
	return NULL;
}
int url_decode(char* str, int len=0, kgl_url* url=NULL, bool space2plus=true);
/* A header name or value with CR, LF or NUL would end its line early and
 * let the rest be read as more headers. Values built from decoded URLs
 * (rewrite captures, redirects) can carry them. */
inline bool kgl_header_has_ctl(const char* s, size_t len) {
	for (size_t i = 0; i < len; i++) {
		char c = s[i];
		if (c == '\r' || c == '\n' || c == '\0') {
			return true;
		}
	}
	return false;
}
/* replace CR, LF and NUL with spaces */
inline void kgl_header_strip_ctl(char* s, size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (s[i] == '\r' || s[i] == '\n' || s[i] == '\0') {
			s[i] = ' ';
		}
	}
}
void CTIME_R(time_t* a, char* b, size_t l);
inline int kgl_parse_value_time(const char* val, int val_len, time_t* value) {
	time_t parsed;
	if (val_len == KGL_HEADER_VALUE_TIME) {
		parsed = *(const time_t*)val;
	} else {
		if (val_len <= 0) {
			return -1;
		}
		parsed = kgl_parse_http_time((u_char*)val, val_len);
	}
	if (parsed < 0) {
		return -1;
	}
	*value = parsed;
	return 0;
}
inline int kgl_parse_value_int64(const char* val, int val_len, int64_t* value) {
	if (val_len == KGL_HEADER_VALUE_INT64) {
		*value = *(int64_t*)val;
		return 0;
	}
	if (val_len <= 0) {
		return -1;
	}
	*value = kgl_atol((u_char*)val, val_len);
	return 0;
}
inline int kgl_parse_value_int(const char* val, int val_len, int* value) {
	if (val_len == KGL_HEADER_VALUE_INT) {
		*value = *(int*)val;
		return 0;
	}
	if (val_len <= 0) {
		return -1;
	}
	*value = (int)kgl_atol((u_char*)val, val_len);
	return 0;
}
bool kgl_adjust_range(kgl_request_range* range, int64_t* len);
inline int kgl_string_cmp(const kgl_ref_str_t* a, const kgl_ref_str_t* b) {
	if (!a) {
		if (!b) {
			return 0;
		} else {
			return 1;
		}
	}
	if (!b) {
		return -1;
	}
	return kgl_cmp(a->data, a->len, b->data, b->len);
}
inline int kgl_string_case_cmp(const kgl_ref_str_t* a, const kgl_ref_str_t* b) {
	if (!a) {
		if (!b) {
			return 0;
		} else {
			return 1;
		}
	}
	if (!b) {
		return -1;
	}
	return kgl_icmp(a->data, a->len, b->data, b->len);
}
inline void* kgl_memrchr(const void* s, int c, size_t n) 	{
	if (n == 0) {
		return NULL;
	}
	const u_char* end = (const u_char*)s + n - 1;
	while (end >= s) {
		if (*end == c) {
			return (void *)end;
		}
		end--;
	}
	return NULL;
}
inline int kgl_domain_cmp(const domain_t s1, const domain_t s2) {
	return kgl_cmp((const char*)(s1 + 1), *s1, (const char*)(s2 + 1), *s2);
}
extern int program_rand_value;
extern int open_file_limit;
#endif	/* !_LIB_H_INCLUDED_ */
