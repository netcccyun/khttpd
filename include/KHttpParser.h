#ifndef KHTTPPARSER_H
#define KHTTPPARSER_H
#include "kfeature.h"
typedef enum {
	kgl_parse_error,//protocol error
	kgl_parse_success,//have header parsed in result
	kgl_parse_finished,//no header finished
	kgl_parse_want_read,
	kgl_parse_continue //no data parsed, need more data
} kgl_parse_result;

typedef struct {
	char* val;
	int val_len;
} khttp_field;

typedef struct {
	char* attr;
	char* val;
	int attr_len;
	int val_len;
	uint8_t is_first : 1;
	uint8_t request_line : 1;
	/* field name is not an HTTP token */
	uint8_t bad_name : 1;
} khttp_parse_result;

typedef struct {
	int header_len;
	int scan_offset;
	uint8_t started : 1;
	uint8_t finished : 1;
	uint8_t first_same : 1;
} khttp_parser;

#define KHTTP_ISSPACE(c) (c==' ')
INLINE bool khttp_is_token(unsigned char ch) {
	return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
		(ch >= 'a' && ch <= 'z') || ch == '!' || ch == '#' || ch == '$' ||
		ch == '%' || ch == '&' || ch == '\'' || ch == '*' || ch == '+' ||
		ch == '-' || ch == '.' || ch == '^' || ch == '_' || ch == '`' ||
		ch == '|' || ch == '~';
}
INLINE kgl_parse_result khttp_parse_header(khttp_parser* parser, char* header, char* end, khttp_parse_result* rs) {
	char* val;
	bool request_line = false;
	if (rs->is_first && !parser->first_same) {
		val = (char *)memchr(header, ' ', end-header);
		rs->request_line = 1;
		request_line = true;
	} else {
		val = (char*)memchr(header, ':', end - header);
	}
	if (val == NULL) {
		return kgl_parse_error;
	}
	char* sep = val;
	*val = '\0';
	val++;
	while (*val && KHTTP_ISSPACE(*val)) {
		val++;
	}
	char* header_end = header;
	while (*header_end && !KHTTP_ISSPACE(*header_end)) {
		header_end++;
	}
	rs->attr = header;
	rs->attr_len = (int)(header_end - header);
	rs->bad_name = (!request_line && header_end != sep);
	if (!request_line) {
		rs->bad_name = rs->bad_name || header == sep;
		for (char* p = header; p < sep; ++p) {
			if (!khttp_is_token((unsigned char)*p)) {
				rs->bad_name = 1;
				break;
			}
		}
	}
	*header_end = '\0';
	rs->val_len = (int)(end - val);
	rs->val = val;
	return kgl_parse_success;
}
INLINE kgl_parse_result khttp_parse(khttp_parser* parser, char** start, char* end, khttp_parse_result* rs) {
restart:
	kassert(end >= *start);
	if (*start == end) {
		return kgl_parse_continue;
	}
	kassert(parser->scan_offset <= end - *start);
	char* pn = (char*)memchr(*start + parser->scan_offset, '\n', end - *start - parser->scan_offset);
	if (pn == NULL) {
		parser->scan_offset = (int)(end - *start);
		return kgl_parse_continue;
	}
	if (*start[0] == '\n' || *start[0] == '\r') {
		int checked = (int)(pn + 1 - *start);
		parser->header_len += checked;
		*start += checked;
		parser->scan_offset = 0;
		assert(*start <= end);
		if (!parser->started) {
			goto restart;
		}
		parser->finished = 1;
		return kgl_parse_finished;
	}
	if (parser->started) {
		/*
		 * 我们还要看看这个http域有没有换行，据rfc2616.
		 *        LWS            = [CRLF] 1*( SP | HT )
		 *        我们还要看看下一行第一个字符是否是空行。
		 */
		for (;;) {
			/* 如果\n是最后的字符,则要continue. */
			if (pn + 1 >= end) {
				parser->scan_offset = (int)(pn - *start);
				return kgl_parse_continue;
			}
			/* 如果下一行开头字符是SP或HT，则要并行处理。把\r和\n都换成SP */
			if (pn[1] != ' ' && pn[1] != '\t') {
				break;
			}
			*pn = ' ';
			if (pn > *start && pn[-1] == '\r') {
				pn[-1] = ' ';
			}
			char* next = pn + 1;
			pn = (char*)memchr(next, '\n', end - next);
			if (pn == NULL) {
				parser->scan_offset = (int)(end - *start);
				return kgl_parse_continue;
			}
		}
	}
	int checked = (int)(pn + 1 - *start);
	parser->scan_offset = 0;
	parser->header_len += checked;
	char* hot = *start;
	*start += checked;
	assert(*start <= end);
	if (checked > 3 && *(pn - 1) == '\r') {
		pn--;
	}
	*pn = '\0';
	rs->is_first = !parser->started;
	parser->started = 1;
	return khttp_parse_header(parser, hot, pn, rs);
}
#endif
