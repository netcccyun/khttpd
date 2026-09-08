#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "kmalloc.h"
#include "khttp.h"
#include "KHttpParser.h"
#if 0
kgl_parse_result khttp_parse2(khttp_parser *parser, char **start, int *len, khttp_parse_result *rs)
{
restart:
	kassert(*len >= 0);
	if (*len <= 0) {
		kassert(*len == 0);
		return kgl_parse_continue;
	}
	char *pn = (char *)memchr(*start, '\n', *len);
	if (pn == NULL) {
		return kgl_parse_continue;
	}
	if (*start[0] == '\n' || *start[0] == '\r') {
		int checked = (int)(pn + 1 - *start);
		parser->header_len += checked;
		*start += checked;
		*len -= checked;
		if (!parser->started) {			
			goto restart;
		}
		parser->finished = 1;
		//printf("body[0]=%d,bodyLen=%d\n",body[0],bodyLen);
		return kgl_parse_finished;
	}
	if (parser->started) {
		/*
		 * 我们还要看看这个http域有没有换行，据rfc2616.
		 *        LWS            = [CRLF] 1*( SP | HT )
		 *        我们还要看看下一行第一个字符是否是空行。
		 */
		if (pn - *start == *len - 1) {
			/*
			 * 如果\n是最后的字符,则要continue.
			 */
			return kgl_parse_continue;
		}
		/*
		 * 如果下一行开头字符是SP或HT，则要并行处理。把\r和\n都换成SP
		 */
		while (pn[1]==' ' || pn[1]=='\t') {
			*pn = ' ';
			int checked = (int)(pn + 1 - *start);
			char *pr = (char *)memchr(*start, '\r', checked);
			if (pr) {
				*pr = ' ';
			}
			pn = (char *)memchr(pn,'\n', *len - checked);
			if (pn == NULL) {
				return kgl_parse_continue;
			}
		}
	}
	int checked = (int)(pn + 1 - *start);
	parser->header_len += checked;
	char *hot = *start;
	int hot_len = (int)(pn - *start);
	*start += checked;
	*len -= checked;
	if (hot_len > 2 && *(pn-1)=='\r') {
		pn--;
	}
	*pn = '\0';
	rs->is_first = !parser->started;
	parser->started = 1;
	return khttp_parse_header(parser, hot, pn, rs);
}
#endif
