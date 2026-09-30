#ifndef KHTTPHEADER_H_
#define KHTTPHEADER_H_
#include <stdio.h>
#include "kmalloc.h"
#include "kstring.h"
#include "khttp.h"
KBEGIN_DECLS
typedef struct _kgl_header_string
{
	kgl_str_t value;
	kgl_str_t low_case;
	kgl_str_t http11;
#ifdef ENABLE_HTTP2
	u_char http2_index;
#endif
} kgl_header_string;

extern kgl_header_string kgl_header_type_string[];
void kgl_init_header_string();
bool kgl_build_know_header_value(kgl_pool_t *pool, KHttpHeader* header, const char* val, int val_len);
#define kgl_cpymem(dst, src, n)   (((u_char *) kgl_memcpy(dst, src, n)) + (n))
inline void kgl_get_header_name(KHttpHeader* header, kgl_str_t* result) {
	if (header->name_is_know) {
		result->data = kgl_header_type_string[header->know_header].value.data;
		result->len = kgl_header_type_string[header->know_header].value.len;
		return;
	}
	result->data = header->buf;
	result->len = header->name_len;
	return;
}
inline KHttpHeader* new_pool_http_header(kgl_pool_t* pool, const char* attr, int attr_len, const char* val, int val_len) {
	if (attr_len > MAX_HEADER_ATTR_VAL_SIZE || val_len > MAX_HEADER_ATTR_VAL_SIZE) {
		return NULL;
	}
	assert(val_len>=0);
	KHttpHeader* header = (KHttpHeader*)(pool ? kgl_pnalloc(pool, sizeof(KHttpHeader)) : xmalloc(sizeof(KHttpHeader)));
	memset(header, 0, sizeof(KHttpHeader));
	header->header_in_pool = !!pool;
	header->buf_in_pool = !!pool;
	header->buf = (char*)(pool ? kgl_pnalloc(pool, attr_len + val_len + 2) : xmalloc(attr_len + val_len + 2)); 
	kgl_memcpy(header->buf, attr, attr_len);
	header->buf[attr_len] = '\0';
	header->val_offset = attr_len + 1;
	kgl_memcpy(header->buf + header->val_offset, val, val_len);
	header->buf[attr_len + val_len + 1] = '\0';
	header->val_len = val_len;
	header->name_len = attr_len;
	return header;
}
inline KHttpHeader* new_pool_http_know_header(kgl_pool_t* pool, kgl_header_type type, const char* val, int val_len) {
	assert(type >= 0 && type < kgl_header_unknow);
	if (val_len > MAX_HEADER_ATTR_VAL_SIZE) {
		return NULL;
	}
	KHttpHeader* header = (KHttpHeader*)(pool ? kgl_pnalloc(pool, sizeof(KHttpHeader)) : xmalloc(sizeof(KHttpHeader)));
	memset(header, 0, sizeof(KHttpHeader));
	header->header_in_pool = !!pool;
	if (!kgl_build_know_header_value(pool, header, val, val_len)) {
		if (!pool) {
			xfree(header);
		}
		return NULL;
	}
	header->know_header = (uint16_t)type;
	header->name_is_know = 1;
	return header;
}
inline KHttpHeader* new_http_know_header(kgl_header_type type, const char* val, int val_len) {
	return new_pool_http_know_header(NULL, type, val, val_len);
}
inline KHttpHeader* new_http_header(const char* attr, int attr_len, const char* val, int val_len) {
	return new_pool_http_header(NULL, attr, attr_len, val, val_len);
}
inline void xfree_header_buffer(KHttpHeader* av) {
	if (!av->buf_in_pool) {
		xfree(av->buf);
	}
}
inline void xfree_header(KHttpHeader* av) {
	xfree_header_buffer(av);
	if (!av->header_in_pool) {
		xfree(av);
	}
}
inline void free_header_list(KHttpHeader* av) {
	KHttpHeader* next;
	while (av) {
		next = av->next;
		xfree_header(av);
		av = next;
	}
}
KEND_DECLS
#endif /*KHTTPHEADER_H_*/
