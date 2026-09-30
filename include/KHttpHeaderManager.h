#ifndef KHTTPHEADERMANAGER_H_99
#define KHTTPHEADERMANAGER_H_99
#include <ctype.h>
#include "KHttpHeader.h"
#include "KHttpLib.h"

#if 0
inline int attr_casecmp(const char* s1, const char* s2) {
	const unsigned char* p1 = (const unsigned char*)s1;
	const unsigned char* p2 = (const unsigned char*)s2;
	int result;
	if (p1 == p2)
		return 0;

	while ((result = kgl_attr_tolower(*p1) - kgl_attr_tolower(*p2++)) == 0)
		if (*p1++ == '\0')
			break;
	return result;
}
#endif
enum class KHttpHeaderIteratorResult
{
	Continue,
	Remove,
	Free
};

typedef KHttpHeaderIteratorResult(*kgl_http_header_iterator) (void* arg, KHttpHeader* av);

class KHttpHeaderManager
{
public:
	KHttpHeader *append(KHttpHeader* new_t) {
		if (header == NULL) {
			header = last = new_t;
			return new_t;
		}
		new_t->next = header;
		header = new_t;
		return new_t;
	}
	KHttpHeader *insert(KHttpHeader* new_t) {
		if (header == NULL) {
			header = last = new_t;
			return new_t;
		}
		kassert(last);
		last->next = new_t;
		last = new_t;
		return new_t;
	}
	void iterator(kgl_http_header_iterator it, void* arg) {
		KHttpHeader* l = header;
		last = NULL;
	next:
		while (l) {
			KHttpHeader* next = l->next;
			switch (it(arg, l)) {
			case KHttpHeaderIteratorResult::Remove:
				if (last) {
					last->next = next;
				} else {
					header = next;
				}
				l = next;
				goto next;
			case KHttpHeaderIteratorResult::Free:
			{
				if (last) {
					last->next = next;
				} else {
					header = next;
				}
				xfree_header(l);
				l = next;
				goto next;
			}
			default:
				break;
			}
			last = l;
			l = next;
		}
		assert((header == NULL && last == NULL) || (header != NULL && last->next == NULL));
	}
	void adjust_buffer_offset(ptrdiff_t offset) {
		KHttpHeader* av = header;
		while (av) {
			if (av->buf_reoffset) {
				av->buf += offset;
			}
			av = av->next;
		}
	}
	KHttpHeader* add_header(kgl_pool_t* pool, const char* attr, int attr_len, const char* val, int val_len, bool tail = true) {
		KHttpHeader* new_t = new_pool_http_header(pool, attr, attr_len, val, val_len);
		if (!new_t) {
			return nullptr;
		}
		return tail ? insert(new_t) : append(new_t);
	}
	KHttpHeader* add_header(const char* attr, int attr_len, const char* val, int val_len, bool tail = true) {
		return add_header(nullptr, attr, attr_len, val, val_len, tail);
	}
	bool add_header(kgl_header_type type, time_t tm) {
		char tmp_buf[42];
		mk1123time(tm, tmp_buf, 41);
		return add_header(type, (const char *)tmp_buf, 29);
	}
	KHttpHeader* add_header(kgl_header_type type, const char* val, int val_len, bool tail = true) {
		return add_header(nullptr, type, val, val_len, tail);
	}
	KHttpHeader* add_header(kgl_pool_t* pool, char* attr, int attr_len, char* val, int val_len, bool tail = true) {
		assert(pool);
		if (val_len < 0) {
			return nullptr;
		}
		if (attr_len > MAX_HEADER_ATTR_VAL_SIZE || val_len > MAX_HEADER_ATTR_VAL_SIZE) {
			return nullptr;
		}
		KHttpHeader* header = (KHttpHeader*)kgl_pnalloc(pool, sizeof(KHttpHeader));
		memset(header, 0, sizeof(KHttpHeader));
		header->buf_in_pool = 1;
		header->header_in_pool = 1;
		header->buf_reoffset = 1;
		header->buf = attr;
		header->name_len = (uint16_t)attr_len;
		header->val_offset = (uint16_t)(val-attr);
		assert(header->buf + header->val_offset == val);
		header->val_len = (uint16_t)val_len;
		return tail ? insert(header) : append(header);
	}
	KHttpHeader* add_header(kgl_pool_t* pool, kgl_header_type type, char* val, int val_len, bool tail = true) {
		assert(pool);
		if (val_len < 0) {
			return add_header(pool, type, (const char*)val, val_len, tail);
		}
		if (val_len > MAX_HEADER_ATTR_VAL_SIZE) {
			return nullptr;
		}
		KHttpHeader* header = (KHttpHeader*)kgl_pnalloc(pool, sizeof(KHttpHeader));
		memset(header, 0, sizeof(KHttpHeader));
		header->buf_in_pool = 1;
		header->header_in_pool = 1;
		header->buf_reoffset = 1;
		header->buf = val;
		header->val_offset = 0;
		header->val_len = (uint16_t)val_len;
		header->know_header = (uint16_t)type;
		header->name_is_know = 1;
		return tail ? insert(header) : append(header);
	}
	KHttpHeader* add_header(kgl_pool_t* pool, kgl_header_type type, const char* val, int val_len, bool tail = true) {
		KHttpHeader* new_t = new_pool_http_know_header(pool, type, val, val_len);
		if (!new_t) {
			return nullptr;
		}
		return tail ? insert(new_t) : append(new_t);
	}
	KHttpHeader* find(kgl_header_type attr) {
		KHttpHeader* l = header;
		while (l) {
			if (l->name_is_know && l->know_header == attr) {
				return l;
			}
			l = l->next;
		}
		return NULL;
	}
	KHttpHeader* find(const char* attr, int len) {
		KHttpHeader* l = header;
		while (l) {
			if (kgl_is_attr(l, attr, len)) {
				return l;
			}
			l = l->next;
		}
		return NULL;
	}
	KHttpHeader* remove(const char* attr, int attr_len) {
		KHttpHeader* l = header;
		KHttpHeader* prev = NULL;
		while (l) {
			if (kgl_is_attr(l, attr, attr_len)) {
				if (prev) {
					prev->next = l->next;
				} else {
					header = l->next;
				}
				if (last == l) {
					last = prev;
				}
				l->next = NULL;
				return l;
			}
			prev = l;
			l = l->next;
		}
		return NULL;
	}
	KHttpHeader* get_header() {
		return header;
	}
	KHttpHeader* steal_header() {
		KHttpHeader* h = header;
		header = last = NULL;
		return h;
	}
	KHttpHeader* header;
	KHttpHeader* last;
};
#endif
