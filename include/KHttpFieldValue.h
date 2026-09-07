/*
 * KHttpFieldValue.h
 *
 *  Created on: 2010-6-3
 *      Author: keengo
 */

#ifndef KHTTPFIELDVALUE_H_
#define KHTTPFIELDVALUE_H_
#include "KHttpLib.h"
class KHttpFieldValue
{
public:
	KHttpFieldValue(const char* val, const char* end) {
		while (val < end && isspace((unsigned char)*val)) {
			val++;
		}
		this->val = val;
		this->end = end;
	}
	bool contain(const char* field, size_t len) {
		do {
			if (is(field, len)) {
				return true;
			}
		} while (next());
		return false;
	}
	bool get_double_param(const char* param, size_t param_len, const char* field_end, size_t point, int64_t* value) {
		const char* hot = val;
		while (hot < field_end) {
			const char* param_end = (char*)memchr(hot, ';', field_end - hot);
			if (param_end == NULL) {
				param_end = field_end;
			}
			while (hot < param_end && isspace((unsigned char)*hot)) {
				hot++;
			}
			const char* eq = (char*)memchr(hot, '=', param_end - hot);
			if (eq == NULL) {
				hot = param_end + 1;
				continue;
			}
			if (!kgl_mem_case_same(hot, eq - hot, param, param_len)) {
				hot = param_end + 1;
				continue;
			}
			eq++;
			while (eq < param_end && isspace((unsigned char)*eq)) {
				eq++;
			}
			*value = kgl_atofp(eq, param_end - eq, point);
			return true;
		}
		return false;
	}
	bool is(const char* field, size_t field_len) {
		if ((size_t)(end - val) < field_len) {
			return false;
		}
		return strncasecmp(val, field, field_len) == 0;
	}
	bool is(const char* field, size_t field_len, int* n) {
		if ((size_t)(end - val) < field_len) {
			return false;
		}
		if (strncasecmp(val, field, field_len) != 0) {
			return false;
		}
		if (val + field_len >= end) {
			return false;
		}
		val += field_len;
		*n = kgl_atoi((u_char*)val, end - val);
		return true;
	}
	bool next() {
		const char* field_end = get_field_end();
		return next(field_end);
	}
	bool next(const char* prev_field_end) {
		if (prev_field_end == end) {
			return false;
		}
		val = prev_field_end;
		assert(*val == ',');
		val++;
		while (val < end && isspace((unsigned char)*val)) {
			val++;
		}
		return true;
	}
	const char* get_field_end() {
		const char* field_end = (const char*)memchr(val, ',', end - val);
		if (field_end == NULL) {
			return end;
		}
		return field_end;
	}
	const char* val;
	const char* end;
};
#endif /* KHTTPFIELDVALUE_H_ */
