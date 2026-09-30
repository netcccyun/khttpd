/*
 * KHttpKeyValue.cpp
 *
 *  Created on: 2010-4-23
 *      Author: keengo
 */
#include <stdlib.h>
#include <string.h>
#include "KHttpKeyValue.h"
#include "kforwin32.h"
#include "kstring.h"
#include "kmalloc.h"
#include "KHttpLib.h"
kgl_str_t http_methods[MAX_METHOD] = {
	    kgl_string("UNSET"),
		kgl_string("GET"),
		kgl_string("HEAD"),
		kgl_string("POST"),
		kgl_string("OPTIONS"),
		kgl_string("PUT"),
		kgl_string("DELETE"),
		kgl_string("TRACE"),
		kgl_string("PROPFIND"),
		kgl_string("PROPPATCH"),
		kgl_string("MKCOL"),
		kgl_string("COPY"),
		kgl_string("MOVE"),
		kgl_string("LOCK"),
		kgl_string("UNLOCK"),
		kgl_string("ACL"),
		kgl_string("REPORT"),
		kgl_string("VERSION-CONTROL"),
		kgl_string("CHECKIN"),
		kgl_string("CHECKOUT"),
		kgl_string("UNCHECKOUT"),
		kgl_string("SEARCH"),
		kgl_string("MKWORKSPACE"),
		kgl_string("UPDATE"),
		kgl_string("LABEL"),
		kgl_string("MERGE"),
		kgl_string("BASELINE-CONTROL"),
		kgl_string("MKACTIVITY"),
		kgl_string("CONNECT"),
		kgl_string("PURGE"),
		kgl_string("PATCH"),
		kgl_string("SUBSCRIBE"),
		kgl_string("UNSUBSCRIBE"),
		kgl_string("PRI")
};
