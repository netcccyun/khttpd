/*
 * Copyright (c) 2010, NanChang BangTeng Inc
 *
 * kangle web server              http://www.kangleweb.net/
 * ---------------------------------------------------------------------
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *  See COPYING file for detail.
 *
 *  Author: KangHongjiu <keengo99@gmail.com>
 */
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <sstream>
#include <iostream>
#include <assert.h>
#include "KXml.h"
#include "klog.h"
#include "kforwin32.h"
 //#include "kfiber.h"
 //#include "KFileName.h"
#include "kmalloc.h"
#include "KDefer.h"
using namespace std;
kxml_fopen KXml::fopen = NULL;
kxml_fclose KXml::fclose = NULL;
kxml_fsize KXml::fsize = NULL;
kxml_fread KXml::fread = NULL;


void buildAttribute(char* buf, KXmlAttribute& attribute) {
	attribute.clear();
	//	printf("buf=[%s]\n",buf);
	while (*buf) {
		while (*buf && isspace((unsigned char)*buf))
			buf++;
		char* p = strchr(buf, '=');
		if (p == NULL)
			return;
		int name_len = (int)(p - buf);
		for (int i = name_len - 1; i >= 0; i--) {
			if (isspace((unsigned char)buf[i]))
				buf[i] = 0;
			else
				break;
		}
		*p = 0;
		p++;
		const char* name = buf;
		buf = p;
		buf = getString(buf, &p, NULL, false, true);
		if (buf == NULL) {
			return;
		}
		int len;
		//KString value = KXml::htmlDecode(buf, len);
		attribute.emplace(name, KXml::htmlDecode(buf, len));
		buf = p;
	}
}

KString replace(const char* str, map<KString, KString>& replaceMap,
	const char* start, const char* end) {
	KStringBuf s;
	if (str == NULL)
		return "";
	int startLen = 0;
	int endLen = 0;
	if (start) {
		startLen = (int)strlen(start);
	}
	if (end) {
		endLen = (int)strlen(end);
	}
	while (*str) {
		if (start) {
			if (strncmp(str, start, startLen) != 0) {
				s << *str;
				str++;
				continue;
			}
			str += startLen;
		}
		bool find = false;
		for (auto it = replaceMap.begin(); it != replaceMap.end(); it++) {
			if (strncmp(str, (*it).first.c_str(), (*it).first.size()) == 0) {
				if (end) {
					if (strncmp(str + (*it).first.size(), end, endLen) != 0) {
						continue;
					}
				}
				s << (*it).second;
				str += ((*it).first.size() + endLen);
				find = true;
				break;
			}
		}
		if (!find) {
			if (start) {
				s << start;
			}
			s << *str;
			str++;
		}
	}
	return s.str();
}
KXml::KXml() {
	file = NULL;
	origBuf = NULL;
	line = 0;
	hot = NULL;
	data = NULL;
}
KXml::~KXml() {
	clear();
}
void KXml::clear() {
	for (auto it = contexts.begin(); it != contexts.end(); it++) {
		delete (*it);
	}
	contexts.clear();
}
void KXml::setEvent(KXmlEvent* event) {
	//this->event = event;
	events.clear();
	events.push_back(event);
}
void KXml::addEvent(KXmlEvent* event) {
	events.push_back(event);
}
char* KXml::htmlEncode(const char* str, int& len, char* buf) {
	if (buf == NULL) {
		buf = (char*)malloc(5 * len + 1);
	}
	char* dst = buf;
	const char* src = str;
	while (*src) {
		switch (*src) {
		case '\'':
			*dst++ = '&';
			*dst++ = '#';
			*dst++ = '3';
			*dst++ = '9';
			*dst++ = ';';
			break;
		case '"':
			*dst++ = '&';
			*dst++ = '#';
			*dst++ = '3';
			*dst++ = '4';
			*dst++ = ';';
			break;
		case '&':
			*dst++ = '&';
			*dst++ = 'a';
			*dst++ = 'm';
			*dst++ = 'p';
			*dst++ = ';';
			break;
		case '>':
			*dst++ = '&';
			*dst++ = 'g';
			*dst++ = 't';
			*dst++ = ';';
			break;
		case '<':
			*dst++ = '&';
			*dst++ = 'l';
			*dst++ = 't';
			*dst++ = ';';
			break;
		default:
			*dst++ = *src;
		}
		src++;
	}
	*dst = '\0';
	len = (int)(dst - buf);
	return buf;
}
char* KXml::htmlDecode(char* str, int& len) {
	char* dst = str;
	char* src = str;
	while (*src) {
		if ((*src) == '&' && *(src + 1)) {
			if (strncasecmp(src + 1, "lt;", 3) == 0) {
				*dst++ = '<';
				src += 4;
				continue;
			}
			if (strncasecmp(src + 1, "gt;", 3) == 0) {
				*dst++ = '>';
				src += 4;
				continue;
			}
			if (strncasecmp(src + 1, "quot;", 5) == 0) {
				*dst++ = '"';
				src += 6;
				continue;
			}
			if (strncasecmp(src + 1, "apos;", 5) == 0) {
				*dst++ = '\'';
				src += 6;
				continue;
			}
			if (strncasecmp(src + 1, "amp;", 4) == 0) {
				*dst++ = '&';
				src += 5;
				continue;
			}
			if (*(src + 1) == '#') {
				char* e = strchr(src + 1, ';');
				if (e) {
					*dst++ = atoi(src + 2);
					src = e + 1;
					continue;
				}
			}
		}
		*dst++ = *src++;
	}
	*dst = '\0';
	len = (int)(dst - str);
	return str;
}
KString KXml::param(const char* str) {
	return encode(str);
}
KString KXml::encode(const KString &str) {
	map<KString, KString> transfer;
	transfer["&"] = "&amp;";
	transfer["'"] = "&#39;";
	transfer["\""] = "&#34;";
	transfer[">"] = "&gt;";
	transfer["<"] = "&lt;";
	return replace(str.c_str(), transfer);
}
KString KXml::decode(const KString &str) {
	map<KString, KString> transfer;
	transfer["&#39;"] = "'";
	transfer["&#34;"] = "\"";
	transfer["&amp;"] = "&";
	transfer["&gt;"] = ">";
	transfer["&lt;"] = "<";
	return replace(str.c_str(), transfer);
}
int KXml::getLine() {
	char* buf = origBuf;
	//int l = line;
	int len = (int)(hot - buf);
	//printf("len=%d\n",len);
	while (len-- > 0) {
		if (*buf == '\n') {
			line++;
		}
		buf++;
	}
	origBuf = hot;
	//line = l;
	return line;
}
bool KXml::startParse(char* buf) {
	origBuf = buf;
	line = 1;
	if (events.empty()) {
		throw KXmlException("not set event");
	}
	bool result = false;
	hot = strchr(buf, '<');
	if (hot == NULL) {
		throw KXmlException("file is not a xml format");
	}
	if (hot[1] == '?') {
		//first
		hot[1] = '\0';
		buf = hot + 2;
		hot = strchr(buf, '?');
		if (hot == NULL || hot[1] != '>') {
			throw KXmlException("file is not a xml format");
		}
		*hot = 0;
		KXmlAttribute attribute;
		buildAttribute(buf, attribute);
		encoding = attribute("encoding");
		buf = hot + 2;
	}
	try {
		startXml(encoding);
		result = internelParseString(buf);
	} catch (KXmlException& e) {
		endXml(result);
		throw e;
	} catch (std::exception& e) {
		endXml(result);
		throw e;
	}
	endXml(result);
	return result;

}
bool KXml::parseString(const char* buf) {

	char* str = strdup(buf);
	if (!str) {
		return false;
	}
	defer(free(str));
	return startParse(str);
}
bool KXml::internelParseString(char* buf) {
	//std::map<KString, KString> attibute;
	std::list<KXmlEvent*>::iterator it;
	bool single = false;
	KXmlContext* curContext = NULL;
	int state = 0;
	hot = buf;
	char* p;
	clear();
	//	hot=buf;
	while (*hot) {
		bool cdata = false;
		while (*hot && isspace((unsigned char)*hot))
			hot++;
		if (*hot == '<') {
			//	printf("buf=[%s]",buf);
			if (strncmp(hot, "<![CDATA[", 9) == 0) {
				cdata = true;
				hot += 9;
				state = START_CHAR;
			} else if (strncmp(hot, "<!--", 4) == 0) {
				//注释
				hot = strstr(hot + 4, "-->");
				if (hot == NULL) {
					throw KXmlException("cann't get comment end");
				}
				hot += 3;
				continue;
			} else {
				hot++;
				while (*hot && isspace((unsigned char)*hot))
					hot++;
				if (*hot == '/') {
					state = END_ELEMENT;
					hot++;
				} else {
					state = START_ELEMENT;
				}
			}
		} else {
			if (state == START_CHAR) {
				//				printf("xml end\n");
				break;
			}
			state = START_CHAR;
		}
		if (state == START_ELEMENT) {
			single = false;
			while (*hot && isspace((unsigned char)*hot))
				hot++;
			p = strchr(hot, '>');
			if (!p) {
				throw KXmlException("cann't get element end");
			}
			*p = 0;
			char* end = p + 1;
			int end_pos = (int)(p - hot);
			for (int i = end_pos - 1; i >= 0; i--) {
				if (isspace((unsigned char)hot[i]))
					continue;
				if (hot[i] == '/') {
					single = true;
					hot[i] = '\0';
					break;
				} else {
					break;
				}
			}
			p = hot;
			while (*p && !isspace((unsigned char)*p))
				p++;

			if (*p != 0) {
				*p = 0;
				curContext = newContext(hot);
				hot = p + 1;
				buildAttribute(hot, curContext->attribute);
			} else {
				curContext = newContext(hot);
			}
			try {
				for (it = events.begin(); it != events.end(); ++it) {
					(*it)->startElement(curContext);
				}
				hot = end;
				if (single) {
					for (it = events.begin(); it != events.end(); ++it) {
						(*it)->endElement(curContext);
					}
					delete curContext;
					curContext = NULL;
					if (contexts.empty()) {
						//printf("xml end\n");
						break;
					}
					continue;
				}
				contexts.push_back(curContext);
			} catch (const KXmlException& e2) {
				delete curContext;
				throw e2;
			}
		} else if (state == START_CHAR) {
			int char_len;
			if (cdata) {
				p = strstr(hot, "]]>");
				if (p == NULL) {
					throw KXmlException("Cann't read cdata end");
				}
				char_len = (int)(p - hot);
				p += 3;
			} else {
				p = strchr(hot, '<');
				if (p == NULL) {
					return true;
				}
				char_len = (int)(p - hot);
			}
			if (curContext) {
				//assert(char_len>0);
				char* charBuf = (char*)malloc(char_len + 1);
				defer(free(charBuf));
				kgl_memcpy(charBuf, hot, char_len);
				charBuf[char_len] = '\0';
				if (!cdata) {
					htmlDecode(charBuf, char_len);
				}
				for (it = events.begin(); it != events.end(); it++) {
					(*it)->startCharacter(curContext, charBuf, char_len);
				}
			}
			hot = p;
		} else if (state == END_ELEMENT) {
			while (*hot && isspace((unsigned char)*hot))
				hot++;
			p = strchr(hot, '>');
			if (p == NULL) {
				throw KXmlException("cann't get charater end");
			}
			*p = 0;
			char* end = p + 1;
			p = hot;
			while (*p && !isspace((unsigned char)*p))
				p++;
			*p = 0;
			if (contexts.size() <= 0) {
				throw KXmlException("contexts not enoungh");
				//				printf("contexts 不够\n");
				//				return false;
			}
			auto it2 = contexts.end();
			--it2;
			if ((*it2)->qName != hot) {
				throw KXmlException("end tag not match start tag");
			}
			curContext = (*it2);
			contexts.pop_back();

			//getContext(context);
			for (it = events.begin(); it != events.end(); it++) {
				(*it)->endElement(curContext);
			}
			delete curContext;
			curContext = NULL;
			hot = end;
			if (contexts.empty()) {
				//	printf("xml end\n");
				//break;
			}

		}
	}
	return true;
}
bool KXml::parseFile(KString file) {
	stringstream s;
	bool result;
	this->file = file.c_str();
	char* content = getContent(file);
	if (content == NULL || *content == '\0') {
		if (content) {
			free(content);
			return false;
		}
		throw KXmlException("cann't read file");
	}
	defer(free(content));
	try {
		result = startParse(content);
	} catch (KXmlException& e) {
		fprintf(stderr, "Error happen in %s:%d\n", file.c_str(), getLine());
		throw e;
	}
	return result;
}
KXmlContext* KXml::newContext(const char* qName) {
	KXmlContext* context = new KXmlContext(this);
	context->qName = qName;
	stringstream s;
	bool begin = true;
	for (auto it = contexts.begin(); it != contexts.end(); ++it) {
		if (!begin) {
			s << "/";
		}
		begin = false;
		s << (*it)->qName;
		context->parent = (*it);
		context->level++;
	}
	s.str().swap(context->path);
	return context;
}
char* KXml::getContent(const KString& file) {
	void* fp = KXml::fopen(file.c_str(), fileRead, 0);
	if (fp == NULL) {
		return NULL;
	}
	char* buf = NULL;
	INT64 fileSize = KXml::fsize(fp);
	if (fileSize > (INT64)max_file_size) {
		goto clean;
	}
	buf = (char*)malloc((int)fileSize + 1);
	if (buf == NULL) {
		goto clean;
	}
	if (KXml::fread(fp, buf, (int)fileSize) != (int)fileSize) {
		free(buf);
		buf = NULL;
		goto clean;
	}
	buf[fileSize] = '\0';
clean:
	KXml::fclose(fp);
	return buf;

}
