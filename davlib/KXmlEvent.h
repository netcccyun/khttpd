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
#ifndef KXmlEvent_h_1l2kj312312
#define KXmlEvent_h_1l2kj312312
#include <map>
#include "KXmlContext.h"
#include "KStringBuf.h"
#define CDATA_START	"<![CDATA["
#define CDATA_END	"]]>"
/*
 * xml解析事件接听器
 */
class KXmlEvent {
public:
	virtual ~KXmlEvent() {
	}
	virtual void startXml(const KString &encoding) {
	}
	virtual void endXml(bool success) {
	}

	/*
	 * 开始一个标签
	 * context 标签上下文
	 * attribute 标签属性
	 */
	virtual bool startElement(KXmlContext* context) {
		return false;
	}
	/*
	 * 开始一个标签文本
	 * context 标签上下文
	 * character 文本
	 * len 文本长度
	 */
	virtual bool startCharacter(KXmlContext *context, char *character, int len) {
		return false;
	}

	/*
	 * 结束一个标签
	 * context 标签上下文
	 */
	virtual bool endElement(KXmlContext *context) {
		return false;
	}

};
#endif
