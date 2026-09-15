#include <stdlib.h>
#include <string.h>
#include <vector>
#include "KXml.h"
#include "KXmlDocument.h"
using namespace std;
namespace khttpd {
	const KString KXmlNodeBody::text_as_attribute_name(internal_xml_attribute);
	KXmlDocument::KXmlDocument(bool skip_ns) {
		this->skip_ns = skip_ns;
	}
	KXmlDocument::~KXmlDocument(void) {
	}
	KXmlNode* KXmlDocument::getNode(const std::string& name) const {
		KXmlNode* rootNode = getRootNode();
		if (rootNode == NULL) {
			return NULL;
		}
		std::string tag;
		auto pos = name.find('/');
		if (pos != std::string::npos) {
			tag = name.substr(0, pos);
		} else {
			tag = name;
		}
		if (tag != rootNode->key.tag->data) {
			return NULL;
		}
		if (pos == std::string::npos) {
			return rootNode;
		}
		return rootNode->find_child(name.substr(pos + 1));
	}
	KXmlNode* KXmlDocument::getRootNode() const {
		return root.get();
	}
	KSafeXmlNode KXmlDocument::parse(char* str) {
		KXml xml;
		xml.setEvent(this);
		try {
			//printf("%s\n", str);
			xml.startParse(str);
		} catch (KXmlException& e) {
			fprintf(stderr, "%s", e.what());
			return nullptr;
		}
		return root;
	}
	bool KXmlDocument::startElement(KXmlContext* context) {
		//printf("parse node=[%s]\n", context->qName.c_str());
		parents.push(std::move(cur_node));
		cur_node = khttpd::KSafeXmlNode(new KXmlNode());
		auto body = cur_node->get_first();
		body->attributes.swap(context->attribute);
		kgl_ref_str_t* tag;
		if (!skip_ns) {
			tag = kstring_from2(context->qName.c_str(), context->qName.size());
		} else {
			auto pos = context->qName.find(':');
			if (pos != std::string::npos) {
				auto q_name = context->qName.substr(pos + 1);
				tag = kstring_from2(q_name.c_str(), q_name.size());
			} else {
				tag = kstring_from2(context->qName.c_str(), context->qName.size());
			}
		}

		if (qname_config) {
			auto it = qname_config->find(tag);
			if (it) {
				auto key_vary = it->value();
				kstring_release(tag);
				tag = kstring_refs(key_vary->tag);
				cur_node->key.tag_id = key_vary->tag_id;
				if (key_vary->vary) {
					auto it2 = body->attributes.find(key_vary->vary->data);
					if (it2 != body->attributes.end()) {
						cur_node->key.vary = kstring_from2((*it2).second.c_str(), (*it2).second.size());
					} else {
						cur_node->key.vary = kstring_from2(_KS(""));
					}
				}
			}
		}
		cur_node->key.tag = tag;
		return true;

	}
	bool KXmlDocument::startCharacter(KXmlContext* context, char* character, int len) {
		if (cur_node == NULL) {
			return false;
		}
		auto body = cur_node->get_first();
		if (!body) {
			return false;
		}
		body->set_text(character);
		return true;
	}
	bool KXmlDocument::endElement(KXmlContext* context) {
		if (cur_node == NULL) {
			return false;
		}
		//printf("end node=[%s]\n", context->qName.c_str());
		khttpd::KSafeXmlNode parent = nullptr;
		if (!parents.empty()) {
			parent = std::move(parents.top());
			parents.pop();
		}
		if (!parent) {
			assert(root == nullptr);
			root = cur_node;
		} else {
			parent->append(cur_node.get());
		}
		cur_node = parent;
		return true;
	}
	KXmlNodeBody::~KXmlNodeBody() {
		childs.iterator([](void* data, void* arg) {
			KXmlNode* node = (KXmlNode*)data;
			((KXmlNode*)data)->release();
			return iterator_remove_continue;
			}, NULL);
	}
	bool KXmlNodeBody::update(KXmlKey* key, uint32_t index, KXmlNode* xml, bool copy_childs, bool create_flag) {
		KMapNode<KXmlNode>* it;
		if (create_flag) {
			if (!xml) {
				return false;
			}
			int new_flag;
			it = childs.insert(key, &new_flag);
			if (new_flag) {
				it->value(xml->add_ref());
				return true;
			}
		} else {
			it = childs.find(key);
			if (!it) {
				return false;
			}
		}
		auto node = it->value();
		if (!xml) {
			//remove
			auto body = node->remove_body(index);
			if (body) {
				delete body;
				if (node->get_body_count() == 0) {
					childs.erase(it);
					node->release();
				}
				return true;
			}
			return false;
		}
		auto body = node->get_body_address(index);
		if (!body) {
			return false;
		}
		auto xml_body = xml->remove_last();
		if (!xml_body) {
			return false;
		}
		if (copy_childs) {
			xml_body->copy_child_from(*body);
		}
		delete (*body);
		*body = xml_body;
		return true;
	}
	KXmlNodeBody* KXmlNodeBody::add(KXmlNode* xml, uint32_t index) {
		int new_flag;
		auto it = childs.insert(&xml->key, &new_flag);
		if (new_flag) {
			it->value(xml->add_ref());
			return xml->get_first();
		}
		auto old_node = it->value();
		auto body = xml->remove_last();
		if (!body) {
			return NULL;
		}
		old_node->insert_body(body, index);
		return body;
	}
	void KXmlNodeBody::copy_child_from(const KXmlNodeBody* node) {
		for (auto it = node->childs.first(); it; it = it->next()) {
			add(it->value()->add_ref(), last_pos);
		}
	}
	static void write_xml_attribute(KWStream* out, const KString& value) {
		out->write_all(_KS("\""));
		for (size_t i = 0; i < value.size(); ++i) {
			switch (value[i]) {
			case '&':
				out->write_all(_KS("&amp;"));
				break;
			case '<':
				out->write_all(_KS("&lt;"));
				break;
			case '>':
				out->write_all(_KS("&gt;"));
				break;
			case '"':
				out->write_all(_KS("&quot;"));
				break;
			default:
				if ((unsigned char)value[i] < 0x20 && value[i] != '\t' && value[i] != '\r' && value[i] != '\n') {
					out->write_all(_KS("&#xfffd;"));
				} else {
					out->write_all(value.c_str() + i, 1);
				}
				break;
			}
		}
		out->write_all(_KS("\""));
	}

	KGL_RESULT KXmlNodeBody::write(KWStream* out, int level) const {
		//write attribute
		const KString* text = nullptr;
		for (auto it = attributes.begin(); it != attributes.end(); ++it) {
			if ((*it).first == text_as_attribute_name) {
				text = &(*it).second;
				continue;
			}
			if ((*it).first[0] == internal_xml_attribute) {
				//skip
				continue;
			}
			out->write_all(_KS(" "));
			out->write_all((*it).first.c_str(), (int)(*it).first.size());
			out->write_all(_KS("="));

			write_xml_attribute(out, (*it).second);
		}

		//write child
		if (!childs.empty()) {
			out->write_all(_KS(">\n"));
		} else if (text == nullptr) {
			out->write_all(_KS("/>\n"));
			return KGL_END;
		} else {
			out->write_all(_KS(">"));
		}
		for (auto node : childs) {
			auto result = node->write(out, level + 1);
			if (result != KGL_OK) {
				return result;
			}
		}
		if (text) {
			if (memchr(text->c_str(), '<', text->size())) {
				out->write_all(_KS(CDATA_START));
				out->write_all(text->c_str(), (int)text->size());
				out->write_all(_KS(CDATA_END));
			} else {
				out->write_all(text->c_str(), (int)text->size());
			}
			if (!childs.empty()) {
				out->write_all(_KS("\n"));
			}
		}
		if (!childs.empty()) {
			for (int i = 0; i < level; i++) {
				out->write_all(_KS("\t"));
			}
		}
		return KGL_OK;
	}
	void KXmlNodeBody::clone_to(KXmlNodeBody* body) const {
		body->attributes = attributes;
		for (auto child : childs) {
			body->add(child->clone().get(), last_pos);
		}
	}
	KXmlNodeBody* KXmlNodeBody::clone() const {
		KXmlNodeBody* node = new KXmlNodeBody;
		clone_to(node);
		return node;
	}
	KMapNode<KXmlNode>* KXmlNodeBody::find_any_child(const KXmlKeyTag *tag) const {
		return childs.find<KXmlKeyTag>(tag);
	}
	KXmlNode* KXmlNodeBody::find_child(const KString& tag) const {
		size_t pos = tag.find('/');
		KString child_tag;
		if (pos != KString::npos) {
			child_tag = tag.substr(0, pos);
		} else {
			child_tag = tag;
		}
		KXmlKey key(child_tag.c_str(), child_tag.size());
		auto it = childs.find(&key);
		if (!it) {
			return nullptr;
		}
		if (pos != KString::npos) {
			return it->value()->find_child(tag.substr(pos + 1));
		}
		return it->value();
	}
}
