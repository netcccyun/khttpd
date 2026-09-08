/*
 * KPoolableStreamContainer.h
 *
 *  Created on: 2010-8-18
 *      Author: keengo
 */

#ifndef KPOOLABLESTREAMCONTAINER_H_
#define KPOOLABLESTREAMCONTAINER_H_
#include <list>
#include "KUpstream.h"
#include "KStringBuf.h"
#include "KMutex.h"
#include "KAtomCountable.h"
void SafeDestroyUpstream(KUpstream *st);
/*
 * 连接池容器类
 */
class KPoolableSocketContainerImp {
public:
	KPoolableSocketContainerImp();
	~KPoolableSocketContainerImp();
	void refresh(bool clean);
	void refreshList(kgl_list *l, bool clean);
	kgl_list *GetList()
	{
		return &head;
	}	
	unsigned size;
protected:
	kgl_list head;
};
class KPoolableSocketContainer: public KAtomCountable {
public:
	KPoolableSocketContainer();
	virtual ~KPoolableSocketContainer();

	/*
	回收连接
	close,是否关闭
	lifeTime 连接时间
	*/
	virtual void gcSocket(KUpstream *st,int life_time);
	void bind(KUpstream *st);
	void unbind(KUpstream *st);
	int getLifeTime() {
		return life_time;
	}
	/*
	 * 设置连接超时时间
	 */
	void setLifeTime(int life_time);
	/*
	 * 定期刷新删除过期连接
	 */
	virtual void refresh(time_t nowTime);
	/*
	 * 清除所有连接
	 */
	void clean();
	/*
	 * 得到连接数
	 */
	 unsigned getSize() {
		unsigned size = 0;
		lock.Lock();
		if (imp) {
			size = imp->size;
		}
		lock.Unlock();
		return size;
	}
	virtual void health(KUpstream *st,HealthStatus stage)
	{
	}
	kgl_refs_string* GetParam();
	void SetParam(const char* param);
	virtual void shutdown() = 0;
	void remove() {
		shutdown();
		release();
	}
	virtual void set_tcp(bool tcp)
	{
		this->tcp = tcp;
	}
#ifdef HTTP_PROXY
	virtual KHttpHeader* get_proxy_header(kgl_pool_t *pool) {
		return nullptr;
	}
#endif
	union
	{
		struct
		{
			uint16_t monitor : 1;
			uint16_t is_unix : 1;
			uint16_t sign : 1;
			uint16_t disable_flag : 1;
#ifdef ENABLE_UPSTREAM_SSL
			uint16_t no_sni : 1;
#endif
			uint16_t tcp : 1;
			uint16_t h2 : 1;
			uint16_t life_time;
		};
		uint32_t flags;
	};
protected:
	KUpstream* new_upstream(kconnection* cn);
	KUpstream* get_pool_socket(uint32_t flags);
	/*
	 * 把连接真正放入池中
	 */
	void PutPoolSocket(KUpstream *st);

	kgl_refs_string* param;
	KMutex lock;
private:
	
	KUpstream *internalGetPoolSocket(uint32_t flags);
	time_t getHttp2ExpireTime()
	{
		int life_time = this->life_time;
		if (life_time <= 10) {
			//http2最少10秒连接时间
			life_time = 10;
		}
		return kgl_current_sec + life_time;
	}
	KPoolableSocketContainerImp *imp;
};
#endif /* KPOOLABLESTREAMCONTAINER_H_ */
