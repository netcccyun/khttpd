#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "khttp.h"
#ifdef ENABLE_HTTP3
#include "klog.h"
#include "KHttp3.h"
#include "KHttp3Sink.h"


#include "KHttpKeyValue.h"
#include "lsxpack_header.h"
#include "kselector_manager.h"
#include "kstring.h"
#include "kudp.h"
#include "KRequest.h"
#include "kfiber.h"
#include "openssl/rand.h"
#define MAX_SELECTOR_COUNT 256

#define  CW_SENDADDR  (1 << 0)
#if ECN_SUPPORTED
#define  CW_ECN       (1 << 1)
#endif
struct kgl_quic_package
{
	sockaddr_i local_addr;
	sockaddr_i* peer_addr;
	char* buffer;
};
kev_result h3_result_udp_recv(KOPAQUE data, void* arg, int got);
int h3_process_package_in(KHttp3ServerEngine* h3_engine, kconnection* uc, int got);
static lsquic_stream_ctx_t* http_server_on_new_stream(void* stream_if_ctx, lsquic_stream_t* stream) {
	auto lsquic_cn = lsquic_stream_conn(stream);
	if (lsquic_cn == NULL) {
		return NULL;
	}
	KHttp3Connection* cn = (KHttp3Connection*)lsquic_conn_get_ctx(lsquic_cn);
	if (cn == NULL) {
		return NULL;
	}
	KHttp3Sink* sink = new KHttp3Sink(cn, stream);
	lsquic_stream_wantread(stream, 1);
	lsquic_stream_wantwrite(stream, 0);
	return (lsquic_stream_ctx_t*)sink;
}

static lsquic_conn_ctx_t* http_server_on_new_conn(void* stream_if_ctx, lsquic_conn_t* conn) {
	KHttp3Connection* cn = new KHttp3Connection(conn, (KHttp3ServerEngine*)stream_if_ctx);
	return (lsquic_conn_ctx_t*)cn;
}
static void http_server_on_conn_closed(lsquic_conn_t* conn) {
	KHttp3Connection* cn = (KHttp3Connection*)lsquic_conn_get_ctx(conn);
	lsquic_conn_set_ctx(conn, NULL);
	cn->detach_connection();
	cn->release();
}
static void http_server_on_read(struct lsquic_stream* stream, lsquic_stream_ctx_t* st_h) {
	assert(st_h);
	KHttp3Sink* sink = (KHttp3Sink*)st_h;
	sink->on_read(stream);
}
static void http_server_on_write(lsquic_stream_t* stream, lsquic_stream_ctx_t* st_h) {
	assert(st_h);
	KHttp3Sink* sink = (KHttp3Sink*)st_h;
	sink->on_write(stream);
}
static void http_server_on_reset(lsquic_stream_t*, lsquic_stream_ctx_t* ctx, int how) {
	if (ctx) ((KHttp3Sink*)ctx)->on_reset(how);
}
static void http_server_on_hset(lsquic_stream_t* stream, lsquic_stream_ctx_t* ctx) {
	if (ctx) ((KHttp3Sink*)ctx)->on_headers(stream);
}
static void http_server_on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* st_h) {
	if (st_h) {
		KHttp3Sink* sink = (KHttp3Sink*)st_h;
		lsquic_stream_set_ctx(stream, NULL);
		if (sink->is_processing()) {
			sink->detach_stream();
		} else {
			delete sink;
		}
	}
}
static void
http_server_on_goaway(lsquic_conn_t* conn) {
	lsquic_conn_ctx_t* conn_h = lsquic_conn_get_ctx(conn);
	//conn_h->flags |= RECEIVED_GOAWAY;
}
static struct lsquic_stream_if http_server_if;
static struct lsquic_hset_if header_bypass_api;
inline kev_result h3_recv_package(KHttp3ServerEngine* h3_engine, kconnection* uc) {
	return selectable_read(&uc->st, h3_result_udp_recv, h3_engine->iov_buf, uc);
}
static void
setup_control_msg(
#ifndef WIN32
	struct msghdr
#else
	WSAMSG
#endif
	* msg, int cw,
	const struct lsquic_out_spec* spec, unsigned char* buf, size_t bufsz) {
	struct cmsghdr* cmsg;
	struct sockaddr_in* local_sa;
	struct sockaddr_in6* local_sa6;
#if __linux__ || __APPLE__ || WIN32
	struct in_pktinfo info;
#endif
	struct in6_pktinfo info6;
	size_t ctl_len;

#ifndef WIN32
	msg->msg_control = buf;
	msg->msg_controllen = bufsz;
#else
	msg->Control.buf = (char*)buf;
	msg->Control.len = bufsz;
#endif

	/* Need to zero the buffer due to a bug(?) in CMSG_NXTHDR.  See
	 * https://stackoverflow.com/questions/27601849/cmsg-nxthdr-returns-null-even-though-there-are-more-cmsghdr-objects
	 */
	memset(buf, 0, bufsz);

	ctl_len = 0;
	for (cmsg = CMSG_FIRSTHDR(msg); cw && cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cw & CW_SENDADDR) {
			if (AF_INET == spec->dest_sa->sa_family) {
				local_sa = (struct sockaddr_in*)spec->local_sa;
#if defined(LINUX) || defined(__APPLE__)
				memset(&info, 0, sizeof(info));
				info.ipi_spec_dst = local_sa->sin_addr;
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_PKTINFO;
				cmsg->cmsg_len = CMSG_LEN(sizeof(info));
				ctl_len += CMSG_SPACE(sizeof(info));
				memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
#elif WIN32
				memset(&info, 0, sizeof(info));
				info.ipi_addr = local_sa->sin_addr;
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_PKTINFO;
				cmsg->cmsg_len = CMSG_LEN(sizeof(info));
				ctl_len += CMSG_SPACE(sizeof(info));
				memcpy(WSA_CMSG_DATA(cmsg), &info, sizeof(info));
#else
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_SENDSRCADDR;
				cmsg->cmsg_len = CMSG_LEN(sizeof(local_sa->sin_addr));
				ctl_len += CMSG_SPACE(sizeof(local_sa->sin_addr));
				memcpy(CMSG_DATA(cmsg), &local_sa->sin_addr,
					sizeof(local_sa->sin_addr));
#endif
			} else {
				local_sa6 = (struct sockaddr_in6*)spec->local_sa;
				memset(&info6, 0, sizeof(info6));
				info6.ipi6_addr = local_sa6->sin6_addr;
				cmsg->cmsg_level = IPPROTO_IPV6;
				cmsg->cmsg_type = IPV6_PKTINFO;
				cmsg->cmsg_len = CMSG_LEN(sizeof(info6));
#ifndef WIN32
				memcpy(CMSG_DATA(cmsg), &info6, sizeof(info6));
#else
				memcpy(WSA_CMSG_DATA(cmsg), &info6, sizeof(info6));
#endif
				ctl_len += CMSG_SPACE(sizeof(info6));
			}
			cw &= ~CW_SENDADDR;
		}
#if ECN_SUPPORTED
		else if (cw & CW_ECN) {
			if (AF_INET == spec->dest_sa->sa_family) {
				const
#if defined(__FreeBSD__)
					unsigned char
#else
					int
#endif
					tos = spec->ecn;
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_TOS;
				cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
				memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
				ctl_len += CMSG_SPACE(sizeof(tos));
			} else {
				const int tos = spec->ecn;
				cmsg->cmsg_level = IPPROTO_IPV6;
				cmsg->cmsg_type = IPV6_TCLASS;
				cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
				memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
				ctl_len += CMSG_SPACE(sizeof(tos));
			}
			cw &= ~CW_ECN;
		}
#endif
		else
			assert(0);
	}

#ifndef WIN32
	msg->msg_controllen = ctl_len;
#else
	msg->Control.len = ctl_len;
#endif
}

#if defined(__linux__) && !ECN_SUPPORTED
/* Linux sends and receives QUIC datagrams in batches. ECN would need a
 * per-datagram TOS, which the batch code does not set, so it stays off then. */
#define KGL_H3_BATCH_UDP 1
#include <netinet/udp.h>
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#define KGL_H3_SEND_BATCH    64    /* datagram messages per sendmmsg() */
#define KGL_H3_SEND_IOV      1024  /* iovecs shared by those messages */
#define KGL_H3_GSO_SEGMENTS  64    /* UDP_MAX_SEGMENTS in the kernel */
#define KGL_H3_GSO_MAX_BYTES 64000 /* stay below the 64KB UDP payload limit */
#define KGL_H3_RECV_BATCH    32    /* datagrams per recvmmsg() */
#define KGL_H3_RECV_ROUNDS   8     /* recvmmsg() calls per readable event */
#define KGL_H3_CTL_SIZE (CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(uint16_t)))
struct kgl_h3_udp_batch
{
	struct mmsghdr send_msgs[KGL_H3_SEND_BATCH];
	unsigned send_specs[KGL_H3_SEND_BATCH]; /* lsquic packets carried by each message */
	struct iovec send_iov[KGL_H3_SEND_IOV];
	unsigned char send_ctl[KGL_H3_SEND_BATCH][KGL_H3_CTL_SIZE];
	struct mmsghdr recv_msgs[KGL_H3_RECV_BATCH];
	struct iovec recv_iov[KGL_H3_RECV_BATCH];
	sockaddr_i recv_peer[KGL_H3_RECV_BATCH];
	unsigned char recv_ctl[KGL_H3_RECV_BATCH][sizeof(kudp_extend)];
	char* recv_buf[KGL_H3_RECV_BATCH];
};
void kgl_h3_free_udp_batch(kgl_h3_udp_batch* batch) {
	for (int i = 0; i < KGL_H3_RECV_BATCH; i++) {
		if (batch->recv_buf[i]) {
			xfree(batch->recv_buf[i]);
		}
	}
	xfree(batch);
}
static kgl_h3_udp_batch* h3_get_udp_batch(KHttp3ServerEngine* h3_engine) {
	if (h3_engine->udp_batch) {
		return h3_engine->udp_batch;
	}
	kgl_h3_udp_batch* batch = (kgl_h3_udp_batch*)xmalloc(sizeof(kgl_h3_udp_batch));
	if (batch == nullptr) {
		return nullptr;
	}
	memset(batch, 0, sizeof(*batch));
	for (int i = 0; i < KGL_H3_RECV_BATCH; i++) {
		batch->recv_buf[i] = (char*)xmalloc(MAX_QUIC_UDP_SIZE);
		if (batch->recv_buf[i] == nullptr) {
			kgl_h3_free_udp_batch(batch);
			return nullptr;
		}
	}
	h3_engine->udp_batch = batch;
	return batch;
}
static inline unsigned h3_spec_size(const struct lsquic_out_spec* spec) {
	size_t size = 0;
	for (size_t i = 0; i < spec->iovlen; i++) {
		size += spec->iov[i].iov_len;
	}
	return (unsigned)size;
}
static inline socklen_t h3_sockaddr_len(const struct sockaddr* sa) {
	return AF_INET == sa->sa_family ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}
/* Packets can share one GSO send only if they go the same way. */
static bool h3_same_path(const struct lsquic_out_spec* a, const struct lsquic_out_spec* b, bool src_ip) {
	if (a->peer_ctx != b->peer_ctx || a->dest_sa->sa_family != b->dest_sa->sa_family) {
		return false;
	}
	if (a->dest_sa != b->dest_sa && memcmp(a->dest_sa, b->dest_sa, h3_sockaddr_len(a->dest_sa)) != 0) {
		return false;
	}
	if (!src_ip || a->local_sa == b->local_sa) {
		return true;
	}
	return a->local_sa->sa_family == b->local_sa->sa_family &&
		(a->local_sa->sa_family == 0 || memcmp(a->local_sa, b->local_sa, h3_sockaddr_len(a->local_sa)) == 0);
}
static size_t h3_build_control(unsigned char* buf, const struct lsquic_out_spec* spec, bool src_ip, uint16_t gso_size) {
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, KGL_H3_CTL_SIZE);
	msg.msg_control = buf;
	msg.msg_controllen = KGL_H3_CTL_SIZE;
	struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
	size_t len = 0;
	if (src_ip && spec->local_sa->sa_family) {
		if (AF_INET == spec->dest_sa->sa_family) {
			struct in_pktinfo info;
			memset(&info, 0, sizeof(info));
			info.ipi_spec_dst = ((const struct sockaddr_in*)spec->local_sa)->sin_addr;
			cmsg->cmsg_level = IPPROTO_IP;
			cmsg->cmsg_type = IP_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(info));
			memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
			len += CMSG_SPACE(sizeof(info));
		} else {
			struct in6_pktinfo info6;
			memset(&info6, 0, sizeof(info6));
			info6.ipi6_addr = ((const struct sockaddr_in6*)spec->local_sa)->sin6_addr;
			cmsg->cmsg_level = IPPROTO_IPV6;
			cmsg->cmsg_type = IPV6_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(info6));
			memcpy(CMSG_DATA(cmsg), &info6, sizeof(info6));
			len += CMSG_SPACE(sizeof(info6));
		}
		cmsg = CMSG_NXTHDR(&msg, cmsg);
	}
	if (gso_size > 0) {
		cmsg->cmsg_level = SOL_UDP;
		cmsg->cmsg_type = UDP_SEGMENT;
		cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
		memcpy(CMSG_DATA(cmsg), &gso_size, sizeof(uint16_t));
		len += CMSG_SPACE(sizeof(uint16_t));
	}
	return len;
}
/* Send lsquic packets with as few system calls as possible:
 * runs of equal-size packets to one peer become one GSO datagram message,
 * and up to KGL_H3_SEND_BATCH messages go out in one sendmmsg().
 * Returns the number of packets sent, -1 on error, or -2 when out of memory. */
static int h3_send_packets_batch(KHttp3ServerEngine* h3_engine, const struct lsquic_out_spec* specs, unsigned count) {
	kgl_h3_udp_batch* batch = h3_get_udp_batch(h3_engine);
	if (batch == nullptr) {
		return -2;
	}
	unsigned sent = 0;
	int saved_errno = 0;
	while (sent < count) {
		KHttp3ServerEngine* peer_engine = (KHttp3ServerEngine*)specs[sent].peer_ctx;
		bool src_ip = peer_engine->allow_src_ip();
		bool gso = h3_engine->udp_gso;
		unsigned nmsg = 0, niov = 0, n = sent;
		while (n < count && nmsg < KGL_H3_SEND_BATCH) {
			const struct lsquic_out_spec* first = &specs[n];
			/* one sendmmsg() writes to one socket */
			if (first->peer_ctx != peer_engine || niov + first->iovlen > KGL_H3_SEND_IOV) {
				break;
			}
			struct msghdr* msg = &batch->send_msgs[nmsg].msg_hdr;
			memset(msg, 0, sizeof(*msg));
			msg->msg_name = (void*)first->dest_sa;
			msg->msg_namelen = h3_sockaddr_len(first->dest_sa);
			msg->msg_iov = &batch->send_iov[niov];
			memcpy(&batch->send_iov[niov], first->iov, first->iovlen * sizeof(struct iovec));
			niov += (unsigned)first->iovlen;
			unsigned seg_size = h3_spec_size(first);
			unsigned total = seg_size, segs = 1;
			++n;
			if (gso && seg_size > 0) {
				while (n < count && segs < KGL_H3_GSO_SEGMENTS && h3_same_path(first, &specs[n], src_ip)) {
					unsigned size = h3_spec_size(&specs[n]);
					if (size == 0 || size > seg_size || total + size > KGL_H3_GSO_MAX_BYTES ||
						niov + specs[n].iovlen > KGL_H3_SEND_IOV) {
						break;
					}
					memcpy(&batch->send_iov[niov], specs[n].iov, specs[n].iovlen * sizeof(struct iovec));
					niov += (unsigned)specs[n].iovlen;
					total += size;
					++segs;
					++n;
					/* only the last segment may be shorter */
					if (size < seg_size) {
						break;
					}
				}
			}
			msg->msg_iovlen = (size_t)(&batch->send_iov[niov] - msg->msg_iov);
			size_t ctl_len = h3_build_control(batch->send_ctl[nmsg], first, src_ip, segs > 1 ? (uint16_t)seg_size : 0);
			if (ctl_len > 0) {
				msg->msg_control = batch->send_ctl[nmsg];
				msg->msg_controllen = ctl_len;
			}
			batch->send_specs[nmsg] = segs;
			++nmsg;
		}
		int done = sendmmsg(peer_engine->uc->st.fd, batch->send_msgs, nmsg, 0);
		if (done < 0) {
			saved_errno = errno;
			if (gso && (saved_errno == EIO || saved_errno == EINVAL)) {
				/* the device cannot offload it: send the packets one by one */
				klog(KLOG_WARNING, "UDP GSO send failed errno=%d, disable it for HTTP/3\n", saved_errno);
				h3_engine->udp_gso = false;
				continue;
			}
			break;
		}
		for (int i = 0; i < done; i++) {
			sent += batch->send_specs[i];
		}
		if ((unsigned)done < nmsg) {
			saved_errno = EAGAIN;
			break;
		}
	}
	if (sent == 0 && count > 0) {
		errno = saved_errno ? saved_errno : EAGAIN;
		return -1;
	}
	if (sent < count) {
		/* lsquic retries the rest once the socket is writable again */
		errno = EAGAIN;
	}
	return (int)sent;
}
/* Read the datagrams already queued on the socket with recvmmsg().
 * Each one goes through the same path as a datagram read by recvmsg().
 * Returns true when the socket queue is empty. */
static bool h3_recv_batch(KHttp3ServerEngine* h3_engine, kconnection* uc) {
	if (uc->udp == nullptr) {
		return false;
	}
	kgl_h3_udp_batch* batch = h3_get_udp_batch(h3_engine);
	if (batch == nullptr) {
		return false;
	}
	for (int round = 0; round < KGL_H3_RECV_ROUNDS; round++) {
		for (int i = 0; i < KGL_H3_RECV_BATCH; i++) {
			struct msghdr* msg = &batch->recv_msgs[i].msg_hdr;
			batch->recv_iov[i].iov_base = batch->recv_buf[i];
			batch->recv_iov[i].iov_len = MAX_QUIC_UDP_SIZE;
			memset(batch->recv_ctl[i], 0, sizeof(batch->recv_ctl[i]));
			msg->msg_name = &batch->recv_peer[i];
			msg->msg_namelen = sizeof(sockaddr_i);
			msg->msg_iov = &batch->recv_iov[i];
			msg->msg_iovlen = 1;
			msg->msg_control = batch->recv_ctl[i];
			msg->msg_controllen = sizeof(batch->recv_ctl[i]);
			msg->msg_flags = 0;
		}
		int n = recvmmsg(uc->st.fd, batch->recv_msgs, KGL_H3_RECV_BATCH, MSG_DONTWAIT, NULL);
		if (n <= 0) {
			return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
		}
		for (int i = 0; i < n; i++) {
			int len = (int)batch->recv_msgs[i].msg_len;
			if (len <= 0 || KBIT_TEST(batch->recv_msgs[i].msg_hdr.msg_flags, MSG_TRUNC)) {
				continue;
			}
			memcpy(&uc->addr, &batch->recv_peer[i], sizeof(sockaddr_i));
			memcpy(uc->udp, batch->recv_ctl[i], sizeof(kudp_extend));
			/* lend the buffer to the engine; a packet that moves to another
			 * thread keeps it and leaves a new buffer in its place */
			char* own_buffer = (char*)h3_engine->iov_buf[1].iov_base;
			h3_engine->iov_buf[1].iov_base = batch->recv_buf[i];
			h3_process_package_in(h3_engine, uc, len);
			batch->recv_buf[i] = (char*)h3_engine->iov_buf[1].iov_base;
			h3_engine->iov_buf[1].iov_base = own_buffer;
		}
		if (n < KGL_H3_RECV_BATCH) {
			/* recvmmsg() takes all it can, so a short batch drained the queue */
			return true;
		}
	}
	return false;
}
#else
void kgl_h3_free_udp_batch(kgl_h3_udp_batch* batch) {
}
#endif

int send_packets_out(
	void* packets_out_ctx,
	const struct lsquic_out_spec* specs,
	unsigned                       count
) {
	KHttp3ServerEngine* h3_engine;
	unsigned n;
	int s = 0;
#ifndef _WIN32
	struct msghdr msg;
#else
	DWORD bytes;
	WSAMSG msg;
#endif
	union
	{
		/* cmsg(3) recommends union for proper alignment */
#if defined(LINUX) || defined(_WIN32)
#	define SIZE1 sizeof(struct in_pktinfo)
#else
#	define SIZE1 sizeof(struct in_addr)
#endif
		unsigned char buf[
			CMSG_SPACE(KGL_MAX(SIZE1, sizeof(struct in6_pktinfo)))
#if ECN_SUPPORTED
				+ CMSG_SPACE(sizeof(int))
#endif
		];
		struct cmsghdr cmsg;
	} ancil;
	uintptr_t ancil_key, prev_ancil_key = 0;
	if (0 == count)
		return 0;
#ifdef KGL_H3_BATCH_UDP
	int batch_sent = h3_send_packets_batch((KHttp3ServerEngine*)packets_out_ctx, specs, count);
	if (batch_sent != -2) {
		return batch_sent;
	}
#endif
	//printf("out package count=[%d]\n", count);
	const unsigned orig_count = count;
#if 0
	const unsigned out_limit = packet_out_limit();
	if (out_limit && count > out_limit)
		count = out_limit;
#endif
	n = 0;
	int cw;
	do {
		h3_engine = (KHttp3ServerEngine*)specs[n].peer_ctx;
		kconnection* uc = h3_engine->uc;
#ifndef _WIN32
		msg.msg_name = (void*)specs[n].dest_sa;
		msg.msg_namelen = (AF_INET == specs[n].dest_sa->sa_family ?
			sizeof(struct sockaddr_in) :
			sizeof(struct sockaddr_in6));
		msg.msg_iov = specs[n].iov;
		msg.msg_iovlen = specs[n].iovlen;
		msg.msg_flags = 0;
#else
		msg.name = (sockaddr*)specs[n].dest_sa;
		msg.namelen = (AF_INET == specs[n].dest_sa->sa_family ?
			sizeof(struct sockaddr_in) :
			sizeof(struct sockaddr_in6));
		msg.dwBufferCount = specs[n].iovlen;
		msg.lpBuffers = specs[n].iov;
		msg.dwFlags = 0;
#endif        
		if (h3_engine->allow_src_ip() && specs[n].local_sa->sa_family) {
			cw = CW_SENDADDR;
			ancil_key = (uintptr_t)specs[n].local_sa;
			assert(0 == (ancil_key & 3));
		} else {
			cw = 0;
			ancil_key = 0;
		}
#if ECN_SUPPORTED
		if (specs[n].ecn) {
			cw |= CW_ECN;
			ancil_key |= specs[n].ecn;
		}
#endif
		if (cw && prev_ancil_key == ancil_key) {
			/* Reuse previous ancillary message */
			;
		} else if (cw) {
			prev_ancil_key = ancil_key;
			setup_control_msg(&msg, cw, &specs[n], ancil.buf, sizeof(ancil.buf));
		} else {
			prev_ancil_key = 0;
#ifndef WIN32
			msg.msg_control = NULL;
			msg.msg_controllen = 0;
#else
			msg.Control.buf = NULL;
			msg.Control.len = 0;
#endif
		}
#ifndef WIN32
		s = sendmsg(uc->st.fd, &msg, 0);
#else
		s = lpfnWsaSendMsg(uc->st.fd, &msg, 0, &bytes, NULL, NULL);
#endif
		if (s < 0) {
			break;
		}
		++n;
	} while (n < count);


	if (n < orig_count) {
		//prog_sport_cant_send(sport->sp_prog, sport->fd);
	}


	if (n > 0) {
		if (n < orig_count)
			errno = EAGAIN;
		return n;
	}
	assert(s < 0);
	return -1;
}
static int parse_local_addr(kgl_quic_package* package, kconnection* uc) {
	package->local_addr.v4.sin_family = package->peer_addr->v4.sin_family;
	package->local_addr.v4.sin_port = uc->addr.v4.sin_port;
	return kudp_get_recvaddr(uc, (struct sockaddr*)&package->local_addr);
}
inline int  kgl_quic_package_in(KHttp3ServerEngine* h3_engine, kgl_quic_package* package, int got) {
	return lsquic_engine_packet_in(h3_engine->engine, (unsigned char*)package->buffer, got, (sockaddr*)&package->local_addr, (sockaddr*)package->peer_addr, h3_engine, 0);
}
static struct lsquic_engine_settings engine_settings = { 0 };

static kev_result next_quic_package_in(KOPAQUE data, void* arg, int got) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)data;
	kgl_quic_package* package = (kgl_quic_package*)arg;
	kgl_quic_package_in(h3_engine, package, got);
	h3_engine->release();
	xfree(package->peer_addr);
	xfree(package->buffer);
	xfree(package);
	return kev_ok;
}
int h3_process_package_in(KHttp3ServerEngine* h3_engine, kconnection* uc, int got) {
	if (h3_engine->is_multi()) {
		lsquic_cid_t cid;
		cid.len = 0;
		if (0 != lsquic_cid_from_packet((unsigned char*)h3_engine->get_udp_buffer(), got, &cid) || cid.len < sizeof(kgl_h3_cid_header)) {
			return -1;

		}
		int index = h3_engine->server->get_engine_index((kgl_h3_cid_header*)cid.idbuf);
		//printf("package index=[%d] current selector=[%p] sid=[%d]\n", index, kgl_get_tls_selector(), kgl_get_tls_selector()->sid);
		if (index != kgl_get_tls_selector()->sid) {
			kselector* selector = get_selector_by_index(index);
			KHttp3ServerEngine* next_engine = h3_engine->server->refs_engine(index);
			kgl_quic_package* package = (kgl_quic_package*)xmalloc(sizeof(kgl_quic_package));
			package->buffer = h3_engine->realloc_buffer();
			package->peer_addr = (sockaddr_i*)xmalloc(sizeof(sockaddr_i));
			memcpy(package->peer_addr, &uc->addr, sizeof(sockaddr_i));
			parse_local_addr(package, uc);
			kgl_selector_module.next(selector, next_engine, next_quic_package_in, package, got);
			return 0;
		}
	}

	kgl_quic_package package;
	package.buffer = (char*)h3_engine->iov_buf[1].iov_base;
	package.peer_addr = &uc->addr;
	parse_local_addr(&package, uc);
	return kgl_quic_package_in(h3_engine, &package, got);
}
kev_result h3_result_udp_recv(KOPAQUE data, void* arg, int got) {
	kconnection* uc = (kconnection*)arg;
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)data;
	if (got == ST_ERR_TIME_OUT) {
		return kev_ok;
	}
	if (got > 0) {
		h3_process_package_in(h3_engine, uc, got);
#ifdef KGL_H3_BATCH_UDP
		/* take the queued datagrams in batches; once the queue is empty, wait
		 * for epoll rather than call recvmsg() just to get EAGAIN */
		if (h3_recv_batch(h3_engine, uc)) {
			KBIT_CLR(uc->st.base.st_flags, STF_RREADY);
		}
#endif
	}
	if (h3_engine->server->is_shutdown()) {
		h3_engine->release();
		return kev_destroy;
	}
	return h3_recv_package(h3_engine, uc);
}
SSL_CTX* h3_lookup_cert(void* lsquic_cert_lookup_ctx, const struct sockaddr* local, const char* hostname) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)lsquic_cert_lookup_ctx;
	if (!hostname) return kgl_get_ssl_ctx(h3_engine->ssl_ctx);
	SSL_CTX* ssl_ctx = nullptr;
	void* sni = kgl_ssl_create_sni(h3_engine->server->get_data(), hostname, &ssl_ctx);
	if (sni) {
		h3_engine->cache_sni(hostname, sni);
	}
	if (ssl_ctx) {
		return ssl_ctx;
	}
	return kgl_get_ssl_ctx(h3_engine->ssl_ctx);
}
SSL_CTX* ea_get_ssl_ctx(void* peer_ctx, const struct sockaddr* local) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)peer_ctx;
	return kgl_get_ssl_ctx(h3_engine->ssl_ctx);
}
static void*
interop_server_hset_create(void* hsi_ctx, lsquic_stream_t* stream, int is_push_promise) {
	// LSQUIC may decode an initial block before a stream context exists.
	return new header_decoder;
}
static struct lsxpack_header*
interop_server_hset_prepare_decode(void* hset_p, struct lsxpack_header* xhdr,
	size_t req_space) {
	struct header_decoder* req = (struct header_decoder*)hset_p;
	if (req_space > sizeof(req->decode_buf)) return NULL;
	if (xhdr) return xhdr;
	// Each field is copied into the header set before decoding the next one.
	lsxpack_header_prepare_decode(&req->xhdr, req->decode_buf, 0, sizeof(req->decode_buf));
	return &req->xhdr;
}
static int
interop_server_hset_add_header(void* hset_p, struct lsxpack_header* xhdr) {
	struct header_decoder* req = (struct header_decoder*)hset_p;
	const char* name, * value;
	int name_len, value_len;
	if (!xhdr) return 0;
	name = lsxpack_header_get_name(xhdr);
	value = lsxpack_header_get_value(xhdr);
	name_len = xhdr->name_len;
	value_len = xhdr->val_len;
	req->bytes += name_len + value_len + 32;
	if (req->invalid || ++req->count > KHTTP_MAX_FIELD_COUNT || req->bytes > 64 * 1024 ||
		!khttp_valid_field(name, name_len, value, value_len, true) ||
		!req->fields.add_header(name, name_len, value, value_len)) req->invalid = true;
	// Defer semantic errors to the sink, to reset only the offending stream.
	return 0;
}
static void
interop_server_hset_destroy(void* hset_p) {
	struct header_decoder* req = (struct header_decoder*)hset_p;
	free_header_decoder(req);
}
static int h3_log_buf(void* ctx, const char* buf, size_t len) {
	FILE* out = (FILE*)ctx;
	fwrite(buf, 1, len, out);
	fflush(out);
	return 0;
}
static const struct lsquic_logger_if logger_if = { h3_log_buf, };

void kgl_shutdown_khttp3() {
	lsquic_global_cleanup();
}
bool kgl_init_khttp3() {
	if (lsquic_global_init(LSQUIC_GLOBAL_SERVER | LSQUIC_GLOBAL_CLIENT) != 0) return false;
	//lsquic_logger_init(&logger_if, stdout, LLTS_HHMMSSUS);
	//lsquic_set_log_level("debug");
	memset(&http_server_if, 0, sizeof(http_server_if));
	http_server_if.on_new_conn = http_server_on_new_conn;
	http_server_if.on_conn_closed = http_server_on_conn_closed;
	http_server_if.on_new_stream = http_server_on_new_stream;
	http_server_if.on_read = http_server_on_read;
	http_server_if.on_write = http_server_on_write;
	http_server_if.on_close = http_server_on_close;
	http_server_if.on_goaway_received = http_server_on_goaway;
	http_server_if.on_reset = http_server_on_reset;
	http_server_if.on_hset_in = http_server_on_hset;
	lsquic_engine_init_settings(&engine_settings, LSENG_SERVER);
	engine_settings.es_versions = (1u << LSQVER_I001) | (1u << LSQVER_I002);
	engine_settings.es_max_header_list_size = 64 * 1024;
	engine_settings.es_rw_once = 1;
	engine_settings.es_send_prst = 1;
	//engine_settings.es_proc_time_thresh = LSQUIC_DF_PROC_TIME_THRESH;
	//engine_settings.es_cc_rtt_thresh = 0;
	//engine_settings.es_cc_algo = 2; //BBRv1

	memset(&header_bypass_api, 0, sizeof(header_bypass_api));
	header_bypass_api.hsi_create_header_set = interop_server_hset_create;
	header_bypass_api.hsi_prepare_decode = interop_server_hset_prepare_decode;
	header_bypass_api.hsi_process_header = interop_server_hset_add_header;
	header_bypass_api.hsi_discard_header_set = interop_server_hset_destroy;
	header_bypass_api.hsi_flags = (lsquic_hsi_flag)(LSQUIC_HSI_HASH_NAME | LSQUIC_HSI_HASH_NAMEVAL | LSQUIC_HSI_APP_CONTENT_LENGTH);

	return true;

}
void kgl_h3_generate_scid(void* ctx, lsquic_conn_t* cn, uint8_t*buf, unsigned len) {
	if (buf == NULL) {
		return;
	}
	if (len < sizeof(kgl_h3_cid_header)) {
		memset(buf, 0, len);
		return;
	}
//}
//void kgl_h3_generate_scid(void* ctx, lsquic_conn_t* cn, lsquic_cid_t* cid, unsigned len) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)ctx;
	kselector* selector = kgl_get_tls_selector();
	kgl_h3_cid_header* header = (kgl_h3_cid_header*)buf;
	header->port_id = (uint8_t)selector->sid;
	header->seq = h3_engine->seq++;
	if (RAND_bytes(buf + sizeof(kgl_h3_cid_header), (int)(len - sizeof(kgl_h3_cid_header))) != 1) {
		memset(buf + sizeof(kgl_h3_cid_header), 0, len - sizeof(kgl_h3_cid_header));
	}
	//cid->len = len;
}

int h3_start_server_engine(void* arg, int got) {
	assert(kgl_get_tls_selector()->sid == got);
	KHttp3Server* server = (KHttp3Server*)arg;
	return server->start_engine(got);
}
int h3_shutdown_engine(void* arg, int got) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)arg;
	return h3_engine->shutdown();
}
int kgl_h3_engine_tick(void* arg, int event_count) {
	KHttp3ServerEngine* h3_engine = (KHttp3ServerEngine*)arg;
	assert(h3_engine->selector_tick);
	h3_engine->ticked();
	int next_time = h3_engine->next_event_time();

	if (h3_engine->server->is_shutdown() && next_time < 0) {
		kselector_close_tick(h3_engine->selector_tick);
		h3_engine->selector_tick = NULL;
		h3_engine->release();
		return 0;
	}
	return next_time;
}
KHttp3Server* kgl_h3_new_server(const char* ip, uint16_t port, int sock_flags, kgl_ssl_ctx* ssl_ctx, uint32_t model) {
	assert(is_selector_manager_init());
	auto selector_count = get_selector_count();
	assert(selector_count > 0);
	if (selector_count > MAX_SELECTOR_COUNT) {
		selector_count = MAX_SELECTOR_COUNT;
	}
	KHttp3Server* server = new KHttp3Server(selector_count);
	if (0 != server->init(ip, port, sock_flags, ssl_ctx, model)) {
		server->release();
		return nullptr;
	}
	return server;
}
int KHttp3Server::shutdown() {
	if (!KBIT_TEST(flags, KGL_SERVER_START)) {
		return false;
	}
	KBIT_CLR(flags, KGL_SERVER_START);
	for (int i = 0; i < engine_count; i++) {
		auto selector = get_selector_by_index(i);
		kfiber* fiber = NULL;
		kfiber_create2(selector, h3_shutdown_engine, engines[i], 0, 0, &fiber);
		int retval = -1;
		kfiber_join(fiber, &retval);
	}
	return 0;
}
static kev_result h3_update_ssl_ctx(KOPAQUE data, void* arg, int) {
	auto engine = (KHttp3ServerEngine*)data;
	auto ssl_ctx = (kgl_ssl_ctx*)arg;
	auto old = engine->ssl_ctx;
	engine->ssl_ctx = ssl_ctx;
	if (old) kgl_release_ssl_ctx(old);
	delete engine->last_sni;
	engine->last_sni = nullptr;
	engine->release();
	return kev_ok;
}
void KHttp3Server::update_ssl_ctx(kgl_ssl_ctx* next) {
	if (!next || next == ssl_ctx) return;
	kgl_add_ref_ssl_ctx(next);
	auto old = ssl_ctx;
	ssl_ctx = next;
	if (old) kgl_release_ssl_ctx(old);
	for (int i = 0; i < engine_count; i++) {
		kgl_add_ref_ssl_ctx(next);
		addRef();
		kgl_selector_module.next(get_selector_by_index(i), engines[i], h3_update_ssl_ctx, next, 0);
	}
}
int KHttp3Server::init(const char* ip, uint16_t port, int sock_flags, kgl_ssl_ctx* ssl_ctx, uint32_t model) {
	if (!ssl_ctx) {
		return -1;
	}
	if (this->ssl_ctx) {
		return -1;
	}
	if (!ksocket_getaddr(ip, port, PF_UNSPEC, AI_NUMERICHOST, &addr)) {
		return -1;
	}
	allow_src_ip = 0;
	if (addr.v4.sin_family == PF_INET) {
		if (addr.v4.sin_addr.s_addr == INADDR_ANY) {
			allow_src_ip = 1;
		}
#ifdef KSOCKET_IPV6
	} else {
		if (memcmp(&addr.v6.sin6_addr, &in6addr_any, sizeof(addr.v6.sin6_addr)) == 0) {
			allow_src_ip = 1;
		}
#endif
	}
	kgl_add_ref_ssl_ctx(ssl_ctx);
	this->ssl_ctx = ssl_ctx;
	this->flags = model;
	for (int i = 0; i < engine_count; i++) {
		int ret = engines[i]->init(get_selector_by_index(i), sock_flags);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}
bool KHttp3Server::start() {
	if (KBIT_TEST(flags, KGL_SERVER_START)) {
		return false;
	}
	if (this->ssl_ctx == nullptr) {
		return false;
	}
	KBIT_SET(flags, KGL_SERVER_START);
	for (int i = 0; i < engine_count; i++) {
		auto selector = get_selector_by_index(i);
		assert(selector->sid == i);
		addRef();
		kfiber_create2(selector, h3_start_server_engine, this, i, 0, NULL);
	}
	return true;
}
int KHttp3Server::start_engine(int index) {
	auto engine = engines[index];
	return engine->start();
}
int KHttp3ServerEngine::start() {
	if (engine == nullptr || uc == nullptr) {
		//not init engine
		release();
		return -1;
	}

	if (selector_tick == nullptr) {
		selector_tick = kselector_new_tick(kgl_h3_engine_tick, this);
		if (selector_tick) {
			if (kselector_register_tick(selector_tick)) {
				server->addRef();
			} else {
				kselector_close_tick(selector_tick);
				selector_tick = nullptr;
			}
		}
	}
	h3_recv_package(this, uc);
	return 0;
}
/* QUIC must not be fragmented (RFC 9000 14), and lsquic's path MTU probes
 * only tell the truth when oversized datagrams are dropped, not split. */
static void h3_set_dont_fragment(SOCKET fd, bool ipv6) {
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_PROBE)
	int val = IP_PMTUDISC_PROBE;
	if (!ipv6 && setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, (const char*)&val, sizeof(val)) != 0) {
		klog(KLOG_WARNING, "cann't set IP_MTU_DISCOVER for HTTP/3 errno=%d\n", errno);
	}
#elif defined(IP_DONTFRAG)
	int val = 1;
	if (!ipv6) {
		setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, (const char*)&val, sizeof(val));
	}
#endif
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_PROBE)
	int val6 = IPV6_PMTUDISC_PROBE;
	if (ipv6 && setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, (const char*)&val6, sizeof(val6)) != 0) {
		klog(KLOG_WARNING, "cann't set IPV6_MTU_DISCOVER for HTTP/3 errno=%d\n", errno);
	}
#elif defined(IPV6_DONTFRAG)
	int val6 = 1;
	if (ipv6) {
		setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, (const char*)&val6, sizeof(val6));
	}
#endif
}
int KHttp3ServerEngine::init(kselector* selector, int udp_flag) {
	kgl_add_ref_ssl_ctx(server->ssl_ctx);
	ssl_ctx = server->ssl_ctx;
	KBIT_SET(udp_flag, KSOCKET_IP_PKTINFO);
	lsquic_engine_api engine_api = { 0 };
	engine_api.ea_packets_out = send_packets_out;
	engine_api.ea_packets_out_ctx = (void*)this;
	engine_api.ea_get_ssl_ctx = ea_get_ssl_ctx;
	engine_api.ea_stream_if = &http_server_if;
	engine_api.ea_stream_if_ctx = (void*)this;

	engine_api.ea_settings = &engine_settings;
	engine_api.ea_hsi_if = &header_bypass_api;
	if (kgl_ssl_create_sni) {
		engine_api.ea_lookup_cert = h3_lookup_cert;
		engine_api.ea_cert_lu_ctx = (void*)this;
	}
	if (is_multi()) {
		engine_api.ea_gen_scid_ctx = (void*)this;
		engine_api.ea_generate_scid = kgl_h3_generate_scid;
		udp_flag |= KSOCKET_REUSEPORT;
	}
	if (engine != nullptr) {
		return -1;
	}
	engine = lsquic_engine_new(LSENG_SERVER | LSENG_HTTP, &engine_api);
	if (!engine) {
		return -1;
	}
	if (uc == nullptr) {
		uc = kudp_new2(udp_flag, selector);
	}
	if (!kudp_bind(uc, &server->addr)) {
		return -1;
	}
	h3_set_dont_fragment(uc->st.fd, server->addr.v4.sin_family == AF_INET6);
#ifdef KGL_H3_BATCH_UDP
	{
		/* kernels before 4.18 do not know UDP_SEGMENT and would send one
		 * oversized datagram, so only use it where the option exists */
		int gso_size = 0;
		socklen_t len = sizeof(gso_size);
		udp_gso = getsockopt(uc->st.fd, SOL_UDP, UDP_SEGMENT, &gso_size, &len) == 0;
	}
#endif
	KBIT_SET(uc->st.base.st_flags, STF_RTIME_OUT);
	selectable_bind_opaque(&uc->st, this);
	return 0;
}
int KHttp3ServerEngine::add_refs() {
	return server->addRef();
}
void KHttp3ServerEngine::release() {
	server->release();
}
bool KHttp3ServerEngine::is_multi() {
	return server->engine_count > 1;
}
bool KHttp3ServerEngine::allow_src_ip() {
	return server->allow_src_ip;
}
int KHttp3ServerEngine::shutdown() {
	if (uc == nullptr) {
		return -1;
	}
	lsquic_engine_cooldown(engine);
	selectable_shutdown(&uc->st);
	return 0;
}
#endif
