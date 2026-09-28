/*
 * kshim.h -- test-facing controls for the userland kernel shim (kshim.c).
 * Include from test and fuzz code; kern.h is already force-included.
 */
#ifndef _KSHIM_KSHIM_H_
#define _KSHIM_KSHIM_H_

#include <setjmp.h>

/* panic()/KASSERT: a test (or fuzz iteration) arms a jump buffer. */
extern jmp_buf	*kshim_panic_jmp;
extern char	 kshim_panic_msg[512];
extern int	 kshim_panics;

/* Lock bookkeeping (WITNESS-lite). */
int	kshim_locks_held(void);
void	kshim_locks_reset(void);

/* Deferred work. */
int	kshim_run_tasks(void);		/* runs the taskqueue until empty */
int	kshim_tasks_pending(void);
void	kshim_tasks_reset(void);	/* drop queued tasks without running */
int	kshim_callout_fire(struct callout *);	/* 1 if it was pending */
extern int kshim_taskq_start_fail;	/* !0: taskqueue_start_threads errno */

/* log(9)/printf capture. */
#define	KSHIM_LOG_PRINTF	(-1)
#define	KSHIM_LOG_DEVCTL	(-2)
int	kshim_log_count(void);
const char *kshim_log_get(int idx, int *pri);
int	kshim_log_find(const char *needle);	/* index or -1 */
void	kshim_log_clear(void);
extern int kshim_log_echo;		/* KSHIM_VERBOSE=1 echoes to stderr */

/* arc4random(9): deterministic; reseed to replay a sequence. */
void	kshim_arc4random_seed(uint64_t);

/* malloc(9) accounting. */
long	kshim_malloc_inuse(struct malloc_type *);
extern int kshim_malloc_nowait_fail;	/* >0: fail the Nth M_NOWAIT alloc */

/* mbufs. */
struct mbuf *kshim_mbuf_from(const void *buf, int len);
struct mbuf *kshim_mbuf_chain(const void *buf, int len, int seglen);
int	kshim_mbuf_count(void);		/* live mbufs */

/* ifnets. */
struct ifnet *kshim_ifnet_new(const char *name, u_char type);
void	kshim_ifnet_free(struct ifnet *);
void	kshim_ifnet_set_lladdr(struct ifnet *, const uint8_t mac[6]);
int	kshim_tx_capture(struct ifnet *, struct mbuf *);	/* if_transmit */
struct mbuf *kshim_tx_pop(struct ifnet *);	/* oldest captured frame */
void	kshim_tx_flush(struct ifnet *);

/* bpf(4): the most recent BPF_MTAP/BPF_MTAP2, header bytes then chain. */
#define	KSHIM_BPF_SNAP	128
int	kshim_bpf_taps(void);		/* taps since reset */
struct ifnet *kshim_bpf_last(uint8_t buf[KSHIM_BPF_SNAP], int *lenp);
void	kshim_bpf_reset(void);

/* netisr: frames handed to netisr_dispatch() are queued here. */
struct mbuf *kshim_netisr_pop(void);
void	kshim_netisr_flush(void);

/* if_clone: the most recent ifc_attach_cloner() registration. */
int	kshim_clone_create(int unit, struct ifnet **ifpp);
int	kshim_clone_destroy(struct ifnet *ifp);

/* SYSUNINIT/VNET_SYSINIT/VNET_SYSUNINIT registrations: 0 and the
 * (subsystem, order) key, or -1 when func was never registered as kind. */
int	kshim_sysinit_find(int kind, const char *func, u_int *sub,
	    u_int *order);

/* Reset every piece of global shim state between tests. */
void	kshim_reset(void);

#endif /* _KSHIM_KSHIM_H_ */
