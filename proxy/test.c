
typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;
typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;
typedef signed long int __int64_t;
typedef unsigned long int __uint64_t;
typedef long int __quad_t;
typedef unsigned long int __u_quad_t;
typedef unsigned long int __dev_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef unsigned long int __ino_t;
typedef unsigned long int __ino64_t;
typedef unsigned int __mode_t;
typedef unsigned long int __nlink_t;
typedef long int __off_t;
typedef long int __off64_t;
typedef int __pid_t;
typedef struct {
    int __val[2];
} __fsid_t;
typedef long int __clock_t;
typedef unsigned long int __rlim_t;
typedef unsigned long int __rlim64_t;
typedef unsigned int __id_t;
typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;
typedef int __daddr_t;
typedef int __key_t;
typedef int __clockid_t;
typedef void *__timer_t;
typedef long int __blksize_t;
typedef long int __blkcnt_t;
typedef long int __blkcnt64_t;
typedef unsigned long int __fsblkcnt_t;
typedef unsigned long int __fsblkcnt64_t;
typedef unsigned long int __fsfilcnt_t;
typedef unsigned long int __fsfilcnt64_t;
typedef long int __fsword_t;
typedef long int __ssize_t;
typedef long int __syscall_slong_t;
typedef unsigned long int __syscall_ulong_t;
typedef __off64_t __loff_t;
typedef __quad_t *__qaddr_t;
typedef char *__caddr_t;
typedef long int __intptr_t;
typedef unsigned int __socklen_t;
typedef __u_char u_char;
typedef __u_short u_short;
typedef __u_int u_int;
typedef __u_long u_long;
typedef __quad_t quad_t;
typedef __u_quad_t u_quad_t;
typedef __fsid_t fsid_t;
typedef __loff_t loff_t;
typedef __ino_t ino_t;
typedef __dev_t dev_t;
typedef __gid_t gid_t;
typedef __mode_t mode_t;
typedef __nlink_t nlink_t;
typedef __uid_t uid_t;
typedef __off_t off_t;
typedef __pid_t pid_t;
typedef __id_t id_t;
typedef __ssize_t ssize_t;
typedef __daddr_t daddr_t;
typedef __caddr_t caddr_t;
typedef __key_t key_t;

typedef __clock_t clock_t;

typedef __time_t time_t;

typedef __clockid_t clockid_t;
typedef __timer_t timer_t;
typedef long unsigned int size_t;
typedef unsigned long int ulong;
typedef unsigned short int ushort;
typedef unsigned int uint;
typedef int int8_t __attribute__((__mode__(__QI__)));
typedef int int16_t __attribute__((__mode__(__HI__)));
typedef int int32_t __attribute__((__mode__(__SI__)));
typedef int int64_t __attribute__((__mode__(__DI__)));
typedef unsigned int u_int8_t __attribute__((__mode__(__QI__)));
typedef unsigned int u_int16_t __attribute__((__mode__(__HI__)));
typedef unsigned int u_int32_t __attribute__((__mode__(__SI__)));
typedef unsigned int u_int64_t __attribute__((__mode__(__DI__)));
typedef int register_t __attribute__((__mode__(__word__)));
static __inline unsigned int __bswap_32(unsigned int __bsx)
{
    return __builtin_bswap32(__bsx);
}
static __inline __uint64_t __bswap_64(__uint64_t __bsx)
{
    return __builtin_bswap64(__bsx);
}
typedef int __sig_atomic_t;
typedef struct {
    unsigned long int __val[(1024 / (8 * sizeof(unsigned long int)))];
} __sigset_t;
typedef __sigset_t sigset_t;
struct timespec {
    __time_t tv_sec;
    __syscall_slong_t tv_nsec;
};
struct timeval {
    __time_t tv_sec;
    __suseconds_t tv_usec;
};
typedef __suseconds_t suseconds_t;
typedef long int __fd_mask;
typedef struct {
    __fd_mask __fds_bits[1024 / (8 * (int)sizeof(__fd_mask))];
} fd_set;
typedef __fd_mask fd_mask;

extern int select(int __nfds, fd_set *__restrict __readfds,
                  fd_set *__restrict __writefds, fd_set *__restrict __exceptfds,
                  struct timeval *__restrict __timeout);
extern int pselect(int __nfds, fd_set *__restrict __readfds,
                   fd_set *__restrict __writefds,
                   fd_set *__restrict __exceptfds,
                   const struct timespec *__restrict __timeout,
                   const __sigset_t *__restrict __sigmask);

__extension__ extern unsigned int gnu_dev_major(unsigned long long int __dev)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__const__));
__extension__ extern unsigned int gnu_dev_minor(unsigned long long int __dev)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__const__));
__extension__ extern unsigned long long int gnu_dev_makedev(
    unsigned int __major, unsigned int __minor)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__const__));

typedef __blksize_t blksize_t;
typedef __blkcnt_t blkcnt_t;
typedef __fsblkcnt_t fsblkcnt_t;
typedef __fsfilcnt_t fsfilcnt_t;
typedef unsigned long int pthread_t;
union pthread_attr_t {
    char __size[56];
    long int __align;
};
typedef union pthread_attr_t pthread_attr_t;
typedef struct __pthread_internal_list {
    struct __pthread_internal_list *__prev;
    struct __pthread_internal_list *__next;
} __pthread_list_t;
typedef union {
    struct __pthread_mutex_s {
        int __lock;
        unsigned int __count;
        int __owner;
        unsigned int __nusers;
        int __kind;
        short __spins;
        short __elision;
        __pthread_list_t __list;
    } __data;
    char __size[40];
    long int __align;
} pthread_mutex_t;
typedef union {
    char __size[4];
    int __align;
} pthread_mutexattr_t;
typedef union {
    struct {
        int __lock;
        unsigned int __futex;
        __extension__ unsigned long long int __total_seq;
        __extension__ unsigned long long int __wakeup_seq;
        __extension__ unsigned long long int __woken_seq;
        void *__mutex;
        unsigned int __nwaiters;
        unsigned int __broadcast_seq;
    } __data;
    char __size[48];
    __extension__ long long int __align;
} pthread_cond_t;
typedef union {
    char __size[4];
    int __align;
} pthread_condattr_t;
typedef unsigned int pthread_key_t;
typedef int pthread_once_t;
typedef union {
    struct {
        int __lock;
        unsigned int __nr_readers;
        unsigned int __readers_wakeup;
        unsigned int __writer_wakeup;
        unsigned int __nr_readers_queued;
        unsigned int __nr_writers_queued;
        int __writer;
        int __shared;
        unsigned long int __pad1;
        unsigned long int __pad2;
        unsigned int __flags;
    } __data;
    char __size[56];
    long int __align;
} pthread_rwlock_t;
typedef union {
    char __size[8];
    long int __align;
} pthread_rwlockattr_t;
typedef volatile int pthread_spinlock_t;
typedef union {
    char __size[32];
    long int __align;
} pthread_barrier_t;
typedef union {
    char __size[4];
    int __align;
} pthread_barrierattr_t;

struct iovec {
    void *iov_base;
    size_t iov_len;
};
extern ssize_t readv(int __fd, const struct iovec *__iovec, int __count);
extern ssize_t writev(int __fd, const struct iovec *__iovec, int __count);
extern ssize_t preadv(int __fd, const struct iovec *__iovec, int __count,
                      __off_t __offset);
extern ssize_t pwritev(int __fd, const struct iovec *__iovec, int __count,
                       __off_t __offset);

typedef __socklen_t socklen_t;
enum __socket_type {
    SOCK_STREAM = 1,
    SOCK_DGRAM = 2,
    SOCK_RAW = 3,
    SOCK_RDM = 4,
    SOCK_SEQPACKET = 5,
    SOCK_DCCP = 6,
    SOCK_PACKET = 10,
    SOCK_CLOEXEC = 02000000,
    SOCK_NONBLOCK = 00004000
};
typedef unsigned short int sa_family_t;
struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};
struct sockaddr_storage {
    sa_family_t ss_family;
    unsigned long int __ss_align;
    char __ss_padding[(128 - (2 * sizeof(unsigned long int)))];
};
enum {
    MSG_OOB = 0x01,
    MSG_PEEK = 0x02,
    MSG_DONTROUTE = 0x04,
    MSG_CTRUNC = 0x08,
    MSG_PROXY = 0x10,
    MSG_TRUNC = 0x20,
    MSG_DONTWAIT = 0x40,
    MSG_EOR = 0x80,
    MSG_WAITALL = 0x100,
    MSG_FIN = 0x200,
    MSG_SYN = 0x400,
    MSG_CONFIRM = 0x800,
    MSG_RST = 0x1000,
    MSG_ERRQUEUE = 0x2000,
    MSG_NOSIGNAL = 0x4000,
    MSG_MORE = 0x8000,
    MSG_WAITFORONE = 0x10000,
    MSG_FASTOPEN = 0x20000000,
    MSG_CMSG_CLOEXEC = 0x40000000
};
struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};
struct cmsghdr {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
    __extension__ unsigned char __cmsg_data[];
};
extern struct cmsghdr *__cmsg_nxthdr(struct msghdr *__mhdr,
                                     struct cmsghdr *__cmsg)
    __attribute__((__nothrow__, __leaf__));
enum { SCM_RIGHTS = 0x01 };
struct linger {
    int l_onoff;
    int l_linger;
};
struct osockaddr {
    unsigned short int sa_family;
    unsigned char sa_data[14];
};
enum { SHUT_RD = 0, SHUT_WR, SHUT_RDWR };
extern int socket(int __domain, int __type, int __protocol)
    __attribute__((__nothrow__, __leaf__));
extern int socketpair(int __domain, int __type, int __protocol, int __fds[2])
    __attribute__((__nothrow__, __leaf__));
extern int bind(int __fd, const struct sockaddr *__addr, socklen_t __len)
    __attribute__((__nothrow__, __leaf__));
extern int getsockname(int __fd, struct sockaddr *__restrict __addr,
                       socklen_t *__restrict __len)
    __attribute__((__nothrow__, __leaf__));
extern int connect(int __fd, const struct sockaddr *__addr, socklen_t __len);
extern int getpeername(int __fd, struct sockaddr *__restrict __addr,
                       socklen_t *__restrict __len)
    __attribute__((__nothrow__, __leaf__));
extern ssize_t send(int __fd, const void *__buf, size_t __n, int __flags);
extern ssize_t recv(int __fd, void *__buf, size_t __n, int __flags);
extern ssize_t sendto(int __fd, const void *__buf, size_t __n, int __flags,
                      const struct sockaddr *__addr, socklen_t __addr_len);
extern ssize_t recvfrom(int __fd, void *__restrict __buf, size_t __n,
                        int __flags, struct sockaddr *__restrict __addr,
                        socklen_t *__restrict __addr_len);
extern ssize_t sendmsg(int __fd, const struct msghdr *__message, int __flags);
extern ssize_t recvmsg(int __fd, struct msghdr *__message, int __flags);
extern int getsockopt(int __fd, int __level, int __optname,
                      void *__restrict __optval, socklen_t *__restrict __optlen)
    __attribute__((__nothrow__, __leaf__));
extern int setsockopt(int __fd, int __level, int __optname,
                      const void *__optval, socklen_t __optlen)
    __attribute__((__nothrow__, __leaf__));
extern int listen(int __fd, int __n) __attribute__((__nothrow__, __leaf__));
extern int accept(int __fd, struct sockaddr *__restrict __addr,
                  socklen_t *__restrict __addr_len);
extern int shutdown(int __fd, int __how) __attribute__((__nothrow__, __leaf__));
extern int sockatmark(int __fd) __attribute__((__nothrow__, __leaf__));
extern int isfdtype(int __fd, int __fdtype)
    __attribute__((__nothrow__, __leaf__));

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};
typedef struct timezone *__restrict __timezone_ptr_t;
extern int gettimeofday(struct timeval *__restrict __tv, __timezone_ptr_t __tz)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern int settimeofday(const struct timeval *__tv, const struct timezone *__tz)
    __attribute__((__nothrow__, __leaf__));
extern int adjtime(const struct timeval *__delta, struct timeval *__olddelta)
    __attribute__((__nothrow__, __leaf__));
enum __itimer_which { ITIMER_REAL = 0, ITIMER_VIRTUAL = 1, ITIMER_PROF = 2 };
struct itimerval {
    struct timeval it_interval;
    struct timeval it_value;
};
typedef int __itimer_which_t;
extern int getitimer(__itimer_which_t __which, struct itimerval *__value)
    __attribute__((__nothrow__, __leaf__));
extern int setitimer(__itimer_which_t __which,
                     const struct itimerval *__restrict __new,
                     struct itimerval *__restrict __old)
    __attribute__((__nothrow__, __leaf__));
extern int utimes(const char *__file, const struct timeval __tvp[2])
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern int lutimes(const char *__file, const struct timeval __tvp[2])
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern int futimes(int __fd, const struct timeval __tvp[2])
    __attribute__((__nothrow__, __leaf__));

typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long int uint64_t;
typedef signed char int_least8_t;
typedef short int int_least16_t;
typedef int int_least32_t;
typedef long int int_least64_t;
typedef unsigned char uint_least8_t;
typedef unsigned short int uint_least16_t;
typedef unsigned int uint_least32_t;
typedef unsigned long int uint_least64_t;
typedef signed char int_fast8_t;
typedef long int int_fast16_t;
typedef long int int_fast32_t;
typedef long int int_fast64_t;
typedef unsigned char uint_fast8_t;
typedef unsigned long int uint_fast16_t;
typedef unsigned long int uint_fast32_t;
typedef unsigned long int uint_fast64_t;
typedef long int intptr_t;
typedef unsigned long int uintptr_t;
typedef long int intmax_t;
typedef unsigned long int uintmax_t;
typedef long int ptrdiff_t;
typedef int wchar_t;
typedef __builtin_va_list __gnuc_va_list;
typedef __gnuc_va_list va_list;

typedef uint32_t in_addr_t;
struct in_addr {
    in_addr_t s_addr;
};
struct ip_opts {
    struct in_addr ip_dst;
    char ip_opts[40];
};
struct ip_mreqn {
    struct in_addr imr_multiaddr;
    struct in_addr imr_address;
    int imr_ifindex;
};
struct in_pktinfo {
    int ipi_ifindex;
    struct in_addr ipi_spec_dst;
    struct in_addr ipi_addr;
};
enum {
    IPPROTO_IP = 0,
    IPPROTO_ICMP = 1,
    IPPROTO_IGMP = 2,
    IPPROTO_IPIP = 4,
    IPPROTO_TCP = 6,
    IPPROTO_EGP = 8,
    IPPROTO_PUP = 12,
    IPPROTO_UDP = 17,
    IPPROTO_IDP = 22,
    IPPROTO_TP = 29,
    IPPROTO_DCCP = 33,
    IPPROTO_IPV6 = 41,
    IPPROTO_RSVP = 46,
    IPPROTO_GRE = 47,
    IPPROTO_ESP = 50,
    IPPROTO_AH = 51,
    IPPROTO_MTP = 92,
    IPPROTO_BEETPH = 94,
    IPPROTO_ENCAP = 98,
    IPPROTO_PIM = 103,
    IPPROTO_COMP = 108,
    IPPROTO_SCTP = 132,
    IPPROTO_UDPLITE = 136,
    IPPROTO_RAW = 255,
    IPPROTO_MAX
};
enum {
    IPPROTO_HOPOPTS = 0,
    IPPROTO_ROUTING = 43,
    IPPROTO_FRAGMENT = 44,
    IPPROTO_ICMPV6 = 58,
    IPPROTO_NONE = 59,
    IPPROTO_DSTOPTS = 60,
    IPPROTO_MH = 135
};
typedef uint16_t in_port_t;
enum {
    IPPORT_ECHO = 7,
    IPPORT_DISCARD = 9,
    IPPORT_SYSTAT = 11,
    IPPORT_DAYTIME = 13,
    IPPORT_NETSTAT = 15,
    IPPORT_FTP = 21,
    IPPORT_TELNET = 23,
    IPPORT_SMTP = 25,
    IPPORT_TIMESERVER = 37,
    IPPORT_NAMESERVER = 42,
    IPPORT_WHOIS = 43,
    IPPORT_MTP = 57,
    IPPORT_TFTP = 69,
    IPPORT_RJE = 77,
    IPPORT_FINGER = 79,
    IPPORT_TTYLINK = 87,
    IPPORT_SUPDUP = 95,
    IPPORT_EXECSERVER = 512,
    IPPORT_LOGINSERVER = 513,
    IPPORT_CMDSERVER = 514,
    IPPORT_EFSSERVER = 520,
    IPPORT_BIFFUDP = 512,
    IPPORT_WHOSERVER = 513,
    IPPORT_ROUTESERVER = 520,
    IPPORT_RESERVED = 1024,
    IPPORT_USERRESERVED = 5000
};
struct in6_addr {
    union {
        uint8_t __u6_addr8[16];
        uint16_t __u6_addr16[8];
        uint32_t __u6_addr32[4];
    } __in6_u;
};
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;
struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[sizeof(struct sockaddr) -
                           (sizeof(unsigned short int)) - sizeof(in_port_t) -
                           sizeof(struct in_addr)];
};
struct sockaddr_in6 {
    sa_family_t sin6_family;
    in_port_t sin6_port;
    uint32_t sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};
struct ip_mreq {
    struct in_addr imr_multiaddr;
    struct in_addr imr_interface;
};
struct ip_mreq_source {
    struct in_addr imr_multiaddr;
    struct in_addr imr_interface;
    struct in_addr imr_sourceaddr;
};
struct ipv6_mreq {
    struct in6_addr ipv6mr_multiaddr;
    unsigned int ipv6mr_interface;
};
struct group_req {
    uint32_t gr_interface;
    struct sockaddr_storage gr_group;
};
struct group_source_req {
    uint32_t gsr_interface;
    struct sockaddr_storage gsr_group;
    struct sockaddr_storage gsr_source;
};
struct ip_msfilter {
    struct in_addr imsf_multiaddr;
    struct in_addr imsf_interface;
    uint32_t imsf_fmode;
    uint32_t imsf_numsrc;
    struct in_addr imsf_slist[1];
};
struct group_filter {
    uint32_t gf_interface;
    struct sockaddr_storage gf_group;
    uint32_t gf_fmode;
    uint32_t gf_numsrc;
    struct sockaddr_storage gf_slist[1];
};
extern uint32_t ntohl(uint32_t __netlong) __attribute__((__nothrow__, __leaf__))
__attribute__((__const__));
extern uint16_t ntohs(uint16_t __netshort)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__const__));
extern uint32_t htonl(uint32_t __hostlong)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__const__));
extern uint16_t htons(uint16_t __hostshort)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__const__));
extern int bindresvport(int __sockfd, struct sockaddr_in *__sock_in)
    __attribute__((__nothrow__, __leaf__));
extern int bindresvport6(int __sockfd, struct sockaddr_in6 *__sock_in)
    __attribute__((__nothrow__, __leaf__));

struct rpcent {
    char *r_name;
    char **r_aliases;
    int r_number;
};
extern void setrpcent(int __stayopen) __attribute__((__nothrow__, __leaf__));
extern void endrpcent(void) __attribute__((__nothrow__, __leaf__));
extern struct rpcent *getrpcbyname(const char *__name)
    __attribute__((__nothrow__, __leaf__));
extern struct rpcent *getrpcbynumber(int __number)
    __attribute__((__nothrow__, __leaf__));
extern struct rpcent *getrpcent(void) __attribute__((__nothrow__, __leaf__));
extern int getrpcbyname_r(const char *__name, struct rpcent *__result_buf,
                          char *__buffer, size_t __buflen,
                          struct rpcent **__result)
    __attribute__((__nothrow__, __leaf__));
extern int getrpcbynumber_r(int __number, struct rpcent *__result_buf,
                            char *__buffer, size_t __buflen,
                            struct rpcent **__result)
    __attribute__((__nothrow__, __leaf__));
extern int getrpcent_r(struct rpcent *__result_buf, char *__buffer,
                       size_t __buflen, struct rpcent **__result)
    __attribute__((__nothrow__, __leaf__));

struct netent {
    char *n_name;
    char **n_aliases;
    int n_addrtype;
    uint32_t n_net;
};

extern int *__h_errno_location(void) __attribute__((__nothrow__, __leaf__))
__attribute__((__const__));
extern void herror(const char *__str) __attribute__((__nothrow__, __leaf__));
extern const char *hstrerror(int __err_num)
    __attribute__((__nothrow__, __leaf__));
struct hostent {
    char *h_name;
    char **h_aliases;
    int h_addrtype;
    int h_length;
    char **h_addr_list;
};
extern void sethostent(int __stay_open);
extern void endhostent(void);
extern struct hostent *gethostent(void);
extern struct hostent *gethostbyaddr(const void *__addr, __socklen_t __len,
                                     int __type);
extern struct hostent *gethostbyname(const char *__name);
extern struct hostent *gethostbyname2(const char *__name, int __af);
extern int gethostent_r(struct hostent *__restrict __result_buf,
                        char *__restrict __buf, size_t __buflen,
                        struct hostent **__restrict __result,
                        int *__restrict __h_errnop);
extern int gethostbyaddr_r(const void *__restrict __addr, __socklen_t __len,
                           int __type, struct hostent *__restrict __result_buf,
                           char *__restrict __buf, size_t __buflen,
                           struct hostent **__restrict __result,
                           int *__restrict __h_errnop);
extern int gethostbyname_r(const char *__restrict __name,
                           struct hostent *__restrict __result_buf,
                           char *__restrict __buf, size_t __buflen,
                           struct hostent **__restrict __result,
                           int *__restrict __h_errnop);
extern int gethostbyname2_r(const char *__restrict __name, int __af,
                            struct hostent *__restrict __result_buf,
                            char *__restrict __buf, size_t __buflen,
                            struct hostent **__restrict __result,
                            int *__restrict __h_errnop);
extern void setnetent(int __stay_open);
extern void endnetent(void);
extern struct netent *getnetent(void);
extern struct netent *getnetbyaddr(uint32_t __net, int __type);
extern struct netent *getnetbyname(const char *__name);
extern int getnetent_r(struct netent *__restrict __result_buf,
                       char *__restrict __buf, size_t __buflen,
                       struct netent **__restrict __result,
                       int *__restrict __h_errnop);
extern int getnetbyaddr_r(uint32_t __net, int __type,
                          struct netent *__restrict __result_buf,
                          char *__restrict __buf, size_t __buflen,
                          struct netent **__restrict __result,
                          int *__restrict __h_errnop);
extern int getnetbyname_r(const char *__restrict __name,
                          struct netent *__restrict __result_buf,
                          char *__restrict __buf, size_t __buflen,
                          struct netent **__restrict __result,
                          int *__restrict __h_errnop);
struct servent {
    char *s_name;
    char **s_aliases;
    int s_port;
    char *s_proto;
};
extern void setservent(int __stay_open);
extern void endservent(void);
extern struct servent *getservent(void);
extern struct servent *getservbyname(const char *__name, const char *__proto);
extern struct servent *getservbyport(int __port, const char *__proto);
extern int getservent_r(struct servent *__restrict __result_buf,
                        char *__restrict __buf, size_t __buflen,
                        struct servent **__restrict __result);
extern int getservbyname_r(const char *__restrict __name,
                           const char *__restrict __proto,
                           struct servent *__restrict __result_buf,
                           char *__restrict __buf, size_t __buflen,
                           struct servent **__restrict __result);
extern int getservbyport_r(int __port, const char *__restrict __proto,
                           struct servent *__restrict __result_buf,
                           char *__restrict __buf, size_t __buflen,
                           struct servent **__restrict __result);
struct protoent {
    char *p_name;
    char **p_aliases;
    int p_proto;
};
extern void setprotoent(int __stay_open);
extern void endprotoent(void);
extern struct protoent *getprotoent(void);
extern struct protoent *getprotobyname(const char *__name);
extern struct protoent *getprotobynumber(int __proto);
extern int getprotoent_r(struct protoent *__restrict __result_buf,
                         char *__restrict __buf, size_t __buflen,
                         struct protoent **__restrict __result);
extern int getprotobyname_r(const char *__restrict __name,
                            struct protoent *__restrict __result_buf,
                            char *__restrict __buf, size_t __buflen,
                            struct protoent **__restrict __result);
extern int getprotobynumber_r(int __proto,
                              struct protoent *__restrict __result_buf,
                              char *__restrict __buf, size_t __buflen,
                              struct protoent **__restrict __result);
extern int setnetgrent(const char *__netgroup);
extern void endnetgrent(void);
extern int getnetgrent(char **__restrict __hostp, char **__restrict __userp,
                       char **__restrict __domainp);
extern int innetgr(const char *__netgroup, const char *__host,
                   const char *__user, const char *__domain);
extern int getnetgrent_r(char **__restrict __hostp, char **__restrict __userp,
                         char **__restrict __domainp, char *__restrict __buffer,
                         size_t __buflen);
extern int rcmd(char **__restrict __ahost, unsigned short int __rport,
                const char *__restrict __locuser,
                const char *__restrict __remuser, const char *__restrict __cmd,
                int *__restrict __fd2p);
extern int rcmd_af(char **__restrict __ahost, unsigned short int __rport,
                   const char *__restrict __locuser,
                   const char *__restrict __remuser,
                   const char *__restrict __cmd, int *__restrict __fd2p,
                   sa_family_t __af);
extern int rexec(char **__restrict __ahost, int __rport,
                 const char *__restrict __name, const char *__restrict __pass,
                 const char *__restrict __cmd, int *__restrict __fd2p);
extern int rexec_af(char **__restrict __ahost, int __rport,
                    const char *__restrict __name,
                    const char *__restrict __pass, const char *__restrict __cmd,
                    int *__restrict __fd2p, sa_family_t __af);
extern int ruserok(const char *__rhost, int __suser, const char *__remuser,
                   const char *__locuser);
extern int ruserok_af(const char *__rhost, int __suser, const char *__remuser,
                      const char *__locuser, sa_family_t __af);
extern int iruserok(uint32_t __raddr, int __suser, const char *__remuser,
                    const char *__locuser);
extern int iruserok_af(const void *__raddr, int __suser, const char *__remuser,
                       const char *__locuser, sa_family_t __af);
extern int rresvport(int *__alport);
extern int rresvport_af(int *__alport, sa_family_t __af);
struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};
extern int getaddrinfo(const char *__restrict __name,
                       const char *__restrict __service,
                       const struct addrinfo *__restrict __req,
                       struct addrinfo **__restrict __pai);
extern void freeaddrinfo(struct addrinfo *__ai)
    __attribute__((__nothrow__, __leaf__));
extern const char *gai_strerror(int __ecode)
    __attribute__((__nothrow__, __leaf__));
extern int getnameinfo(const struct sockaddr *__restrict __sa,
                       socklen_t __salen, char *__restrict __host,
                       socklen_t __hostlen, char *__restrict __serv,
                       socklen_t __servlen, int __flags);

int evutil_socketpair(int d, int type, int protocol, int sv[2]);
int evutil_make_socket_nonblocking(int sock);
int evutil_make_listen_socket_reuseable(int sock);
int evutil_make_socket_closeonexec(int sock);
int evutil_closesocket(int sock);
int64_t evutil_strtoll(const char *s, char **endptr, int base);
int evutil_snprintf(char *buf, size_t buflen, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
int evutil_vsnprintf(char *buf, size_t buflen, const char *format, va_list ap)
    __attribute__((format(printf, 3, 0)));
const char *evutil_inet_ntop(int af, const void *src, char *dst, size_t len);
int evutil_inet_pton(int af, const char *src, void *dst);
struct sockaddr;
int evutil_parse_sockaddr_port(const char *str, struct sockaddr *out,
                               int *outlen);
int evutil_sockaddr_cmp(const struct sockaddr *sa1, const struct sockaddr *sa2,
                        int include_port);
int evutil_ascii_strcasecmp(const char *str1, const char *str2);
int evutil_ascii_strncasecmp(const char *str1, const char *str2, size_t n);
struct addrinfo;
int evutil_getaddrinfo(const char *nodename, const char *servname,
                       const struct addrinfo *hints_in, struct addrinfo **res);
void evutil_freeaddrinfo(struct addrinfo *ai);
const char *evutil_gai_strerror(int err);
void evutil_secure_rng_get_bytes(void *buf, size_t n);
int evutil_secure_rng_init(void);
void evutil_secure_rng_add_bytes(const char *dat, size_t datlen);
typedef int (*nat_lookup_cb_t)(struct sockaddr *, socklen_t *, int,
                               struct sockaddr *, socklen_t);
typedef int (*nat_socket_cb_t)(int);
int nat_exist(const char *) __attribute__((warn_unused_result));
int nat_used(const char *) __attribute__((warn_unused_result));
nat_lookup_cb_t nat_getlookupcb(const char *)
    __attribute__((warn_unused_result));
nat_socket_cb_t nat_getsocketcb(const char *)
    __attribute__((warn_unused_result));
int nat_ipv6ready(const char *) __attribute__((warn_unused_result));
const char *nat_getdefaultname(void) __attribute__((warn_unused_result));
void nat_list_engines(void);
int nat_preinit(void) __attribute__((warn_unused_result));
int nat_init(void) __attribute__((warn_unused_result));
void nat_fini(void);
void nat_version(void);

typedef enum { P_ALL, P_PID, P_PGID } idtype_t;
union wait {
    int w_status;
    struct {
        unsigned int __w_termsig : 7;
        unsigned int __w_coredump : 1;
        unsigned int __w_retcode : 8;
        unsigned int : 16;
    } __wait_terminated;
    struct {
        unsigned int __w_stopval : 8;
        unsigned int __w_stopsig : 8;
        unsigned int : 16;
    } __wait_stopped;
};
typedef union {
    union wait *__uptr;
    int *__iptr;
} __WAIT_STATUS __attribute__((__transparent_union__));

typedef struct {
    int quot;
    int rem;
} div_t;
typedef struct {
    long int quot;
    long int rem;
} ldiv_t;

__extension__ typedef struct {
    long long int quot;
    long long int rem;
} lldiv_t;

extern size_t __ctype_get_mb_cur_max(void)
    __attribute__((__nothrow__, __leaf__));

extern double atof(const char *__nptr) __attribute__((__nothrow__, __leaf__))
__attribute__((__pure__)) __attribute__((__nonnull__(1)));
extern int atoi(const char *__nptr) __attribute__((__nothrow__, __leaf__))
__attribute__((__pure__)) __attribute__((__nonnull__(1)));
extern long int atol(const char *__nptr) __attribute__((__nothrow__, __leaf__))
__attribute__((__pure__)) __attribute__((__nonnull__(1)));

__extension__ extern long long int atoll(const char *__nptr)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1)));

extern double strtod(const char *__restrict __nptr, char **__restrict __endptr)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));

extern float strtof(const char *__restrict __nptr, char **__restrict __endptr)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern long double strtold(const char *__restrict __nptr,
                           char **__restrict __endptr)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));

extern long int strtol(const char *__restrict __nptr,
                       char **__restrict __endptr, int __base)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern unsigned long int strtoul(const char *__restrict __nptr,
                                 char **__restrict __endptr, int __base)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));

__extension__ extern long long int strtoq(const char *__restrict __nptr,
                                          char **__restrict __endptr,
                                          int __base)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
__extension__ extern unsigned long long int strtouq(
    const char *__restrict __nptr, char **__restrict __endptr, int __base)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));

__extension__ extern long long int strtoll(const char *__restrict __nptr,
                                           char **__restrict __endptr,
                                           int __base)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
__extension__ extern unsigned long long int strtoull(
    const char *__restrict __nptr, char **__restrict __endptr, int __base)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));

extern char *l64a(long int __n) __attribute__((__nothrow__, __leaf__));
extern long int a64l(const char *__s) __attribute__((__nothrow__, __leaf__))
__attribute__((__pure__)) __attribute__((__nonnull__(1)));
extern long int random(void) __attribute__((__nothrow__, __leaf__));
extern void srandom(unsigned int __seed) __attribute__((__nothrow__, __leaf__));
extern char *initstate(unsigned int __seed, char *__statebuf, size_t __statelen)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(2)));
extern char *setstate(char *__statebuf) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1)));
struct random_data {
    int32_t *fptr;
    int32_t *rptr;
    int32_t *state;
    int rand_type;
    int rand_deg;
    int rand_sep;
    int32_t *end_ptr;
};
extern int random_r(struct random_data *__restrict __buf,
                    int32_t *__restrict __result)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern int srandom_r(unsigned int __seed, struct random_data *__buf)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(2)));
extern int initstate_r(unsigned int __seed, char *__restrict __statebuf,
                       size_t __statelen, struct random_data *__restrict __buf)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(2, 4)));
extern int setstate_r(char *__restrict __statebuf,
                      struct random_data *__restrict __buf)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));

extern int rand(void) __attribute__((__nothrow__, __leaf__));
extern void srand(unsigned int __seed) __attribute__((__nothrow__, __leaf__));

extern int rand_r(unsigned int *__seed) __attribute__((__nothrow__, __leaf__));
extern double drand48(void) __attribute__((__nothrow__, __leaf__));
extern double erand48(unsigned short int __xsubi[3])
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern long int lrand48(void) __attribute__((__nothrow__, __leaf__));
extern long int nrand48(unsigned short int __xsubi[3])
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern long int mrand48(void) __attribute__((__nothrow__, __leaf__));
extern long int jrand48(unsigned short int __xsubi[3])
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern void srand48(long int __seedval) __attribute__((__nothrow__, __leaf__));
extern unsigned short int *seed48(unsigned short int __seed16v[3])
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern void lcong48(unsigned short int __param[7])
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
struct drand48_data {
    unsigned short int __x[3];
    unsigned short int __old_x[3];
    unsigned short int __c;
    unsigned short int __init;
    __extension__ unsigned long long int __a;
};
extern int drand48_r(struct drand48_data *__restrict __buffer,
                     double *__restrict __result)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern int erand48_r(unsigned short int __xsubi[3],
                     struct drand48_data *__restrict __buffer,
                     double *__restrict __result)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern int lrand48_r(struct drand48_data *__restrict __buffer,
                     long int *__restrict __result)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern int nrand48_r(unsigned short int __xsubi[3],
                     struct drand48_data *__restrict __buffer,
                     long int *__restrict __result)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern int mrand48_r(struct drand48_data *__restrict __buffer,
                     long int *__restrict __result)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern int jrand48_r(unsigned short int __xsubi[3],
                     struct drand48_data *__restrict __buffer,
                     long int *__restrict __result)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern int srand48_r(long int __seedval, struct drand48_data *__buffer)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(2)));
extern int seed48_r(unsigned short int __seed16v[3],
                    struct drand48_data *__buffer)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern int lcong48_r(unsigned short int __param[7],
                     struct drand48_data *__buffer)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));

extern void *malloc(size_t __size) __attribute__((__nothrow__, __leaf__))
__attribute__((__malloc__));
extern void *calloc(size_t __nmemb, size_t __size)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__malloc__));

extern void *realloc(void *__ptr, size_t __size)
    __attribute__((__nothrow__, __leaf__))
    __attribute__((__warn_unused_result__));
extern void free(void *__ptr) __attribute__((__nothrow__, __leaf__));

extern void cfree(void *__ptr) __attribute__((__nothrow__, __leaf__));

extern void *alloca(size_t __size) __attribute__((__nothrow__, __leaf__));

extern void *valloc(size_t __size) __attribute__((__nothrow__, __leaf__))
__attribute__((__malloc__));
extern int posix_memalign(void **__memptr, size_t __alignment, size_t __size)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));

extern void abort(void) __attribute__((__nothrow__, __leaf__))
__attribute__((__noreturn__));
extern int atexit(void (*__func)(void)) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1)));

extern int on_exit(void (*__func)(int __status, void *__arg), void *__arg)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));

extern void exit(int __status) __attribute__((__nothrow__, __leaf__))
__attribute__((__noreturn__));

extern void _Exit(int __status) __attribute__((__nothrow__, __leaf__))
__attribute__((__noreturn__));

extern char *getenv(const char *__name) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1)));

extern int putenv(char *__string) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1)));
extern int setenv(const char *__name, const char *__value, int __replace)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(2)));
extern int unsetenv(const char *__name) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1)));
extern int clearenv(void) __attribute__((__nothrow__, __leaf__));
extern char *mktemp(char *__template) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1)));
extern int mkstemp(char *__template) __attribute__((__nonnull__(1)));
extern int mkstemps(char *__template, int __suffixlen)
    __attribute__((__nonnull__(1)));
extern char *mkdtemp(char *__template) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1)));

extern int system(const char *__command);

extern char *realpath(const char *__restrict __name,
                      char *__restrict __resolved)
    __attribute__((__nothrow__, __leaf__));
typedef int (*__compar_fn_t)(const void *, const void *);

extern void *bsearch(const void *__key, const void *__base, size_t __nmemb,
                     size_t __size, __compar_fn_t __compar)
    __attribute__((__nonnull__(1, 2, 5)));
extern void qsort(void *__base, size_t __nmemb, size_t __size,
                  __compar_fn_t __compar) __attribute__((__nonnull__(1, 4)));
extern int abs(int __x) __attribute__((__nothrow__, __leaf__))
__attribute__((__const__));
extern long int labs(long int __x) __attribute__((__nothrow__, __leaf__))
__attribute__((__const__));

__extension__ extern long long int llabs(long long int __x)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__const__));

extern div_t div(int __numer, int __denom)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__const__));
extern ldiv_t ldiv(long int __numer, long int __denom)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__const__));

__extension__ extern lldiv_t lldiv(long long int __numer, long long int __denom)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__const__));

extern char *ecvt(double __value, int __ndigit, int *__restrict __decpt,
                  int *__restrict __sign) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(3, 4)));
extern char *fcvt(double __value, int __ndigit, int *__restrict __decpt,
                  int *__restrict __sign) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(3, 4)));
extern char *gcvt(double __value, int __ndigit, char *__buf)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(3)));
extern char *qecvt(long double __value, int __ndigit, int *__restrict __decpt,
                   int *__restrict __sign)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(3, 4)));
extern char *qfcvt(long double __value, int __ndigit, int *__restrict __decpt,
                   int *__restrict __sign)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(3, 4)));
extern char *qgcvt(long double __value, int __ndigit, char *__buf)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(3)));
extern int ecvt_r(double __value, int __ndigit, int *__restrict __decpt,
                  int *__restrict __sign, char *__restrict __buf, size_t __len)
    __attribute__((__nothrow__, __leaf__))
    __attribute__((__nonnull__(3, 4, 5)));
extern int fcvt_r(double __value, int __ndigit, int *__restrict __decpt,
                  int *__restrict __sign, char *__restrict __buf, size_t __len)
    __attribute__((__nothrow__, __leaf__))
    __attribute__((__nonnull__(3, 4, 5)));
extern int qecvt_r(long double __value, int __ndigit, int *__restrict __decpt,
                   int *__restrict __sign, char *__restrict __buf, size_t __len)
    __attribute__((__nothrow__, __leaf__))
    __attribute__((__nonnull__(3, 4, 5)));
extern int qfcvt_r(long double __value, int __ndigit, int *__restrict __decpt,
                   int *__restrict __sign, char *__restrict __buf, size_t __len)
    __attribute__((__nothrow__, __leaf__))
    __attribute__((__nonnull__(3, 4, 5)));

extern int mblen(const char *__s, size_t __n)
    __attribute__((__nothrow__, __leaf__));
extern int mbtowc(wchar_t *__restrict __pwc, const char *__restrict __s,
                  size_t __n) __attribute__((__nothrow__, __leaf__));
extern int wctomb(char *__s, wchar_t __wchar)
    __attribute__((__nothrow__, __leaf__));
extern size_t mbstowcs(wchar_t *__restrict __pwcs, const char *__restrict __s,
                       size_t __n) __attribute__((__nothrow__, __leaf__));
extern size_t wcstombs(char *__restrict __s, const wchar_t *__restrict __pwcs,
                       size_t __n) __attribute__((__nothrow__, __leaf__));

extern int rpmatch(const char *__response)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern int getsubopt(char **__restrict __optionp,
                     char *const *__restrict __tokens,
                     char **__restrict __valuep)
    __attribute__((__nothrow__, __leaf__))
    __attribute__((__nonnull__(1, 2, 3)));
extern int getloadavg(double __loadavg[], int __nelem)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));

struct _IO_FILE;

typedef struct _IO_FILE FILE;

typedef struct _IO_FILE __FILE;
typedef struct {
    int __count;
    union {
        unsigned int __wch;
        char __wchb[4];
    } __value;
} __mbstate_t;
typedef struct {
    __off_t __pos;
    __mbstate_t __state;
} _G_fpos_t;
typedef struct {
    __off64_t __pos;
    __mbstate_t __state;
} _G_fpos64_t;
struct _IO_jump_t;
struct _IO_FILE;
typedef void _IO_lock_t;
struct _IO_marker {
    struct _IO_marker *_next;
    struct _IO_FILE *_sbuf;
    int _pos;
};
enum __codecvt_result {
    __codecvt_ok,
    __codecvt_partial,
    __codecvt_error,
    __codecvt_noconv
};
struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    unsigned short _cur_column;
    signed char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    void *__pad1;
    void *__pad2;
    void *__pad3;
    void *__pad4;
    size_t __pad5;
    int _mode;
    char _unused2[15 * sizeof(int) - 4 * sizeof(void *) - sizeof(size_t)];
};
typedef struct _IO_FILE _IO_FILE;
struct _IO_FILE_plus;
extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;
typedef __ssize_t __io_read_fn(void *__cookie, char *__buf, size_t __nbytes);
typedef __ssize_t __io_write_fn(void *__cookie, const char *__buf, size_t __n);
typedef int __io_seek_fn(void *__cookie, __off64_t *__pos, int __w);
typedef int __io_close_fn(void *__cookie);
typedef __io_read_fn cookie_read_function_t;
typedef __io_write_fn cookie_write_function_t;
typedef __io_seek_fn cookie_seek_function_t;
typedef __io_close_fn cookie_close_function_t;
typedef struct {
    __io_read_fn *read;
    __io_write_fn *write;
    __io_seek_fn *seek;
    __io_close_fn *close;
} _IO_cookie_io_functions_t;
typedef _IO_cookie_io_functions_t cookie_io_functions_t;
struct _IO_cookie_file;
extern void _IO_cookie_init(struct _IO_cookie_file *__cfile, int __read_write,
                            void *__cookie, _IO_cookie_io_functions_t __fns);
extern int __underflow(_IO_FILE *);
extern int __uflow(_IO_FILE *);
extern int __overflow(_IO_FILE *, int);
extern int _IO_getc(_IO_FILE *__fp);
extern int _IO_putc(int __c, _IO_FILE *__fp);
extern int _IO_feof(_IO_FILE *__fp) __attribute__((__nothrow__, __leaf__));
extern int _IO_ferror(_IO_FILE *__fp) __attribute__((__nothrow__, __leaf__));
extern int _IO_peekc_locked(_IO_FILE *__fp);
extern void _IO_flockfile(_IO_FILE *) __attribute__((__nothrow__, __leaf__));
extern void _IO_funlockfile(_IO_FILE *) __attribute__((__nothrow__, __leaf__));
extern int _IO_ftrylockfile(_IO_FILE *) __attribute__((__nothrow__, __leaf__));
extern int _IO_vfscanf(_IO_FILE *__restrict, const char *__restrict,
                       __gnuc_va_list, int *__restrict);
extern int _IO_vfprintf(_IO_FILE *__restrict, const char *__restrict,
                        __gnuc_va_list);
extern __ssize_t _IO_padn(_IO_FILE *, int, __ssize_t);
extern size_t _IO_sgetn(_IO_FILE *, void *, size_t);
extern __off64_t _IO_seekoff(_IO_FILE *, __off64_t, int, int);
extern __off64_t _IO_seekpos(_IO_FILE *, __off64_t, int);
extern void _IO_free_backup_area(_IO_FILE *)
    __attribute__((__nothrow__, __leaf__));

typedef _G_fpos_t fpos_t;

extern struct _IO_FILE *stdin;
extern struct _IO_FILE *stdout;
extern struct _IO_FILE *stderr;

extern int remove(const char *__filename)
    __attribute__((__nothrow__, __leaf__));
extern int rename(const char *__old, const char *__new)
    __attribute__((__nothrow__, __leaf__));

extern int renameat(int __oldfd, const char *__old, int __newfd,
                    const char *__new) __attribute__((__nothrow__, __leaf__));

extern FILE *tmpfile(void);
extern char *tmpnam(char *__s) __attribute__((__nothrow__, __leaf__));

extern char *tmpnam_r(char *__s) __attribute__((__nothrow__, __leaf__));
extern char *tempnam(const char *__dir, const char *__pfx)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__malloc__));

extern int fclose(FILE *__stream);
extern int fflush(FILE *__stream);

extern int fflush_unlocked(FILE *__stream);

extern FILE *fopen(const char *__restrict __filename,
                   const char *__restrict __modes);
extern FILE *freopen(const char *__restrict __filename,
                     const char *__restrict __modes, FILE *__restrict __stream);

extern FILE *fdopen(int __fd, const char *__modes)
    __attribute__((__nothrow__, __leaf__));
extern FILE *fmemopen(void *__s, size_t __len, const char *__modes)
    __attribute__((__nothrow__, __leaf__));
extern FILE *open_memstream(char **__bufloc, size_t *__sizeloc)
    __attribute__((__nothrow__, __leaf__));

extern void setbuf(FILE *__restrict __stream, char *__restrict __buf)
    __attribute__((__nothrow__, __leaf__));
extern int setvbuf(FILE *__restrict __stream, char *__restrict __buf,
                   int __modes, size_t __n)
    __attribute__((__nothrow__, __leaf__));

extern void setbuffer(FILE *__restrict __stream, char *__restrict __buf,
                      size_t __size) __attribute__((__nothrow__, __leaf__));
extern void setlinebuf(FILE *__stream) __attribute__((__nothrow__, __leaf__));

extern int fprintf(FILE *__restrict __stream, const char *__restrict __format,
                   ...);
extern int printf(const char *__restrict __format, ...);
extern int sprintf(char *__restrict __s, const char *__restrict __format, ...)
    __attribute__((__nothrow__));
extern int vfprintf(FILE *__restrict __s, const char *__restrict __format,
                    __gnuc_va_list __arg);
extern int vprintf(const char *__restrict __format, __gnuc_va_list __arg);
extern int vsprintf(char *__restrict __s, const char *__restrict __format,
                    __gnuc_va_list __arg) __attribute__((__nothrow__));

extern int snprintf(char *__restrict __s, size_t __maxlen,
                    const char *__restrict __format, ...)
    __attribute__((__nothrow__)) __attribute__((__format__(__printf__, 3, 4)));
extern int vsnprintf(char *__restrict __s, size_t __maxlen,
                     const char *__restrict __format, __gnuc_va_list __arg)
    __attribute__((__nothrow__)) __attribute__((__format__(__printf__, 3, 0)));

extern int vdprintf(int __fd, const char *__restrict __fmt,
                    __gnuc_va_list __arg)
    __attribute__((__format__(__printf__, 2, 0)));
extern int dprintf(int __fd, const char *__restrict __fmt, ...)
    __attribute__((__format__(__printf__, 2, 3)));

extern int fscanf(FILE *__restrict __stream, const char *__restrict __format,
                  ...);
extern int scanf(const char *__restrict __format, ...);
extern int sscanf(const char *__restrict __s, const char *__restrict __format,
                  ...) __attribute__((__nothrow__, __leaf__));
extern int
fscanf(FILE *__restrict __stream, const char *__restrict __format, ...) __asm__(
    ""
    "__isoc99_fscanf");
extern int scanf(const char *__restrict __format, ...) __asm__(
    ""
    "__isoc99_scanf");
extern int
sscanf(const char *__restrict __s, const char *__restrict __format, ...) __asm__(
    ""
    "__isoc99_sscanf") __attribute__((__nothrow__, __leaf__));

extern int vfscanf(FILE *__restrict __s, const char *__restrict __format,
                   __gnuc_va_list __arg)
    __attribute__((__format__(__scanf__, 2, 0)));
extern int vscanf(const char *__restrict __format, __gnuc_va_list __arg)
    __attribute__((__format__(__scanf__, 1, 0)));
extern int vsscanf(const char *__restrict __s, const char *__restrict __format,
                   __gnuc_va_list __arg) __attribute__((__nothrow__, __leaf__))
__attribute__((__format__(__scanf__, 2, 0)));
extern int
vfscanf(FILE *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg) __asm__(
    ""
    "__isoc99_vfscanf") __attribute__((__format__(__scanf__, 2, 0)));
extern int
vscanf(const char *__restrict __format, __gnuc_va_list __arg) __asm__(
    ""
    "__isoc99_vscanf") __attribute__((__format__(__scanf__, 1, 0)));
extern int
vsscanf(const char *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg) __asm__(
    ""
    "__isoc99_vsscanf") __attribute__((__nothrow__, __leaf__))
__attribute__((__format__(__scanf__, 2, 0)));

extern int fgetc(FILE *__stream);
extern int getc(FILE *__stream);
extern int getchar(void);

extern int getc_unlocked(FILE *__stream);
extern int getchar_unlocked(void);
extern int fgetc_unlocked(FILE *__stream);

extern int fputc(int __c, FILE *__stream);
extern int putc(int __c, FILE *__stream);
extern int putchar(int __c);

extern int fputc_unlocked(int __c, FILE *__stream);
extern int putc_unlocked(int __c, FILE *__stream);
extern int putchar_unlocked(int __c);
extern int getw(FILE *__stream);
extern int putw(int __w, FILE *__stream);

extern char *fgets(char *__restrict __s, int __n, FILE *__restrict __stream);
extern char *gets(char *__s) __attribute__((__deprecated__));

extern __ssize_t __getdelim(char **__restrict __lineptr, size_t *__restrict __n,
                            int __delimiter, FILE *__restrict __stream);
extern __ssize_t getdelim(char **__restrict __lineptr, size_t *__restrict __n,
                          int __delimiter, FILE *__restrict __stream);
extern __ssize_t getline(char **__restrict __lineptr, size_t *__restrict __n,
                         FILE *__restrict __stream);

extern int fputs(const char *__restrict __s, FILE *__restrict __stream);
extern int puts(const char *__s);
extern int ungetc(int __c, FILE *__stream);
extern size_t fread(void *__restrict __ptr, size_t __size, size_t __n,
                    FILE *__restrict __stream);
extern size_t fwrite(const void *__restrict __ptr, size_t __size, size_t __n,
                     FILE *__restrict __s);

extern size_t fread_unlocked(void *__restrict __ptr, size_t __size, size_t __n,
                             FILE *__restrict __stream);
extern size_t fwrite_unlocked(const void *__restrict __ptr, size_t __size,
                              size_t __n, FILE *__restrict __stream);

extern int fseek(FILE *__stream, long int __off, int __whence);
extern long int ftell(FILE *__stream);
extern void rewind(FILE *__stream);

extern int fseeko(FILE *__stream, __off_t __off, int __whence);
extern __off_t ftello(FILE *__stream);

extern int fgetpos(FILE *__restrict __stream, fpos_t *__restrict __pos);
extern int fsetpos(FILE *__stream, const fpos_t *__pos);

extern void clearerr(FILE *__stream) __attribute__((__nothrow__, __leaf__));
extern int feof(FILE *__stream) __attribute__((__nothrow__, __leaf__));
extern int ferror(FILE *__stream) __attribute__((__nothrow__, __leaf__));

extern void clearerr_unlocked(FILE *__stream)
    __attribute__((__nothrow__, __leaf__));
extern int feof_unlocked(FILE *__stream) __attribute__((__nothrow__, __leaf__));
extern int ferror_unlocked(FILE *__stream)
    __attribute__((__nothrow__, __leaf__));

extern void perror(const char *__s);

extern int sys_nerr;
extern const char *const sys_errlist[];
extern int fileno(FILE *__stream) __attribute__((__nothrow__, __leaf__));
extern int fileno_unlocked(FILE *__stream)
    __attribute__((__nothrow__, __leaf__));
extern FILE *popen(const char *__command, const char *__modes);
extern int pclose(FILE *__stream);
extern char *ctermid(char *__s) __attribute__((__nothrow__, __leaf__));
extern void flockfile(FILE *__stream) __attribute__((__nothrow__, __leaf__));
extern int ftrylockfile(FILE *__stream) __attribute__((__nothrow__, __leaf__));
extern void funlockfile(FILE *__stream) __attribute__((__nothrow__, __leaf__));

extern void *memcpy(void *__restrict __dest, const void *__restrict __src,
                    size_t __n) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1, 2)));
extern void *memmove(void *__dest, const void *__src, size_t __n)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));

extern void *memccpy(void *__restrict __dest, const void *__restrict __src,
                     int __c, size_t __n) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1, 2)));

extern void *memset(void *__s, int __c, size_t __n)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern int memcmp(const void *__s1, const void *__s2, size_t __n)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern void *memchr(const void *__s, int __c, size_t __n)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1)));

extern char *strcpy(char *__restrict __dest, const char *__restrict __src)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern char *strncpy(char *__restrict __dest, const char *__restrict __src,
                     size_t __n) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1, 2)));
extern char *strcat(char *__restrict __dest, const char *__restrict __src)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern char *strncat(char *__restrict __dest, const char *__restrict __src,
                     size_t __n) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1, 2)));
extern int strcmp(const char *__s1, const char *__s2)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern int strncmp(const char *__s1, const char *__s2, size_t __n)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern int strcoll(const char *__s1, const char *__s2)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern size_t strxfrm(char *__restrict __dest, const char *__restrict __src,
                      size_t __n) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(2)));

typedef struct __locale_struct {
    struct __locale_data *__locales[13];
    const unsigned short int *__ctype_b;
    const int *__ctype_tolower;
    const int *__ctype_toupper;
    const char *__names[13];
} * __locale_t;
typedef __locale_t locale_t;
extern int strcoll_l(const char *__s1, const char *__s2, __locale_t __l)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2, 3)));
extern size_t strxfrm_l(char *__dest, const char *__src, size_t __n,
                        __locale_t __l) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(2, 4)));
extern char *strdup(const char *__s) __attribute__((__nothrow__, __leaf__))
__attribute__((__malloc__)) __attribute__((__nonnull__(1)));
extern char *strndup(const char *__string, size_t __n)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__malloc__))
    __attribute__((__nonnull__(1)));

extern char *strchr(const char *__s, int __c)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1)));
extern char *strrchr(const char *__s, int __c)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1)));

extern size_t strcspn(const char *__s, const char *__reject)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern size_t strspn(const char *__s, const char *__accept)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern char *strpbrk(const char *__s, const char *__accept)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern char *strstr(const char *__haystack, const char *__needle)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern char *strtok(char *__restrict __s, const char *__restrict __delim)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(2)));

extern char *__strtok_r(char *__restrict __s, const char *__restrict __delim,
                        char **__restrict __save_ptr)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(2, 3)));
extern char *strtok_r(char *__restrict __s, const char *__restrict __delim,
                      char **__restrict __save_ptr)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(2, 3)));

extern size_t strlen(const char *__s) __attribute__((__nothrow__, __leaf__))
__attribute__((__pure__)) __attribute__((__nonnull__(1)));

extern size_t strnlen(const char *__string, size_t __maxlen)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1)));

extern char *strerror(int __errnum) __attribute__((__nothrow__, __leaf__));

extern int strerror_r(int __errnum, char *__buf, size_t __buflen) __asm__(
    ""
    "__xpg_strerror_r") __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(2)));
extern char *strerror_l(int __errnum, __locale_t __l)
    __attribute__((__nothrow__, __leaf__));
extern void __bzero(void *__s, size_t __n)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1)));
extern void bcopy(const void *__src, void *__dest, size_t __n)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern void bzero(void *__s, size_t __n) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1)));
extern int bcmp(const void *__s1, const void *__s2, size_t __n)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern char *index(const char *__s, int __c)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1)));
extern char *rindex(const char *__s, int __c)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1)));
extern int ffs(int __i) __attribute__((__nothrow__, __leaf__))
__attribute__((__const__));
extern int strcasecmp(const char *__s1, const char *__s2)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern int strncasecmp(const char *__s1, const char *__s2, size_t __n)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__pure__))
    __attribute__((__nonnull__(1, 2)));
extern char *strsep(char **__restrict __stringp, const char *__restrict __delim)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern char *strsignal(int __sig) __attribute__((__nothrow__, __leaf__));
extern char *__stpcpy(char *__restrict __dest, const char *__restrict __src)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern char *stpcpy(char *__restrict __dest, const char *__restrict __src)
    __attribute__((__nothrow__, __leaf__)) __attribute__((__nonnull__(1, 2)));
extern char *__stpncpy(char *__restrict __dest, const char *__restrict __src,
                       size_t __n) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1, 2)));
extern char *stpncpy(char *__restrict __dest, const char *__restrict __src,
                     size_t __n) __attribute__((__nothrow__, __leaf__))
__attribute__((__nonnull__(1, 2)));

extern int *__errno_location(void) __attribute__((__nothrow__, __leaf__))
__attribute__((__const__));

typedef __signed__ char __s8;
typedef unsigned char __u8;
typedef __signed__ short __s16;
typedef unsigned short __u16;
typedef __signed__ int __s32;
typedef unsigned int __u32;
__extension__ typedef __signed__ long long __s64;
__extension__ typedef unsigned long long __u64;
typedef struct {
    unsigned long fds_bits[1024 / (8 * sizeof(long))];
} __kernel_fd_set;
typedef void (*__kernel_sighandler_t)(int);
typedef int __kernel_key_t;
typedef int __kernel_mqd_t;
typedef unsigned short __kernel_old_uid_t;
typedef unsigned short __kernel_old_gid_t;
typedef unsigned long __kernel_old_dev_t;
typedef long __kernel_long_t;
typedef unsigned long __kernel_ulong_t;
typedef __kernel_ulong_t __kernel_ino_t;
typedef unsigned int __kernel_mode_t;
typedef int __kernel_pid_t;
typedef int __kernel_ipc_pid_t;
typedef unsigned int __kernel_uid_t;
typedef unsigned int __kernel_gid_t;
typedef __kernel_long_t __kernel_suseconds_t;
typedef int __kernel_daddr_t;
typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef __kernel_long_t __kernel_ptrdiff_t;
typedef struct {
    int val[2];
} __kernel_fsid_t;
typedef __kernel_long_t __kernel_off_t;
typedef long long __kernel_loff_t;
typedef __kernel_long_t __kernel_time_t;
typedef __kernel_long_t __kernel_clock_t;
typedef int __kernel_timer_t;
typedef int __kernel_clockid_t;
typedef char *__kernel_caddr_t;
typedef unsigned short __kernel_uid16_t;
typedef unsigned short __kernel_gid16_t;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;
typedef __u16 __sum16;
typedef __u32 __wsum;
struct sysinfo {
    __kernel_long_t uptime;
    __kernel_ulong_t loads[3];
    __kernel_ulong_t totalram;
    __kernel_ulong_t freeram;
    __kernel_ulong_t sharedram;
    __kernel_ulong_t bufferram;
    __kernel_ulong_t totalswap;
    __kernel_ulong_t freeswap;
    __u16 procs;
    __u16 pad;
    __kernel_ulong_t totalhigh;
    __kernel_ulong_t freehigh;
    __u32 mem_unit;
    char _f[20 - 2 * sizeof(__kernel_ulong_t) - sizeof(__u32)];
};
struct completion;
struct __sysctl_args {
    int *name;
    int nlen;
    void *oldval;
    size_t *oldlenp;
    void *newval;
    size_t newlen;
    unsigned long __unused[4];
};
enum {
    CTL_KERN = 1,
    CTL_VM = 2,
    CTL_NET = 3,
    CTL_PROC = 4,
    CTL_FS = 5,
    CTL_DEBUG = 6,
    CTL_DEV = 7,
    CTL_BUS = 8,
    CTL_ABI = 9,
    CTL_CPU = 10,
    CTL_ARLAN = 254,
    CTL_S390DBF = 5677,
    CTL_SUNRPC = 7249,
    CTL_PM = 9899,
    CTL_FRV = 9898,
};
enum { CTL_BUS_ISA = 1 };
enum {
    INOTIFY_MAX_USER_INSTANCES = 1,
    INOTIFY_MAX_USER_WATCHES = 2,
    INOTIFY_MAX_QUEUED_EVENTS = 3
};
enum {
    KERN_OSTYPE = 1,
    KERN_OSRELEASE = 2,
    KERN_OSREV = 3,
    KERN_VERSION = 4,
    KERN_SECUREMASK = 5,
    KERN_PROF = 6,
    KERN_NODENAME = 7,
    KERN_DOMAINNAME = 8,
    KERN_PANIC = 15,
    KERN_REALROOTDEV = 16,
    KERN_SPARC_REBOOT = 21,
    KERN_CTLALTDEL = 22,
    KERN_PRINTK = 23,
    KERN_NAMETRANS = 24,
    KERN_PPC_HTABRECLAIM = 25,
    KERN_PPC_ZEROPAGED = 26,
    KERN_PPC_POWERSAVE_NAP = 27,
    KERN_MODPROBE = 28,
    KERN_SG_BIG_BUFF = 29,
    KERN_ACCT = 30,
    KERN_PPC_L2CR = 31,
    KERN_RTSIGNR = 32,
    KERN_RTSIGMAX = 33,
    KERN_SHMMAX = 34,
    KERN_MSGMAX = 35,
    KERN_MSGMNB = 36,
    KERN_MSGPOOL = 37,
    KERN_SYSRQ = 38,
    KERN_MAX_THREADS = 39,
    KERN_RANDOM = 40,
    KERN_SHMALL = 41,
    KERN_MSGMNI = 42,
    KERN_SEM = 43,
    KERN_SPARC_STOP_A = 44,
    KERN_SHMMNI = 45,
    KERN_OVERFLOWUID = 46,
    KERN_OVERFLOWGID = 47,
    KERN_SHMPATH = 48,
    KERN_HOTPLUG = 49,
    KERN_IEEE_EMULATION_WARNINGS = 50,
    KERN_S390_USER_DEBUG_LOGGING = 51,
    KERN_CORE_USES_PID = 52,
    KERN_TAINTED = 53,
    KERN_CADPID = 54,
    KERN_PIDMAX = 55,
    KERN_CORE_PATTERN = 56,
    KERN_PANIC_ON_OOPS = 57,
    KERN_HPPA_PWRSW = 58,
    KERN_HPPA_UNALIGNED = 59,
    KERN_PRINTK_RATELIMIT = 60,
    KERN_PRINTK_RATELIMIT_BURST = 61,
    KERN_PTY = 62,
    KERN_NGROUPS_MAX = 63,
    KERN_SPARC_SCONS_PWROFF = 64,
    KERN_HZ_TIMER = 65,
    KERN_UNKNOWN_NMI_PANIC = 66,
    KERN_BOOTLOADER_TYPE = 67,
    KERN_RANDOMIZE = 68,
    KERN_SETUID_DUMPABLE = 69,
    KERN_SPIN_RETRY = 70,
    KERN_ACPI_VIDEO_FLAGS = 71,
    KERN_IA64_UNALIGNED = 72,
    KERN_COMPAT_LOG = 73,
    KERN_MAX_LOCK_DEPTH = 74,
    KERN_NMI_WATCHDOG = 75,
    KERN_PANIC_ON_NMI = 76,
};
enum {
    VM_UNUSED1 = 1,
    VM_UNUSED2 = 2,
    VM_UNUSED3 = 3,
    VM_UNUSED4 = 4,
    VM_OVERCOMMIT_MEMORY = 5,
    VM_UNUSED5 = 6,
    VM_UNUSED7 = 7,
    VM_UNUSED8 = 8,
    VM_UNUSED9 = 9,
    VM_PAGE_CLUSTER = 10,
    VM_DIRTY_BACKGROUND = 11,
    VM_DIRTY_RATIO = 12,
    VM_DIRTY_WB_CS = 13,
    VM_DIRTY_EXPIRE_CS = 14,
    VM_NR_PDFLUSH_THREADS = 15,
    VM_OVERCOMMIT_RATIO = 16,
    VM_PAGEBUF = 17,
    VM_HUGETLB_PAGES = 18,
    VM_SWAPPINESS = 19,
    VM_LOWMEM_RESERVE_RATIO = 20,
    VM_MIN_FREE_KBYTES = 21,
    VM_MAX_MAP_COUNT = 22,
    VM_LAPTOP_MODE = 23,
    VM_BLOCK_DUMP = 24,
    VM_HUGETLB_GROUP = 25,
    VM_VFS_CACHE_PRESSURE = 26,
    VM_LEGACY_VA_LAYOUT = 27,
    VM_SWAP_TOKEN_TIMEOUT = 28,
    VM_DROP_PAGECACHE = 29,
    VM_PERCPU_PAGELIST_FRACTION = 30,
    VM_ZONE_RECLAIM_MODE = 31,
    VM_MIN_UNMAPPED = 32,
    VM_PANIC_ON_OOM = 33,
    VM_VDSO_ENABLED = 34,
    VM_MIN_SLAB = 35,
};
enum {
    NET_CORE = 1,
    NET_ETHER = 2,
    NET_802 = 3,
    NET_UNIX = 4,
    NET_IPV4 = 5,
    NET_IPX = 6,
    NET_ATALK = 7,
    NET_NETROM = 8,
    NET_AX25 = 9,
    NET_BRIDGE = 10,
    NET_ROSE = 11,
    NET_IPV6 = 12,
    NET_X25 = 13,
    NET_TR = 14,
    NET_DECNET = 15,
    NET_ECONET = 16,
    NET_SCTP = 17,
    NET_LLC = 18,
    NET_NETFILTER = 19,
    NET_DCCP = 20,
    NET_IRDA = 412,
};
enum {
    RANDOM_POOLSIZE = 1,
    RANDOM_ENTROPY_COUNT = 2,
    RANDOM_READ_THRESH = 3,
    RANDOM_WRITE_THRESH = 4,
    RANDOM_BOOT_ID = 5,
    RANDOM_UUID = 6
};
enum { PTY_MAX = 1, PTY_NR = 2 };
enum { BUS_ISA_MEM_BASE = 1, BUS_ISA_PORT_BASE = 2, BUS_ISA_PORT_SHIFT = 3 };
enum {
    NET_CORE_WMEM_MAX = 1,
    NET_CORE_RMEM_MAX = 2,
    NET_CORE_WMEM_DEFAULT = 3,
    NET_CORE_RMEM_DEFAULT = 4,
    NET_CORE_MAX_BACKLOG = 6,
    NET_CORE_FASTROUTE = 7,
    NET_CORE_MSG_COST = 8,
    NET_CORE_MSG_BURST = 9,
    NET_CORE_OPTMEM_MAX = 10,
    NET_CORE_HOT_LIST_LENGTH = 11,
    NET_CORE_DIVERT_VERSION = 12,
    NET_CORE_NO_CONG_THRESH = 13,
    NET_CORE_NO_CONG = 14,
    NET_CORE_LO_CONG = 15,
    NET_CORE_MOD_CONG = 16,
    NET_CORE_DEV_WEIGHT = 17,
    NET_CORE_SOMAXCONN = 18,
    NET_CORE_BUDGET = 19,
    NET_CORE_AEVENT_ETIME = 20,
    NET_CORE_AEVENT_RSEQTH = 21,
    NET_CORE_WARNINGS = 22,
};
enum {
    NET_UNIX_DESTROY_DELAY = 1,
    NET_UNIX_DELETE_DELAY = 2,
    NET_UNIX_MAX_DGRAM_QLEN = 3,
};
enum {
    NET_NF_CONNTRACK_MAX = 1,
    NET_NF_CONNTRACK_TCP_TIMEOUT_SYN_SENT = 2,
    NET_NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV = 3,
    NET_NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED = 4,
    NET_NF_CONNTRACK_TCP_TIMEOUT_FIN_WAIT = 5,
    NET_NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT = 6,
    NET_NF_CONNTRACK_TCP_TIMEOUT_LAST_ACK = 7,
    NET_NF_CONNTRACK_TCP_TIMEOUT_TIME_WAIT = 8,
    NET_NF_CONNTRACK_TCP_TIMEOUT_CLOSE = 9,
    NET_NF_CONNTRACK_UDP_TIMEOUT = 10,
    NET_NF_CONNTRACK_UDP_TIMEOUT_STREAM = 11,
    NET_NF_CONNTRACK_ICMP_TIMEOUT = 12,
    NET_NF_CONNTRACK_GENERIC_TIMEOUT = 13,
    NET_NF_CONNTRACK_BUCKETS = 14,
    NET_NF_CONNTRACK_LOG_INVALID = 15,
    NET_NF_CONNTRACK_TCP_TIMEOUT_MAX_RETRANS = 16,
    NET_NF_CONNTRACK_TCP_LOOSE = 17,
    NET_NF_CONNTRACK_TCP_BE_LIBERAL = 18,
    NET_NF_CONNTRACK_TCP_MAX_RETRANS = 19,
    NET_NF_CONNTRACK_SCTP_TIMEOUT_CLOSED = 20,
    NET_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_WAIT = 21,
    NET_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_ECHOED = 22,
    NET_NF_CONNTRACK_SCTP_TIMEOUT_ESTABLISHED = 23,
    NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_SENT = 24,
    NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_RECD = 25,
    NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_ACK_SENT = 26,
    NET_NF_CONNTRACK_COUNT = 27,
    NET_NF_CONNTRACK_ICMPV6_TIMEOUT = 28,
    NET_NF_CONNTRACK_FRAG6_TIMEOUT = 29,
    NET_NF_CONNTRACK_FRAG6_LOW_THRESH = 30,
    NET_NF_CONNTRACK_FRAG6_HIGH_THRESH = 31,
    NET_NF_CONNTRACK_CHECKSUM = 32,
};
enum {
    NET_IPV4_FORWARD = 8,
    NET_IPV4_DYNADDR = 9,
    NET_IPV4_CONF = 16,
    NET_IPV4_NEIGH = 17,
    NET_IPV4_ROUTE = 18,
    NET_IPV4_FIB_HASH = 19,
    NET_IPV4_NETFILTER = 20,
    NET_IPV4_TCP_TIMESTAMPS = 33,
    NET_IPV4_TCP_WINDOW_SCALING = 34,
    NET_IPV4_TCP_SACK = 35,
    NET_IPV4_TCP_RETRANS_COLLAPSE = 36,
    NET_IPV4_DEFAULT_TTL = 37,
    NET_IPV4_AUTOCONFIG = 38,
    NET_IPV4_NO_PMTU_DISC = 39,
    NET_IPV4_TCP_SYN_RETRIES = 40,
    NET_IPV4_IPFRAG_HIGH_THRESH = 41,
    NET_IPV4_IPFRAG_LOW_THRESH = 42,
    NET_IPV4_IPFRAG_TIME = 43,
    NET_IPV4_TCP_MAX_KA_PROBES = 44,
    NET_IPV4_TCP_KEEPALIVE_TIME = 45,
    NET_IPV4_TCP_KEEPALIVE_PROBES = 46,
    NET_IPV4_TCP_RETRIES1 = 47,
    NET_IPV4_TCP_RETRIES2 = 48,
    NET_IPV4_TCP_FIN_TIMEOUT = 49,
    NET_IPV4_IP_MASQ_DEBUG = 50,
    NET_TCP_SYNCOOKIES = 51,
    NET_TCP_STDURG = 52,
    NET_TCP_RFC1337 = 53,
    NET_TCP_SYN_TAILDROP = 54,
    NET_TCP_MAX_SYN_BACKLOG = 55,
    NET_IPV4_LOCAL_PORT_RANGE = 56,
    NET_IPV4_ICMP_ECHO_IGNORE_ALL = 57,
    NET_IPV4_ICMP_ECHO_IGNORE_BROADCASTS = 58,
    NET_IPV4_ICMP_SOURCEQUENCH_RATE = 59,
    NET_IPV4_ICMP_DESTUNREACH_RATE = 60,
    NET_IPV4_ICMP_TIMEEXCEED_RATE = 61,
    NET_IPV4_ICMP_PARAMPROB_RATE = 62,
    NET_IPV4_ICMP_ECHOREPLY_RATE = 63,
    NET_IPV4_ICMP_IGNORE_BOGUS_ERROR_RESPONSES = 64,
    NET_IPV4_IGMP_MAX_MEMBERSHIPS = 65,
    NET_TCP_TW_RECYCLE = 66,
    NET_IPV4_ALWAYS_DEFRAG = 67,
    NET_IPV4_TCP_KEEPALIVE_INTVL = 68,
    NET_IPV4_INET_PEER_THRESHOLD = 69,
    NET_IPV4_INET_PEER_MINTTL = 70,
    NET_IPV4_INET_PEER_MAXTTL = 71,
    NET_IPV4_INET_PEER_GC_MINTIME = 72,
    NET_IPV4_INET_PEER_GC_MAXTIME = 73,
    NET_TCP_ORPHAN_RETRIES = 74,
    NET_TCP_ABORT_ON_OVERFLOW = 75,
    NET_TCP_SYNACK_RETRIES = 76,
    NET_TCP_MAX_ORPHANS = 77,
    NET_TCP_MAX_TW_BUCKETS = 78,
    NET_TCP_FACK = 79,
    NET_TCP_REORDERING = 80,
    NET_TCP_ECN = 81,
    NET_TCP_DSACK = 82,
    NET_TCP_MEM = 83,
    NET_TCP_WMEM = 84,
    NET_TCP_RMEM = 85,
    NET_TCP_APP_WIN = 86,
    NET_TCP_ADV_WIN_SCALE = 87,
    NET_IPV4_NONLOCAL_BIND = 88,
    NET_IPV4_ICMP_RATELIMIT = 89,
    NET_IPV4_ICMP_RATEMASK = 90,
    NET_TCP_TW_REUSE = 91,
    NET_TCP_FRTO = 92,
    NET_TCP_LOW_LATENCY = 93,
    NET_IPV4_IPFRAG_SECRET_INTERVAL = 94,
    NET_IPV4_IGMP_MAX_MSF = 96,
    NET_TCP_NO_METRICS_SAVE = 97,
    NET_TCP_DEFAULT_WIN_SCALE = 105,
    NET_TCP_MODERATE_RCVBUF = 106,
    NET_TCP_TSO_WIN_DIVISOR = 107,
    NET_TCP_BIC_BETA = 108,
    NET_IPV4_ICMP_ERRORS_USE_INBOUND_IFADDR = 109,
    NET_TCP_CONG_CONTROL = 110,
    NET_TCP_ABC = 111,
    NET_IPV4_IPFRAG_MAX_DIST = 112,
    NET_TCP_MTU_PROBING = 113,
    NET_TCP_BASE_MSS = 114,
    NET_IPV4_TCP_WORKAROUND_SIGNED_WINDOWS = 115,
    NET_TCP_DMA_COPYBREAK = 116,
    NET_TCP_SLOW_START_AFTER_IDLE = 117,
    NET_CIPSOV4_CACHE_ENABLE = 118,
    NET_CIPSOV4_CACHE_BUCKET_SIZE = 119,
    NET_CIPSOV4_RBM_OPTFMT = 120,
    NET_CIPSOV4_RBM_STRICTVALID = 121,
    NET_TCP_AVAIL_CONG_CONTROL = 122,
    NET_TCP_ALLOWED_CONG_CONTROL = 123,
    NET_TCP_MAX_SSTHRESH = 124,
    NET_TCP_FRTO_RESPONSE = 125,
};
enum {
    NET_IPV4_ROUTE_FLUSH = 1,
    NET_IPV4_ROUTE_MIN_DELAY = 2,
    NET_IPV4_ROUTE_MAX_DELAY = 3,
    NET_IPV4_ROUTE_GC_THRESH = 4,
    NET_IPV4_ROUTE_MAX_SIZE = 5,
    NET_IPV4_ROUTE_GC_MIN_INTERVAL = 6,
    NET_IPV4_ROUTE_GC_TIMEOUT = 7,
    NET_IPV4_ROUTE_GC_INTERVAL = 8,
    NET_IPV4_ROUTE_REDIRECT_LOAD = 9,
    NET_IPV4_ROUTE_REDIRECT_NUMBER = 10,
    NET_IPV4_ROUTE_REDIRECT_SILENCE = 11,
    NET_IPV4_ROUTE_ERROR_COST = 12,
    NET_IPV4_ROUTE_ERROR_BURST = 13,
    NET_IPV4_ROUTE_GC_ELASTICITY = 14,
    NET_IPV4_ROUTE_MTU_EXPIRES = 15,
    NET_IPV4_ROUTE_MIN_PMTU = 16,
    NET_IPV4_ROUTE_MIN_ADVMSS = 17,
    NET_IPV4_ROUTE_SECRET_INTERVAL = 18,
    NET_IPV4_ROUTE_GC_MIN_INTERVAL_MS = 19,
};
enum { NET_PROTO_CONF_ALL = -2, NET_PROTO_CONF_DEFAULT = -3 };
enum {
    NET_IPV4_CONF_FORWARDING = 1,
    NET_IPV4_CONF_MC_FORWARDING = 2,
    NET_IPV4_CONF_PROXY_ARP = 3,
    NET_IPV4_CONF_ACCEPT_REDIRECTS = 4,
    NET_IPV4_CONF_SECURE_REDIRECTS = 5,
    NET_IPV4_CONF_SEND_REDIRECTS = 6,
    NET_IPV4_CONF_SHARED_MEDIA = 7,
    NET_IPV4_CONF_RP_FILTER = 8,
    NET_IPV4_CONF_ACCEPT_SOURCE_ROUTE = 9,
    NET_IPV4_CONF_BOOTP_RELAY = 10,
    NET_IPV4_CONF_LOG_MARTIANS = 11,
    NET_IPV4_CONF_TAG = 12,
    NET_IPV4_CONF_ARPFILTER = 13,
    NET_IPV4_CONF_MEDIUM_ID = 14,
    NET_IPV4_CONF_NOXFRM = 15,
    NET_IPV4_CONF_NOPOLICY = 16,
    NET_IPV4_CONF_FORCE_IGMP_VERSION = 17,
    NET_IPV4_CONF_ARP_ANNOUNCE = 18,
    NET_IPV4_CONF_ARP_IGNORE = 19,
    NET_IPV4_CONF_PROMOTE_SECONDARIES = 20,
    NET_IPV4_CONF_ARP_ACCEPT = 21,
    NET_IPV4_CONF_ARP_NOTIFY = 22,
};
enum {
    NET_IPV4_NF_CONNTRACK_MAX = 1,
    NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_SYN_SENT = 2,
    NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV = 3,
    NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED = 4,
    NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_FIN_WAIT = 5,
    NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT = 6,
    NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_LAST_ACK = 7,
    NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_TIME_WAIT = 8,
    NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_CLOSE = 9,
    NET_IPV4_NF_CONNTRACK_UDP_TIMEOUT = 10,
    NET_IPV4_NF_CONNTRACK_UDP_TIMEOUT_STREAM = 11,
    NET_IPV4_NF_CONNTRACK_ICMP_TIMEOUT = 12,
    NET_IPV4_NF_CONNTRACK_GENERIC_TIMEOUT = 13,
    NET_IPV4_NF_CONNTRACK_BUCKETS = 14,
    NET_IPV4_NF_CONNTRACK_LOG_INVALID = 15,
    NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_MAX_RETRANS = 16,
    NET_IPV4_NF_CONNTRACK_TCP_LOOSE = 17,
    NET_IPV4_NF_CONNTRACK_TCP_BE_LIBERAL = 18,
    NET_IPV4_NF_CONNTRACK_TCP_MAX_RETRANS = 19,
    NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_CLOSED = 20,
    NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_WAIT = 21,
    NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_ECHOED = 22,
    NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_ESTABLISHED = 23,
    NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_SENT = 24,
    NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_RECD = 25,
    NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_ACK_SENT = 26,
    NET_IPV4_NF_CONNTRACK_COUNT = 27,
    NET_IPV4_NF_CONNTRACK_CHECKSUM = 28,
};
enum {
    NET_IPV6_CONF = 16,
    NET_IPV6_NEIGH = 17,
    NET_IPV6_ROUTE = 18,
    NET_IPV6_ICMP = 19,
    NET_IPV6_BINDV6ONLY = 20,
    NET_IPV6_IP6FRAG_HIGH_THRESH = 21,
    NET_IPV6_IP6FRAG_LOW_THRESH = 22,
    NET_IPV6_IP6FRAG_TIME = 23,
    NET_IPV6_IP6FRAG_SECRET_INTERVAL = 24,
    NET_IPV6_MLD_MAX_MSF = 25,
};
enum {
    NET_IPV6_ROUTE_FLUSH = 1,
    NET_IPV6_ROUTE_GC_THRESH = 2,
    NET_IPV6_ROUTE_MAX_SIZE = 3,
    NET_IPV6_ROUTE_GC_MIN_INTERVAL = 4,
    NET_IPV6_ROUTE_GC_TIMEOUT = 5,
    NET_IPV6_ROUTE_GC_INTERVAL = 6,
    NET_IPV6_ROUTE_GC_ELASTICITY = 7,
    NET_IPV6_ROUTE_MTU_EXPIRES = 8,
    NET_IPV6_ROUTE_MIN_ADVMSS = 9,
    NET_IPV6_ROUTE_GC_MIN_INTERVAL_MS = 10
};
enum {
    NET_IPV6_FORWARDING = 1,
    NET_IPV6_HOP_LIMIT = 2,
    NET_IPV6_MTU = 3,
    NET_IPV6_ACCEPT_RA = 4,
    NET_IPV6_ACCEPT_REDIRECTS = 5,
    NET_IPV6_AUTOCONF = 6,
    NET_IPV6_DAD_TRANSMITS = 7,
    NET_IPV6_RTR_SOLICITS = 8,
    NET_IPV6_RTR_SOLICIT_INTERVAL = 9,
    NET_IPV6_RTR_SOLICIT_DELAY = 10,
    NET_IPV6_USE_TEMPADDR = 11,
    NET_IPV6_TEMP_VALID_LFT = 12,
    NET_IPV6_TEMP_PREFERED_LFT = 13,
    NET_IPV6_REGEN_MAX_RETRY = 14,
    NET_IPV6_MAX_DESYNC_FACTOR = 15,
    NET_IPV6_MAX_ADDRESSES = 16,
    NET_IPV6_FORCE_MLD_VERSION = 17,
    NET_IPV6_ACCEPT_RA_DEFRTR = 18,
    NET_IPV6_ACCEPT_RA_PINFO = 19,
    NET_IPV6_ACCEPT_RA_RTR_PREF = 20,
    NET_IPV6_RTR_PROBE_INTERVAL = 21,
    NET_IPV6_ACCEPT_RA_RT_INFO_MAX_PLEN = 22,
    NET_IPV6_PROXY_NDP = 23,
    NET_IPV6_ACCEPT_SOURCE_ROUTE = 25,
    __NET_IPV6_MAX
};
enum { NET_IPV6_ICMP_RATELIMIT = 1 };
enum {
    NET_NEIGH_MCAST_SOLICIT = 1,
    NET_NEIGH_UCAST_SOLICIT = 2,
    NET_NEIGH_APP_SOLICIT = 3,
    NET_NEIGH_RETRANS_TIME = 4,
    NET_NEIGH_REACHABLE_TIME = 5,
    NET_NEIGH_DELAY_PROBE_TIME = 6,
    NET_NEIGH_GC_STALE_TIME = 7,
    NET_NEIGH_UNRES_QLEN = 8,
    NET_NEIGH_PROXY_QLEN = 9,
    NET_NEIGH_ANYCAST_DELAY = 10,
    NET_NEIGH_PROXY_DELAY = 11,
    NET_NEIGH_LOCKTIME = 12,
    NET_NEIGH_GC_INTERVAL = 13,
    NET_NEIGH_GC_THRESH1 = 14,
    NET_NEIGH_GC_THRESH2 = 15,
    NET_NEIGH_GC_THRESH3 = 16,
    NET_NEIGH_RETRANS_TIME_MS = 17,
    NET_NEIGH_REACHABLE_TIME_MS = 18,
};
enum {
    NET_DCCP_DEFAULT = 1,
};
enum { NET_IPX_PPROP_BROADCASTING = 1, NET_IPX_FORWARDING = 2 };
enum {
    NET_LLC2 = 1,
    NET_LLC_STATION = 2,
};
enum {
    NET_LLC2_TIMEOUT = 1,
};
enum {
    NET_LLC_STATION_ACK_TIMEOUT = 1,
};
enum {
    NET_LLC2_ACK_TIMEOUT = 1,
    NET_LLC2_P_TIMEOUT = 2,
    NET_LLC2_REJ_TIMEOUT = 3,
    NET_LLC2_BUSY_TIMEOUT = 4,
};
enum {
    NET_ATALK_AARP_EXPIRY_TIME = 1,
    NET_ATALK_AARP_TICK_TIME = 2,
    NET_ATALK_AARP_RETRANSMIT_LIMIT = 3,
    NET_ATALK_AARP_RESOLVE_TIME = 4
};
enum {
    NET_NETROM_DEFAULT_PATH_QUALITY = 1,
    NET_NETROM_OBSOLESCENCE_COUNT_INITIALISER = 2,
    NET_NETROM_NETWORK_TTL_INITIALISER = 3,
    NET_NETROM_TRANSPORT_TIMEOUT = 4,
    NET_NETROM_TRANSPORT_MAXIMUM_TRIES = 5,
    NET_NETROM_TRANSPORT_ACKNOWLEDGE_DELAY = 6,
    NET_NETROM_TRANSPORT_BUSY_DELAY = 7,
    NET_NETROM_TRANSPORT_REQUESTED_WINDOW_SIZE = 8,
    NET_NETROM_TRANSPORT_NO_ACTIVITY_TIMEOUT = 9,
    NET_NETROM_ROUTING_CONTROL = 10,
    NET_NETROM_LINK_FAILS_COUNT = 11,
    NET_NETROM_RESET = 12
};
enum {
    NET_AX25_IP_DEFAULT_MODE = 1,
    NET_AX25_DEFAULT_MODE = 2,
    NET_AX25_BACKOFF_TYPE = 3,
    NET_AX25_CONNECT_MODE = 4,
    NET_AX25_STANDARD_WINDOW = 5,
    NET_AX25_EXTENDED_WINDOW = 6,
    NET_AX25_T1_TIMEOUT = 7,
    NET_AX25_T2_TIMEOUT = 8,
    NET_AX25_T3_TIMEOUT = 9,
    NET_AX25_IDLE_TIMEOUT = 10,
    NET_AX25_N2 = 11,
    NET_AX25_PACLEN = 12,
    NET_AX25_PROTOCOL = 13,
    NET_AX25_DAMA_SLAVE_TIMEOUT = 14
};
enum {
    NET_ROSE_RESTART_REQUEST_TIMEOUT = 1,
    NET_ROSE_CALL_REQUEST_TIMEOUT = 2,
    NET_ROSE_RESET_REQUEST_TIMEOUT = 3,
    NET_ROSE_CLEAR_REQUEST_TIMEOUT = 4,
    NET_ROSE_ACK_HOLD_BACK_TIMEOUT = 5,
    NET_ROSE_ROUTING_CONTROL = 6,
    NET_ROSE_LINK_FAIL_TIMEOUT = 7,
    NET_ROSE_MAX_VCS = 8,
    NET_ROSE_WINDOW_SIZE = 9,
    NET_ROSE_NO_ACTIVITY_TIMEOUT = 10
};
enum {
    NET_X25_RESTART_REQUEST_TIMEOUT = 1,
    NET_X25_CALL_REQUEST_TIMEOUT = 2,
    NET_X25_RESET_REQUEST_TIMEOUT = 3,
    NET_X25_CLEAR_REQUEST_TIMEOUT = 4,
    NET_X25_ACK_HOLD_BACK_TIMEOUT = 5,
    NET_X25_FORWARD = 6
};
enum { NET_TR_RIF_TIMEOUT = 1 };
enum {
    NET_DECNET_NODE_TYPE = 1,
    NET_DECNET_NODE_ADDRESS = 2,
    NET_DECNET_NODE_NAME = 3,
    NET_DECNET_DEFAULT_DEVICE = 4,
    NET_DECNET_TIME_WAIT = 5,
    NET_DECNET_DN_COUNT = 6,
    NET_DECNET_DI_COUNT = 7,
    NET_DECNET_DR_COUNT = 8,
    NET_DECNET_DST_GC_INTERVAL = 9,
    NET_DECNET_CONF = 10,
    NET_DECNET_NO_FC_MAX_CWND = 11,
    NET_DECNET_MEM = 12,
    NET_DECNET_RMEM = 13,
    NET_DECNET_WMEM = 14,
    NET_DECNET_DEBUG_LEVEL = 255
};
enum {
    NET_DECNET_CONF_LOOPBACK = -2,
    NET_DECNET_CONF_DDCMP = -3,
    NET_DECNET_CONF_PPP = -4,
    NET_DECNET_CONF_X25 = -5,
    NET_DECNET_CONF_GRE = -6,
    NET_DECNET_CONF_ETHER = -7
};
enum {
    NET_DECNET_CONF_DEV_PRIORITY = 1,
    NET_DECNET_CONF_DEV_T1 = 2,
    NET_DECNET_CONF_DEV_T2 = 3,
    NET_DECNET_CONF_DEV_T3 = 4,
    NET_DECNET_CONF_DEV_FORWARDING = 5,
    NET_DECNET_CONF_DEV_BLKSIZE = 6,
    NET_DECNET_CONF_DEV_STATE = 7
};
enum {
    NET_SCTP_RTO_INITIAL = 1,
    NET_SCTP_RTO_MIN = 2,
    NET_SCTP_RTO_MAX = 3,
    NET_SCTP_RTO_ALPHA = 4,
    NET_SCTP_RTO_BETA = 5,
    NET_SCTP_VALID_COOKIE_LIFE = 6,
    NET_SCTP_ASSOCIATION_MAX_RETRANS = 7,
    NET_SCTP_PATH_MAX_RETRANS = 8,
    NET_SCTP_MAX_INIT_RETRANSMITS = 9,
    NET_SCTP_HB_INTERVAL = 10,
    NET_SCTP_PRESERVE_ENABLE = 11,
    NET_SCTP_MAX_BURST = 12,
    NET_SCTP_ADDIP_ENABLE = 13,
    NET_SCTP_PRSCTP_ENABLE = 14,
    NET_SCTP_SNDBUF_POLICY = 15,
    NET_SCTP_SACK_TIMEOUT = 16,
    NET_SCTP_RCVBUF_POLICY = 17,
};
enum {
    NET_BRIDGE_NF_CALL_ARPTABLES = 1,
    NET_BRIDGE_NF_CALL_IPTABLES = 2,
    NET_BRIDGE_NF_CALL_IP6TABLES = 3,
    NET_BRIDGE_NF_FILTER_VLAN_TAGGED = 4,
    NET_BRIDGE_NF_FILTER_PPPOE_TAGGED = 5,
};
enum {
    NET_IRDA_DISCOVERY = 1,
    NET_IRDA_DEVNAME = 2,
    NET_IRDA_DEBUG = 3,
    NET_IRDA_FAST_POLL = 4,
    NET_IRDA_DISCOVERY_SLOTS = 5,
    NET_IRDA_DISCOVERY_TIMEOUT = 6,
    NET_IRDA_SLOT_TIMEOUT = 7,
    NET_IRDA_MAX_BAUD_RATE = 8,
    NET_IRDA_MIN_TX_TURN_TIME = 9,
    NET_IRDA_MAX_TX_DATA_SIZE = 10,
    NET_IRDA_MAX_TX_WINDOW = 11,
    NET_IRDA_MAX_NOREPLY_TIME = 12,
    NET_IRDA_WARN_NOREPLY_TIME = 13,
    NET_IRDA_LAP_KEEPALIVE_TIME = 14,
};
enum {
    FS_NRINODE = 1,
    FS_STATINODE = 2,
    FS_MAXINODE = 3,
    FS_NRDQUOT = 4,
    FS_MAXDQUOT = 5,
    FS_NRFILE = 6,
    FS_MAXFILE = 7,
    FS_DENTRY = 8,
    FS_NRSUPER = 9,
    FS_MAXSUPER = 10,
    FS_OVERFLOWUID = 11,
    FS_OVERFLOWGID = 12,
    FS_LEASES = 13,
    FS_DIR_NOTIFY = 14,
    FS_LEASE_TIME = 15,
    FS_DQSTATS = 16,
    FS_XFS = 17,
    FS_AIO_NR = 18,
    FS_AIO_MAX_NR = 19,
    FS_INOTIFY = 20,
    FS_OCFS2 = 988,
};
enum {
    FS_DQ_LOOKUPS = 1,
    FS_DQ_DROPS = 2,
    FS_DQ_READS = 3,
    FS_DQ_WRITES = 4,
    FS_DQ_CACHE_HITS = 5,
    FS_DQ_ALLOCATED = 6,
    FS_DQ_FREE = 7,
    FS_DQ_SYNCS = 8,
    FS_DQ_WARNINGS = 9,
};
enum {
    DEV_CDROM = 1,
    DEV_HWMON = 2,
    DEV_PARPORT = 3,
    DEV_RAID = 4,
    DEV_MAC_HID = 5,
    DEV_SCSI = 6,
    DEV_IPMI = 7,
};
enum {
    DEV_CDROM_INFO = 1,
    DEV_CDROM_AUTOCLOSE = 2,
    DEV_CDROM_AUTOEJECT = 3,
    DEV_CDROM_DEBUG = 4,
    DEV_CDROM_LOCK = 5,
    DEV_CDROM_CHECK_MEDIA = 6
};
enum { DEV_PARPORT_DEFAULT = -3 };
enum { DEV_RAID_SPEED_LIMIT_MIN = 1, DEV_RAID_SPEED_LIMIT_MAX = 2 };
enum { DEV_PARPORT_DEFAULT_TIMESLICE = 1, DEV_PARPORT_DEFAULT_SPINTIME = 2 };
enum {
    DEV_PARPORT_SPINTIME = 1,
    DEV_PARPORT_BASE_ADDR = 2,
    DEV_PARPORT_IRQ = 3,
    DEV_PARPORT_DMA = 4,
    DEV_PARPORT_MODES = 5,
    DEV_PARPORT_DEVICES = 6,
    DEV_PARPORT_AUTOPROBE = 16
};
enum {
    DEV_PARPORT_DEVICES_ACTIVE = -3,
};
enum {
    DEV_PARPORT_DEVICE_TIMESLICE = 1,
};
enum {
    DEV_MAC_HID_KEYBOARD_SENDS_LINUX_KEYCODES = 1,
    DEV_MAC_HID_KEYBOARD_LOCK_KEYCODES = 2,
    DEV_MAC_HID_MOUSE_BUTTON_EMULATION = 3,
    DEV_MAC_HID_MOUSE_BUTTON2_KEYCODE = 4,
    DEV_MAC_HID_MOUSE_BUTTON3_KEYCODE = 5,
    DEV_MAC_HID_ADB_MOUSE_SENDS_KEYCODES = 6
};
enum {
    DEV_SCSI_LOGGING_LEVEL = 1,
};
enum {
    DEV_IPMI_POWEROFF_POWERCYCLE = 1,
};
enum {
    ABI_DEFHANDLER_COFF = 1,
    ABI_DEFHANDLER_ELF = 2,
    ABI_DEFHANDLER_LCALL7 = 3,
    ABI_DEFHANDLER_LIBCSO = 4,
    ABI_TRACE = 5,
    ABI_FAKE_UTSNAME = 6,
};
enum nf_inet_hooks {
    NF_INET_PRE_ROUTING,
    NF_INET_LOCAL_IN,
    NF_INET_FORWARD,
    NF_INET_LOCAL_OUT,
    NF_INET_POST_ROUTING,
    NF_INET_NUMHOOKS
};
enum {
    NFPROTO_UNSPEC = 0,
    NFPROTO_IPV4 = 2,
    NFPROTO_ARP = 3,
    NFPROTO_BRIDGE = 7,
    NFPROTO_IPV6 = 10,
    NFPROTO_DECNET = 12,
    NFPROTO_NUMPROTO,
};
union nf_inet_addr {
    __u32 all[4];
    __be32 ip;
    __be32 ip6[4];
    struct in_addr in;
    struct in6_addr in6;
};
enum nf_ip_hook_priorities {
    NF_IP_PRI_FIRST = (-2147483647 - 1),
    NF_IP_PRI_CONNTRACK_DEFRAG = -400,
    NF_IP_PRI_RAW = -300,
    NF_IP_PRI_SELINUX_FIRST = -225,
    NF_IP_PRI_CONNTRACK = -200,
    NF_IP_PRI_MANGLE = -150,
    NF_IP_PRI_NAT_DST = -100,
    NF_IP_PRI_FILTER = 0,
    NF_IP_PRI_SECURITY = 50,
    NF_IP_PRI_NAT_SRC = 100,
    NF_IP_PRI_SELINUX_LAST = 225,
    NF_IP_PRI_CONNTRACK_HELPER = 300,
    NF_IP_PRI_CONNTRACK_CONFIRM = 2147483647,
    NF_IP_PRI_LAST = 2147483647,
};
enum nf_ip6_hook_priorities {
    NF_IP6_PRI_FIRST = (-2147483647 - 1),
    NF_IP6_PRI_CONNTRACK_DEFRAG = -400,
    NF_IP6_PRI_RAW = -300,
    NF_IP6_PRI_SELINUX_FIRST = -225,
    NF_IP6_PRI_CONNTRACK = -200,
    NF_IP6_PRI_MANGLE = -150,
    NF_IP6_PRI_NAT_DST = -100,
    NF_IP6_PRI_FILTER = 0,
    NF_IP6_PRI_SECURITY = 50,
    NF_IP6_PRI_NAT_SRC = 100,
    NF_IP6_PRI_SELINUX_LAST = 225,
    NF_IP6_PRI_CONNTRACK_HELPER = 300,
    NF_IP6_PRI_LAST = 2147483647,
};
static int nat_netfilter_lookup_cb(struct sockaddr *dst_addr,
                                   socklen_t *dst_addrlen, int s,
                                   struct sockaddr *src_addr,
                                   __attribute__((unused))
                                   socklen_t src_addrlen)
{
    int rv;
    if (src_addr->sa_family != 2) {
        printf(
            "The netfilter NAT engine only "
            "supports IPv4 state lookups\n");
        return -1;
    }
    rv = getsockopt(s, 0, 80, dst_addr, dst_addrlen);
    if (rv == -1) {
        printf("Error from getsockopt(SO_ORIGINAL_DST): %s\n",
               strerror((*__errno_location())));
    }
    return rv;
}
static int nat_iptransparent_socket_cb(int s)
{
    int on = 1;
    int rv;
    rv = setsockopt(s, 0, 19, (void *)&on, sizeof(on));
    if (rv == -1) {
        printf("Error from setsockopt(IP_TRANSPARENT): %s\n",
               strerror((*__errno_location())));
    }
    return rv;
}
static int nat_getsockname_lookup_cb(
    struct sockaddr *dst_addr, socklen_t *dst_addrlen, int s,
    __attribute__((unused)) struct sockaddr *src_addr,
    __attribute__((unused)) socklen_t src_addrlen)
{
    if (getsockname(s, dst_addr, dst_addrlen) == -1) {
        printf("Error from getsockname(): %s\n",
               strerror((*__errno_location())));
        return -1;
    }
    return 0;
}
typedef int (*nat_init_cb_t)(void);
typedef void (*nat_fini_cb_t)(void);
struct engine {
    const char *name;
    unsigned int ipv6 : 1;
    unsigned int used : 1;
    nat_init_cb_t preinitcb;
    nat_init_cb_t initcb;
    nat_fini_cb_t finicb;
    nat_lookup_cb_t lookupcb;
    nat_socket_cb_t socketcb;
};
struct engine engines[] = {
    {"netfilter", 0, 0, ((void *)0), ((void *)0), ((void *)0),
     nat_netfilter_lookup_cb, ((void *)0)},
    {"tproxy", 1, 0, ((void *)0), ((void *)0), ((void *)0),
     nat_getsockname_lookup_cb, nat_iptransparent_socket_cb},
    {((void *)0), 0, 0, ((void *)0), ((void *)0), ((void *)0), ((void *)0),
     ((void *)0)}};
const char *nat_getdefaultname(void) { return engines[0].name; }
static int nat_index(const char *name)
{
    if (name)
        for (int i = 0; engines[i].name; i++)
            if (!strcmp(name, engines[i].name)) return i;
    return ((sizeof(engines) / sizeof(struct engine)) - 1);
}
int nat_exist(const char *name)
{
    if (!name) name = engines[0].name;
    return !!engines[nat_index(name)].name;
}
int nat_used(const char *name)
{
    if (!name) name = engines[0].name;
    return !!engines[nat_index(name)].used;
}
nat_lookup_cb_t nat_getlookupcb(const char *name)
{
    int i;
    if (!name) name = engines[0].name;
    i = nat_index(name);
    engines[i].used = 1;
    return engines[i].lookupcb;
}
nat_socket_cb_t nat_getsocketcb(const char *name)
{
    if (!name) name = engines[0].name;
    return engines[nat_index(name)].socketcb;
}
int nat_ipv6ready(const char *name)
{
    if (!name) name = engines[0].name;
    return engines[nat_index(name)].ipv6;
}
void nat_list_engines(void)
{
    for (int i = 0; engines[i].name; i++) {
        fprintf(stdout, "%s%s\n", engines[i].name, i ? "" : " (default)");
    }
    fflush(stdout);
}
int nat_preinit(void)
{
    for (int i = 0; engines[i].preinitcb && engines[i].used; i++) {
        printf("NAT engine preinit '%s'\n", engines[i].name);
        if (engines[i].preinitcb() == -1) return -1;
    }
    return 0;
}
int nat_init(void)
{
    for (int i = 0; engines[i].initcb && engines[i].used; i++) {
        printf("NAT engine init '%s'\n", engines[i].name);
        if (engines[i].initcb() == -1) return -1;
    }
    return 0;
}
void nat_fini(void)
{
    for (int i = 0; engines[i].finicb && engines[i].used; i++) {
        printf("NAT engine fini '%s'\n", engines[i].name);
        engines[i].finicb();
    }
}
void nat_version(void)
{
    fprintf(stderr, "NAT engines:");
    for (int i = 0; engines[i].name; i++) {
        fprintf(stderr, " %s%s", engines[i].name, i ? "" : "*");
    }
    if (!engines[0].name) fprintf(stderr, " -");
    fprintf(stderr, "\n");
    fprintf(stderr, "netfilter:");
    fprintf(stderr, " IP_TRANSPARENT");
    fprintf(stderr, " SOL_IPV6");
    fprintf(stderr, " !IPV6_ORIGINAL_DST");
    fprintf(stderr, "\n");
}
