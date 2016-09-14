#include <stdlib.h>
#include <sys/socket.h>
#include <stdbool.h>
#include "constants.h"

#ifdef __cplusplus
extern "C" {
#endif
enum BevState {OPEN, TO_CLOSE, CLOSED};
struct pxy_conn {
  enum BevState serv_state;
  enum BevState cli_state;
  struct sockaddr_storage dstsock;
  socklen_t dstsocklen;
  int index;
  struct bufferevent *cli_bev;
  struct bufferevent *serv_bev;
  struct proxy_ctx *parent;
};

struct proxy_ctx {
  int counts;
  struct pxy_conn *conns[MAXCONNS];
  struct event *timer;
  struct event *cleantimer;
  struct event_base *base;
};

int find_next_slot(struct proxy_ctx *);

struct proxy_ctx *proxy_ctx_new();
void proxy_ctx_free(struct proxy_ctx *);
struct pxy_conn *pxy_conn_new(struct proxy_ctx *);
void pxy_conn_free(struct pxy_conn *);
#ifdef __cplusplus
};
#endif
