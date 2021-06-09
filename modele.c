#include "modele.h"

#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

uint16_t sum(uint16_t seqno, int n) {
  return (uint16_t)((seqno + n) % UINT16_MAX);
}

char less_or_equals(uint16_t seqno1, uint16_t seqno2) {
  return ((seqno2 - seqno1) & (INT16_MAX + 1)) == 0;
}

uint64_t random_id() { return ((uint64_t)rand() << 32 | rand()); }

int sock_addr_cmp_addr(addr *sa, struct sockaddr_in6 *sb) {
  return memcmp((char *)&sa->ip, (char *)&sb->sin6_addr, sizeof(sa)) == 0 &&
         sa->port == sb->sin6_port;
}

struct sockaddr *addrToSockaddr(addr *ad) {
  struct sockaddr_in6 *addr = calloc(1, sizeof(struct sockaddr_in6));
  addr->sin6_family = AF_INET6;
  addr->sin6_addr = ad->ip;
  addr->sin6_port = ad->port;
  return (struct sockaddr *)addr;
}
