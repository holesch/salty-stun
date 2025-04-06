#ifndef INET_UDP_H_
#define INET_UDP_H_

#include <stdint.h>

#include "context.h"

int udp_handle_request(struct context *ctx, uint32_t ip_header_sum);

#endif // INET_UDP_H_
