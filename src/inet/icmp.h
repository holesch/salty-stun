#ifndef INET_ICMP_H_
#define INET_ICMP_H_

#include "packet.h"

int icmp_handle_request(struct packet *request, struct packet *response);

#endif // INET_ICMP_H_
