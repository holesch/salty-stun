#ifndef IP_H_
#define IP_H_

#include "packet.h"

int ip_handle_request(struct packet *request, struct packet *response);

#endif // IP_H_
