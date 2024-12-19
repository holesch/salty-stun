#ifndef CONTEXT_H_
#define CONTEXT_H_

#include <netinet/in.h>

#include "packet.h"

struct context {
    struct packet request;
    struct packet response;
    struct sockaddr_in outer_remote_addr;
};

#endif // CONTEXT_H_
