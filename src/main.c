#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#include "log.h"
#include "packet.h"
#include "wireguard/wireguard.h"

int main(void) {
    if (sodium_init() == -1) {
        return 1;
    }
    log_init(LOG_DEBUG);

    struct wireguard wg;
    // yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
    static const uint8_t private_key[32] = { 0xc8, 0x09, 0xf3, 0xe5, 0x31, 0x7e, 0x95,
        0x75, 0xc9, 0xb5, 0xed, 0x78, 0xb6, 0x38, 0xb7, 0xce, 0x53, 0x0d, 0xab, 0xe8,
        0x5d, 0xda, 0xb6, 0x14, 0x22, 0x02, 0x41, 0x80, 0x1d, 0xdf, 0x06, 0x69 };
    wireguard_init(&wg, private_key);

    // create UDP server
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_errnum_error("socket");
        return 1;
    }

    // bind to port 51820
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    const uint16_t port = 51820;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_errnum_error("bind");
        return 1;
    }
    log_info("Listening on port %d", port);

    static ALIGNED_BUFFER(request_buffer, 4096);
    static ALIGNED_BUFFER(response_buffer, 4096);
    struct context ctx;
    ssize_t len = 0;

    while (1) {
        socklen_t src_addr_len = sizeof(ctx.outer_remote_addr);
        len = recvfrom(sockfd, request_buffer.bytes, sizeof(request_buffer), 0,
                (struct sockaddr *)&ctx.outer_remote_addr, &src_addr_len);
        if (len < 0) {
            log_errnum_error("recvfrom");
            return 1;
        }

        ctx.request.head = request_buffer.bytes;
        ctx.request.len = len;
        ctx.response.head = response_buffer.bytes;
        ctx.response.len = 0;

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ctx.outer_remote_addr.sin_addr, ip, INET_ADDRSTRLEN);
        log_debug("received %zu bytes from %s:%d", ctx.request.len, ip,
                ntohs(ctx.outer_remote_addr.sin_port));

        int err = wireguard_handle_request(&wg, &ctx);
        if (!err && ctx.response.len != 0) {
            log_debug("sending %zu bytes to %s:%d", ctx.response.len, ip,
                    ntohs(ctx.outer_remote_addr.sin_port));
            len = sendto(sockfd, ctx.response.head, ctx.response.len, 0,
                    (struct sockaddr *)&ctx.outer_remote_addr, src_addr_len);
            if (len < 0) {
                log_errnum_error("sendto");
            }
        }
    }

    return 0;
}
