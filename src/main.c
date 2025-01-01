#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#include "args.h"
#include "log.h"
#include "packet.h"
#include "wireguard/wireguard.h"

int main(int argc, char *argv[]) {
    struct args args;
    parse_args(argc, argv, &args);

    if (sodium_init() == -1) {
        return 1;
    }
    log_init(args.level);

    struct wireguard wg;
    wireguard_init(&wg, args.private_key, args.key_log);

    // create UDP server
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_errnum_error("socket");
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(args.port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_errnum_error("bind");
        return 1;
    }
    log_info("Listening on port %d", args.port);

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

        packet_init(&ctx.request, request_buffer.bytes, len);
        packet_init(&ctx.response, response_buffer.bytes, sizeof(response_buffer));

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
