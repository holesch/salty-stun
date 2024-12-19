#include "udp.h"

#include <endian.h>
#include <stdint.h>

#include "context.h"
#include "log.h"
#include "packet.h"
#include "stun/stun.h"

enum {
    UDP_PORT_STUN = 3478,
};

struct udp_packet {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t data[];
};

int udp_handle_request(struct context *ctx) {
    int err = 0;

    if (ctx->request.len < sizeof(struct udp_packet)) {
        log_warn("UDP packet is too short");
        return 1;
    }

    struct udp_packet *req = (struct udp_packet *)ctx->request.head;

    if (ctx->request.len != be16toh(req->length)) {
        log_warn("UDP length is incorrect: %u != %u", ctx->request.len,
                be16toh(req->length));
        return 1;
    }

    packet_shrink(&ctx->request, sizeof(*req));
    packet_reserve(&ctx->response, sizeof(struct udp_packet));

    switch (be16toh(req->destination_port)) {
    case UDP_PORT_STUN:
        err = stun_handle_request(ctx);
        break;
    default:
        log_warn("Unknown UDP destination port: %u", be16toh(req->destination_port));
        err = 1;
    }

    if (err) {
        return 1;
    }

    packet_expand(&ctx->response, sizeof(struct udp_packet));
    packet_expand(&ctx->request, sizeof(*req));
    struct udp_packet *resp = (struct udp_packet *)ctx->response.head;

    resp->source_port = req->destination_port;
    resp->destination_port = req->source_port;
    resp->length = htobe16(ctx->response.len);
    resp->checksum = 0;

    return 0;
}
