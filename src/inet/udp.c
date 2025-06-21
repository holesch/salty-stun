// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "udp.h"

#include <endian.h>
#include <stdint.h>

#include "checksum.h"
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

int udp_handle_request(struct context *ctx, uint32_t ip_header_sum) {
    int err = 0;

    struct udp_packet *req = packet_pop_head(&ctx->request, sizeof(*req));
    if (!req) {
        log_warn("UDP packet is too short");
        return 1;
    }

    size_t data_len = ctx->request.len;
    size_t total_len = sizeof(*req) + data_len;
    if (be16toh(req->length) != total_len) {
        log_warn("UDP length is incorrect: expected %zu, got %u", total_len,
                be16toh(req->length));
        return 1;
    }

    if (be16toh(req->checksum) != 0) {
        uint32_t initial_sum = ip_header_sum + req->length;
        uint16_t checksum = inet_checksum((void *)req, total_len, initial_sum);
        if (checksum != 0) {
            log_warn("UDP checksum is incorrect");
            return 1;
        }
    }

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

    struct udp_packet *resp = packet_push_head(&ctx->response, sizeof(*resp));
    resp->source_port = req->destination_port;
    resp->destination_port = req->source_port;
    resp->length = htobe16(ctx->response.len);
    resp->checksum = 0;

    uint32_t initial_sum = ip_header_sum + resp->length;
    resp->checksum = inet_checksum((void *)resp, ctx->response.len, initial_sum);
    if (resp->checksum == 0) {
        resp->checksum = UINT16_MAX;
    }

    return 0;
}
