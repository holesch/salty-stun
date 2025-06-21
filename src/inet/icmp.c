// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "icmp.h"

#include <endian.h>
#include <stdint.h>

#include "context.h"
#include "inet/checksum.h"
#include "log.h"
#include "packet.h"

enum {
    ICMP_TYPE_ECHO_REPLY = 0,
    ICMP_TYPE_ECHO_REQUEST = 8,
    ICMPV6_TYPE_ECHO_REQUEST = 128,
    ICMPV6_TYPE_ECHO_REPLY = 129,
};

struct icmp_echo_packet {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence_number;
    uint8_t payload[];
};

static int handle_request(struct context *ctx, const char *protocol,
        uint8_t request_type, uint8_t response_type, uint32_t initial_sum);

int icmp_handle_request(struct context *ctx) {
    return handle_request(ctx, "ICMP", ICMP_TYPE_ECHO_REQUEST, ICMP_TYPE_ECHO_REPLY, 0);
}

int icmpv6_handle_request(struct context *ctx, uint32_t ip_header_sum) {
    uint32_t initial_sum = ip_header_sum + htobe16(ctx->request.len);
    return handle_request(ctx, "ICMPv6", ICMPV6_TYPE_ECHO_REQUEST,
            ICMPV6_TYPE_ECHO_REPLY, initial_sum);
}

static int handle_request(struct context *ctx, const char *protocol,
        uint8_t request_type, uint8_t response_type, uint32_t initial_sum) {
    struct icmp_echo_packet *req =
            packet_pop_head(&ctx->request, sizeof(struct icmp_echo_packet));
    if (!req) {
        log_warn("%s request too short", protocol);
        return 1;
    }

    if (req->type != request_type || req->code != 0x00) {
        log_warn("%s request type or code not supported: type=%d code=%d", protocol,
                req->type, req->code);
        return 1;
    }

    size_t payload_len = ctx->request.len;
    size_t total_len = sizeof(*req) + payload_len;
    if (inet_checksum((void *)req, total_len, initial_sum) != 0) {
        log_warn("%s request checksum is incorrect", protocol);
        return 1;
    }

    struct icmp_echo_packet *resp = packet_set_len(&ctx->response, total_len);
    resp->type = response_type;
    resp->code = 0x00;
    resp->checksum = 0;
    resp->identifier = req->identifier;
    resp->sequence_number = req->sequence_number;
    memcpy(resp->payload, req->payload, payload_len);

    resp->checksum = inet_checksum((void *)resp, total_len, initial_sum);

    return 0;
}
