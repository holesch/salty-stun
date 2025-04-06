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
};

struct icmp_echo_packet {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence_number;
    uint8_t payload[];
};

int icmp_handle_request(struct context *ctx) {
    struct icmp_echo_packet *req =
            packet_pop_head(&ctx->request, sizeof(struct icmp_echo_packet));
    if (!req) {
        log_warn("ICMP request too short");
        return 1;
    }

    if (req->type != ICMP_TYPE_ECHO_REQUEST || req->code != 0x00) {
        log_warn("ICMP request type or code not supported: type=%d code=%d", req->type,
                req->code);
        return 1;
    }

    size_t payload_len = ctx->request.len;
    if (inet_checksum((void *)req, sizeof(*req) + payload_len, 0) != 0) {
        log_warn("ICMP request checksum is incorrect");
        return 1;
    }

    struct icmp_echo_packet *resp =
            packet_set_len(&ctx->response, sizeof(*resp) + payload_len);
    resp->type = ICMP_TYPE_ECHO_REPLY;
    resp->code = 0x00;
    resp->checksum = 0;
    resp->identifier = req->identifier;
    resp->sequence_number = req->sequence_number;
    memcpy(resp->payload, req->payload, payload_len);

    resp->checksum = inet_checksum((void *)resp, sizeof(*resp) + payload_len, 0);

    return 0;
}
