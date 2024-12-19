#include "ip.h"

#include <endian.h>
#include <stdint.h>

#include "context.h"
#include "inet/checksum.h"
#include "inet/icmp.h"
#include "inet/udp.h"
#include "log.h"
#include "packet.h"

enum {
    IP_VERSION = 4,
    IP_MORE_FRAGMENTS_MASK = 0x2000,
    IP_DEFAULT_TTL = 64,
};

enum {
    IP_PROTOCOL_ICMP = 1,
    IP_PROTOCOL_UDP = 17,
};

struct ip_packet {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t data[];
};

int ip_handle_request(struct context *ctx) {
    int err = 0;

    struct ip_packet *req = packet_pop_head(&ctx->request, sizeof(struct ip_packet));
    if (!req) {
        log_warn("IP packet is too short");
        return 1;
    }

    size_t ihl = sizeof(*req) / sizeof(uint32_t);
    if (req->version_ihl != (IP_VERSION << 4 | ihl)) {
        log_warn("IP version or IHL is incorrect: 0x%02x", req->version_ihl);
        return 1;
    }

    if (inet_checksum((void *)req, sizeof(*req)) != 0) {
        log_warn("IP checksum is incorrect");
        return 1;
    }

    int more_fragments = req->flags_fragment_offset & IP_MORE_FRAGMENTS_MASK;
    if (more_fragments) {
        log_warn("Dropping fragmented IP packet");
        return 1;
    }

    size_t data_len = ctx->request.len;
    size_t total_len = be16toh(req->total_length);
    if (data_len + sizeof(*req) < total_len) {
        log_warn("IP packet is too short");
        return 1;
    }
    // Wireguard adds padding. Remove it here.
    packet_pop_tail(&ctx->request, (sizeof(*req) + data_len) - total_len);

    packet_reserve(&ctx->response, sizeof(struct ip_packet));

    switch (req->protocol) {
    case IP_PROTOCOL_ICMP:
        err = icmp_handle_request(ctx);
        break;
    case IP_PROTOCOL_UDP:
        err = udp_handle_request(ctx);
        break;
    default:
        log_warn("Unsupported IP protocol: %d", req->protocol);
        err = 1;
    }

    if (err) {
        return 1;
    }

    struct ip_packet *resp = packet_push_head(&ctx->response, sizeof(*resp));

    resp->version_ihl = IP_VERSION << 4 | ihl;
    resp->dscp_ecn = 0;
    resp->total_length = htobe16(ctx->response.len);
    resp->identification = 0;
    resp->flags_fragment_offset = 0;
    resp->ttl = IP_DEFAULT_TTL;
    resp->protocol = req->protocol;
    resp->checksum = 0;
    resp->source_ip = req->destination_ip;
    resp->destination_ip = req->source_ip;

    resp->checksum = inet_checksum((void *)resp, sizeof(*resp));

    return 0;
}
