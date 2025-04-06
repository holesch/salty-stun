#include "ip.h"

#include <assert.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdint.h>

#include "context.h"
#include "inet/checksum.h"
#include "inet/icmp.h"
#include "inet/udp.h"
#include "log.h"
#include "packet.h"

enum {
    IPV4_VERSION = 4,
    IPV4_MORE_FRAGMENTS_MASK = 0x2000,
    IPV4_DEFAULT_TTL = 64,
    IPV6_VERSION = 6,
    IPV6_DEFAULT_HOP_LIMIT = IPV4_DEFAULT_TTL,
};

enum {
    IP_PROTOCOL_ICMP = 1,
    IP_PROTOCOL_UDP = 17,
    IP_PROTOCOL_ICMPV6 = 58,
};

struct ipv4_packet {
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

struct ipv6_packet {
    uint32_t version_traffic_class_flow_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source_ip[sizeof(struct in6_addr)];
    uint8_t destination_ip[sizeof(struct in6_addr)];
};

static int ipv4_handle_request(struct context *ctx);
static uint32_t calculate_ipv4_pseudo_header_sum(const struct ipv4_packet *req);
static int ipv6_handle_request(struct context *ctx);
static uint32_t calculate_ipv6_pseudo_header_sum(const struct ipv6_packet *req);

int ip_handle_request(struct context *ctx) {
    assert(ctx->request.len > 0);

    uint8_t *version_head = packet_peak_head(&ctx->request, sizeof(uint8_t));
    uint8_t version = *version_head >> 4;

    switch (version) {
    case IPV4_VERSION:
        return ipv4_handle_request(ctx);
    case IPV6_VERSION:
        return ipv6_handle_request(ctx);
    default:
        log_warn("Unsupported IP version: %d", version);
    }

    return 1;
}

static int ipv4_handle_request(struct context *ctx) {
    int err = 0;

    struct ipv4_packet *req =
            packet_pop_head(&ctx->request, sizeof(struct ipv4_packet));
    if (!req) {
        log_warn("IP packet is too short");
        return 1;
    }

    size_t ihl = sizeof(*req) / sizeof(uint32_t);
    if (req->version_ihl != (IPV4_VERSION << 4 | ihl)) {
        log_warn("IP version or IHL is incorrect: 0x%02x", req->version_ihl);
        return 1;
    }

    if (inet_checksum((void *)req, sizeof(*req), 0) != 0) {
        log_warn("IP checksum is incorrect");
        return 1;
    }

    int more_fragments = be16toh(req->flags_fragment_offset) & IPV4_MORE_FRAGMENTS_MASK;
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

    packet_reserve(&ctx->response, sizeof(struct ipv4_packet));

    switch (req->protocol) {
    case IP_PROTOCOL_ICMP:
        err = icmp_handle_request(ctx);
        break;
    case IP_PROTOCOL_UDP: {
        uint32_t ip_header_sum = calculate_ipv4_pseudo_header_sum(req);
        err = udp_handle_request(ctx, ip_header_sum);
        break;
    }
    default:
        log_warn("Unsupported IP protocol: %d", req->protocol);
        err = 1;
    }

    if (err) {
        return 1;
    }

    struct ipv4_packet *resp = packet_push_head(&ctx->response, sizeof(*resp));

    resp->version_ihl = IPV4_VERSION << 4 | ihl;
    resp->dscp_ecn = 0;
    resp->total_length = htobe16(ctx->response.len);
    resp->identification = 0;
    resp->flags_fragment_offset = 0;
    resp->ttl = IPV4_DEFAULT_TTL;
    resp->protocol = req->protocol;
    resp->checksum = 0;
    resp->source_ip = req->destination_ip;
    resp->destination_ip = req->source_ip;

    resp->checksum = inet_checksum((void *)resp, sizeof(*resp), 0);

    return 0;
}

static uint32_t calculate_ipv4_pseudo_header_sum(const struct ipv4_packet *req) {
    uint32_t sum = 0;
    const uint16_t *data16 = (const uint16_t *)&req->source_ip;
    size_t len =
            (sizeof(req->source_ip) + sizeof(req->destination_ip)) / sizeof(*data16);

    for (size_t i = 0; i < len; i++) {
        sum += data16[i];
    }

    sum += htobe16(IP_PROTOCOL_UDP);
    return sum;
}

static int ipv6_handle_request(struct context *ctx) {
    struct ipv6_packet *req =
            packet_pop_head(&ctx->request, sizeof(struct ipv6_packet));
    if (!req) {
        log_warn("IPv6 packet is too short");
        return 1;
    }

    size_t data_len = ctx->request.len;
    size_t payload_length = be16toh(req->payload_length);
    if (data_len < payload_length) {
        log_warn("IPv6 payload is too short");
        return 1;
    }
    // Wireguard adds padding. Remove it here.
    packet_pop_tail(&ctx->request, data_len - payload_length);

    packet_reserve(&ctx->response, sizeof(struct ipv6_packet));

    int err = 0;
    switch (req->next_header) {
    case IP_PROTOCOL_ICMPV6: {
        uint32_t ip_header_sum = calculate_ipv6_pseudo_header_sum(req);
        err = icmpv6_handle_request(ctx, ip_header_sum);
        break;
    }
    default:
        log_warn("Unsupported IP protocol: %d", req->next_header);
        err = 1;
    }

    if (err) {
        return 1;
    }

    struct ipv6_packet *resp = packet_push_head(&ctx->response, sizeof(*resp));

    resp->version_traffic_class_flow_label = req->version_traffic_class_flow_label;
    resp->payload_length = htobe16(ctx->response.len - sizeof(*resp));
    resp->next_header = req->next_header;
    resp->hop_limit = IPV6_DEFAULT_HOP_LIMIT;
    memcpy(resp->source_ip, req->destination_ip, sizeof(req->destination_ip));
    memcpy(resp->destination_ip, req->source_ip, sizeof(req->source_ip));

    return 0;
}

static uint32_t calculate_ipv6_pseudo_header_sum(const struct ipv6_packet *req) {
    uint32_t sum = 0;
    const uint16_t *data16 = (const uint16_t *)req->source_ip;
    size_t len =
            (sizeof(req->source_ip) + sizeof(req->destination_ip)) / sizeof(*data16);

    for (size_t i = 0; i < len; i++) {
        sum += data16[i];
    }

    sum += htobe16(req->next_header);
    return sum;
}
