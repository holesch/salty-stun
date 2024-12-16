#include "ip.h"

#include <endian.h>
#include <stdint.h>

#include "inet/checksum.h"
#include "inet/icmp.h"
#include "packet.h"

enum {
    IP_VERSION = 4,
    IP_MORE_FRAGMENTS_MASK = 0x2000,
    IP_DEFAULT_TTL = 64,
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

int ip_handle_request(struct packet *request, struct packet *response) {
    int err = 0;

    if (request->len < sizeof(struct ip_packet)) {
        return 1;
    }

    struct ip_packet *req = (struct ip_packet *)request->head;

    size_t ihl = sizeof(*req) / sizeof(uint32_t);
    if (req->version_ihl != (IP_VERSION << 4 | ihl)) {
        return 1;
    }

    if (inet_checksum((void *)request->head, sizeof(struct ip_packet)) != 0) {
        return 1;
    }

    int more_fragments = req->flags_fragment_offset & IP_MORE_FRAGMENTS_MASK;
    if (more_fragments) {
        return 1;
    }

    size_t packet_len = be16toh(req->total_length);
    if (request->len < packet_len) {
        return 1;
    }
    request->len = packet_len;
    packet_shrink(request, sizeof(struct ip_packet));
    packet_reserve(response, sizeof(struct ip_packet));

    switch (req->protocol) {
    case 1:
        err = icmp_handle_request(request, response);
        break;
    // case 17:
    //     return udp_handle_request(request, response);
    //     break;
    default:
        err = 1;
    }

    if (err) {
        return 1;
    }

    packet_expand(response, sizeof(struct ip_packet));
    packet_expand(request, sizeof(struct ip_packet));
    struct ip_packet *resp = (struct ip_packet *)response->head;

    resp->version_ihl = IP_VERSION << 4 | ihl;
    resp->dscp_ecn = 0;
    resp->total_length = htobe16(response->len);
    resp->identification = 0;
    resp->flags_fragment_offset = 0;
    resp->ttl = IP_DEFAULT_TTL;
    resp->protocol = req->protocol;
    resp->checksum = 0;
    resp->source_ip = req->destination_ip;
    resp->destination_ip = req->source_ip;

    resp->checksum = inet_checksum((void *)response->head, sizeof(struct ip_packet));

    return 0;
}
