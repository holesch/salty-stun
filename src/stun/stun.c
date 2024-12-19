#include "stun.h"

#include <endian.h>
#include <stdint.h>

#include "context.h"
#include "log.h"
#include "packet.h"

enum {
    STUN_MAGIC_COOKIE = 0x2112A442,
    STUN_ADDRESS_FAMILY_IPV4 = 0x01,
    STUN_ADDRESS_FAMILY_IPV6 = 0x02,
    STUN_TRANSACTION_ID_LENGTH = 12,
};

enum {
    STUN_TYPE_BINDING_REQUEST = 0x0001,
    STUN_TYPE_BINDING_RESPONSE = 0x0101,
    STUN_TYPE_BINDING_ERROR_RESPONSE = 0x0111,
};

enum {
    STUN_ATTR_MAPPED_ADDRESS = 0x0001,
    STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020,
    STUN_ATTR_ERROR_CODE = 0x0009,
    STUN_ATTR_UNKNOWN_ATTRIBUTES = 0x000A,
    STUN_ATTR_SOFTWARE = 0x8022,
};

struct stun_packet {
    uint16_t type;
    uint16_t length;
    uint32_t magic_cookie;
    uint8_t transaction_id[STUN_TRANSACTION_ID_LENGTH];
    uint8_t data[];
};

struct stun_attr {
    uint16_t type;
    uint16_t length;
    uint8_t data[];
};

struct stun_mapped_address {
    uint8_t reserved;
    uint8_t family;
    uint16_t port;
    uint32_t address;
};

int stun_handle_request(struct context *ctx) {
    struct stun_packet *req = packet_pop_head(&ctx->request, sizeof(*req));
    if (!req) {
        log_warn("STUN packet is too short");
        return 1;
    }

    if (req->type != htobe16(STUN_TYPE_BINDING_REQUEST)) {
        log_warn("Unknown STUN message type: 0x%04x", be16toh(req->type));
        return 1;
    }

    if (req->length != htobe16(0)) {
        log_warn("Ignoring STUN binding request with attributes");
        return 1;
    }

    uint32_t remote_addr = ctx->outer_remote_addr.sin_addr.s_addr;
    uint16_t remote_port = ctx->outer_remote_addr.sin_port;

    size_t response_len = sizeof(struct stun_packet) + sizeof(struct stun_attr) +
            sizeof(struct stun_mapped_address);
    struct stun_packet *resp = packet_set_len(&ctx->response, response_len);
    struct stun_attr *attr = (struct stun_attr *)resp->data;
    struct stun_mapped_address *mapped_address =
            (struct stun_mapped_address *)attr->data;

    resp->type = htobe16(STUN_TYPE_BINDING_RESPONSE);
    resp->length = htobe16(sizeof(*attr) + sizeof(*mapped_address));
    resp->magic_cookie = req->magic_cookie;
    memcpy(resp->transaction_id, req->transaction_id, sizeof(resp->transaction_id));

    attr->length = htobe16(sizeof(*mapped_address));
    mapped_address->reserved = 0;
    mapped_address->family = STUN_ADDRESS_FAMILY_IPV4;

    if (req->magic_cookie == htobe32(STUN_MAGIC_COOKIE)) {
        attr->type = htobe16(STUN_ATTR_XOR_MAPPED_ADDRESS);
        mapped_address->port = remote_port ^ htobe16(STUN_MAGIC_COOKIE >> 16);
        mapped_address->address = remote_addr ^ htobe32(STUN_MAGIC_COOKIE);
    } else {
        attr->type = htobe16(STUN_ATTR_MAPPED_ADDRESS);
        mapped_address->port = remote_port;
        mapped_address->address = remote_addr;
    }

    return 0;
}
