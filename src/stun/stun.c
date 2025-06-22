// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "stun.h"

#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

#include "context.h"
#include "log.h"
#include "packet.h"
#include "version.h"

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

struct stun_mapped_address_v4 {
    uint8_t reserved;
    uint8_t family;
    uint16_t port;
    uint32_t address;
};

struct stun_mapped_address_v6 {
    uint8_t reserved;
    uint8_t family;
    uint16_t port;
    uint8_t address[sizeof(struct in6_addr)];
};

static void fill_mapped_address(struct context *ctx, struct stun_packet *req);
static void fill_mapped_address_v4(
        struct context *ctx, struct sockaddr_in *addr, struct stun_packet *req);
static void fill_mapped_address_v6(
        struct context *ctx, struct sockaddr_in6 *addr, struct stun_packet *req);
static void fill_software(struct context *ctx);
static void log_request_v4(const char *protocol_type, const struct sockaddr_in *addr);
static void log_request_v6(const char *protocol_type, const struct sockaddr_in6 *addr);

static const char SOFTWARE[] =
        "salty-stun " SALTY_STUN_VERSION " (" SALTY_STUN_SOURCE_URL ")";

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

    packet_reserve(&ctx->response, sizeof(struct stun_packet));
    struct packet response_attributes = ctx->response;

    fill_mapped_address(ctx, req);

    size_t content_len = ctx->response.len;
    ctx->response = response_attributes;
    packet_pop_head(&ctx->response, content_len);

    fill_software(ctx);

    content_len += ctx->response.len;
    ctx->response = response_attributes;
    packet_set_len(&ctx->response, content_len);

    struct stun_packet *resp = packet_push_head(&ctx->response, sizeof(*resp));

    resp->type = htobe16(STUN_TYPE_BINDING_RESPONSE);
    resp->length = htobe16(content_len);
    resp->magic_cookie = req->magic_cookie;
    memcpy(resp->transaction_id, req->transaction_id, sizeof(resp->transaction_id));

    return 0;
}

static void fill_mapped_address(struct context *ctx, struct stun_packet *req) {
    if (ctx->outer_remote_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&ctx->outer_remote_addr;
        if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
            struct sockaddr_in addr4;
            addr4.sin_family = AF_INET;
            static const size_t mapped_addr_offset =
                    sizeof(addr6->sin6_addr) - sizeof(addr4.sin_addr);
            memcpy(&addr4.sin_addr, &addr6->sin6_addr.s6_addr[mapped_addr_offset],
                    sizeof(addr4.sin_addr));
            addr4.sin_port = addr6->sin6_port;
            fill_mapped_address_v4(ctx, &addr4, req);
        } else {
            fill_mapped_address_v6(ctx, addr6, req);
        }
    } else {
        assert(ctx->outer_remote_addr.ss_family == AF_INET);
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&ctx->outer_remote_addr;
        fill_mapped_address_v4(ctx, addr4, req);
    }
}

static void fill_mapped_address_v4(
        struct context *ctx, struct sockaddr_in *addr, struct stun_packet *req) {
    struct stun_attr *attr = packet_set_len(
            &ctx->response, sizeof(*attr) + sizeof(struct stun_mapped_address_v4));
    struct stun_mapped_address_v4 *mapped_address =
            (struct stun_mapped_address_v4 *)attr->data;

    attr->length = htobe16(sizeof(*mapped_address));
    mapped_address->reserved = 0;
    mapped_address->family = STUN_ADDRESS_FAMILY_IPV4;

    if (req->magic_cookie == htobe32(STUN_MAGIC_COOKIE)) {
        attr->type = htobe16(STUN_ATTR_XOR_MAPPED_ADDRESS);
        mapped_address->port = addr->sin_port ^ htobe16(STUN_MAGIC_COOKIE >> 16);
        mapped_address->address = addr->sin_addr.s_addr ^ htobe32(STUN_MAGIC_COOKIE);
        log_request_v4("STUN", addr);
    } else {
        attr->type = htobe16(STUN_ATTR_MAPPED_ADDRESS);
        mapped_address->port = addr->sin_port;
        mapped_address->address = addr->sin_addr.s_addr;
        log_request_v4("classic STUN", addr);
    }
}

static void fill_mapped_address_v6(
        struct context *ctx, struct sockaddr_in6 *addr, struct stun_packet *req) {
    struct stun_attr *attr = packet_set_len(
            &ctx->response, sizeof(*attr) + sizeof(struct stun_mapped_address_v6));
    struct stun_mapped_address_v6 *mapped_address =
            (struct stun_mapped_address_v6 *)attr->data;

    attr->length = htobe16(sizeof(*mapped_address));
    mapped_address->reserved = 0;
    mapped_address->family = STUN_ADDRESS_FAMILY_IPV6;

    if (req->magic_cookie == htobe32(STUN_MAGIC_COOKIE)) {
        attr->type = htobe16(STUN_ATTR_XOR_MAPPED_ADDRESS);
        mapped_address->port = addr->sin6_port ^ htobe16(STUN_MAGIC_COOKIE >> 16);
        uint32_t *mapped_addr_words = (uint32_t *)mapped_address->address;
        uint32_t *addr_words = (uint32_t *)addr->sin6_addr.s6_addr;
        uint32_t *xor_words = &req->magic_cookie;
        for (int i = 0; i < 4; i++) {
            mapped_addr_words[i] = addr_words[i] ^ xor_words[i];
        }
        log_request_v6("STUN", addr);
    } else {
        attr->type = htobe16(STUN_ATTR_MAPPED_ADDRESS);
        mapped_address->port = addr->sin6_port;
        memcpy(mapped_address->address, addr->sin6_addr.s6_addr,
                sizeof(mapped_address->address));
        log_request_v6("classic STUN", addr);
    }
}

static void fill_software(struct context *ctx) {
    size_t software_len = sizeof(SOFTWARE) - 1;
    struct stun_attr *attr =
            packet_set_len(&ctx->response, sizeof(*attr) + software_len);

    attr->type = htobe16(STUN_ATTR_SOFTWARE);
    attr->length = htobe16(software_len);

    memcpy(attr->data, SOFTWARE, software_len);

    packet_pad(&ctx->response, sizeof(uint32_t));
}

static void log_request_v4(const char *protocol_type, const struct sockaddr_in *addr) {
    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, addr_str, sizeof(addr_str));
    log_info("%s binding request from %s port %d", protocol_type, addr_str,
            be16toh(addr->sin_port));
}

static void log_request_v6(const char *protocol_type, const struct sockaddr_in6 *addr) {
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr->sin6_addr, addr_str, sizeof(addr_str));
    log_info("%s binding request from %s port %d", protocol_type, addr_str,
            be16toh(addr->sin6_port));
}
