#include "icmp.h"

#include <endian.h>
#include <stdint.h>

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
    uint8_t data[];
};

int icmp_handle_request(struct packet *request, struct packet *response) {
    if (request->len < sizeof(struct icmp_echo_packet)) {
        log_warn("ICMP request too short");
        return 1;
    }

    struct icmp_echo_packet *req = (struct icmp_echo_packet *)request->head;

    if (req->type != ICMP_TYPE_ECHO_REQUEST || req->code != 0x00) {
        log_warn("ICMP request type or code not supported: type=%d code=%d", req->type,
                req->code);
        return 1;
    }

    if (inet_checksum((void *)req, request->len) != 0) {
        log_warn("ICMP request checksum is incorrect");
        return 1;
    }

    response->len = request->len;
    struct icmp_echo_packet *resp = (struct icmp_echo_packet *)response->head;
    resp->type = ICMP_TYPE_ECHO_REPLY;
    resp->code = 0x00;
    resp->checksum = 0;
    resp->identifier = req->identifier;
    resp->sequence_number = req->sequence_number;
    memcpy(resp->data, req->data, request->len - sizeof(struct icmp_echo_packet));

    resp->checksum = inet_checksum((void *)resp, response->len);

    return 0;
}
