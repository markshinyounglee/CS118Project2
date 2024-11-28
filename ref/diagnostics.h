#ifndef DIAGNOSTICS_H
#define DIAGNOSTICS_H

// Diagnostic messages
#define RECV 0
#define SEND 1
#define RTOS 2
#define DUPA 3
#define MIN(a, b) (a < b) ? a : b

static inline void print_tlv(uint8_t* buffer, size_t len) {
    uint8_t* buf = buffer;

    while (buf - buffer < len) {
        uint8_t type = *buf;
        fprintf(stderr, "Type: 0x%02x\n", type);
        buf += 1;
        if (buf - buffer >= len)
            return;

        uint16_t length = ntohs(*((uint16_t*) buf));
        buf += 2;
        fprintf(stderr, "Length: %hu\n", length);

        if (type == CLIENT_HELLO || type == SERVER_HELLO ||
            type == KEY_EXCHANGE_REQUEST || type == FINISHED ||
            type == CERTIFICATE || type == DATA)
            continue;
        else {
            uint16_t min_length = MIN(len - (buf - buffer), length);
            print_hex(buf, min_length);
            buf += min_length;
        }
    }
}

static inline void print_diag(packet* pkt, int diag) {
    switch (diag) {
    case RECV:
        fprintf(stderr, "RECV");
        break;
    case SEND:
        fprintf(stderr, "SEND");
        break;
    case RTOS:
        fprintf(stderr, "RTOS");
        break;
    case DUPA:
        fprintf(stderr, "DUPS");
        break;
    }

    bool syn = pkt->flags & 0b01;
    bool ack = pkt->flags & 0b10;
    fprintf(stderr, " %u ACK %u SIZE %hu FLAGS ", ntohl(pkt->seq),
            ntohl(pkt->ack), ntohs(pkt->length));
    if (!syn && !ack) {
        fprintf(stderr, "NONE");
    } else {
        if (syn) {
            fprintf(stderr, "SYN ");
        }
        if (ack) {
            fprintf(stderr, "ACK ");
        }
    }
    fprintf(stderr, "\n");
}

#endif