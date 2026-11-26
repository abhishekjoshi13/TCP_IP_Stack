
#include "tcp_ip_stack.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define IPV4_MIN_HEADER_SIZE 20
#define IPV4_MAX_HEADER_SIZE 60
#define IPV4_MAX_PACKET_SIZE 65535
#define ICMP_MAX_PACKET_SIZE (IPV4_MAX_PACKET_SIZE - IPV4_MIN_HEADER_SIZE)

uint8_t local_mac[ETH_ALEN] = {
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc
};

uint32_t local_ip = 0;
arp_entry arp_table[MAX_ARP_ENTRIES];
tcp_connection tcp_connections[TCP_MAX_PORTS];
int arp_count = 0;

static bool is_valid_mac(const uint8_t* mac) {
    if (mac == NULL || (mac[0] & 0x01) != 0) {
        return false;
    }

    static const uint8_t zero_mac[ETH_ALEN] = {0};

    return memcmp(mac, zero_mac, ETH_ALEN) != 0;
}

void network_init(const char* ip_str) {
    local_ip = parse_ipv4(ip_str);

    memset(arp_table, 0, sizeof(arp_table));
    memset(tcp_connections, 0, sizeof(tcp_connections));

    arp_count = 0;

    if (local_ip == 0) {
        printf("Warning: Invalid or unspecified IPv4 address.\n");
        return;
    }

    printf("Network initialized: IP ");
    print_ip(local_ip);
    printf(", MAC ");
    print_mac(local_mac);
    printf("\n");
}

void process_frame(const uint8_t* frame, size_t length) {
    if (frame == NULL || length < sizeof(struct eth_header)) {
        return;
    }

    const struct eth_header* eth =
        (const struct eth_header*)frame;

    uint16_t ethertype = ntohs(eth->ethertype);

    static const uint8_t broadcast_mac[ETH_ALEN] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    bool is_broadcast =
        memcmp(eth->dst_mac, broadcast_mac, ETH_ALEN) == 0;

    bool is_for_us =
        memcmp(eth->dst_mac, local_mac, ETH_ALEN) == 0;

    if (!is_for_us && !is_broadcast) {
        return;
    }

    const uint8_t* payload =
        frame + sizeof(struct eth_header);

    size_t payload_len =
        length - sizeof(struct eth_header);

    switch (ethertype) {
        case ETHERTYPE_ARP:
            process_arp(payload, payload_len);
            break;

        case ETHERTYPE_IP:
            process_ip(payload, payload_len);
            break;

        default:
            break;
    }
}

void process_arp(const uint8_t* packet, size_t length) {
    if (packet == NULL || length < sizeof(struct arp_header)) {
        return;
    }

    const struct arp_header* arp =
        (const struct arp_header*)packet;

    uint16_t hw_type = ntohs(arp->hw_type);
    uint16_t proto_type = ntohs(arp->proto_type);
    uint16_t opcode = ntohs(arp->opcode);

    if (hw_type != 1 ||
        proto_type != ETHERTYPE_IP ||
        arp->hw_len != ETH_ALEN ||
        arp->proto_len != 4) {
        return;
    }

    if (opcode != ARP_OP_REQUEST && opcode != ARP_OP_REPLY) {
        return;
    }

    if (!is_valid_mac(arp->sender_mac)) {
        return;
    }

    uint32_t sender_ip = ntohl(arp->sender_ip);
    uint32_t target_ip = ntohl(arp->target_ip);

    if (target_ip != local_ip) {
        return;
    }

    if (sender_ip != 0) {
        add_arp_entry(sender_ip, arp->sender_mac);
    }

    if (opcode == ARP_OP_REQUEST) {
        uint8_t reply[
            sizeof(struct eth_header) + sizeof(struct arp_header)
        ] = {0};

        struct eth_header* eth_reply =
            (struct eth_header*)reply;

        struct arp_header* arp_reply =
            (struct arp_header*)(reply + sizeof(struct eth_header));

        memcpy(eth_reply->dst_mac, arp->sender_mac, ETH_ALEN);
        memcpy(eth_reply->src_mac, local_mac, ETH_ALEN);

        eth_reply->ethertype = htons(ETHERTYPE_ARP);

        arp_reply->hw_type = htons(1);
        arp_reply->proto_type = htons(ETHERTYPE_IP);
        arp_reply->hw_len = ETH_ALEN;
        arp_reply->proto_len = 4;
        arp_reply->opcode = htons(ARP_OP_REPLY);

        memcpy(arp_reply->sender_mac, local_mac, ETH_ALEN);
        arp_reply->sender_ip = htonl(local_ip);

        memcpy(arp_reply->target_mac, arp->sender_mac, ETH_ALEN);
        arp_reply->target_ip = arp->sender_ip;

        printf("ARP reply prepared for ");
        print_ip(sender_ip);
        printf("\n");
    }
}

void process_ip(const uint8_t* packet, size_t length) {
    if (packet == NULL || length < IPV4_MIN_HEADER_SIZE) {
        return;
    }

    const struct ip_header* ip =
        (const struct ip_header*)packet;

    uint8_t version = ip->version_ihl >> 4;

    size_t hdr_len =
        (size_t)(ip->version_ihl & 0x0F) * 4;

    if (version != 4) {
        return;
    }

    if (hdr_len < IPV4_MIN_HEADER_SIZE ||
        hdr_len > IPV4_MAX_HEADER_SIZE) {
        return;
    }

    if (hdr_len > length) {
        return;
    }

    size_t total_len = ntohs(ip->total_len);

    if (total_len < hdr_len ||
        total_len > length ||
        total_len > IPV4_MAX_PACKET_SIZE) {
        return;
    }

    uint8_t header_copy[IPV4_MAX_HEADER_SIZE];

    memcpy(header_copy, packet, hdr_len);

    header_copy[10] = 0;
    header_copy[11] = 0;

    uint16_t calculated_checksum =
        calculate_checksum(header_copy, hdr_len);

    if (ip->checksum != calculated_checksum) {
        return;
    }

    uint16_t flags_frag = ntohs(ip->flags_frag);

    if ((flags_frag & 0x3FFF) != 0) {
        return;
    }

    uint32_t dst_ip = ntohl(ip->dst_ip);

    if (dst_ip != local_ip) {
        return;
    }

    if (ip->ttl == 0) {
        return;
    }

    const uint8_t* payload = packet + hdr_len;

    size_t payload_len = total_len - hdr_len;

    switch (ip->protocol) {
        case IP_PROTOCOL_ICMP:
            process_icmp(
                payload,
                payload_len,
                ntohl(ip->src_ip)
            );
            break;

        case IP_PROTOCOL_TCP:
            process_tcp(
                payload,
                payload_len,
                ntohl(ip->src_ip)
            );
            break;

        default:
            break;
    }
}

void process_icmp(
    const uint8_t* packet,
    size_t length,
    uint32_t src_ip
) {
    if (packet == NULL ||
        length < sizeof(struct icmp_header) ||
        length > ICMP_MAX_PACKET_SIZE) {
        return;
    }

    const struct icmp_header* icmp =
        (const struct icmp_header*)packet;

    if (calculate_checksum(packet, length) != 0) {
        return;
    }

    if (icmp->type != ICMP_TYPE_ECHO_REQUEST ||
        icmp->code != 0) {
        return;
    }

    size_t reply_size =
        sizeof(struct eth_header) +
        sizeof(struct ip_header) +
        length;

    uint8_t* reply = (uint8_t*)calloc(1, reply_size);

    if (reply == NULL) {
        return;
    }

    struct eth_header* eth_reply =
        (struct eth_header*)reply;

    struct ip_header* ip_reply =
        (struct ip_header*)(reply + sizeof(struct eth_header));

    struct icmp_header* icmp_reply =
        (struct icmp_header*)(
            reply +
            sizeof(struct eth_header) +
            sizeof(struct ip_header)
        );

    memset(eth_reply->dst_mac, 0, ETH_ALEN);
    memcpy(eth_reply->src_mac, local_mac, ETH_ALEN);

    eth_reply->ethertype = htons(ETHERTYPE_IP);

    ip_reply->version_ihl = 0x45;
    ip_reply->tos = 0;

    ip_reply->total_len =
        htons((uint16_t)(sizeof(struct ip_header) + length));

    ip_reply->ident = htons(12345);
    ip_reply->flags_frag = 0;
    ip_reply->ttl = 64;
    ip_reply->protocol = IP_PROTOCOL_ICMP;
    ip_reply->checksum = 0;

    ip_reply->src_ip = htonl(local_ip);
    ip_reply->dst_ip = htonl(src_ip);

    ip_reply->checksum =
        calculate_checksum(ip_reply, sizeof(struct ip_header));

    icmp_reply->type = ICMP_TYPE_ECHO_REPLY;
    icmp_reply->code = 0;
    icmp_reply->checksum = 0;

    icmp_reply->identifier = icmp->identifier;
    icmp_reply->sequence = icmp->sequence;

    memcpy(
        (uint8_t*)icmp_reply + sizeof(struct icmp_header),
        packet + sizeof(struct icmp_header),
        length - sizeof(struct icmp_header)
    );

    icmp_reply->checksum =
        calculate_checksum(icmp_reply, length);

    printf("ICMP reply prepared for ");
    print_ip(src_ip);
    printf("\n");

    free(reply);
}

void process_tcp(
    const uint8_t* packet,
    size_t length,
    uint32_t src_ip
) {
    if (packet == NULL ||
        length < sizeof(struct tcp_header)) {
        return;
    }

    const struct tcp_header* tcp =
        (const struct tcp_header*)packet;

    size_t hdr_len =
        (size_t)(tcp->data_offset >> 4) * 4;

    if (hdr_len < sizeof(struct tcp_header) ||
        hdr_len > 60) {
        return;
    }

    if (hdr_len > length) {
        return;
    }

    const uint8_t* payload = packet + hdr_len;

    size_t payload_len = length - hdr_len;

    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dst_port = ntohs(tcp->dst_port);

    printf(
        "TCP packet: %u -> %u, flags=0x%02x",
        (unsigned int)src_port,
        (unsigned int)dst_port,
        tcp->flags
    );

    if (payload_len > 0) {
        size_t display_len =
            payload_len > 20 ? 20 : payload_len;

        printf(", data: ");

        for (size_t i = 0; i < display_len; i++) {
            printf("%02x", payload[i]);

            if (i + 1 < display_len) {
                printf(" ");
            }
        }
    }

    printf("\n");

    if (tcp->flags & TCP_SYN) {
        printf(
            "TCP connection attempt on port %u\n",
            (unsigned int)dst_port
        );
    }

    (void)src_ip;
}

uint16_t calculate_checksum(
    const void* data,
    size_t length
) {
    if (data == NULL || length == 0) {
        return 0;
    }

    const uint8_t* bytes = (const uint8_t*)data;

    uint32_t sum = 0;

    size_t i = 0;

    while (i + 1 < length) {
        uint16_t word =
            ((uint16_t)bytes[i] << 8) |
            (uint16_t)bytes[i + 1];

        sum += word;
        i += 2;
    }

    if (i < length) {
        sum += (uint16_t)bytes[i] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return htons((uint16_t)(~sum));
}

uint32_t parse_ipv4(const char* ip_str) {
    if (ip_str == NULL || *ip_str == '\0') {
        return 0;
    }

    uint32_t ip = 0;

    const char* p = ip_str;

    for (int part = 0; part < 4; part++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }

        unsigned int value = 0;
        unsigned int digits = 0;

        while (*p >= '0' && *p <= '9') {
            value = value * 10 + (unsigned int)(*p - '0');

            if (value > 255) {
                return 0;
            }

            p++;
            digits++;
        }

        if (digits == 0) {
            return 0;
        }

        ip = (ip << 8) | value;

        if (part < 3) {
            if (*p != '.') {
                return 0;
            }

            p++;
        } else if (*p != '\0') {
            return 0;
        }
    }

    return ip;
}

void print_mac(const uint8_t* mac) {
    if (mac == NULL) {
        return;
    }

    printf(
        "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5]
    );
}

void print_ip(uint32_t ip) {
    printf(
        "%u.%u.%u.%u",
        (unsigned int)((ip >> 24) & 0xFF),
        (unsigned int)((ip >> 16) & 0xFF),
        (unsigned int)((ip >> 8) & 0xFF),
        (unsigned int)(ip & 0xFF)
    );
}

bool add_arp_entry(uint32_t ip, const uint8_t* mac) {
    if (mac == NULL ||
        !is_valid_mac(mac) ||
        ip == 0 ||
        arp_count < 0 ||
        arp_count > MAX_ARP_ENTRIES) {
        return false;
    }

    for (int i = 0; i < arp_count; i++) {
        if (arp_table[i].ip == ip) {
            memcpy(arp_table[i].mac, mac, ETH_ALEN);
            arp_table[i].timestamp = (uint32_t)time(NULL);
            return true;
        }
    }

    if (arp_count < MAX_ARP_ENTRIES) {
        arp_table[arp_count].ip = ip;

        memcpy(
            arp_table[arp_count].mac,
            mac,
            ETH_ALEN
        );

        arp_table[arp_count].timestamp =
            (uint32_t)time(NULL);

        arp_count++;

        return true;
    }

    return false;
}
