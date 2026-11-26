#include "tcp_ip_stack.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

uint8_t local_mac[ETH_ALEN] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
uint32_t local_ip = 0;
arp_entry arp_table[MAX_ARP_ENTRIES];
tcp_connection tcp_connections[TCP_MAX_PORTS];
int arp_count = 0;

void network_init(const char* ip_str) {
    local_ip = parse_ipv4(ip_str);
    memset(arp_table, 0, sizeof(arp_table));
    memset(tcp_connections, 0, sizeof(tcp_connections));
    printf("Network initialized: IP ");
    print_ip(local_ip);
    printf(", MAC ");
    print_mac(local_mac);
    printf("\n");
}

void process_frame(const uint8_t* frame, size_t length) {
    if (length < sizeof(struct eth_header)) {
        return;
    }

    struct eth_header* eth = (struct eth_header*)frame;
    uint16_t ethertype = ntohs(eth->ethertype);

    int is_broadcast = memcmp(eth->dst_mac, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) == 0;
    int is_for_us = memcmp(eth->dst_mac, local_mac, ETH_ALEN) == 0;

    if (!is_for_us && !is_broadcast) {
        return;
    }

    const uint8_t* payload = frame + sizeof(struct eth_header);
    size_t payload_len = length - sizeof(struct eth_header);

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
    if (length < sizeof(struct arp_header)) {
        return;
    }

    struct arp_header* arp = (struct arp_header*)packet;
    uint16_t opcode = ntohs(arp->opcode);
    uint32_t target_ip = ntohl(arp->target_ip);

    if (target_ip != local_ip) {
        return;
    }

    add_arp_entry(ntohl(arp->sender_ip), arp->sender_mac);

    if (opcode == ARP_OP_REQUEST) {
        uint8_t reply[sizeof(struct eth_header) + sizeof(struct arp_header)];
        struct eth_header* eth_reply = (struct eth_header*)reply;
        struct arp_header* arp_reply = (struct arp_header*)(reply + sizeof(struct eth_header));

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
        print_ip(ntohl(arp->sender_ip));
        printf("\n");
    }
}


void process_ip(const uint8_t* packet, size_t length) {
    if (packet == NULL || length < sizeof(struct ip_header)) {
        return;
    }

    const struct ip_header* ip = (const struct ip_header*)packet;

    uint8_t version = ip->version_ihl >> 4;
    size_t hdr_len = (size_t)(ip->version_ihl & 0x0F) * 4;

    if (version != 4) {
        return;
    }

    if (hdr_len < sizeof(struct ip_header) || hdr_len > 60) {
        return;
    }

    if (hdr_len > length) {
        return;
    }

    size_t total_len = ntohs(ip->total_len);

    if (total_len < hdr_len || total_len > length) {
        return;
    }

    uint16_t header_words[30] = {0};

    memcpy(header_words, packet, hdr_len);

    uint8_t* header_bytes = (uint8_t*)header_words;
    header_bytes[10] = 0;
    header_bytes[11] = 0;

    uint16_t calculated_checksum =
        calculate_checksum(header_words, hdr_len);

    if (ip->checksum != calculated_checksum) {
        return;
    }

    uint32_t dst_ip = ntohl(ip->dst_ip);

    if (dst_ip != local_ip) {
        return;
    }

    const uint8_t* payload = packet + hdr_len;
    size_t payload_len = total_len - hdr_len;

    switch (ip->protocol) {
        case IP_PROTOCOL_ICMP:
            process_icmp(payload, payload_len, ntohl(ip->src_ip));
            break;

        case IP_PROTOCOL_TCP:
            process_tcp(payload, payload_len, ntohl(ip->src_ip));
            break;

        default:
            break;
    }
}


void process_icmp(const uint8_t* packet, size_t length, uint32_t src_ip) {
    if (length < sizeof(struct icmp_header)) {
        return;
    }

    struct icmp_header* icmp = (struct icmp_header*)packet;

    if (icmp->type == ICMP_TYPE_ECHO_REQUEST) {
        uint8_t reply[sizeof(struct eth_header) + sizeof(struct ip_header) + length];
        
        struct eth_header* eth_reply = (struct eth_header*)reply;
        memset(eth_reply->dst_mac, 0, ETH_ALEN);
        memcpy(eth_reply->src_mac, local_mac, ETH_ALEN);
        eth_reply->ethertype = htons(ETHERTYPE_IP);

        struct ip_header* ip_reply = (struct ip_header*)(reply + sizeof(struct eth_header));
        ip_reply->version_ihl = 0x45;
        ip_reply->tos = 0;
        ip_reply->total_len = htons(sizeof(struct ip_header) + length);
        ip_reply->ident = htons(12345);
        ip_reply->flags_frag = 0;
        ip_reply->ttl = 64;
        ip_reply->protocol = IP_PROTOCOL_ICMP;
        ip_reply->checksum = 0;
        ip_reply->src_ip = htonl(local_ip);
        ip_reply->dst_ip = htonl(src_ip);
        ip_reply->checksum = calculate_checksum(ip_reply, sizeof(struct ip_header));

        struct icmp_header* icmp_reply = (struct icmp_header*)(reply + sizeof(struct eth_header) + sizeof(struct ip_header));
        icmp_reply->type = ICMP_TYPE_ECHO_REPLY;
        icmp_reply->code = 0;
        icmp_reply->checksum = 0;
        icmp_reply->identifier = icmp->identifier;
        icmp_reply->sequence = icmp->sequence;

        memcpy((uint8_t*)icmp_reply + sizeof(struct icmp_header), 
               packet + sizeof(struct icmp_header), 
               length - sizeof(struct icmp_header));

        icmp_reply->checksum = calculate_checksum(icmp_reply, length);

        printf("ICMP reply prepared for ");
        print_ip(src_ip);
        printf("\n");
    }
}


void process_tcp(const uint8_t* packet, size_t length, uint32_t src_ip) {
    if (packet == NULL || length < sizeof(struct tcp_header)) {
        return;
    }

    const struct tcp_header* tcp = (const struct tcp_header*)packet;

    size_t hdr_len = (size_t)(tcp->data_offset >> 4) * 4;

    if (hdr_len < sizeof(struct tcp_header) || hdr_len > 60) {
        return;
    }

    if (hdr_len > length) {
        return;
    }

    const uint8_t* payload = packet + hdr_len;
    size_t payload_len = length - hdr_len;

    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dst_port = ntohs(tcp->dst_port);

    printf("TCP packet: %u -> %u, flags=0x%02x",
           (unsigned int)src_port,
           (unsigned int)dst_port,
           tcp->flags);

    if (payload_len > 0) {
        size_t display_len = payload_len > 20 ? 20 : payload_len;

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
        printf("TCP connection attempt on port %u\n",
               (unsigned int)dst_port);
    }

    (void)src_ip;
}

void print_mac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint32_t ip) {
    printf("%d.%d.%d.%d", 
           (ip >> 24) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF,
           ip & 0xFF);
}

bool add_arp_entry(uint32_t ip, const uint8_t* mac) {
    for (int i = 0; i < arp_count; i++) {
        if (arp_table[i].ip == ip) {
            memcpy(arp_table[i].mac, mac, ETH_ALEN);
            arp_table[i].timestamp = time(NULL);
            return true;
        }
    }

    if (arp_count < MAX_ARP_ENTRIES) {
        arp_table[arp_count].ip = ip;
        memcpy(arp_table[arp_count].mac, mac, ETH_ALEN);
        arp_table[arp_count].timestamp = time(NULL);
        arp_count++;
        return true;
    }

    return false;
}
