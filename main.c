
#include <stdio.h>
#include <string.h>
#include "tcp_ip_stack.h"

#define TEST_FRAME_SIZE 128

static int tests_passed = 0;
static int tests_failed = 0;

static void check_result(const char* name, bool condition) {
    if (condition) {
        printf("[PASS] %s\n", name);
        tests_passed++;
    } else {
        printf("[FAIL] %s\n", name);
        tests_failed++;
    }
}

static void test_ipv4_parser(void) {
    printf("\n=== IPv4 Parser Tests ===\n");

    check_result(
        "Valid IPv4 address",
        parse_ipv4("192.168.1.1") == 0xC0A80101
    );

    check_result(
        "Valid loopback address",
        parse_ipv4("127.0.0.1") == 0x7F000001
    );

    check_result(
        "Reject out-of-range octet",
        parse_ipv4("192.168.1.256") == 0
    );

    check_result(
        "Reject incomplete address",
        parse_ipv4("192.168.1") == 0
    );

    check_result(
        "Reject trailing characters",
        parse_ipv4("192.168.1.1abc") == 0
    );

    check_result(
        "Reject null input",
        parse_ipv4(NULL) == 0
    );
}

static void test_checksum(void) {
    printf("\n=== Checksum Tests ===\n");

    uint8_t data[] = {
        0x01, 0x02, 0x03
    };

    uint16_t checksum =
        calculate_checksum(data, sizeof(data));

    uint8_t packet_with_checksum[5];

    memcpy(packet_with_checksum, data, sizeof(data));
    memcpy(
        packet_with_checksum + sizeof(data),
        &checksum,
        sizeof(checksum)
    );

    check_result(
        "Odd-length checksum validation",
        calculate_checksum(
            packet_with_checksum,
            sizeof(packet_with_checksum)
        ) == 0
    );

    check_result(
        "Null checksum input",
        calculate_checksum(NULL, 5) == 0
    );

    check_result(
        "Empty checksum input",
        calculate_checksum(data, 0) == 0
    );
}

static size_t create_arp_frame(uint8_t* frame) {
    memset(frame, 0, TEST_FRAME_SIZE);

    struct eth_header* eth =
        (struct eth_header*)frame;

    memcpy(eth->dst_mac, local_mac, ETH_ALEN);

    const uint8_t sender_mac[ETH_ALEN] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    memcpy(eth->src_mac, sender_mac, ETH_ALEN);
    eth->ethertype = htons(ETHERTYPE_ARP);

    struct arp_header* arp =
        (struct arp_header*)(frame + sizeof(struct eth_header));

    arp->hw_type = htons(1);
    arp->proto_type = htons(ETHERTYPE_IP);
    arp->hw_len = ETH_ALEN;
    arp->proto_len = 4;
    arp->opcode = htons(ARP_OP_REQUEST);

    memcpy(arp->sender_mac, sender_mac, ETH_ALEN);
    arp->sender_ip = htonl(0xC0A80102);

    arp->target_ip = htonl(local_ip);

    return sizeof(struct eth_header) + sizeof(struct arp_header);
}

static size_t create_icmp_frame(uint8_t* frame) {
    memset(frame, 0, TEST_FRAME_SIZE);

    struct eth_header* eth =
        (struct eth_header*)frame;

    memcpy(eth->dst_mac, local_mac, ETH_ALEN);

    const uint8_t sender_mac[ETH_ALEN] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    memcpy(eth->src_mac, sender_mac, ETH_ALEN);
    eth->ethertype = htons(ETHERTYPE_IP);

    struct ip_header* ip =
        (struct ip_header*)(frame + sizeof(struct eth_header));

    ip->version_ihl = 0x45;
    ip->total_len = htons(48);
    ip->ident = htons(100);
    ip->flags_frag = 0;
    ip->ttl = 64;
    ip->protocol = IP_PROTOCOL_ICMP;
    ip->src_ip = htonl(0xC0A80102);
    ip->dst_ip = htonl(local_ip);

    struct icmp_header* icmp =
        (struct icmp_header*)(
            frame +
            sizeof(struct eth_header) +
            sizeof(struct ip_header)
        );

    icmp->type = ICMP_TYPE_ECHO_REQUEST;
    icmp->code = 0;
    icmp->identifier = htons(1234);
    icmp->sequence = htons(1);

    uint8_t* payload =
        (uint8_t*)icmp + sizeof(struct icmp_header);

    memcpy(payload, "Hello TCP/IP Stack!", 20);

    icmp->checksum = 0;
    icmp->checksum =
        calculate_checksum(icmp, 28);

    ip->checksum = 0;
    ip->checksum =
        calculate_checksum(ip, sizeof(struct ip_header));

    return sizeof(struct eth_header) + 48;
}

static size_t create_tcp_frame(uint8_t* frame) {
    memset(frame, 0, TEST_FRAME_SIZE);

    struct eth_header* eth =
        (struct eth_header*)frame;

    memcpy(eth->dst_mac, local_mac, ETH_ALEN);

    const uint8_t sender_mac[ETH_ALEN] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    memcpy(eth->src_mac, sender_mac, ETH_ALEN);
    eth->ethertype = htons(ETHERTYPE_IP);

    struct ip_header* ip =
        (struct ip_header*)(frame + sizeof(struct eth_header));

    ip->version_ihl = 0x45;
    ip->total_len = htons(53);
    ip->ident = htons(101);
    ip->flags_frag = 0;
    ip->ttl = 64;
    ip->protocol = IP_PROTOCOL_TCP;
    ip->src_ip = htonl(0xC0A80102);
    ip->dst_ip = htonl(local_ip);

    struct tcp_header* tcp =
        (struct tcp_header*)(
            frame +
            sizeof(struct eth_header) +
            sizeof(struct ip_header)
        );

    tcp->src_port = htons(5000);
    tcp->dst_port = htons(8080);
    tcp->seq_num = htonl(1);
    tcp->ack_num = 0;
    tcp->data_offset = 0x50;
    tcp->flags = TCP_SYN;
    tcp->window = htons(8192);

    uint8_t* payload =
        (uint8_t*)tcp + sizeof(struct tcp_header);

    memcpy(payload, "TCP Test Data", 13);

    ip->checksum = 0;
    ip->checksum =
        calculate_checksum(ip, sizeof(struct ip_header));

    return sizeof(struct eth_header) + 53;
}

static void test_packet_processing(void) {
    printf("\n=== Packet Processing Tests ===\n");

    uint8_t frame[TEST_FRAME_SIZE];

    size_t length = create_arp_frame(frame);

    printf("\nProcessing valid ARP request:\n");
    process_frame(frame, length);

    length = create_icmp_frame(frame);

    printf("\nProcessing valid ICMP request:\n");
    process_frame(frame, length);

    length = create_tcp_frame(frame);

    printf("\nProcessing valid TCP packet:\n");
    process_frame(frame, length);

    printf("\nProcessing malformed Ethernet frame:\n");
    process_frame(frame, 5);

    printf("\nProcessing null Ethernet frame:\n");
    process_frame(NULL, 100);

    printf("\nMalformed packet submissions completed.\n");
    printf("These cases require dedicated assertions for "
           "full automated rejection testing.\n");
}

static void test_malformed_ipv4(void) {
    printf("\n=== Malformed IPv4 Tests ===\n");

    uint8_t frame[TEST_FRAME_SIZE];

    size_t length = create_icmp_frame(frame);

    struct ip_header* ip =
        (struct ip_header*)(frame + sizeof(struct eth_header));

    ip->total_len = htons(10);

    printf("Submitting IPv4 packet with total length "
           "smaller than its header:\n");

    process_frame(frame, length);

    length = create_icmp_frame(frame);

    ip = (struct ip_header*)(frame + sizeof(struct eth_header));

    ip->total_len = htons(100);

    printf("Submitting IPv4 packet with total length "
           "larger than received packet:\n");

    process_frame(frame, length);

    length = create_icmp_frame(frame);

    ip = (struct ip_header*)(frame + sizeof(struct eth_header));

    ip->version_ihl = 0x44;

    printf("Submitting IPv4 packet with invalid IHL:\n");

    process_frame(frame, length);

    printf("Malformed IPv4 submissions completed.\n");
}

int main(void) {
    printf("====================================\n");
    printf(" Educational TCP/IP Stack Test Suite\n");
    printf("====================================\n");

    network_init("192.168.1.1");

    test_ipv4_parser();
    test_checksum();

    test_packet_processing();
    test_malformed_ipv4();

    printf("\n====================================\n");
    printf("Unit tests passed: %d\n", tests_passed);
    printf("Unit tests failed: %d\n", tests_failed);
    printf("====================================\n");

    return tests_failed == 0 ? 0 : 1;
}
