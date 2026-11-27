
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
        "Valid zero-network address",
        parse_ipv4("10.0.0.1") == 0x0A000001
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
        "Reject extra octet",
        parse_ipv4("192.168.1.1.5") == 0
    );

    check_result(
        "Reject trailing characters",
        parse_ipv4("192.168.1.1abc") == 0
    );

    check_result(
        "Reject null input",
        parse_ipv4(NULL) == 0
    );

    check_result(
        "Reject empty input",
        parse_ipv4("") == 0
    );
}

static void test_checksum(void) {
    printf("\n=== Checksum Tests ===\n");

    const uint8_t known_data[] = {
        0x00, 0x01, 0xF2, 0x03,
        0xF4, 0xF5, 0xF6, 0xF7
    };

    check_result(
        "Known Internet checksum vector",
        calculate_checksum(
            known_data,
            sizeof(known_data)
        ) == htons(0x220D)
    );

    uint8_t odd_data[] = {
        0x01, 0x02, 0x03
    };

    uint16_t checksum =
        calculate_checksum(odd_data, sizeof(odd_data));

    uint8_t packet_with_checksum[5];

    memcpy(packet_with_checksum, odd_data, sizeof(odd_data));

    memcpy(
        packet_with_checksum + sizeof(odd_data),
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
        calculate_checksum(odd_data, 0) == 0
    );
}

static size_t create_arp_frame(
    uint8_t* frame,
    uint32_t sender_ip,
    uint32_t target_ip
) {
    memset(frame, 0, TEST_FRAME_SIZE);

    struct eth_header* eth =
        (struct eth_header*)frame;

    memcpy(eth->dst_mac, local_mac, ETH_ALEN);

    const uint8_t sender_mac[ETH_ALEN] = {
        0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE
    };

    memcpy(eth->src_mac, sender_mac, ETH_ALEN);
    eth->ethertype = htons(ETHERTYPE_ARP);

    struct arp_header* arp =
        (struct arp_header*)(
            frame + sizeof(struct eth_header)
        );

    arp->hw_type = htons(1);
    arp->proto_type = htons(ETHERTYPE_IP);
    arp->hw_len = ETH_ALEN;
    arp->proto_len = 4;
    arp->opcode = htons(ARP_OP_REQUEST);

    memcpy(arp->sender_mac, sender_mac, ETH_ALEN);

    arp->sender_ip = htonl(sender_ip);
    arp->target_ip = htonl(target_ip);

    return sizeof(struct eth_header) +
           sizeof(struct arp_header);
}

static void test_arp_processing(void) {
    printf("\n=== ARP Processing Tests ===\n");

    network_init("192.168.1.1");

    uint8_t frame[TEST_FRAME_SIZE];

    const uint32_t sender_ip = 0xC0A80102;

    size_t length = create_arp_frame(
        frame,
        sender_ip,
        local_ip
    );

    process_frame(frame, length);

    check_result(
        "Valid ARP request adds sender to cache",
        arp_count == 1 &&
        arp_table[0].ip == sender_ip
    );

    const uint8_t expected_mac[ETH_ALEN] = {
        0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE
    };

    check_result(
        "ARP cache stores correct sender MAC",
        memcmp(
            arp_table[0].mac,
            expected_mac,
            ETH_ALEN
        ) == 0
    );

    length = create_arp_frame(
        frame,
        0xC0A80103,
        0xC0A80199
    );

    process_frame(frame, length);

    check_result(
        "ARP request for another IP is ignored",
        arp_count == 1
    );

    length = create_arp_frame(
        frame,
        0xC0A80104,
        local_ip
    );

    struct arp_header* arp =
        (struct arp_header*)(
            frame + sizeof(struct eth_header)
        );

    arp->hw_len = 5;

    process_frame(frame, length);

    check_result(
        "ARP with invalid hardware length is rejected",
        arp_count == 1
    );

    length = create_arp_frame(
        frame,
        0xC0A80105,
        local_ip
    );

    arp = (struct arp_header*)(
        frame + sizeof(struct eth_header)
    );

    const uint8_t multicast_mac[ETH_ALEN] = {
        0x01, 0x00, 0x5E, 0x00, 0x00, 0x01
    };

    memcpy(
        arp->sender_mac,
        multicast_mac,
        ETH_ALEN
    );

    process_frame(frame, length);

    check_result(
        "ARP with multicast sender MAC is rejected",
        arp_count == 1
    );
}

static void test_arp_cache(void) {
    printf("\n=== ARP Cache Tests ===\n");

    network_init("192.168.1.1");

    const uint8_t first_mac[ETH_ALEN] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    const uint8_t updated_mac[ETH_ALEN] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02
    };

    check_result(
        "Insert valid ARP entry",
        add_arp_entry(0x0A000001, first_mac) &&
        arp_count == 1
    );

    check_result(
        "Update existing IP without duplicate entry",
        add_arp_entry(0x0A000001, updated_mac) &&
        arp_count == 1 &&
        memcmp(
            arp_table[0].mac,
            updated_mac,
            ETH_ALEN
        ) == 0
    );

    check_result(
        "Reject null MAC address",
        !add_arp_entry(0x0A000002, NULL)
    );

    const uint8_t zero_mac[ETH_ALEN] = {0};

    check_result(
        "Reject zero MAC address",
        !add_arp_entry(0x0A000002, zero_mac)
    );

    const uint8_t multicast_mac[ETH_ALEN] = {
        0x01, 0x00, 0x5E, 0x00, 0x00, 0x01
    };

    check_result(
        "Reject multicast MAC address",
        !add_arp_entry(0x0A000002, multicast_mac)
    );

    bool filled = true;

    for (int i = 2; i <= MAX_ARP_ENTRIES; i++) {
        uint8_t mac[ETH_ALEN] = {
            0x02, 0x00, 0x00, 0x00, 0x01,
            (uint8_t)i
        };

        uint32_t ip = 0x0A000000 + (uint32_t)i;

        if (!add_arp_entry(ip, mac)) {
            filled = false;
            break;
        }
    }

    check_result(
        "Fill ARP cache to configured capacity",
        filled && arp_count == MAX_ARP_ENTRIES
    );

    const uint8_t extra_mac[ETH_ALEN] = {
        0x02, 0x00, 0x00, 0x00, 0x02, 0x01
    };

    check_result(
        "Reject insertion when ARP cache is full",
        !add_arp_entry(0x0A000100, extra_mac) &&
        arp_count == MAX_ARP_ENTRIES
    );
}

static void test_ethernet_filtering(void) {
    printf("\n=== Ethernet Filtering Tests ===\n");

    network_init("192.168.1.1");

    uint8_t frame[TEST_FRAME_SIZE];

    size_t length = create_arp_frame(
        frame,
        0xC0A80102,
        local_ip
    );

    struct eth_header* eth =
        (struct eth_header*)frame;

    const uint8_t other_mac[ETH_ALEN] = {
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55
    };

    memcpy(eth->dst_mac, other_mac, ETH_ALEN);

    process_frame(frame, length);

    check_result(
        "Ignore Ethernet frame addressed to another MAC",
        arp_count == 0
    );

    const uint8_t broadcast_mac[ETH_ALEN] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    memcpy(
        eth->dst_mac,
        broadcast_mac,
        ETH_ALEN
    );

    process_frame(frame, length);

    check_result(
        "Process broadcast Ethernet ARP frame",
        arp_count == 1
    );
}

static size_t create_icmp_frame(uint8_t* frame) {
    memset(frame, 0, TEST_FRAME_SIZE);

    struct eth_header* eth =
        (struct eth_header*)frame;

    memcpy(eth->dst_mac, local_mac, ETH_ALEN);

    const uint8_t sender_mac[ETH_ALEN] = {
        0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE
    };

    memcpy(eth->src_mac, sender_mac, ETH_ALEN);
    eth->ethertype = htons(ETHERTYPE_IP);

    struct ip_header* ip =
        (struct ip_header*)(
            frame + sizeof(struct eth_header)
        );

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
    icmp->checksum = calculate_checksum(icmp, 28);

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
        0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE
    };

    memcpy(eth->src_mac, sender_mac, ETH_ALEN);
    eth->ethertype = htons(ETHERTYPE_IP);

    struct ip_header* ip =
        (struct ip_header*)(
            frame + sizeof(struct eth_header)
        );

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
    printf("\n=== Packet Processing Demonstrations ===\n");

    uint8_t frame[TEST_FRAME_SIZE];

    size_t length = create_arp_frame(
        frame,
        0xC0A80102,
        local_ip
    );

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
}

static void test_malformed_ipv4(void) {
    printf("\n=== Malformed IPv4 Demonstrations ===\n");

    uint8_t frame[TEST_FRAME_SIZE];

    size_t length = create_icmp_frame(frame);

    struct ip_header* ip =
        (struct ip_header*)(
            frame + sizeof(struct eth_header)
        );

    ip->total_len = htons(10);

    printf("\nSubmitting IPv4 packet with total length smaller than header:\n");
    process_frame(frame, length);

    length = create_icmp_frame(frame);

    ip = (struct ip_header*)(
        frame + sizeof(struct eth_header)
    );

    ip->total_len = htons(100);

    printf("\nSubmitting IPv4 packet with total length larger than received data:\n");
    process_frame(frame, length);

    length = create_icmp_frame(frame);

    ip = (struct ip_header*)(
        frame + sizeof(struct eth_header)
    );

    ip->version_ihl = 0x44;

    printf("\nSubmitting IPv4 packet with invalid header length:\n");
    process_frame(frame, length);

    printf("\nMalformed IPv4 demonstrations completed.\n");
}

static void test_null_and_short_inputs(void) {
    printf("\n=== Null and Short Input Demonstrations ===\n");

    process_frame(NULL, 100);
    process_frame((const uint8_t*)"abc", 3);

    process_arp(NULL, 10);
    process_arp((const uint8_t*)"abc", 3);

    process_ip(NULL, 10);
    process_ip((const uint8_t*)"abc", 3);

    process_icmp(NULL, 10, 0);
    process_tcp(NULL, 10, 0);

    printf("Null and short input submissions completed.\n");
}

int main(void) {
    printf("========================================\n");
    printf(" Educational TCP/IP Stack Test Suite\n");
    printf("========================================\n");

    test_ipv4_parser();
    test_checksum();
    test_arp_processing();
    test_arp_cache();
    test_ethernet_filtering();

    network_init("192.168.1.1");

    test_packet_processing();
    test_malformed_ipv4();
    test_null_and_short_inputs();

    printf("\n========================================\n");
    printf("Assertions passed: %d\n", tests_passed);
    printf("Assertions failed: %d\n", tests_failed);
    printf("========================================\n");

    return tests_failed == 0 ? 0 : 1;
}
