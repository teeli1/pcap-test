#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

//ethernet header 출력
void printEthernetHeader(const struct libnet_ethernet_hdr* ethHeader) {
    printf("\nEthernet Header\n");
    printf("Src MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", ethHeader->ether_shost[i]);
        if (i != ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\nDst MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", ethHeader->ether_dhost[i]);
        if (i != ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n");
}

//ip header 출력
void printIPHeader(const struct libnet_ipv4_hdr* ipHeader) {
    printf("\nIP Header\n");
    printf("Src IP: %s\n", inet_ntoa(ipHeader->ip_src));
    printf("Dst IP: %s\n", inet_ntoa(ipHeader->ip_dst));
	printf("\n");
}

//tcp header 출력
void printTCPHeader(const struct libnet_tcp_hdr* tcpHeader) {
    printf("TCP Header\n");
    printf("Src Port: %d\n", ntohs(tcpHeader->th_sport));
    printf("Dst Port: %d\n", ntohs(tcpHeader->th_dport));
	printf("\n");
}

//payload(data) hexadecimal value 출력
void printPayload(const u_char* payload, int length) {
	if (length == 0) {
		printf("Payload (first 20 bytes): 0\n");
        return;
    }
    printf("Payload (first 20 bytes): ");
    for (int i = 0; i < length && i < 20; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

//main 함수
int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr *ethHeader;
        struct libnet_ipv4_hdr *ipHeader;
        struct libnet_tcp_hdr *tcpHeader;
        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("\n<%u bytes captured>\n", header->caplen);

        ethHeader = (struct libnet_ethernet_hdr*)packet;
        printEthernetHeader(ethHeader);
		
		//ip 패킷인지 확인
        if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
            ipHeader = (struct libnet_ipv4_hdr*)(packet + sizeof(*ethHeader));
            printIPHeader(ipHeader);

			//tcp 패킷인지 확인
            if (ipHeader->ip_p == IPPROTO_TCP) {
                tcpHeader = (struct libnet_tcp_hdr*)(packet + sizeof(*ethHeader) + (ipHeader->ip_hl * 4));
                printTCPHeader(tcpHeader);

                const u_char* payload = packet + sizeof(*ethHeader) + (ipHeader-> ip_hl * 4) + (tcpHeader->th_off * 4);
                int payloadLength = header->caplen - (payload - packet);
				printPayload(payload, payloadLength);
            }

        }

        printf("\nclose.\n");
    }

    pcap_close(pcap);
    return 0;
}

