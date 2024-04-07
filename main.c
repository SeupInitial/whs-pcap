#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

typedef struct ethernet_header {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short eth_type;
} ethernet_header;

typedef struct ip_header {
    unsigned char hlen: 4, hver: 4;
    unsigned char tos: 8;
    unsigned short tot_len;
    unsigned short iden;
    unsigned short frag_flag_offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    struct in_addr src_ip;
    struct in_addr dst_ip;
} ip_header;

typedef struct tcp_header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int sequence_num;
    unsigned int acknowledge_num;
    unsigned char offset_reserved;
    unsigned char flags;
    unsigned short winsize;
    unsigned short checksum;
    unsigned short urgent_ptr;
} tcp_header;



void packet_handler(__u_char *data, const struct pcap_pkthdr *packet_header, const __u_char *packet);

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr packet_header;
    const unsigned char *packet;

    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "No device detected, %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &packet_header)) != NULL) {
        packet_handler(NULL, &packet_header, packet);
    }
    
    pcap_close(handle);
    return 0;
}



void packet_handler(__u_char *data, const struct pcap_pkthdr *packet_header, const __u_char *packet) {
    ethernet_header* ethernetHeader = (ethernet_header*)packet;
    ip_header* ipHeader = (ip_header*)(packet + sizeof(ethernet_header));
    tcp_header* tcpHeader = (tcp_header*)(packet + sizeof(ethernet_header) + ipHeader->hlen * 4);

    printf("=============== info ===============\n");

    //Ethernet Header Info
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)ethernetHeader->src_mac));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)ethernetHeader->dst_mac));

    //IP Header Info
    printf("Source IP: %s\n", inet_ntoa(ipHeader->src_ip));
    printf("Destination IP: %s\n", inet_ntoa(ipHeader->dst_ip));

    //TCP Header Info
    printf("Source Port: %d\n", ntohs(tcpHeader->src_port));
    printf("Destination Port: %d\n", ntohs(tcpHeader->dst_port));

    printf("\n");
}