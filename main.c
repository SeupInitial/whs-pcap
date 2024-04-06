#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>

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
    char error_buff[PCAP_ERRBUF_SIZE];
    pcap_t *captured;

    captured = pcap_open_live("eth0", BUFSIZ, 1, 1000, error_buff);
    
    if (captured == NULL)   return 1;

    pcap_loop(captured, 0, packet_handler, NULL);
    pcap_close(captured);

    return 0;
}

void packet_handler(__u_char *data, const struct pcap_pkthdr *packet_header, const __u_char *packet) {
    return 0;
}