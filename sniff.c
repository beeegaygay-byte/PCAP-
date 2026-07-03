#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* 1. 이더넷 헤더 구조체 (14바이트 고정) */
struct ethheader {
    u_char  ether_dhost[6]; /* 목적지 MAC */
    u_char  ether_shost[6]; /* 출발지 MAC */
    u_short ether_type;     /* 타입 (IP 패킷인지 구별용) */
};

/* 2. IP 헤더 구조체 */
struct ipheader {
    unsigned char      iph_ihl : 4, iph_ver : 4; /* 이 두개만 있으면 헤더 크기 계산  */
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flags_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol; /* TCP 패킷인지 구별용 */
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip; /* 출발지 IP */
    struct  in_addr    iph_destip;   /* 목적지 IP */
};

/* 3. TCP 헤더 구조체 */
struct tcp_header {
    unsigned short source_port; /* 출발지 포트 */
    unsigned short dest_port;   /* 목적지 포트 */
    unsigned int   sequence;
    unsigned int   acknowledge;
    unsigned char  reserved : 4, data_offset : 4; 
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    // IPv4 패킷인지 검사
    if (ntohs(eth->ether_type) == 0x0800) { 
        // 14바이트 뒤로 이동해서 IP 헤더 주소 설정
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 

        // TCP 프로토콜인지 검사
        if (ip->iph_protocol == 6) {
            
           
            int ip_header_len = ip->iph_ihl * 4;
            struct tcp_header *tcp = (struct tcp_header *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = tcp->data_offset * 4;

      
            int total_header_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = ntohs(ip->iph_len) - (ip_header_len + tcp_header_len);

           
            printf("==================================================\n");
            printf("Src MAC  : %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Dst MAC  : %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            printf("Src IP   : %s\n", inet_ntoa(ip->iph_sourceip));   
            printf("Dst IP   : %s\n", inet_ntoa(ip->iph_destip));    
            printf("Src Port : %d\n", ntohs(tcp->source_port));
            printf("Dst Port : %d\n", ntohs(tcp->dest_port));
            printf("Total Byte: %d\n", header->caplen);

      
            if (payload_len > 0) {
                const u_char *payload = packet + total_header_size;
                printf("HTTP Message (Hex) : ");
                for (int i = 0; i < payload_len && i < 16; i++) {
                    printf("%02X ", payload[i]);
                }
                printf("\n");
            } else {
                printf("HTTP Message : (No Payload)\n");
            }
            printf("==================================================\n\n");
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; 


    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    

    pcap_compile(handle, &fp, filter_exp, 0, 0);
    pcap_setfilter(handle, &fp);

    printf("PCAP Sniffing started on eth0...\n");
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   
    return 0;
}