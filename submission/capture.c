/*
    This file contains the main logic for capturing packets
    Defines all of the structs used to store packet information as well
    as creates the main buffer where all packets are stored

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h> 
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

#define ETHER_SIZE 14
#define PACKET_LEN 1518


// Struct to handle IP info
// This struct is a child of the other protocol structs below 
 typedef struct ip_info {
    char srcip[64];
    char dstip[64];
    int id;
    int ttl;
    int ip_len;
} ip_info;


// Struct to store port info, seqeunce number, etc, of TCP packets
typedef struct tcp_packet {
    ip_info ip_packet;
    char protocol[4];
    int src_port;
    int dst_port;
    int seq_num;
    int len;
} tcp_packet;


// Stores info regarding UDP packets
typedef struct udp_packet {
    ip_info ip_packet;
    char protocol[4];
    int src_port;
    int dst_port;
} udp_packet;

// Stores infor regarding TCP packets
typedef struct icmp_packet {
    ip_info ip_packet;
    char protocol[4];
    int type;
    int code;
} icmp_packet;

// Kinda like a rust enum
// Lets us have multiple different types of structs 
// in one memory location
typedef union packet_union {
    tcp_packet tcp;
    udp_packet udp;
    icmp_packet icmp;
} packet_union;

// TCP = 1, UDP = 2, ICMP = 3
typedef struct packet_wrapper {
    int type;
    packet_union packet;
} packet_wrapper;

// Here we create a pointer to memory with our packet wrapper containing
// the other packet structs in a union
packet_wrapper *packet_buf = NULL;

int packet_ct = 0;
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*  packet) {

    struct eth_header* eth;
    struct ip* iphdr;
    struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;

    // Custom packet struct union
    // Continusouly reallocated memory to account for each packet
    // Basically realloc will take the pointer and continually resize it
    // based on the packet count and the size of our packet_union 
    packet_buf = realloc(packet_buf, (packet_ct + 1) * sizeof(packet_wrapper));
    
    // create the new packet to be stored
    // Instantiate a new union and set it equal to the current index of the 
    // allocated memory 
    packet_wrapper *new_packet = &packet_buf[packet_ct];
    
    // Allows us access to the ethernet header part of the struct
    eth = (struct eth_header*)(packet);

    // Lets us access the ip header struct within the packet and create a custom struct
    iphdr = (struct ip*)(packet + ETHER_SIZE);


    // Based on the IP of the packet, we type cast it to the requisite protocl and then
    // grab information from it and store it in our main structs which then go in the main 
    // packet buffer
    switch (iphdr->ip_p) {
        case IPPROTO_TCP: {
                tcphdr = (struct tcphdr*)(packet + ETHER_SIZE + (4*iphdr->ip_hl));
                
                strcpy(new_packet->packet.tcp.protocol, "tcp");
                strcpy(new_packet->packet.tcp.ip_packet.srcip, inet_ntoa(iphdr->ip_src));
                strcpy(new_packet->packet.tcp.ip_packet.dstip, inet_ntoa(iphdr->ip_dst));
                new_packet->packet.tcp.src_port = ntohs(tcphdr->th_sport);
                new_packet->packet.tcp.dst_port = ntohs(tcphdr->th_dport);
                new_packet->packet.tcp.seq_num = ntohl(tcphdr->th_seq);
                new_packet->packet.tcp.len = 4*tcphdr->th_off;
                new_packet->type = 1;
                break;
            }
        case IPPROTO_UDP: {
                udphdr = (struct udphdr*)(packet + ETHER_SIZE + (4*iphdr->ip_hl));
                strcpy(new_packet->packet.udp.protocol, "udp");
                strcpy(new_packet->packet.udp.ip_packet.srcip, inet_ntoa(iphdr->ip_src));
                strcpy(new_packet->packet.udp.ip_packet.dstip, inet_ntoa(iphdr->ip_dst));
                new_packet->packet.udp.src_port = ntohs(udphdr->uh_sport);
                new_packet->packet.udp.dst_port = ntohs(udphdr->uh_dport);
                new_packet->type = 2;
                break;
            }
        case IPPROTO_ICMP: {
                icmphdr = (struct icmp*)(packet + ETHER_SIZE + (4*iphdr->ip_hl));
                strcpy(new_packet->packet.icmp.protocol, "icmp");
                strcpy(new_packet->packet.icmp.ip_packet.srcip, inet_ntoa(iphdr->ip_src));
                strcpy(new_packet->packet.icmp.ip_packet.dstip, inet_ntoa(iphdr->ip_dst));
                new_packet->packet.icmp.type = icmphdr->icmp_type;
                new_packet->packet.icmp.code = icmphdr->icmp_code;
                new_packet->type = 3;
                break;
            }
    }

    
    printf("Src IP is %s:%d\n", new_packet->packet.tcp.ip_packet.srcip, new_packet->packet.tcp.src_port);
    printf("DST IP is %s:%d\n", new_packet->packet.tcp.ip_packet.dstip, new_packet->packet.tcp.dst_port);

    // printf("%d\n", packet_ct);
    fflush(stdout);
    packet_ct++;
}

