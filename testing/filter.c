#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void filter_src_ip(packet_wrapper *packet_p, char src_filter[], int count) {
    // puts("testing does this work");
    // printf("Src IP is %s:%d\n", packet_p[0].packet.tcp.ip_packet.srcip, packet_buf[0].packet.tcp.src_port);
    // printf("DST IP is %s:%d\n", packet_p[0].packet.tcp.ip_packet.dstip, packet_buf[0].packet.tcp.dst_port);
    int protocol;        
    for (int i = 0; i < count; i++) {
      protocol = packet_p[i].type;
      switch (protocol) {
        // TCP Packet
        case 1: {
          if (!strcmp(src_filter, packet_p[i].packet.tcp.ip_packet.srcip)) {
             puts("===== TCP =====");
             printf("Src IP is %s:%d  --------->  Dst IP is %s:%d\n", packet_p[i].packet.tcp.ip_packet.srcip, packet_p[i].packet.tcp.src_port,
               packet_p[i].packet.tcp.ip_packet.dstip, packet_p[i].packet.tcp.dst_port);
          }
          break;
        }

        case 2: {
             if (!strcmp(src_filter, packet_p[i].packet.udp.ip_packet.srcip)) {
               puts("===== UDP =====");
               printf("Src IP is %s:%d  --------->  Dst IP is %s:%d\n", packet_p[i].packet.udp.ip_packet.srcip, packet_p[i].packet.udp.src_port,
                 packet_p[i].packet.udp.ip_packet.dstip, packet_p[i].packet.udp.dst_port);

            }
            break;
        }
        case 3: {
             if (!strcmp(src_filter, packet_p[i].packet.icmp.ip_packet.srcip)) {
               puts("===== ICMP =====");
               printf("Src IP is %s ---------->  Dst IP is %s\n", packet_p[i].packet.icmp.ip_packet.srcip,
                packet_p[i].packet.icmp.ip_packet.dstip);
               printf("ICMP Type: %d ====== ICMP code %d", packet_p[i].packet.icmp.type, packet_p[i].packet.icmp.code);
             }
             break;
        }
      }
    }
}

void filter_dst_ip(packet_wrapper *packet_p, char src_filter[], int count) {
    // puts("testing does this work");
    // printf("Src IP is %s:%d\n", packet_p[0].packet.tcp.ip_packet.srcip, packet_buf[0].packet.tcp.src_port);
    // printf("DST IP is %s:%d\n", packet_p[0].packet.tcp.ip_packet.dstip, packet_buf[0].packet.tcp.dst_port);
    int protocol;        
    for (int i = 0; i < count; i++) {
      protocol = packet_p[i].type;
      switch (protocol) {
        // TCP Packet
        case 1: {
          if (!strcmp(src_filter, packet_p[i].packet.tcp.ip_packet.dstip)) {
             puts("===== TCP =====");
             printf("Src IP is %s:%d  --------->  Dst IP is %s:%d\n", packet_p[i].packet.tcp.ip_packet.srcip, packet_p[i].packet.tcp.src_port,
               packet_p[i].packet.tcp.ip_packet.dstip, packet_p[i].packet.tcp.dst_port);
          }
          break;
        }

        case 2: {
             if (!strcmp(src_filter, packet_p[i].packet.udp.ip_packet.dstip)) {
               puts("===== UDP ====");
               printf("Src IP is %s ---------->  Dst IP is %s\n", packet_p[i].packet.icmp.ip_packet.srcip,
                packet_p[i].packet.icmp.ip_packet.dstip);
               printf("ICMP Type: %d ====== ICMP code %d", packet_p[i].packet.icmp.type, packet_p[i].packet.icmp.code);

            }
            break;
        }
        case 3: {
             if (!strcmp(src_filter, packet_p[i].packet.icmp.ip_packet.dstip)) {
                puts("===== ICMP =====");
                printf("Src IP is %s ---------->  Dst IP is %s\n", packet_p[i].packet.icmp.ip_packet.srcip,
                  packet_p[i].packet.icmp.ip_packet.dstip);
                printf("ICMP Type: %d ====== ICMP code %d", packet_p[i].packet.icmp.type, packet_p[i].packet.icmp.code);
             }
             break;
     
        }
      }
    }
}

void filter_src_port(packet_wrapper *packet_p, int src_filter, int count) {
  int protocol;
  for (int i = 0; i < count; i++) {
    protocol = packet_p[i].type;
    switch (protocol) {
      case 1: {
          if (src_filter == packet_p[i].packet.tcp.src_port) {
            puts("===== TCP =====");
            printf("Src IP is %s:%d ---------->  Dst IP is %s:%d\n", packet_p[i].packet.tcp.ip_packet.srcip, packet_p[i].packet.tcp.src_port,
              packet_p[i].packet.tcp.ip_packet.dstip, packet_p[i].packet.tcp.dst_port);
          }
          break;
      }

      case 2: {
          if (src_filter == packet_p[i].packet.udp.src_port) {
            puts("===== UDP =====");
            printf("Src IP is %s:%d ---------->  Dst IP is %s:%d\n", packet_p[i].packet.udp.ip_packet.srcip, packet_p[i].packet.udp.src_port,
              packet_p[i].packet.udp.ip_packet.dstip, packet_p[i].packet.udp.dst_port);
          }
          break;
      }
    // I don't think this is needed, icmp doesn't deal with ports
    
    //   case 3: {
    //       if (src_filter == packet_p[i].packet.icmp.src_port) {
    //         printf("Src IP is %s:%d ---------->  Dst IP is %s:%d\n", packet_p[i].packet.icmp.ip_packet.srcip, packet_p[i].packet.icmp.src_port,
    //           packet_p[i].packet.icmp.ip_packet.dstip, packet_p[i].packet.icmp.dst_port);
    //       }
    //       break;
    //     }
    // }
    }
  }
}

void filter_dst_port(packet_wrapper *packet_p, int src_filter, int count) {
  int protocol;
  for (int i = 0; i < count; i++) {
    protocol = packet_p[i].type;
    switch (protocol) {
      case 1: {
          if (src_filter == packet_p[i].packet.tcp.dst_port) {
            puts("==== TCP =====");
            printf("Src IP is %s:%d ---------->  Dst IP is %s:%d\n", packet_p[i].packet.tcp.ip_packet.srcip, packet_p[i].packet.tcp.src_port,
              packet_p[i].packet.tcp.ip_packet.dstip, packet_p[i].packet.tcp.dst_port);
          }
          break;
      }

      case 2: {
          if (src_filter == packet_p[i].packet.udp.src_port) {
            puts("===== UDP =====");
            printf("Src IP is %s:%d ---------->  Dst IP is %s:%d\n", packet_p[i].packet.udp.ip_packet.srcip, packet_p[i].packet.udp.src_port,
              packet_p[i].packet.udp.ip_packet.dstip, packet_p[i].packet.udp.dst_port);
          }
          break;

      }

    // Technically not needed since icmp will never filter by port
    
    //   case 3: {
    //       if (src_filter == packet_p[i].packet.icmp.src_port) {
    //         printf("Src IP is %s ---------->  Dst IP is %s\n", packet_p[i].packet.icmp.ip_packet.srcip,
    //           packet_p[i].packet.icmp.ip_packet.dstip);
    //         printf("ICMP Type: %d ====== ICMP code %d", packet_p[i].packet.icmp.type, packet_p[i].packet.icmp.code);
    //       }
    //       break;
    //     }
    // }
    }
  }
}

