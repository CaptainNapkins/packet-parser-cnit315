/*

  The functions in this file take the structs in the main packet buffer and parse through 
  them to print various things to a file. 

  Each function iterates through this struct, looks for packets containing requisite information,
  then writes the contents of the struct to a file

*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Writes all network traffic to a file
void write_all(packet_wrapper *packet_p, int count, FILE *fp) {
    int protocol;        
    for (int i = 0; i < count; i++) {
      protocol = packet_p[i].type;
      switch (protocol) {
        // TCP Packet
        case 1: {
            fprintf(fp, "===== TCP =====\n");
            fprintf(fp, "Src IP is %s:%d  --------->  Dst IP is %s:%d\n", packet_p[i].packet.tcp.ip_packet.srcip, packet_p[i].packet.tcp.src_port,
              packet_p[i].packet.tcp.ip_packet.dstip, packet_p[i].packet.tcp.dst_port);
        
          break;
        }

        case 2: {
              fprintf(fp, "===== UDP =====\n");
              fprintf(fp, "Src IP is %s:%d  --------->  Dst IP is %s:%d\n", packet_p[i].packet.udp.ip_packet.srcip, packet_p[i].packet.udp.src_port,
                packet_p[i].packet.udp.ip_packet.dstip, packet_p[i].packet.udp.dst_port);
            break;
        }
        case 3: {
              fprintf(fp, "===== ICMP =====\n");
              fprintf(fp, "Src IP is %s ---------->  Dst IP is %s\n", packet_p[i].packet.icmp.ip_packet.srcip,
                packet_p[i].packet.icmp.ip_packet.dstip);
              fprintf(fp, "ICMP Type: %d ====== ICMP code %d", packet_p[i].packet.icmp.type, packet_p[i].packet.icmp.code);
             break;
        }
      }
    }
}

// Writes the source IP information to a file
void write_src_ip(packet_wrapper *packet_p, char src_filter[], int count, FILE *fp) {
    int protocol;        
    for (int i = 0; i < count; i++) {
      protocol = packet_p[i].type;
      switch (protocol) {
        // TCP Packet
        case 1: {
          if (!strcmp(src_filter, packet_p[i].packet.tcp.ip_packet.srcip)) {
              fprintf(fp, "===== TCP =====\n");
              fprintf(fp, "Src IP is %s:%d  --------->  Dst IP is %s:%d\n", packet_p[i].packet.tcp.ip_packet.srcip, packet_p[i].packet.tcp.src_port,
                packet_p[i].packet.tcp.ip_packet.dstip, packet_p[i].packet.tcp.dst_port);
             }
        
          break;
        }

        case 2: {
             if (!strcmp(src_filter, packet_p[i].packet.udp.ip_packet.srcip)) {
                fprintf(fp, "===== UDP =====\n");
                fprintf(fp, "Src IP is %s:%d  --------->  Dst IP is %s:%d\n", packet_p[i].packet.udp.ip_packet.srcip, packet_p[i].packet.udp.src_port,
                  packet_p[i].packet.udp.ip_packet.dstip, packet_p[i].packet.udp.dst_port);
            }
            break;
        }
        case 3: {
             if (!strcmp(src_filter, packet_p[i].packet.icmp.ip_packet.srcip)) {
                fprintf(fp, "===== ICMP =====\n");
                fprintf(fp, "Src IP is %s ---------->  Dst IP is %s\n", packet_p[i].packet.icmp.ip_packet.srcip,
                  packet_p[i].packet.icmp.ip_packet.dstip);
                fprintf(fp, "ICMP Type: %d ====== ICMP code %d", packet_p[i].packet.icmp.type, packet_p[i].packet.icmp.code);
               }
             break;
        }
      }
    }
}

// Writes the destination ip information to a file
void write_dst_ip(packet_wrapper *packet_p, char src_filter[], int count, FILE *fp) {
    int protocol;        
    for (int i = 0; i < count; i++) {
      protocol = packet_p[i].type;
      switch (protocol) {
        // TCP Packet
        case 1: {
          if (!strcmp(src_filter, packet_p[i].packet.tcp.ip_packet.dstip)) {
            fprintf(fp, "===== TCP =====\n");
            fprintf(fp, "Src IP is %s:%d  --------->  Dst IP is %s:%d\n", packet_p[i].packet.tcp.ip_packet.srcip, packet_p[i].packet.tcp.src_port,
              packet_p[i].packet.tcp.ip_packet.dstip, packet_p[i].packet.tcp.dst_port);
          }
          break;
        }

        case 2: {
             if (!strcmp(src_filter, packet_p[i].packet.udp.ip_packet.dstip)) {
                fprintf(fp, "===== UDP ====\n");
                fprintf(fp, "Src IP is %s ---------->  Dst IP is %s\n", packet_p[i].packet.icmp.ip_packet.srcip,
                  packet_p[i].packet.icmp.ip_packet.dstip);
                fprintf(fp, "ICMP Type: %d ====== ICMP code %d", packet_p[i].packet.icmp.type, packet_p[i].packet.icmp.code);
            }
            break;
        }
        case 3: {
             if (!strcmp(src_filter, packet_p[i].packet.icmp.ip_packet.dstip)) {
                  fprintf(fp, "===== ICMP =====\n");
                  fprintf(fp, "Src IP is %s ---------->  Dst IP is %s\n", packet_p[i].packet.icmp.ip_packet.srcip,
                    packet_p[i].packet.icmp.ip_packet.dstip);
                  fprintf(fp, "ICMP Type: %d ====== ICMP code %d", packet_p[i].packet.icmp.type, packet_p[i].packet.icmp.code);
             }
             break;
     
        }
      }
    }
}

// Writes the src port information to a file
void write_src_port(packet_wrapper *packet_p, int src_filter, int count, FILE *fp) {
  int protocol;
  for (int i = 0; i < count; i++) {
    protocol = packet_p[i].type;
    switch (protocol) {
      case 1: {
          if (src_filter == packet_p[i].packet.tcp.src_port) {
            fprintf(fp, "===== TCP =====\n");
            fprintf(fp, "Src IP is %s:%d ---------->  Dst IP is %s:%d\n", packet_p[i].packet.tcp.ip_packet.srcip, packet_p[i].packet.tcp.src_port,
              packet_p[i].packet.tcp.ip_packet.dstip, packet_p[i].packet.tcp.dst_port);
          }
          break;
      }

      case 2: {
          if (src_filter == packet_p[i].packet.udp.src_port) {
            fprintf(fp, "===== UDP =====\n");
            fprintf(fp, "Src IP is %s:%d ---------->  Dst IP is %s:%d\n", packet_p[i].packet.udp.ip_packet.srcip, packet_p[i].packet.udp.src_port,
              packet_p[i].packet.udp.ip_packet.dstip, packet_p[i].packet.udp.dst_port);
          }
          break;
      }
    }
  }
}

// writes the destination IP to a file
void write_dst_port(packet_wrapper *packet_p, int src_filter, int count, FILE *fp) {
  int protocol;
  for (int i = 0; i < count; i++) {
    protocol = packet_p[i].type;
    switch (protocol) {
      case 1: {
          if (src_filter == packet_p[i].packet.tcp.src_port) {
            fprintf(fp, "==== TCP =====\n");
            fprintf(fp, "Src IP is %s:%d ---------->  Dst IP is %s:%d\n", packet_p[i].packet.tcp.ip_packet.srcip, packet_p[i].packet.tcp.src_port,
              packet_p[i].packet.tcp.ip_packet.dstip, packet_p[i].packet.tcp.dst_port);
          }
          break;
      }

      case 2: {
          if (src_filter == packet_p[i].packet.udp.src_port) {
            fprintf(fp, "===== UDP =====\n");
            fprintf(fp, "Src IP is %s:%d ---------->  Dst IP is %s:%d\n", packet_p[i].packet.udp.ip_packet.srcip, packet_p[i].packet.udp.src_port,
              packet_p[i].packet.udp.ip_packet.dstip, packet_p[i].packet.udp.dst_port);
          }
          break;

      }

    }
  }
}
