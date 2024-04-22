#include <stdio.h>
#include <string.h> 
#include <stdlib.h> 
#include "capture.c"
#include "filter.c"

char *queryInterface(); // Returns pointer to 'char *'
// Queries for the user's requested interface

void filter_menu () {
    puts("Protocol to Capture");
    puts("1. TCP");
    puts("2. UDP");
    puts("3. ICMP");
    puts("4. All");
    printf("Enter protocol choice: ");
}

void print_initial_menu() {
    puts("Main Menu");
    puts("1. Choose Interface to Listen");
    puts("2. Quit");
    printf("Please enter a number (1-2): ");

}

void additional_filters_menu() {
    puts("Additional Filters");
    puts("1. Src IP");
    puts("2. Dst IP");
    puts("3. Src Port");
    puts("4. Dst Port");
    puts("5. Exit");
}

void display_filters(int display_choice, packet_wrapper *packet_p, int count) {
    switch (display_choice) {
        // src ip filter
        char ip_to_filter[20];
        int port_to_filter;
        case 1: {
                printf("What src IP do you want to filter by? ");
                scanf("%s", ip_to_filter);
                filter_src_ip(packet_p, ip_to_filter, count);
                break;
            }
        case 2: {
                printf("What dst IP do you want to filter by? ");
                scanf("%s", ip_to_filter);
                filter_src_ip(packet_p, ip_to_filter, count);
                break;
            }
        case 3: {
                printf("What src port do you want to filter by? ");
                scanf("%d", &port_to_filter);
                filter_src_port(packet_p, port_to_filter, count);
                break;
            }
        case 4: {
                printf("What dst port do you want to filter by? ");
                scanf("%d", &port_to_filter);
                filter_dst_port(packet_p, port_to_filter, count);
                break;
            }
        case 5: {
                break;
            }
    }
}
int main() {
    int choice1;
    // Ends whole program
    int endFlag = 0;
    // sets capture status
    int capturing;
    int packet_num;
    char *interface;

    // int i;
    // This is an error buffer that ensures libpcap can print errors
    char errbuf[PCAP_ERRBUF_SIZE];
    // a pointer to the pcap handler 
    pcap_t* descr;

    // Whole code loop
    while (endFlag == 0) {
        print_initial_menu();
        scanf("%d", &choice1);
        
        switch (choice1) {
            case 1: {
                    interface = queryInterface();
                    endFlag = 1;
                    capturing = 1;
                    break;
                }
            case 2: {
                    capturing = 1;
                    endFlag = 1;
                    break;
                }
            case 3: {
                    endFlag = 1;
                    break;
                }
        }
    
    }

    int protocol_choice;
    // testing a nested loop here
    while (capturing) {
        int running = 1;
        char start[2];
        while (running) {
            printf("How many packets would you like to capture: ");
            scanf("%d", &packet_num);

            filter_menu();
            scanf("%d", &protocol_choice);

            printf("Start capture? [y/n]: ");
            scanf("%s", start);
            if (!strcmp(start, "y")) {
                puts("bruh");
                capturing = 0;
                break;
            }
        }
    }
    // Based on protocol choice, function here to compile filter

    // have logic to analyze/print capture here
    // Can have func that takes that displays each packet 
    // depending on protocol 
    
    printf("Capturing on %s...\n", interface);
    descr = pcap_open_live(interface, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live failed: %s\n", errbuf);
        exit(1);
    }

    pcap_loop(descr, packet_num, my_callback, NULL);
    
    // puts("GOING GLOBAL: Printing first packet from the global malloced chunk");
    // printf("Src IP is %s:%d\n", packet_buf[0].packet.tcp.ip_packet.srcip, packet_buf[0].packet.tcp.src_port);
    // printf("DST IP is %s:%d\n", packet_buf[0].packet.tcp.ip_packet.dstip, packet_buf[0].packet.tcp.dst_port);

    int additional_filter_choice;
    int filtering = 1;
    while (filtering) {
        additional_filters_menu();
        scanf("%d", &additional_filter_choice);
        display_filters(additional_filter_choice, packet_buf, packet_num);
        if (additional_filter_choice == 5) {
            break;
        }
    }

    puts("Goodbye!");
    free(packet_buf);
    return 0;
}

//Queries for the user's requested interface
char *queryInterface() {
    // Creates usr var for use in for (otherwise out of scope)
    char *usr = NULL;
    // Runs 3 times to attempt memory alloc, if it fails 3 times ends program
    for (int c = 3; c > 0; c--) {
        // creates dynamic memory for the usr response
        // declares usr to address of first char in malloc's 50 char string
        usr = malloc(sizeof(char) * 50); // sizeof(char) gets size per char (1 byte) malloc allocates * 50 times
        if (usr == NULL) { // If alloc is NULL, nothing was allocated meaning a failiure
            printf("Memory allocation failed\nRetrying...\n"); 
        }
        else { break; } // Successful alloc exits for
    }
    // Ends program if memory alloc fails 3 times, returns 1
    if (usr == NULL) { printf("Memory allocation failed\nEnding.\n"); exit(1);}

    /* WARNING - The printf line below will malfunction if typing spaces into asnwers,
       it will return every word for every space entered. I didn't fix it cause the
       interface names' format is uinknown right now. Just making a note of it now. */
    printf("Enter an interface (q to quit): "); /*THIS LINE*/
    scanf("%s", usr);
    return usr;
}
