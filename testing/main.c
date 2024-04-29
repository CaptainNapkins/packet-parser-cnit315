#include <stdio.h>
#include <string.h> 
#include <stdlib.h> 
#include "capture.c"
#include "filter.c"

char *queryInterface(); // Returns pointer to 'char *'
// Queries for the user's requested interface

void filter_menu() {
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
        case 1: {
            char ip_to_filter[20];
            printf("What src IP do you want to filter by? ");
            scanf("%s", ip_to_filter);
            filter_src_ip(packet_p, ip_to_filter, count);
            break;
        }
        case 2: {
            char ip_to_filter[20];
            printf("What dst IP do you want to filter by? ");
            scanf("%s", ip_to_filter);
            filter_dst_ip(packet_p, ip_to_filter, count);
            break;
        }
        case 3: {
            int port_to_filter;
            printf("What src port do you want to filter by? ");
            scanf("%d", &port_to_filter);
            filter_src_port(packet_p, port_to_filter, count);
            break;
        }
        case 4: {
            int port_to_filter;
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
    int endFlag = 0; // Flag to end the program
    int capturing;
    int packet_num;
    char *interface;

    // int i;
    // This is an error buffer that ensures libpcap can print errors
     char errbuf[PCAP_ERRBUF_SIZE];
    // a pointer to the pcap handler 
     pcap_t *descr;

    // Loop to select interface or quit
    while (!endFlag) {
        print_initial_menu();
        if (scanf("%d", &choice1) != 1) {
            printf("Error: Invalid input.\n");
            exit(EXIT_FAILURE);
        }

        switch (choice1) {
            case 1: {
                interface = queryInterface();
                endFlag = 1;
                capturing = 1;
                break;
            }
            case 2: {
                endFlag = 1;
                break;
            }
            default: {
                printf("Error: Invalid choice.\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    int protocol_choice;
    // Nested loop for packet capturing
    while (capturing) {
        char start[2];
        while (1) {
            printf("How many packets would you like to capture: ");
            if (scanf("%d", &packet_num) != 1) {
                printf("Error: Invalid input.\n");
                exit(EXIT_FAILURE);
            }

            filter_menu();
            if (scanf("%d", &protocol_choice) != 1) {
                printf("Error: Invalid input.\n");
                exit(EXIT_FAILURE);
            }

            printf("Start capture? [y/n]: ");
            if (scanf("%s", start) != 1) {
                printf("Error: Invalid input.\n");
                exit(EXIT_FAILURE);
            }
            if (!strcmp(start, "y")) {
                puts("Starting capture...");
                capturing = 0;
                break;
            }
        }
    }

    // Based on protocol choice, function here to compile filter
 
 
    // have logic to analyze/print capture here
    // Open interface for capturing
    // Can have func that takes that displays each packet 
    // depending on protocol 
    printf("Capturing on %s...\n", interface);
    descr = pcap_open_live(interface, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL) {
        printf("Error: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Capture packets
    pcap_loop(descr, packet_num, my_callback, NULL);

    // Additional filters
    int additional_filter_choice;
    int filtering = 1;
    while (filtering) {
        additional_filters_menu();
        if (scanf("%d", &additional_filter_choice) != 1) {
            printf("Error: Invalid input.\n");
            exit(EXIT_FAILURE);
        }
        display_filters(additional_filter_choice, packet_buf, packet_num);
        if (additional_filter_choice == 5) {
            break;
        }
    }

    // Cleanup
    puts("Goodbye!");
    free(packet_buf);
    pcap_close(descr);

    return 0;
}

// Queries for the user's requested interface
char *queryInterface() {
    char *usr = NULL;
    for (int c = 3; c > 0; c--) {
        usr = malloc(sizeof(char) * 50);
        if (usr == NULL) {
            printf("Memory allocation failed\nRetrying...\n");
        } else {
            break;
        }
    }
    if (usr == NULL) {
        printf("Memory allocation failed\nEnding.\n");
        exit(EXIT_FAILURE);
    }
    printf("Enter an interface (q to quit): ");
    if (scanf("%s", usr) != 1) {
        printf("Error: Failed to read interface name.\n");
        exit(EXIT_FAILURE);
    }
    return usr;
}
