#include <stdio.h>
#include <string.h> 
#include <stdlib.h> 
#include <stdbool.h>
#include "capture.c"
#include "filter.c"
#include "file_ops.c"

char *queryInterface(); // Returns pointer to 'char *'
// Queries for the user's requested interface

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
    puts("5. All");
    puts("6. Exit");
}

void final_menu() {
    puts("Would you like to write results to a file? [y/n]");
}


// Logic here will take the packet_buffer with all of the structs with different kinds of packets
// and can filter and display results and/or write the results to a file of the users' choice
// pass the protocol choice, the main packet buffer (packet_p), total number of packets, and file pointer
// such that the functions in filter.c and file_ops.c can handle them
void display_filters(int display_choice, packet_wrapper *packet_p, int count, bool file_write, FILE *fp) {
    switch (display_choice) {
        // src ip filter
        char ip_to_filter[20];
        int port_to_filter;
        case 1: {
                printf("What src IP do you want to filter by? ");
                scanf("%s", ip_to_filter);
                filter_src_ip(packet_p, ip_to_filter, count);
                // if that variable is true then we will write to a file
                if (file_write) {
                    write_src_ip(packet_p, ip_to_filter, count, fp);
                }
                break;
            }
        case 2: {
                printf("What dst IP do you want to filter by? ");
                scanf("%s", ip_to_filter);
                filter_src_ip(packet_p, ip_to_filter, count);
                if (file_write) {
                    write_dst_ip(packet_p, ip_to_filter, count, fp);
                }
                break;
            }
        case 3: {
                printf("What src port do you want to filter by? ");
                scanf("%d", &port_to_filter);
                filter_src_port(packet_p, port_to_filter, count);
                if (file_write) {
                    write_src_port(packet_p, port_to_filter, count, fp);
                }
                break;
            }
        case 4: {
                printf("What dst port do you want to filter by? ");
                scanf("%d", &port_to_filter);
                filter_dst_port(packet_p, port_to_filter, count);
                if (file_write) {
                    write_dst_port(packet_p, port_to_filter, count, fp);
                }
                break;
            }
        case 5: {
                printf("Displaying all traffic\n");
                display_all(packet_p, count);
                if (file_write) {
                    write_all(packet_p, count, fp);
                }
            }
        case 6: {
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
                    // Exit program here
                    return 1;
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

            printf("Start capture? [y/n]: ");
            scanf("%s", start);
            if (!strcmp(start, "y")) {
                puts("bruh");
                capturing = 0;
                break;
            }
        }
    }
    
    printf("Capturing on %s...\n", interface);
    descr = pcap_open_live(interface, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live failed: %s\n", errbuf);
        exit(1);
    }

    pcap_loop(descr, packet_num, my_callback, NULL);
    
    int additional_filter_choice;
    int filtering = 1;
    char file_option[2];
    char file_name[20];
    bool file_write = false;
    // This loop takes care of all the filtering logic
    // Asks user for a file if they wish to write results to one and passes on program logic to the 
    // display_filters function
    while (filtering) {
        additional_filters_menu();
        scanf("%d", &additional_filter_choice);

        printf("Would you like to write the results to a file? ");
        scanf("%2s", file_option);

        if (!strcmp(file_option, "y")) {
            file_write = true;
            printf("Enter the desired filename: ");
            scanf("%s", file_name);
            FILE *fp = fopen(file_name, "w");
            if (fp == NULL) {
                printf("Error opening file.\n");
                return 1;
            }
            display_filters(additional_filter_choice, packet_buf, packet_num, file_write, fp);
            
        }
        else {

            display_filters(additional_filter_choice, packet_buf, packet_num, file_write, NULL);
        }
        
        if (additional_filter_choice == 6) {
            break;
        }
    }

    puts("Goodbye!");
    // Frees our main packet_buf from memory to prevent memory leaks
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
