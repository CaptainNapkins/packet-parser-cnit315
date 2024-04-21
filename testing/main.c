#include <stdio.h>
#include <string.h> 
#include <stdlib.h> )

char *queryInterface(); // Returns pointer to 'char *'

int main() {
    int choice1;
    // Ends whole program
    int endFlag = 0;
    // sets capture status
    int capturing;
    char *interface;
    // Whole code loop
    while (endFlag == 0) {
        print_initial_menu();
        scanf("%d", &choice1);
        
        switch (choice1) {
            case 1: {
                    interface = queryInterface();
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

    // Begin while loop here for capturing stuff

    printf("%s\n", interface);
    return 0;
}

void print_initial_menu() {
    puts("Main Menu");
    puts("1. Choose Interface to Listen");
    puts("2. View Capture");
    puts("3. Quit");
    printf("Please enter a number (1-2): ");

}
// Queries for the user's requested interface
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

