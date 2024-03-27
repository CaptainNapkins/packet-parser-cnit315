#include <stdio.h>
#include <string.h> // String functions, used in *queryInterface()
#include <stdlib.h> // Dynamic memory allocation, used in *queryInterface()

// Function prototypes
char *queryInterface(); // Returns pointer to 'char *'

// Main function
int main() {
    // Creates flag to end whole code loop
    int endFlag = 0;
    // Whole code loop
    while (endFlag == 0) {
        // Gets user interface result
        char *result = queryInterface();
        printf("  You entered: %s\n", result);
        // Checks user end program result (uses string compare strcmp(str1, str2))
        if (strcmp(result, "q") == 0) { // strcmp returns 0 if they are equal
            printf("\n-= Goodbye, ending program. =-\n");
            // Sets flag to 1, ending program
            endFlag = 1;
        }
    }
    return 0;
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


