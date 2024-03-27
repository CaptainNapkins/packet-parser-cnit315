#include <stdio.h>

// Function prototypes
int queryInterface();

// Main function
int main() {
    // Creates flag to end whole code loop
    int endFlag = 0
    // Whole code loop
    while (endFlag == 0) {
        // Gets user interface result
        int result = queryInterface();
        printf("You entered: %d\n", result);
        // Gets user end program result
        int result = queryInterface();
        if (result == ) {
            printf("Goodbye.");
        }
    }
    return 0;
}

// Queries for the user's requested interface
int queryInterface() {
    int usr;
    printf("Enter an interface: ");
    scanf("%d", &usr);
    return usr;
}


