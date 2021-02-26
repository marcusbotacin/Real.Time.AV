// Receiver for intercepted function call's data
// Marcus Botacin - UFPR - 2021

// Imports and definitions

#define _GNU_SOURCE
#define RUNNING_CORE 2
#define PIPE_NAME "./fifoChannel"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>

int main() {

    // Let's run on a distinct core to stress cache coherence and so on
    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(RUNNING_CORE, &mask);
    int result = sched_setaffinity(0, sizeof(mask), &mask);

    // Open PIPE
    const char* file = PIPE_NAME;
    int fd = open(file, O_CREAT | O_RDONLY);
    // Check if pipe was opened
    if (fd < 0){
        printf("pipe open failed\n");
        return -1;
    }

    // Run Forever (adjust to your criteria)
    while (1) {
        int next;
        // Get data from intercepted APIs
        ssize_t count = read(fd, &next, sizeof(next));
        // Check if data is avalilable
        if(count != 0)
        {   
            // Add your detection routine here
            printf("received %d\n",next);
        }
    }

    // Ideally, close descriptors and perform cleanup
    close(fd);      
    unlink(file);   

    return 0;
}
