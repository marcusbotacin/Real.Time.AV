// Sender for intercepted function call's data
// Marcus Botacin - UFPR - 2021

// Imports and definitions

#define _GNU_SOURCE
#define RUNNING_CORE 0
#define PIPE_NAME "./fifoChannel"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>

// Hooked Function Prototypes
typedef size_t* (*orig_fwrite_type)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
typedef size_t* (*orig_fwrite_unlocked_type)(const void *ptr, size_t size, size_t n, FILE *stream);

// Hook Main function to pin process to a core and stress cache coherence
static void init (void) __attribute__ ((constructor));
static void init (void)
{
    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(RUNNING_CORE, &mask);
    int result = sched_setaffinity(0, sizeof(mask), &mask);
}

// Hook WRITE function (and variations)
size_t fwrite_unlocked(const void *ptr, size_t size, size_t n, FILE *stream){
    // Get address original function
    orig_fwrite_unlocked_type orig_fwrite_unlocked;
    orig_fwrite_unlocked = (orig_fwrite_unlocked_type)dlsym(RTLD_NEXT,"fwrite_unlocked");
    // Open PIPE
    const char* pipeName = PIPE_NAME;
    mkfifo(pipeName, 0666);                     
    int fd = open(pipeName, O_WRONLY);
    // Send data if pipe is open
    if (fd >= 0)
    {
      // serialize arguments and pipe it
      // add your implementation here
      int data = 99;
      write(fd, &data, sizeof(data));
      close(fd);
    }
    // invoke original function
    return orig_fwrite_unlocked(ptr,size,n,stream);   
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream){
    orig_fwrite_type orig_fwrite;
    orig_fwrite = (orig_fwrite_type)dlsym(RTLD_NEXT,"fwrite");
    return orig_fwrite(ptr,size,nmemb,stream);   
}
