// Matching YARA rules against syscall arguments
// inspired from: https://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code/
// Adapted by: Lucas Galante
// Updated by: Marcus Botacin

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <yara.h>
#include"syscalls.h"
#include"yarah.h"

int main(int argc, char **argv) {
    int ret;

    // currently only supporting a single yara rule (PoC only)
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <yara_rule> <app_path> <app_args>\n", argv[0]);
        exit(1);
    }
   
    // YARA setup and some user notifications

    fprintf(stderr, "Setting Up YARA\n");

    if(yr_initialize()!=ERROR_SUCCESS)
    {
        fprintf(stderr,"YARA failed to init\n");
    }
    if(yr_compiler_create(&cc)!=ERROR_SUCCESS)
    {
        fprintf(stderr,"YARA compiler not created\n");
    }

    // Compile all rules at startup so no overhead during matching
    FILE *fd = fopen(argv[1],"r");
    if(yr_compiler_add_file(cc, fd, NULL, NULL)!=ERROR_SUCCESS)
    {
        fprintf(stderr,"YARA rule not parsed\n");
    }
    fclose(fd);
    if(yr_compiler_get_rules(cc, &rule)!=ERROR_SUCCESS)
    {
        fprintf(stderr,"YARA rule not compiled\n");
    }

    fprintf(stderr, "Starting Tracing\n");

    // then trace process
    pid_t child = fork();
    if (child == 0) {
        return do_child(argc-2, argv+2);
    }
    else {
        ret = do_trace(child);
    }
    
    fprintf(stderr, "Trace Finished\n");

    // free yara stuff beforing finishing

    yr_compiler_destroy(cc);
    if(yr_finalize()!=ERROR_SUCCESS)
    {
        fprintf(stderr,"YARA failed to finish\n");
    }
    fprintf(stderr, "YARA Finished\n");

    return ret;
 }
