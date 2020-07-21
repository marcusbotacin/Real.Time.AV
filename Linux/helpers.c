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
#include "syscalls.h"
#include"yarah.h"

// Monitoring code itself
int do_trace(pid_t child) {
    int status, syscall, retval;
    struct user_regs_struct regs;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    while(1) {

        // wait for a syscall and identifies which one
        if (wait_for_syscall(child) != 0) break;
        syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
        int ident = 25 - strlen(syscalls[syscall]);
        fprintf(stderr, "syscall(%s)%*s", syscalls[syscall], ident," = ");
       
        // executes it and get return value
        if (wait_for_syscall(child) != 0) break;
        retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);
        fprintf(stderr, "%#x\n", retval);

        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        // only monitoring the write syscall in this PoC 
        if (syscall == WRITE_SYSCALL_NUMBER)
        {
            // need to get buffer argument to inspect
            long p = ptrace(PTRACE_PEEKDATA, child, BUFFER_REG, NULL);
            char buffer[FEW_BYTES];
            // only a few bytes inspected, since we want to check its start only
            memcpy(buffer,&p,FEW_BYTES);
            // YARA match
            if(yr_rules_scan_mem(rule,buffer,FEW_BYTES,0,&callback_function,NULL,0)!=ERROR_SUCCESS)
            {
                fprintf(stderr,"yara scan failed\n");
            }
        }
        if (syscall == 257)
        {
            fprintf(stderr,"open\n");
            long p = ptrace(PTRACE_PEEKDATA, child, regs.rsi, NULL);
            char buffer[100];
            memcpy(buffer,&p,100);
            printf("%s\n",buffer);
        }
    }
    return 0;
}

// Just wait until a syscall happens
int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            return 0;
        if (WIFEXITED(status))
            return 1;
    }
}

// Just create a child process that will be traced since its launch
int do_child(int argc, char **argv) {
    char *args [argc+1];
    memcpy(args, argv, argc * sizeof(char*));
    args[argc] = NULL;

    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    return execvp(args[0], args);
}
