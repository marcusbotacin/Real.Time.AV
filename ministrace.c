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

// some definitions
#define WRITE_SYSCALL_NUMBER 1
#define FEW_BYTES 10
#define BUFFER_REG regs.rbp

// Prototypes
int do_child(int argc, char **argv);
int do_trace(pid_t child);
int wait_for_syscall(pid_t child);

// Lets read syscall names from a file. Any better idea?
char* syscallArray[333];
void syscallName(void){
  FILE* fp;
  fp = fopen("syscall-names.txt","r");
  char syscall[30];
  int i = 0,j = 0;
  for(i = 0;i<333;i++){
    fscanf(fp, "%s",syscall);
    char* syscallmalloc = malloc(sizeof(char)*30);
    strcpy(syscallmalloc,syscall);
    syscallArray[j++] = syscallmalloc;
  }
  fclose(fp);
}

// YARA callback for matching rules
int callback_function(int message,void* message_data, void* user_data)
{
    if(message == CALLBACK_MSG_RULE_MATCHING)
    {
        YR_RULE *rule = (YR_RULE*)message_data;
        fprintf(stderr,"\033[1;31m");
        fprintf(stderr,">>> Matched %s!\n",rule->identifier);
        fprintf(stderr,"\033[0m;");
    }
    return CALLBACK_CONTINUE;
}

// Global vars (ok, these should be arguments but...)
YR_COMPILER *cc;
YR_RULES *rule;

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
    syscallName();

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

// Just create a child process that will be traced since its launch
int do_child(int argc, char **argv) {
    char *args [argc+1];
    memcpy(args, argv, argc * sizeof(char*));
    args[argc] = NULL;

    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    return execvp(args[0], args);
}

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
        fprintf(stderr, "syscall(%s) = ", syscallArray[syscall]);
       
        // executes it and get return value
        if (wait_for_syscall(child) != 0) break;
        retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);
        fprintf(stderr, "%d\n", retval);

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
