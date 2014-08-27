#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <elf.h>

#include "elf_tools.h"

#define PID_MODE   0b01
#define PROGR_MODE 0b10

#define PID_MIN     0       // 0 < PID <= 65535
#define PID_MAX     65535   


int print_usage(char *name)
{
    printf("USAGE: %s [-i PID | -p PROGRAM ARGUMENTS | -h ]\n", name);
    return 0;
}

int main(int argc, char **argv, char **envp)
{

    if(argc < 2) {
        print_usage(argv[0]);
        exit(1);
    }

    int mode;
    mode = 0;

    char c;
    char *ival = NULL;
    int child_index = 0;

    opterr = 0;

    while((c = getopt(argc, argv, "i:p:")) != -1) {
        switch(c) {
            case 'i':
                mode |= PID_MODE; 
                ival = optarg;
                break;
            case 'p':
                mode |= PROGR_MODE;
                child_index = optind - 1;
                break;
            default:
                print_usage(argv[0]);
                exit(1);
                break;
        }
    } 

    pid_t pid;

    switch(mode) {

        case PID_MODE:
            {
                int ipid = atoi(ival);
                if(ipid <= PID_MIN || ipid > PID_MAX) {
                    fprintf(stderr, "Invalid PID \"%s\"\n",ival);
                    exit(1);
                }

                pid = (pid_t)ipid;

                // Attempt to attach to process and halt execution
                if (ptrace(PTRACE_ATTACH,pid,0,0)) {
                    perror("Failed to attach to process\n");
                    exit(1);
                }     

                kill(pid, SIGSTOP);
                printf("Stopped %d\n", (int)pid);
                break;
            }
        case PROGR_MODE:
            {
                char **child_argv = &argv[child_index];

                pid = fork();
                if(!pid) { // Child
                    ptrace(PTRACE_TRACEME, 0, 0, 0);
                    return execvp(child_argv[0], child_argv); 
                } else { // Parent
                    int status;
                    wait(&status);
                    printf("Attached to process %d\n", (int)pid);
                    // Bring execution forward until 
                    //  ELF is loaded
                    if(jump_to_start(pid)) {
                        perror("Failed to step execution.\n");
                        exit(1);
                    }  
                }

                break;
            }
        default:
            {
                perror("Input error.\n");
                exit(1);
            }

    }

    // Declare an empty header node and populate
    // a linked-list with the possible header node
    // addresses.
    int num_headers = 0;
    elf_header_list_node *start = 
        (elf_header_list_node*)malloc(
                sizeof(elf_header_list_node));
    start->elf = 0;
    start->next = 0;

    num_headers = find_possible_elf_headers(pid, start);
    if(num_headers == -1) {
        perror("Failed during attempt to find headers.\n");
        goto fail;
    } else if (num_headers == 0) {
        perror("Couldn't find any headers.\n");
        goto fail;
    } else if(!start->elf)
        goto fail;

    elf_header_list_node *real_elf = start;
    while(real_elf->elf->e_type != 2) {
        if(real_elf->next == NULL) {
            perror("No executable header found.\n");
            goto fail;
        }
        real_elf = real_elf->next;
    }
    printf("Found the executable header at %p\n",start->child_elf);

    

    free_elf_headers(start);
    return 0;
fail:
    {
        // Free all elements of the linked-list
        free_elf_headers(start);
        return 1;
    }
}
