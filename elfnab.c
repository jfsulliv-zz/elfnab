#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
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

/*
 * Writes num bytes to the file filename, creating it 
 * if it does not exist.
 * 
 */
int write_to_file(char *filename, char *buf, size_t num)
{
    FILE *fp;
    fp = fopen(filename, "wb");
    fwrite(buf, num, sizeof(char), fp);
    int fd = fileno(fp);

    
    // Set execution bit
    int flags = 0;
    flags |= S_IXUSR;
    flags |= S_IRUSR;
    flags |= S_IXGRP;
    flags |= S_IRGRP;

    fchmod(fd, flags);
    fclose(fp);

    return 0;
}

/*
 * Attempts to attach to pid, if it is valid.
 * Returns 1 on failure, 0 on success.
 */
int attach_to_pid(pid_t pid) {

    if(pid <= PID_MIN || pid > PID_MAX) {
        fprintf(stderr, "Invalid PID \"%d\"\n",pid);
        return 1;
    }

    if (ptrace(PTRACE_ATTACH,pid,0,0)) {
        perror("Failed to attach to process\n");
        return 1;
    }     

    kill(pid, SIGSTOP);
    printf("Stopped %d\n", (int)pid);

    return 0;
}

/*
 * Attempts to spawn and attach to a process.
 * Also steps the process until it is ready to be scanned.
 * The child will not return since execl(args) is called.
 * The parent will return 0 on failure and pid on success.
 */
pid_t spawn_and_attach_process(char **child_argv)
{
    pid_t pid = fork();

    if(!pid) { // Child
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(child_argv[0], child_argv); 
        fprintf(stderr,"Failed to execute %s\n", child_argv[0]);
    } else { // Parent
        int status;
        if (!waitpid(pid,&status,WUNTRACED))
            return 0;
        if (WIFEXITED(status)) 
            return 0;
        printf("Attached to process %d\n", (int)pid);
    }

    return pid;
}

/* 
 * Scans the process for the real ELF header and
 * returns a pointer to an elf_header_list node,
 * which contains a copy of the Ehdr, Phdr, and the child
 * address of them.
 *
 * Returns:
 *      *elf_header on success
 *      0 on failure
 *
 */
elf_header_list_node *get_header(pid_t pid)
{
    // Populate a linked-list with the possible elf headers.
    elf_header_list_node *start = find_possible_elf_headers(pid);
    if(!start) {
        perror("Could not find any nodes.\n");
        goto fail;
    } else if(!start->elf) {
        goto fail;
    }

    elf_header_list_node *real_elf = start;

    // Try to find one with a valid program header
    while(real_elf) {
        real_elf->shdr = find_elf_shdr(pid, real_elf);
        if(!real_elf->shdr) {
            printf("No section header found for %p\n",real_elf->child_elf);
        }

        real_elf->phdr = find_elf_phdr(pid, real_elf);
        if(!real_elf->phdr) {
            printf("No program header found for %p - invalid Ehdr\n",real_elf->child_elf);
            // Remove this node and increment ptr
            if(real_elf->shdr)
                free(real_elf->shdr);
            if(real_elf->elf)
                free(real_elf->elf);
            free(real_elf);
            real_elf = real_elf->next;
        } else {
            break;
        }

    }
    if(!real_elf)
        goto fail;

    // Free any later nodes
    if(real_elf->next)
        free_elf_headers(real_elf->next);

    printf("Using header %p\n",real_elf->child_elf);
    return real_elf;

fail:
    if(start) 
        free_elf_headers(start);
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


    char *filename = NULL;
    char c;
    char *ival = NULL;
    int child_index = 0;

    opterr = 0;

    while((c = getopt(argc, argv, "i:p:o:")) != -1) {
        switch(c) {
            case 'i':
                mode |= PID_MODE; 
                ival = optarg;
                break;
            case 'p':
                mode |= PROGR_MODE;
                child_index = optind - 1;
                break;
            case 'o':
                filename = optarg;
                break;
            default:
                print_usage(argv[0]);
                exit(1);
                break;
        }
    } 

    if(!mode) {
        print_usage(argv[0]);
        exit(1);
    }

    if(!filename) {
        filename = "a.out";
    }

    pid_t pid;
    switch(mode) {
        case PID_MODE:
            {
                pid = atoi(ival);
                if (attach_to_pid(pid))
                    exit(1);
                break;
            }
        case PROGR_MODE:
            {
                char **child_argv = &argv[child_index];
                pid = spawn_and_attach_process(child_argv); 
                if (!pid)
                    exit(1);
                break;
            }
        default:
            {
                perror("Input error.\n");
                exit(1);
            }

    }

    elf_header_list_node *hdr = get_header(pid);
    if(!hdr)
        exit(1);

    int size = 0;
    char *text;
    size = read_program(pid, hdr, &text);
    if(text) {
        printf("Writing %d bytes to file %s\n",size,filename);
        write_to_file(filename, text, size);
        free(text);
    } else {
        printf("Failed to read ELF. No file written.\n");
    } 
    if(hdr) 
        free_elf_headers(hdr);

    return 0;
}


