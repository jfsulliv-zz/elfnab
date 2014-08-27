#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "elf_tools.h"

#define ORIG_EAX_OFFSET     44

/* Tools for elfnab to find and fetch ELFs */

/* Continue execution of a program until the ELF 
 * is loaded in memory. This should ONLY be used
 * on a program that is JUST starting its life, 
 * ie one that was fork()'d and exec()'d by us.
 */
int jump_to_start(pid_t pid) 
{
    int status;
    int ret;
    int brks_left = 3;
    struct user_regs_struct regs;
    do {
        // Step to the next system call entry/exit
        if(ptrace(PTRACE_SYSCALL, pid, 0, 0)) {
            return 1;
        }
        wait(&status);   

        errno = 0; 
        ptrace(PTRACE_GETREGS, pid,
                0, &regs);

        if(errno) {
            return 1;
        }  
        ret = regs.orig_rax;
        if(ret == SYS_brk)
            brks_left--;
    } while(brks_left > 0);
    // Step once more to exit BRK
    ptrace(PTRACE_SYSCALL, pid, 0, 0);

    return 0; 

}

/* Reads and four bytes at addr
 * in the process address space of pid,
 * and writes it into memory at desti.
 * Returns: 
 *      1 on failure
 *      0 on success
 */
int read_word(pid_t pid, int *addr, unsigned long *dest)
{
    if(pid <= 0 ) {
        return 1;
    } 

    errno = 0;
    int ret;
    ret = ptrace(PTRACE_PEEKDATA, pid,
            addr, 0);
    if(errno) {
        return 1;
    }
    *dest = ret;

    return 0;
}

/* Reads sizeof(Elf64_Ehdr) bytes from addr in pid,
 * and copies it to dest.
 * Returns:
 *      1 on failure
 *      0 on success
 */
int read_header(pid_t pid, void *addr, Elf64_Ehdr *dest)
{
    if(pid <= 0 || !dest) {
        return 1;
    }

    unsigned long long ret;
    int i;
    int max = sizeof(Elf64_Ehdr);
    int word_size = sizeof(void *);
    for(i = 0; i < max; i += word_size) {
        char *off = (char *)(dest) + i;
        errno = 0;
        ret = ptrace(PTRACE_PEEKDATA, pid, addr+i, 0);
        if(errno) {
            free(dest);
            return 1;
        }
        memcpy(off, &ret, word_size);
    }

    return 0; 
}

/* Finds the address of the ELF header(s) in the given
 * process address space. The process must already be
 * attached to with ptrace by the caller.
 *
 * Creates a linked list of ELF headers.
 *
 * Returns:
 *  num_headers the number of headers found on success
 *  -1 if no headers are found 
 */
int find_possible_elf_headers(pid_t pid, struct elf_header_list_node *node) 
{
    // Most ELF headers (on x86_64) are loaded at 0x400000
    // but they can be loaded _anywhere_ that is page aligned,
    // so we check a reasonable range of addresses at the page
    // boundary.
    unsigned long long BASE_ADDR = 0;
    unsigned long long MAX_ADDR = 0xf0000000;
    int PG_SIZE = getpagesize();

    const char* elf_start = "\177ELF"; 

    int num_headers = 0; 

    elf_header_list_node *start = node;

    unsigned long long i;
    unsigned long word;
    int ret;
    int size = strlen(elf_start);
    // Iterate by page boundary and check for magic ELF value
    for(i = BASE_ADDR; i < MAX_ADDR; i+=PG_SIZE) {
        ret = read_word(pid, (void*)i, &word);
        if(!ret && !memcmp(elf_start, (void *)&word, size)) {
            printf("Found possible header at %p\n",(void*)i);

            // Add a new node to the list
            if(node == start) {
                node->elf = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
                read_header(pid, (void*)i, (void*)node->elf);
                node->next = NULL;
                node->child_elf = (void*)i;
            } else {
                elf_header_list_node *new = 
                        (elf_header_list_node*)malloc(
                        sizeof(elf_header_list_node)); 
                
                // Copies the header into our address space
                new->elf = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
                read_header(pid, (void*)i, (void*)new->elf);
                new->next = NULL;
                new->child_elf = (void*)i;

                node->next = new;
                node = new;
                
            }
            num_headers++;
        }
    }
    return (num_headers ? num_headers : -1);
}

/*
 * Frees all elements of the linked-list as well as their
 * respective Elf64_Ehdr elements.
 * Returns:
 *      1 on failure
 *      0 on success
 */
int free_elf_headers(struct elf_header_list_node *node)
{
    elf_header_list_node *start = node;

    // Get the length of the list
    int length = 0;
    while(node != NULL) {
        node = node->next;
        length++;
    }

    if(length == 0) 
        return 0;       

    int i,j;
    node = start;
    for(i = length-1; i >= 0; i--) {
        j = i;
        // Traverse to the i'th node
        while(j > 0) {
            node = node->next;
        }
        if(node->elf)
            free(node->elf);
        if(node)
            free(node);
    }

    return 0;
}


