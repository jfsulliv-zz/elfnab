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

/*
 * Returns a pointer to a malloc'd node that
 * has null elements.
 */
elf_header_list_node *initialize_node(void) 
{
    elf_header_list_node *start = (elf_header_list_node *)malloc(
            sizeof(elf_header_list_node));
    start->elf = 0;
    start->next = NULL;
    start->child_elf = 0;
    return start;
}

/* Returns the address of the executable header in the
 * linked list if it exists, or 0 otherwise.
 *
 * Also frees all other nodes and their elements, since
 * we are only concerned with the executable one.
 */
elf_header_list_node *find_executable_header(elf_header_list_node *start)
{
    if(!start) 
        return 0;

    //Traverse the list until an elf header is found with e_type = ET_EXEC  
    elf_header_list_node *real_elf = start;

    while(real_elf->elf->e_type != ET_EXEC) {
        if (!real_elf->next) {
            free_elf_headers(real_elf); // Tidy up
        }
        elf_header_list_node *next = real_elf->next;
        if(real_elf->elf)
            free(real_elf->elf);
        if(real_elf)
            free(real_elf);
        real_elf = next;
    }

    free_elf_headers(real_elf->next);

    return real_elf;
}

/* Finds the address of the ELF header(s) in the given
 * process address space. The process must already be
 * attached to with ptrace by the caller.
 *
 * Creates a linked list of ELF headers.
 *
 * Returns the address of the start node, or 0 on failure.
 */
elf_header_list_node *find_possible_elf_headers(pid_t pid) 
{
    // Most ELF headers (on x86_64) are loaded at 0x400000
    // but they can be loaded _anywhere_ that is page aligned,
    // so we check a reasonable range of addresses at the page
    // boundary.
    unsigned long long BASE_ADDR = 0;
    unsigned long long MAX_ADDR = 0xf0000000;
    int PG_SIZE = getpagesize();

    const char* elf_start = "\177ELF"; 

    elf_header_list_node *start = NULL;
    elf_header_list_node *prev = NULL;
    elf_header_list_node *node = start;

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
            node = initialize_node();
            node->elf = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr));
            if (read_header(pid, (void *)i, (void *)node->elf))
                continue;
            node->child_elf = (void *)i;

            // Conditionally modify the start and prev references.
            if (!prev) {
                // First iteration, start = node = prev (abuse of notation)
                prev = node;
                start = node;
            } else if (!prev->next) {
                // Second iteration, start = prev < node
                prev->next = node;
            } else {
                // Higher iterations, start < prev < node
                prev = prev->next;
                prev->next = node;
            }

            // Increment node pointer
            node = node->next;
        }
    }

    return start;
}

/*
 * Recursively frees all elements of the linked-list as well as their
 * respective elements.
 * Returns:
 *      0 on success
 */
int free_elf_headers(struct elf_header_list_node *node)
{
    if(!node) 
        return 1;

    if (node->next) {
        free_elf_headers(node->next);
    }
    
    if(node->elf)
        free(node->elf);
    if(node)
        free(node);
    return 0;
}


