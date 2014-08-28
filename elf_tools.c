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
int read_word(pid_t pid, void *addr, unsigned long *dest)
{
    if(pid <= 0 ) {
        return 1;
    } 

    errno = 0;
    unsigned long ret;
    ret = ptrace(PTRACE_PEEKDATA, pid,
            addr, 0);
    if(errno) {
        return 1;
    }
    *dest = ret;

    return 0;
}

/* Reads num bytes from addr in pid,
 * and copies it to dest.
 *
 * NOT memory safe. You _can_ overflow dest.
 *
 * Returns:
 *
 *      1 on failure
 *      0 on success
 */
int read_from_process(pid_t pid, void *addr, void *dest, size_t num)
{
    if(pid <= 0 || !dest) {
        return 1;
    }

    int word_size = sizeof(void *);
    int dif = num % word_size;
    int i;

    for(i = 0; i < num; i += word_size) {
        unsigned long *off = (void *)(dest) + i;
        if(read_word(pid, addr+i, (void *)off))
            return 1;
    }
    // Zero out extra bytes
    if (dif) {
        char *end = (char *)dest + i - word_size;
        memset(end, 0, dif);
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

/*
 * Scans the process text for the Program Header,
 *
 * Returns:
 *      A pointer to a local copy of the program header table,
 *      or 0 on failure.
 *
 */
Elf64_Phdr *find_elf_phdr(pid_t pid, elf_header_list_node *node)
{

    if(!node) 
        return 0;
    Elf64_Ehdr *header = node->elf;
    if(!header)
        return 0;

    unsigned long offset = (unsigned long)header->e_phoff;
    if(!offset)
        return 0;

    unsigned long phdr_addr = offset + (unsigned long)node->child_elf;
    int p_sz = sizeof(Elf64_Phdr) * header->e_phnum;
    if(p_sz >= getpagesize())
        return 0;
    else if (!p_sz)
        return 0;

    Elf64_Phdr* buf = malloc(p_sz);

    if(read_from_process(pid, (void *)phdr_addr, (void *)buf, p_sz)) {
        free(buf);
        return 0;
    }

    return buf;

}

/*
 * Scans the process text for the Section Header,
 *
 * Returns:
 *      A pointer to a local copy of the section header table,
 *      or 0 on failure.
 *
 */
Elf64_Shdr *find_elf_shdr(pid_t pid, elf_header_list_node *node)
{

    if(!node) 
        return 0;
    Elf64_Ehdr *header = node->elf;
    if(!header)
        return 0;

    unsigned long offset = (unsigned long)header->e_shoff;
    if(!offset)
        return 0;

    unsigned long shdr_addr = offset + (unsigned long)node->child_elf;
    int s_sz = sizeof(Elf64_Shdr) * header->e_shnum;
    if(s_sz >= getpagesize())
        return 0;
    else if (!s_sz)
        return 0;

    Elf64_Shdr* buf = malloc(s_sz);

    if(read_from_process(pid, (void *)shdr_addr, (void *)buf, s_sz)) {
        free(buf);
        return 0;
    }

    return buf;

}

/*
 * Returns the size of the program.
 *
 */
unsigned long get_program_size(pid_t pid, elf_header_list_node *node)
{
    if(!node || !node->elf || !node->phdr || !node->child_elf)
        return 0;

    int i = 0;
    unsigned long size = 0;
    unsigned long this_size = 0;

    // Check for the upper bound of a program entry
    for(i = 0; i < node->elf->e_phnum; i++) {
        Elf64_Phdr *phdr = &node->phdr[i];
        if(phdr->p_memsz > phdr->p_filesz)
            this_size = phdr->p_memsz;
        else
            this_size = phdr->p_filesz;

        if(this_size + phdr->p_offset > size)
            size = this_size + phdr->p_offset;
    }

    // Check to see if the Section Table header is higher than the above
    unsigned long shdr_size = 0;
    if(node->shdr) {
        shdr_size = node->elf->e_shnum * sizeof(Elf64_Shdr);
        this_size = shdr_size;
        if(this_size + node->shdr->sh_offset > size)
            size = node->shdr->sh_offset + size;
    }

    printf("Program size : %lu bytes\n",size);
    return size;
}

/*
 * Reads the entire program into a character buffer on the heap,
 * assuming that Ehdr and Phdr are already populated in node.
 *
 * Returns 0 on failure, and the bytes read on success.. 
 *
 */
unsigned long read_program(pid_t pid, elf_header_list_node *node, char **buf)
{
    if(!node || !node->elf || !node->phdr || !node->child_elf)
        return 0;

    int prog_size = get_program_size(pid, node);

    Elf64_Ehdr *ehdr = node->elf;
    Elf64_Phdr *phdr = node->phdr;
    Elf64_Shdr *shdr = node->shdr;

    *buf = (char *)calloc(prog_size, sizeof(char));
    char *bufptr = *buf;
    if(!bufptr)
        return 0;

    // Iterate through the program headers
    // And read the non-LOAD entries into buf.
    int i;
    unsigned long size = 0;
    int max = ehdr->e_phnum;
    unsigned long p_addr;
    unsigned long s_addr;

    // Write all of the program pages 
    printf("-----\n");
    printf("Program Header\n");
    printf("-----\n");
    for(i = 0; i < max; i ++) {
        Elf64_Phdr *cur = &phdr[i];
        size = cur->p_memsz;
        p_addr = (unsigned long)cur->p_vaddr; 
        printf("Segment %d type 0x%08x flag %d at 0x%08x - 0x%08x ",i+1, (int)cur->p_type, (int)cur->p_flags, (unsigned int )p_addr, (unsigned int)(p_addr + size));
        if(cur->p_type == PT_LOAD || cur->p_type == PT_DYNAMIC) {
            if (read_from_process(pid, (void *)p_addr, &bufptr[cur->p_offset], size)) {
                free(bufptr);
                *buf = 0;
                return 0;
            }
            printf("wrote at %d - %d\n", (unsigned int)cur->p_offset, (unsigned int)(cur->p_offset+size));
        } else {
            printf("nothing to write\n");
        } 
    }

    // Write the section header table if we could recover it
    if(shdr) {
        printf("-----\n");
        printf("Section Header\n");
        printf("-----\n");
        size = sizeof(Elf64_Shdr) * ehdr->e_shnum;
        s_addr = (unsigned long)node->child_elf +
            (unsigned long)ehdr->e_shoff;
        printf("Section Header from 0x%08x - 0x%08x ", (unsigned int)s_addr, (unsigned int)(s_addr + size));
        printf("wrote to %d - %d\n", (unsigned int)ehdr->e_shoff, (unsigned int)(ehdr->e_shoff+size));
        if (read_from_process(pid, (void *)s_addr, &bufptr[ehdr->e_shoff], size)) {
            free(bufptr);
            *buf = 0;
            return 0;
        }
    } else {
        printf("-----\n");
        printf("No Section Header Table recovered\n");
        printf("----\n");
        // Null out the relevant section header data
        Elf64_Ehdr *temp_ptr = (void *)bufptr;
        temp_ptr->e_shoff = 0;
        temp_ptr->e_shnum = 0;
        temp_ptr->e_shnum = 0;
        temp_ptr->e_shstrndx = 0;
    }

    return prog_size;
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
        printf("Not %p\n",real_elf->child_elf);
        if (!real_elf->next) {
            free_elf_headers(real_elf); // Tidy up
            return 0;
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
        ret = read_word(pid, (void *)i, (void *)&word);

        if(!ret && !memcmp(elf_start, (void *)&word, size)) {


            // Add a new node to the list
            node = initialize_node();
            node->elf = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr));
            if (read_from_process(pid, (void *)i, (void *)node->elf,
                        sizeof(Elf64_Ehdr)))
                continue;
            node->child_elf = (void *)i;

            if (node->elf->e_type != ET_EXEC) {
                printf("Discarding non-executable header\n");
                free(node->elf);
                free(node);
                continue;
            }
            printf("Found possible header at %p\n",(void*)i);

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
    if(node->phdr)
        free(node->phdr);
    if(node->shdr)
        free(node->shdr);
    if(node)
        free(node);
    return 0;
}


