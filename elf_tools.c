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

/* Reads a word in the process address space of pid,
 * and writes it into memory at dest.
 *
 *
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
 * Scans the process text for the Section Header,
 *
 * Returns:
 *      A pointer to a local copy of the program header table,
 *      or 0 on failure.
 *
 */
Elf64_Shdr *find_elf64_shdr(pid_t pid, elf_file *elf)
{
    if(!elf) 
        return 0;
    Elf64_Ehdr *header = (Elf64_Ehdr *)elf->ehdr;
    if(!header)
        return 0;

    unsigned long offset = (unsigned long)header->e_shoff;
    if(!offset)
        return 0;

    unsigned long shdr_addr = offset + (unsigned long)elf->child_ehdr;
    int p_sz = sizeof(Elf64_Shdr) * header->e_shnum;
    if(p_sz >= getpagesize())
        return 0;
    else if (!p_sz)
        return 0;

    void* buf = malloc(p_sz);

    if(read_from_process(pid, (void *)shdr_addr, (void *)buf, p_sz)) {
        free(buf);
        return 0;
    }

    return buf;
}
Elf32_Shdr *find_elf32_shdr(pid_t pid, elf_file *elf)
{
    if(!elf) 
        return 0;
    Elf32_Ehdr *header = (Elf32_Ehdr *)elf->ehdr;
    if(!header)
        return 0;

    unsigned long offset = (unsigned long)header->e_shoff;
    if(!offset)
        return 0;

    unsigned long shdr_addr = offset + (unsigned long)elf->child_ehdr;
    int p_sz = sizeof(Elf32_Shdr) * header->e_shnum;
    if(p_sz >= getpagesize())
        return 0;
    else if (!p_sz)
        return 0;

    void* buf = malloc(p_sz);

    if(read_from_process(pid, (void *)shdr_addr, (void *)buf, p_sz)) {
        free(buf);
        return 0;
    }

    return buf;
}

/*
 * Scans the process text for the Program Header,
 *
 * Returns:
 *      A pointer to a local copy of the program header table,
 *      or 0 on failure.
 *
 */
Elf64_Phdr *find_elf64_phdr(pid_t pid, elf_file *elf)
{
    if(!elf) 
        return 0;
    Elf64_Ehdr *header = (Elf64_Ehdr *)elf->ehdr;
    if(!header)
        return 0;

    unsigned long offset = (unsigned long)header->e_phoff;
    if(!offset)
        return 0;

    unsigned long phdr_addr = offset + (unsigned long)elf->child_ehdr;
    int p_sz = sizeof(Elf64_Phdr) * header->e_phnum;
    if(p_sz >= getpagesize())
        return 0;
    else if (!p_sz)
        return 0;

    void* buf = malloc(p_sz);

    if(read_from_process(pid, (void *)phdr_addr, (void *)buf, p_sz)) {
        free(buf);
        return 0;
    }

    return buf;
}
Elf32_Phdr *find_elf32_phdr(pid_t pid, elf_file *elf)
{
    if(!elf) 
        return 0;
    Elf32_Ehdr *header = (Elf32_Ehdr *)elf->ehdr;
    if(!header)
        return 0;

    unsigned long offset = (unsigned long)header->e_phoff;
    if(!offset)
        return 0;

    unsigned long phdr_addr = offset + (unsigned long)elf->child_ehdr;
    int p_sz = sizeof(Elf32_Phdr) * header->e_phnum;
    if(p_sz >= getpagesize())
        return 0;
    else if (!p_sz)
        return 0;

    void* buf = malloc(p_sz);

    if(read_from_process(pid, (void *)phdr_addr, (void *)buf, p_sz)) {
        free(buf);
        return 0;
    }

    return buf;
}

/*
 * Returns the size of the program.
 *
 */
unsigned long get_program64_size(pid_t pid, elf_file *elf)
{
    if(!elf || !elf->ehdr || !elf->phdr)
        return 0;

    int i = 0;
    unsigned long size = 0;
    unsigned long this_size = 0;

    Elf64_Ehdr *ehdr = elf->ehdr;
    Elf64_Phdr *phdr = elf->phdr;
    Elf64_Phdr *this_phdr;
    Elf64_Shdr *shdr = elf->shdr;

    // Check for the upper bound of a program entry
    for(i = 0; i < ehdr->e_phnum; i++) {
        this_phdr = &phdr[i];
        if(this_phdr->p_memsz > this_phdr->p_filesz)
            this_size = this_phdr->p_memsz;
        else
            this_size = this_phdr->p_filesz;

        if(this_size + this_phdr->p_offset > size)
            size = this_size + this_phdr->p_offset;
    }

    // Check to see if the Section Table header is higher than the above
    unsigned long shdr_size = 0;
    if(shdr) {
        shdr_size = ehdr->e_shnum * sizeof(Elf64_Shdr);
        this_size = shdr_size;
        if(this_size + shdr->sh_offset > size)
            size = shdr->sh_offset + size;
    }

    printf("Program size : %lu bytes\n",size);
    return size;
}
/*
 * Returns the size of the program.
 *
 */
unsigned long get_program32_size(pid_t pid, elf_file *elf)
{
    if(!elf || !elf->ehdr || !elf->phdr)
        return 0;

    int i = 0;
    unsigned long size = 0;
    unsigned long this_size = 0;

    Elf32_Ehdr *ehdr = elf->ehdr;
    Elf32_Phdr *phdr = elf->phdr;
    Elf32_Phdr *this_phdr;
    Elf32_Shdr *shdr = elf->shdr;

    // Check for the upper bound of a program entry
    for(i = 0; i < ehdr->e_phnum; i++) {
        this_phdr = &phdr[i];
        if(this_phdr->p_memsz > this_phdr->p_filesz)
            this_size = this_phdr->p_memsz;
        else
            this_size = this_phdr->p_filesz;

        if(this_size + this_phdr->p_offset > size)
            size = this_size + this_phdr->p_offset;
    }

    // Check to see if the Section Table header is higher than the above
    unsigned long shdr_size = 0;
    if(shdr) {
        shdr_size = ehdr->e_shnum * sizeof(Elf32_Shdr);
        this_size = shdr_size;
        if(this_size + shdr->sh_offset > size)
            size = shdr->sh_offset + size;
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
unsigned long read_program64(pid_t pid, elf_file *elf, char **buf)
{
    if(!elf || !elf->ehdr || !elf->phdr)
        return 0;

    int prog_size = get_program64_size(pid, elf);

    Elf64_Ehdr *ehdr = elf->ehdr;
    Elf64_Phdr *phdr = elf->phdr;
    Elf64_Shdr *shdr = elf->shdr;

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
                printf("FAILED to read ");
            } else {
                printf("wrote at ");
            }
            printf("%d - %d\n", (unsigned int)cur->p_offset, (unsigned int)(cur->p_offset+size));
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
        s_addr = (unsigned long)ehdr +
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
unsigned long read_program32(pid_t pid, elf_file *elf, char **buf)
{
    if(!elf || !elf->ehdr || !elf->phdr)
        return 0;

    int prog_size = get_program32_size(pid, elf);

    Elf32_Ehdr *ehdr = elf->ehdr;
    Elf32_Phdr *phdr = elf->phdr;
    Elf32_Shdr *shdr = elf->shdr;

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
        Elf32_Phdr *cur = &phdr[i];
        size = cur->p_memsz;
        p_addr = (unsigned long)cur->p_vaddr; 
        printf("Segment %d type 0x%08x flag %d at 0x%08x - 0x%08x ",i+1, (int)cur->p_type, (int)cur->p_flags, (unsigned int )p_addr, (unsigned int)(p_addr + size));
        if(cur->p_type == PT_LOAD || cur->p_type == PT_DYNAMIC) {
            if (read_from_process(pid, (void *)p_addr, &bufptr[cur->p_offset], size)) {
                printf("FAILED to read at ");
            } else {
                printf("wrote at ");
            }
            printf("%d - %d\n", (unsigned int)cur->p_offset, (unsigned int)(cur->p_offset+size));
        } else {
            printf("nothing to write\n");
        } 
    }

    // Write the section header table if we could recover it
    if(shdr) {
        printf("-----\n");
        printf("Section Header\n");
        printf("-----\n");
        size = sizeof(Elf32_Shdr) * ehdr->e_shnum;
        s_addr = (unsigned long)ehdr +
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
        Elf32_Ehdr *temp_ptr = (void *)bufptr;
        temp_ptr->e_shoff = 0;
        temp_ptr->e_shnum = 0;
        temp_ptr->e_shnum = 0;
        temp_ptr->e_shstrndx = 0;
    }

    return prog_size;
}

int is_executable64(pid_t pid, elf_file *elf)
{

    Elf64_Ehdr *ehdr = elf->ehdr;
    if(!ehdr)
        return 0;
    return ehdr->e_type == ET_EXEC;
}
int is_executable32(pid_t pid, elf_file *elf)
{
    Elf32_Ehdr *ehdr = elf->ehdr;
    if(!ehdr)
        return 0;
    return ehdr->e_type == ET_EXEC;
}

/* Finds the address of the ELF header(s) in the given
 * process address space. The process must already be
 * attached to with ptrace by the caller.
 *
 * Creates a linked list of ELF headers.
 *
 * Returns the address of the start node, or 0 on failure.
 */
elf_list *find_possible_elf_headers(pid_t pid) 
{
    // Most ELF headers (on x86_64) are loaded at 0x400000
    // but they can be loaded _anywhere_ that is page aligned,
    // so we check a reasonable range of addresses at the page
    // boundary.
    unsigned long long BASE_ADDR = 0;
    unsigned long long MAX_ADDR = 0xf0000000;
    int PG_SIZE = getpagesize();

    const char* elf_start = "\177ELF"; 
    const int size = strlen(elf_start);

    elf_list *start = NULL;
    elf_list *prev = NULL;
    elf_list *node = start;

    unsigned long i;
    unsigned long word;
    int ret;

    // Iterate by page boundary and check for magic ELF value
    for(i = BASE_ADDR; i < MAX_ADDR; i+=PG_SIZE) {
        ret = read_word(pid, (void *)i, (void *)&word);
        if(!ret && !memcmp(elf_start, (void *)&word, size)) {
            // Add a new node to the list
            node = initialize_node();

            // Try to get the bit size
            char elf_class = 0;
            if (read_word(pid, (void *)i+size, (void *)&elf_class)) {
                delete_list(node);
                continue;
            }

            if(elf_class == 1)
                node->elf->bits = 32;
            else
                node->elf->bits = 64;

            printf("%d\n",node->elf->bits);

            if(node->elf->bits == 32) { 
                node->elf->ehdr = (void *)malloc(sizeof(Elf32_Ehdr));
                node->elf->ehdr_size = sizeof(Elf32_Ehdr);
            }
            else { 
                node->elf->ehdr = (void *)malloc(sizeof(Elf64_Ehdr));
                node->elf->ehdr_size = sizeof(Elf64_Ehdr);
            }

            // Try to read the ELF header
            if (read_from_process(pid, (void *)i, (void *)node->elf->ehdr,
                        node->elf->ehdr_size)) {
                delete_list(node);
                continue;
            }
           
            int (*is_executable)(pid_t, elf_file *); 
            if(node->elf->bits == 32)
                is_executable = &is_executable32;
            else
                is_executable = &is_executable64;
            if(!is_executable(pid, node->elf)) {
                printf("Discarding non-executable node %p\n",(void*)i);
                delete_list(node);
                continue;
            }
            printf("Found possible header at %p\n",(void*)i);
            node->elf->child_ehdr = (void*)i;

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
