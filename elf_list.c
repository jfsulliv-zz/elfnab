#include "elf_tools.h"
#include <stdlib.h>

/*  
 * Functions relevant to the linked-list 
 * of possible ELF headers that are found
 * in the scan.
 */

/*
 *   Returns a reference to a malloc'd elf_list object.
 *     NULL is returned on failure.
 */
elf_list *initialize_node()
{
    elf_list *node = (elf_list *)malloc(sizeof(elf_list));
    if(!node)
        return 0;
    node->elf = (elf_file *)malloc(sizeof(elf_file));
    if(!node->elf) {
        free(node);
        return 0;
    }
    node->elf->ehdr = 0;
    node->elf->phdr = 0;
    node->elf->shdr = 0;
    node->next = NULL;
    return node;
}

/*
 *  Recursively deletes the linked-list of elf_list nodes
 *  originating at node.
 */
int delete_list(elf_list *node) 
{
    if(!node)
        return 0;
    if(node->next)
        delete_list(node->next);

    if(node->elf) {
        elf_file *elf = node->elf;
        if(elf->ehdr)
            free(elf->ehdr);
        if(elf->phdr)
            free(elf->phdr);
        if(elf->shdr)
            free(elf->shdr);
        free(node->elf);
    }
    free(node);
    node = 0;
    return 0;
}

