#include <elf.h>

typedef struct elf_header_list_node {
    Elf64_Ehdr *elf;
    void *child_elf;
    struct elf_header_list_node *next;
} elf_header_list_node;

int jump_to_start(pid_t pid);
int find_possible_elf_headers(pid_t pid, struct elf_header_list_node *elf_headers);
int free_elf_headers(struct elf_header_list_node *node);
