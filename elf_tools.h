#include <elf.h>

typedef struct elf_header_list_node {
    Elf64_Ehdr *elf;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    void *child_elf;


    struct elf_header_list_node *next;
} elf_header_list_node;

unsigned long read_program(pid_t pid, elf_header_list_node *node, char **buf);

Elf64_Shdr *find_elf_shdr(pid_t pid, elf_header_list_node *node);
Elf64_Phdr *find_elf_phdr(pid_t pid, elf_header_list_node *node);
elf_header_list_node *initialize_node(void);
elf_header_list_node *find_executable_header(elf_header_list_node *start);
elf_header_list_node *find_possible_elf_headers(pid_t pid);
int free_elf_headers(struct elf_header_list_node *node);
