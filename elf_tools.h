#include <elf.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/types.h>
typedef struct elf_file {
    void *child_ehdr;
    void *ehdr;
    size_t ehdr_size;
    void *phdr;
    size_t phdr_size;
    void *shdr;
    size_t shdr_size;
    int bits;
} elf_file;

typedef struct elf_list {
    elf_file *elf;
    struct elf_list *next;
} elf_list;

elf_list *initialize_node();
int delete_list(elf_list *node);

typedef struct elf_header_list_node {
    Elf64_Ehdr *elf;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    void *child_elf;
    struct elf_header_list_node *next;
} elf_header_list_node;

unsigned long read_program32(pid_t pid, elf_file *elf, char **buf);
unsigned long read_program64(pid_t pid, elf_file *elf, char **buf);

Elf32_Shdr *find_elf32_shdr(pid_t pid, elf_file *elf);
Elf32_Phdr *find_elf32_phdr(pid_t pid, elf_file *elf);
Elf64_Shdr *find_elf64_shdr(pid_t pid, elf_file *elf);
Elf64_Phdr *find_elf64_phdr(pid_t pid, elf_file *elf);
elf_list *find_possible_elf_headers(pid_t pid);
