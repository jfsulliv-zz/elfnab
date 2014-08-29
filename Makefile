CC=gcc
CFLAGS=-g -Wall 

all: clean elfnab

elfnab: elf_tools.h elf_tools.o elf_list.o 
	$(CC) $(CFLAGS) elf_tools.o elf_list.o elfnab.c -o elfnab

elf_tools.o: elf_list.o elf_tools.h
	$(CC) $(CFLAGS) -c elf_tools.c -o elf_tools.o

elf_list.o: elf_tools.h
	$(CC) $(CFLAGS) -c elf_list.c -o elf_list.o

clean:
	rm -rf *.o elfnab
