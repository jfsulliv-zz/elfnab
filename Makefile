CC=gcc
CFLAGS=-g -Wall 

all: clean elfnab

elfnab: elf_tools.h elf_tools.o 
	$(CC) $(CFLAGS) elf_tools.o elfnab.c -o elfnab

elf_tools.o: elf_tools.h
	$(CC) $(CFLAGS) -c elf_tools.c -o elf_tools.o

clean:
	rm -rf *.o elfnab
