elfnab
======

Recovers a user-readable ELF file from a user-executable ELF file
or running process. This can effectively create a readable copy of a 
non-readable but executable file.

This is a proof-of-concept demonstration that Linux's read permission
means nothing if the file is executable.


elfnab works by attaching to the process (after spawning it with execl 
if need be) and reading the ELF header and program table entries from
the child's address space, and writing this into a valid ELF file. 

Section data cannot be retained, nor can symbols.

This is more of a proof of concept than anything but has potential use
for reverse engineering a program that an administrator has made executable
but non-readable.

Currently only works with x86_64 and 64-bit executables, I may extend it
to support 32-bit executables as well.

