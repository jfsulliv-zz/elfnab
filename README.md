elfnab
======

Recovers a user-readable ELF32/64 file from a user-executable ELF32/64 file
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


Current implementation of compatibility for ELF32 and ELF64 is ugly,
I may attempt to improve this in the future.


Not a robust program, this is just for fun. 
