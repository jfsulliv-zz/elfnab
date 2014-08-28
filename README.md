elfnab
======

Recovers a user-owned readable ELF file from a user-executable ELF file
or running process. This can effectively create a readable copy of a 
non-readable but executable file.

This is more of a proof of concept than anything but has potential use
for reverse engineering a program that an administrator has made executable
but non-readable.

Currently only works with x86_64 and 64-bit executables, I may extend it
to support 32-bit executables as well.

