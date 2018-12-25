# Shellcode_Infection
Compile by NASM
nasm -f elf shell_Infec_File.asm -o shell.o
ld -o shell shell.o -m elf_i386 (OS 64bit)
objdump -d shell -M intel
