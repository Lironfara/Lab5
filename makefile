all: task2 task1 
task1:
	gcc -m32 -g -Wall -o loader loader.c
	
task2:
	nasm -f elf32 -o start.o start.s
	gcc -m32 -c loader.c -o loader.o
	ld -o loader loader.o startup.o start.o -L/usr/lib32 -lc -T linking_script -dynamic-linker /lib32/ld-linux.so.2

.PHONY: clean
clean:
	rm -f loader task1 task2