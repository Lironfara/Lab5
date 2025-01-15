all: clean loader

loader: loader.o startup.o start.o
	ld -o loader loader.o startup.o start.o -L/usr/lib32 -lc -T linking_script -dynamic-linker /lib32/ld-linux.so.2

loader.o: loader.c
	gcc -m32 -c loader.c -o loader.o

startup.o: startup.s
	nasm -f elf32 -o startup.o startup.s

start.o: start.s
	nasm -f elf32 -o start.o start.s

.PHONY: clean
clean:
	rm -f loader *.o