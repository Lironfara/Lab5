#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#include <errno.h>

extern int system_call();
extern int startup(int argc, char **argv, void (*start)());
int startup(int argc, char **argv, void (*start)());

void print_phdr_details(Elf32_Phdr *phdr, int i);
void load_phdr(Elf32_Phdr *phdr, int fd);



const char *errno_name(int errnum) {
    switch (errnum) {
        case EPERM: return "EPERM";
        case ENOENT: return "ENOENT";
        case ESRCH: return "ESRCH";
        case EINTR: return "EINTR";
        case EIO: return "EIO";
        case ENXIO: return "ENXIO";
        case E2BIG: return "E2BIG";
        case ENOEXEC: return "ENOEXEC";
        case EBADF: return "EBADF";
        case ECHILD: return "ECHILD";
        case EAGAIN: return "EAGAIN";
        case ENOMEM: return "ENOMEM";
        case EACCES: return "EACCES";
        case EFAULT: return "EFAULT";
        case EBUSY: return "EBUSY";
        case EEXIST: return "EEXIST";
        case EXDEV: return "EXDEV";
        case ENODEV: return "ENODEV";
        case ENOTDIR: return "ENOTDIR";
        case EISDIR: return "EISDIR";
        case EINVAL: return "EINVAL";
        case ENFILE: return "ENFILE";
        case EMFILE: return "EMFILE";
        case ENOTTY: return "ENOTTY";
        case ETXTBSY: return "ETXTBSY";
        case EFBIG: return "EFBIG";
        case ENOSPC: return "ENOSPC";
        case ESPIPE: return "ESPIPE";
        case EROFS: return "EROFS";
        case EMLINK: return "EMLINK";
        case EPIPE: return "EPIPE";
        case EDOM: return "EDOM";
        case ERANGE: return "ERANGE";
        // Add more cases as needed.
        default: return "UNKNOWN_ERRNO";
    }
}


void load_phdr(Elf32_Phdr *phdr, int fd) {
    if (phdr->p_type == PT_LOAD) {
        int prot = PROT_NONE; //0
        if (phdr->p_flags & PF_R) prot |= PROT_READ;
        if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr->p_flags & PF_X) prot |= PROT_EXEC;
        
        int mapping = MAP_PRIVATE | MAP_FIXED;

        // Map the segment at the correct virtual address
        void *addr =  (void *)(phdr->p_vaddr&0xfffff000);
        int offset = phdr->p_offset & 0xfffff000;
        int padding = phdr->p_vaddr & 0xfff;

        void* map = mmap(addr, phdr->p_memsz + padding, prot, mapping, fd, offset);

        if (map == MAP_FAILED) {
            fprintf(stderr, "Failed to map segment at 0x%x: %s\n",
                    phdr->p_vaddr, errno_name(errno));
            return;
        }
        print_phdr_details(phdr, 0);
        
        
    }
}


// Function to print program header information

void print_phdr_details(Elf32_Phdr *phdr, int i) {
    const char *type;
     
    switch (phdr->p_type) {
        case PT_NULL: type = "NULL"; break;
        case PT_LOAD: type = "LOAD"; break;
        case PT_DYNAMIC: type = "DYNAMIC"; break;
        case PT_INTERP: type = "INTERP"; break;
        case PT_NOTE: type = "NOTE"; break;
        case PT_SHLIB: type = "SHLIB"; break;
        case PT_PHDR: type = "PHDR"; break;
        default: type = "UNKNOWN"; break;
    }
        //type   offset    vaddr  paddr filesz memsz 
    printf("%-8s 0x%06x 0x%08x \t0x%08x 0x%05x \t0x%05x ",
           type, phdr->p_offset,  phdr->p_vaddr, phdr->p_paddr,
           phdr->p_filesz, phdr->p_memsz); //to print it in hex

    printf("\t%c%c%c \t0x%x\n",
           (phdr->p_flags & PF_R) ? 'R' : ' ',
           (phdr->p_flags & PF_W) ? 'W' : ' ',
           (phdr->p_flags & PF_X) ? 'E' : ' ',
           phdr->p_align);
}


// Function to iterate over program headers
int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *, int), int arg) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start; // ELF stsrt
    Elf32_Phdr *phdr = (Elf32_Phdr *)((char *)map_start + ehdr->e_phoff);

    
    
    if(phdr == NULL){
        fprintf(stderr, "Failed to get program header table.\n");
        return -1;
    }
    // Program header table start

    printf("%-10s %-10s %-10s %-10s %-10s %-10s %-5s %-5s\n",
           "Type", "Offset", "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "\tFlg", "Align");
    for (int i = 0; i < ehdr->e_phnum; i++) {
        func(&phdr[i], arg);
    }

    return 0;
}



int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ELF file>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];

    // Open the ELF file
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    uint8_t e_ident[16]; //buffer to store the ELF header
    if (read(fd, e_ident, 16) != 16) { 
        perror("Failed to read file header");
        close(fd);
        printf("file is fucked up");
        return 0;
    } 

    if (e_ident[0] != 0x7f || e_ident[1] != 'E' ||
        e_ident[2] != 'L' || e_ident[3] != 'F') {
        printf ("Not an ELF file\n");
        return 0; // Not an ELF file
    }


    // Get the file size
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    // Map the ELF file into memory
    void *map_start = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    // Process the program headers
     if (foreach_phdr(map_start, print_phdr_details, 0) < 0) {
        fprintf(stderr, "Failed to iterate over program headers.\n");
    }
    printf("\n");
    /*the if above is to check 1, the function below is to check the loader*/
    foreach_phdr(map_start, load_phdr, fd);

    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start;
    void (*entry_point)() = (void (*)())(ehdr->e_entry);

    // Clean up
    munmap(map_start, st.st_size);
    printf("Starting program at address 0x%x...\n", (unsigned int)entry_point);


    Elf32_Ehdr* elf_head = (Elf32_Ehdr*) map_start;
    if(argc < 2){
        fprintf(stderr, "No program to load.\n");
        return -1;
    }
    if(argv+1 == NULL){
        fprintf(stderr, "No program to load.\n");
        return -1;
    }

    startup(argc-1, argv+1, entry_point);
    printf("Program finished.\n");
    return 0;

}
