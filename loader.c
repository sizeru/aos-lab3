#include <assert.h> /* assert */
#include <elf.h> /* e_type */
#include <errno.h> /* errno */
#include <err.h> /* err */
#include <fcntl.h> /* open */
#include <stdlib.h> /* EXIT_FAILURE */
#include <stdbool.h> /* bool */
#include <stdio.h> /* printf */
#include <stdint.h> /* uint... */
#include <string.h> /* strcmp */
#include <unistd.h> /* read */

#define PAGESIZE 0x1000

typedef Elf64_Ehdr elf_header_t, elf_hdr;
typedef Elf64_Phdr elf_program_header_t, elf_phdr;
typedef Elf64_Shdr elf_section_header_t, elf_shdr;

bool bufdiff(const void* buf1, const void* buf2, int len);
void print_elf_header(elf_hdr* header);
void print_usage(const char* program);
bool parse_elf_header(int fd, elf_header_t* header);
void stack_check(void* top_of_stack, uint64_t argc, char** argv);

void print_elf_header(elf_hdr* header) {
    printf("ELF Header:\n");
    printf("Magic: %02x %02x %02x %02x\n", header->e_ident[EI_MAG0],
                                           header->e_ident[EI_MAG1],
                                           header->e_ident[EI_MAG2],
                                           header->e_ident[EI_MAG3]);
    printf("Class \t\t\t\t\t%d\n", header->e_ident[EI_CLASS]);
    printf("Data \t\t\t\t\t%d\n", header->e_ident[EI_DATA]);
    printf("Version: \t\t\t\t0x%x\n", header->e_ident[EI_VERSION]);
    printf("OS/ABI: \t\t\t\t0x%x\n", header->e_ident[EI_OSABI]);
    printf("ABI Version: \t\t\t\t0x%x\n", header->e_ident[EI_ABIVERSION]);
    printf("Type \t\t\t\t\t%d\n", header->e_type);
    printf("Machine: \t\t\t\t%d\n", header->e_machine);
    printf("Version: \t\t\t\t0x%x\n", header->e_version);
    printf("Entry point address: \t\t\t0x%lu\n", header->e_entry);
    printf("Start of program headers: \t\t0x%lx (bytes into file)\n", header->e_phoff);
    printf("Start of section headers: \t\t0x%lx (bytes into file)\n", header->e_shoff);
    printf("Flags: \t\t\t\t\t0x%x\n", header->e_flags);
    printf("Size of this header: \t\t\t%d (bytes)\n", header->e_ehsize);
    printf("Size of program headers: \t\t%d (bytes)\n", header->e_phentsize);
    printf("Number of program headers: \t\t%d\n", header->e_phnum);
    printf("Size of section headers: \t\t%d (bytes)\n", header->e_shentsize);
    printf("Number of section headers: \t\t%d\n", header->e_shnum);
    printf("Section header string table index: \t%d\n", header->e_shstrndx);
    printf("\n");
}

/**
 * Checking stack made for child program.
 * top_of_stack: stack pointer that will given to child program as %rsp
 * argc: Expected number of arguments
 * argv: Expected argument strings
 */
void stack_check(void* top_of_stack, uint64_t argc, char** argv) {
	printf("----- stack check -----\n");

	assert(((uint64_t)top_of_stack) % 8 == 0);
	printf("top of stack is 8-byte aligned\n");

	uint64_t* stack = top_of_stack;
	uint64_t actual_argc = *(stack++);
	printf("argc: %lu\n", actual_argc);
	assert(actual_argc == argc);

	for (int i = 0; i < argc; i++) {
		char* argp = (char*)*(stack++);
		assert(strcmp(argp, argv[i]) == 0);
		printf("arg %d: %s\n", i, argp);
	}
	// Argument list ends with null pointer
	assert(*(stack++) == 0);

	int envp_count = 0;
	while (*(stack++) != 0)
		envp_count++;

	printf("env count: %d\n", envp_count);

	Elf64_auxv_t* auxv_start = (Elf64_auxv_t*)stack;
	Elf64_auxv_t* auxv_null = auxv_start;
	while (auxv_null->a_type != AT_NULL) {
		auxv_null++;
	}
	printf("aux count: %lu\n", auxv_null - auxv_start);
	printf("----- end stack check -----\n");
}

// Returns if two buffers differ
bool bufdiff(const void* buf1, const void* buf2, int len) {
	const char *b1 = buf1, *b2 = buf2;
	for (int i = 0; i < len; i++) {
		if (b1[i] != b2[i]) {
			return true;
		}
	}
	return false;
}

// Parse an elf header
bool parse_elf_header(int fd, elf_header_t* header) {
	read(fd, header, 64);

	const char magic_number[4] = {0x7f, 'E', 'L', 'F'};
	if (bufdiff(header, magic_number, 4)) {
		warn("Elf magic number not present");
		return false;
	}

	if (header->e_ident[4] != ELFCLASS64) {
		warn("Not a 64b executable");
		return false;
	}

	if (header->e_ident[5] != ELFDATA2LSB) {
		warn("Not little endian");
		return false;
	}

	if (header->e_ident[6] != EV_CURRENT) {
		warn("Unknown elf version");
	}

	if (header->e_ident[7] != ELFOSABI_SYSV && header->e_ident[7] != ELFOSABI_LINUX) {
		warn("Strange OS ABI");
	}

	return true;
}

void print_usage(const char* program) {
	printf("%s <exec>\nLoad and run the ELF file <exec>\n", program);
}

// Execute an x86_64 ELF file
int main(int argc, char* argv[]) {
	// Check arguments
	if (argc < 2) {
		print_usage(argv[0]);
		return -1;
	}

	// Open
	const char* progname = argv[1];
	int progfd = open(progname, O_RDONLY, 0);
	if (-1 == progfd) {
		err(errno, NULL);
	}

	// Read header
	elf_header_t header;
	if (!parse_elf_header(progfd, &header)) {
		err(EXIT_FAILURE, "Elf header not valid");
	}
	print_elf_header(&header);

	// Read program headers
	if(header.e_phnum == PN_XNUM) {
		err(EXIT_FAILURE, "Maxed out program headers. Not supporetd by this loader");
	}
	int phdr_len = header.e_phentsize * header.e_phnum;
	elf_phdr* prog_headers = malloc(phdr_len);
	if (-1 == lseek(progfd, header.e_phoff, SEEK_SET)) {
		err(EXIT_FAILURE, NULL);
	}
	if (-1 == read(progfd, prog_headers, phdr_len)) {
		err(EXIT_FAILURE, "Couldn't read all program headers");
	}

	// Read section headers
	int shdr_len = header.e_phentsize * header.e_phnum;
	elf_shdr* section_headers = malloc(shdr_len);
	if (-1 == lseek(progfd, header.e_shoff, SEEK_SET)) {
		err(EXIT_FAILURE, NULL);
	}
	if (-1 == read(progfd, section_headers, shdr_len)) {
		err(EXIT_FAILURE, "Couldn't read all section headers");
	}


	return 0;
}
