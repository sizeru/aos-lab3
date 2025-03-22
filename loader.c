#include <assert.h> /* assert */
#include <elf.h> /* e_type */
#include <errno.h> /* errno */
#include <err.h> /* err */
#include <fcntl.h> /* open */
#include <stdlib.h> /* EXIT_FAILURE */
#include <stdbool.h> /* bool */
#include <stdio.h> /* printf */
#include <stdint.h> /* uint... */
#include <unistd.h> /* read */

typedef Elf64_Ehdr elf_header_t, elf_hdr;
typedef Elf64_Phdr elf_program_header_t, elf_phdr;
typedef Elf64_Shdr elf_section_header_t, elf_shdr;

bool bufdiff(const void* buf1, const void* buf2, int len);
void print_usage(const char* program);
bool parse_elf_header(int fd, elf_header_t* header);

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

	if (header->e_ident[7] != ELFOSABI_SYSV) {
		warn("Not Linux ABI");
		return false;
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

	int x = 0; // for breaking on
	return 0;
}
