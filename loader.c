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
#include <sys/cdefs.h>
#include <sys/mman.h> /* mmap */
#include <unistd.h> /* read */

#define PAGESIZE 0x1000
#define PAGECEIL(num) (((num) + (PAGESIZE - 1)) & ~(PAGESIZE - 1))
#define PAGEFLOOR(num) ((num) & ~(PAGESIZE - 1))

typedef Elf64_Ehdr elf_header_t, elf_hdr;
typedef Elf64_Phdr elf_program_header_t, elf_phdr;
typedef Elf64_Shdr elf_section_header_t, elf_shdr;

void grow_and_refurbish_stack(const void* initial_sp);
bool bufdiff(const void* buf1, const void* buf2, int len);
void print_elf_header(elf_hdr* header);
void print_usage(const char* program);
void print_phdr(elf_phdr* phdr);
void print_shdr(elf_shdr* shdr, elf_hdr* ehdr, int fd);
bool parse_elf_header(int fd, elf_header_t* header);
void stack_check(void* top_of_stack, uint64_t argc, char** argv);
void prep_regs();
void read_symtab(Elf64_Shdr* shdr, Elf64_Sym** symtab, int elf_fd);
bool relocate_syms(Elf64_Shdr* shdrs, Elf64_Shdr* rela_shdr, Elf64_Rela* rela, Elf64_Sym* symtab, int elf_fd, uint64_t strtab_offset);

bool relocate_syms(Elf64_Shdr* shdrs, Elf64_Shdr* rela_shdr, Elf64_Rela* rela, Elf64_Sym* symtab, int elf_fd, uint64_t strtab_offset) {
	if (!symtab) { // might not be ready yet
		return false;
	}
	printf("Relocating\n");
    for(int i = 0; i < rela_shdr->sh_size / sizeof(Elf64_Rela); i++)
    {
        uint64_t sym_name_offset = strtab_offset + symtab[ELF64_R_SYM(rela[i].r_info)].st_name;
        char sym_name[128] = {0}; // should be enough???
        if (-1 == lseek(elf_fd, sym_name_offset, SEEK_SET)) {
			err(EXIT_FAILURE, "Couldn't seek when searching for symbol name for relocation");
		}
        unsigned long bytes_read = read(elf_fd, sym_name, sizeof(sym_name));
        if (bytes_read <= 0) {
			err(EXIT_FAILURE, "Couldn't read when searching for symbol name for relocation");
		}
		printf("[%i] %s needs relocation.\n", i, sym_name);



        // switch (ELF32_R_TYPE(rel[j].r_info))
        // {
        //     case R_386_JMP_SLOT:
        //     case R_386_GLOB_DAT:
        //         *(Elf32_Word*)(dst + rel[j].r_offset) = (Elf32_Word)resolve(sym);
        //         break;
        // }
    }
    return false;
}

void read_symtab(Elf64_Shdr* shdr, Elf64_Sym** symtab, int elf_fd) {
	Elf64_Sym* symbols = malloc(shdr->sh_size);
	*symtab = symbols;
	if (-1 == lseek(elf_fd, shdr->sh_offset, SEEK_SET)) {
		err(EXIT_FAILURE, "Couldn't seek when searching for main symbol");
	}
	if (shdr->sh_size != read(elf_fd, symbols, shdr->sh_size)) {
		err(EXIT_FAILURE, "Couldn't read when searching for main symbol");
	}
}

// Grow the stack and 'refurbish' it so that it appears like a fresh new stack
// ready for a new main function. Format of stack taken from:
// https://web.archive.org/web/20220126113327/http://www.mindfruit.co.uk/2012/01/initial-stack-reading-process-arguments.html
__always_inline void grow_and_refurbish_stack(const void* initial_sp) {
}

// Prep regs for the control transfer
__always_inline void prep_regs() {
}

void print_shdr(elf_shdr* shdr, elf_hdr* ehdr, int fd) {
	char* sh_type;
	switch(shdr->sh_type) {
	case SHT_NULL:           sh_type = "SHT_NULL"; break;
	case SHT_PROGBITS:       sh_type = "SHT_PROGBITS"; break;
	case SHT_SYMTAB:         sh_type = "SHT_SYMTAB"; break;
	case SHT_STRTAB:         sh_type = "SHT_STRTAB"; break;
	case SHT_RELA:           sh_type = "SHT_RELA"; break;
	case SHT_HASH:           sh_type = "SHT_HASH"; break;
	case SHT_DYNAMIC:        sh_type = "SHT_DYNAMIC"; break;
	case SHT_NOTE:           sh_type = "SHT_NOTE"; break;
	case SHT_NOBITS:         sh_type = "SHT_NOBITS"; break;
	case SHT_REL:            sh_type = "SHT_REL"; break;
	case SHT_SHLIB:          sh_type = "SHT_SHLIB"; break;
	case SHT_DYNSYM:         sh_type = "SHT_DYNSYM"; break;
	case SHT_INIT_ARRAY:     sh_type = "SHT_INIT_ARRAY"; break;
	case SHT_FINI_ARRAY:     sh_type = "SHT_FINI_ARRAY"; break;
	case SHT_PREINIT_ARRAY:  sh_type = "SHT_PREINIT_ARRAY"; break;
	case SHT_GROUP:          sh_type = "SHT_GROUP"; break;
	case SHT_SYMTAB_SHNDX:   sh_type = "SHT_SYMTAB_SHNDX"; break;
	case SHT_RELR:           sh_type = "SHT_RELR"; break;
	case SHT_NUM:            sh_type = "SHT_NUM"; break;
	case SHT_LOOS:           sh_type = "SHT_LOOS"; break;
	case SHT_GNU_ATTRIBUTES: sh_type = "SHT_GNU_ATTRIBUTES"; break;
	case SHT_GNU_HASH:       sh_type = "SHT_GNU_HASH"; break;
	case SHT_GNU_LIBLIST:    sh_type = "SHT_GNU_LIBLIST"; break;
	case SHT_CHECKSUM:       sh_type = "SHT_CHECKSUM"; break;
	case SHT_LOSUNW:         sh_type = "SHT_LOSUNW"; break;
	case SHT_SUNW_COMDAT:    sh_type = "SHT_SUNW_COMDAT"; break;
	case SHT_SUNW_syminfo:   sh_type = "SHT_SUNW_syminfo"; break;
	case SHT_GNU_verdef:     sh_type = "SHT_GNU_verdef"; break;
	case SHT_GNU_verneed:    sh_type = "SHT_GNU_verneed"; break;
	case SHT_GNU_versym:     sh_type = "SHT_GNU_versym"; break;
	case SHT_LOPROC:         sh_type = "SHT_LOPROC"; break;
	case SHT_HIPROC:         sh_type = "SHT_HIPROC"; break;
	case SHT_LOUSER:         sh_type = "SHT_LOUSER"; break;
	case SHT_HIUSER:         sh_type = "SHT_HIUSER"; break;
	default: asprintf(&sh_type, "0x%x", shdr->sh_type); break;
	}

	char sflags[17] = {0};
	sflags[ 0] = shdr->sh_flags & SHF_WRITE             ? 'W' : ' ';
	sflags[ 1] = shdr->sh_flags & SHF_ALLOC             ? 'A' : ' ';
	sflags[ 2] = shdr->sh_flags & SHF_EXECINSTR         ? 'X' : ' ';
	sflags[ 3] = shdr->sh_flags & SHF_MERGE             ? 'M' : ' ';
	sflags[ 4] = shdr->sh_flags & SHF_STRINGS           ? 'S' : ' ';
	sflags[ 5] = shdr->sh_flags & SHF_INFO_LINK         ? 'I' : ' ';
	sflags[ 6] = shdr->sh_flags & SHF_LINK_ORDER        ? 'O' : ' ';
	sflags[ 7] = shdr->sh_flags & SHF_OS_NONCONFORMING  ? 'N' : ' ';
	sflags[ 8] = shdr->sh_flags & SHF_GROUP             ? 'G' : ' ';
	sflags[ 9] = shdr->sh_flags & SHF_TLS               ? 'T' : ' ';
	sflags[10] = shdr->sh_flags & SHF_COMPRESSED        ? 'C' : ' ';
	sflags[11] = shdr->sh_flags & SHF_MASKOS            ? 'm' : ' ';
	sflags[12] = shdr->sh_flags & SHF_MASKPROC          ? 'p' : ' ';
	sflags[13] = shdr->sh_flags & SHF_GNU_RETAIN        ? 'r' : ' ';
	sflags[14] = shdr->sh_flags & SHF_ORDERED           ? 'o' : ' ';
	sflags[15] = shdr->sh_flags & SHF_EXCLUDE           ? 'e' : ' ';

	if (shdr->sh_type != SHT_NULL) {
		printf("Elf section header: \n");
		printf("name: 0x%x", shdr->sh_name);
		if (shdr->sh_name != 0) {
			static bool init = false;
			static char* sh_strtab_data;
			if (!init) {
				static elf_shdr sh_strtab;
				// Read header
				int sh_str_tab_offset = ehdr->e_shoff + (ehdr->e_shstrndx * ehdr->e_shentsize);
				if (-1 == lseek(fd, sh_str_tab_offset, SEEK_SET)) {
					err(EXIT_FAILURE, "Couldn't seek to this point in the file");
				}
				if (sizeof(elf_shdr) != read(fd, &sh_strtab, sizeof(elf_shdr))) {
					err(EXIT_FAILURE, "Couldn't read %lu B from 0x%x (for strtab section header)", sizeof(elf_shdr), sh_str_tab_offset);
				}
				// Read data
				sh_strtab_data = malloc(sh_strtab.sh_size);
				if (-1 == lseek(fd, sh_strtab.sh_offset, SEEK_SET)) {
					err(EXIT_FAILURE, "Couldn't seek to this point in the file");
				}
				if (sh_strtab.sh_size != read(fd, sh_strtab_data, sh_strtab.sh_size)) {
					err(EXIT_FAILURE, "Couldn't read %lu B from 0x%x (for strtab section data)", sh_strtab.sh_size, sh_str_tab_offset);
				}
				init = true;
			}
			// Attempts to read from the section string table. Located at the end of all sections
			printf(" (%s)", sh_strtab_data + shdr->sh_name);
		}
		printf("\n");
		printf("type: %s (0x%x)\n", sh_type, shdr->sh_type);
		printf("flags: %s (0x%lx)\n", sflags, shdr->sh_flags);
		printf("addr: 0x%lx\n", shdr->sh_addr);
		printf("offset: 0x%lx\n", shdr->sh_offset);
		printf("size: 0x%lx\n", shdr->sh_size);
		printf("link: 0x%x\n", shdr->sh_link);
		printf("info: 0x%x\n", shdr->sh_info);
		printf("addralign: %lu\n", shdr->sh_addralign);
		printf("entsize: %lu\n", shdr->sh_entsize); // symbol tables?
	} else {
		printf("Elf section header is NULL");
	}
	printf("\n");
}

void print_phdr(elf_phdr* phdr) {
	char* ptype;
	switch (phdr->p_type) {
	case PT_NULL: ptype = "PT_NULL"; break;
	case PT_LOAD: ptype = "PT_LOAD"; break;
	case PT_DYNAMIC: ptype = "PT_DYNAMIC"; break;
	case PT_INTERP: ptype = "PT_INTERP"; break;

	case PT_NOTE: ptype = "PT_NOTE"; break;
	case PT_SHLIB: ptype = "PT_SHLIB"; break;
	case PT_PHDR: ptype = "PT_PHDR"; break;
	case PT_TLS: ptype = "PT_TLS"; break;
	case PT_NUM: ptype = "PT_NUM"; break;
	case PT_LOOS: ptype = "PT_LOOS"; break;
	case PT_GNU_EH_FRAME: ptype = "PT_GNU_EH_FRAME"; break;
	case PT_GNU_STACK: ptype = "PT_GNU_STACK"; break;
	case PT_GNU_RELRO: ptype = "PT_GNU_RELRO"; break;
	case PT_GNU_PROPERTY: ptype = "PT_GNU_PROPERTY"; break;
	case PT_GNU_SFRAME: ptype = "PT_GNU_SFRAME"; break;
	case PT_LOSUNW: ptype = "PT_LOSUNW"; break;
	case PT_SUNWSTACK: ptype = "PT_SUNWSTACK"; break;
	case PT_HIOS: ptype = "PT_HIOS"; break;
	case PT_LOPROC: ptype = "PT_LOPROC"; break;
	case PT_HIPROC: ptype = "PT_HIPROC"; break;
	default: asprintf(&ptype, "0x%x", phdr->p_type); break;
	}

	char pflags[4] = {0};
	pflags[0] = phdr->p_flags & PF_R ? 'R' : ' ';
	pflags[1] = phdr->p_flags & PF_W ? 'W' : ' ';
	pflags[2] = phdr->p_flags & PF_X ? 'X' : ' ';

	printf("Elf Program header: \n");
	printf("Type: %s (0x%x)\n", ptype, phdr->p_type);
	if (phdr->p_type != PT_NULL) {
		printf("Flags: %s (0x%x)\n", pflags, phdr->p_flags);
		printf("Offset: 0x%lx\n", phdr->p_offset);
		printf("Vaddr: 0x%lx\n", phdr->p_vaddr);
		printf("Paddr: 0x%lx\n", phdr->p_paddr);
		printf("Filesize: 0x%lx B\n", phdr->p_filesz);
		printf("Memsize: 0x%lx B\n", phdr->p_memsz);
		printf("Alignment: %lu\n", phdr->p_align);
	}
	printf("\n");
}

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
    printf("Entry point address: \t\t\t0x%lx\n", header->e_entry);
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
__always_inline void stack_check(void* top_of_stack, uint64_t argc, char** argv) {
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
	#ifndef NDEBUG
	print_elf_header(&header);
	#endif

	// Read program headers
	if(header.e_phnum == PN_XNUM) {
		err(EXIT_FAILURE, "Maxed out program headers. Not supporetd by this loader");
	}
	int phdr_len = header.e_phentsize * header.e_phnum;
	elf_phdr* program_headers = malloc(phdr_len);
	if (-1 == lseek(progfd, header.e_phoff, SEEK_SET)) {
		err(EXIT_FAILURE, NULL);
	}
	if (phdr_len != read(progfd, program_headers, phdr_len)) {
		err(EXIT_FAILURE, "Couldn't read all program headers");
	}

	// Read section headers
	int shdr_len = header.e_shentsize * header.e_shnum;
	elf_shdr* section_headers = malloc(shdr_len);
	if (-1 == lseek(progfd, header.e_shoff, SEEK_SET)) {
		err(EXIT_FAILURE, NULL);
	}
	if (shdr_len != read(progfd, section_headers, shdr_len)) {
		err(EXIT_FAILURE, "Couldn't read all section headers");
	}

	// Memory map program headers into their right place
	elf_phdr* phdr = program_headers;
	for (int i = 0; i < header.e_phnum; i++, phdr++) {
		#ifndef NDEBUG
		printf("[%i] ", i);
		print_phdr(phdr);
		#endif
		if (phdr->p_type == PT_LOAD) {
			int prot = 0;
			prot |= phdr->p_flags & PF_X ? PROT_EXEC : 0;
			prot |= phdr->p_flags & PF_R ? PROT_READ : 0;
			prot |= phdr->p_flags & PF_W ? PROT_WRITE : 0;
			uint64_t base_page_offset = phdr->p_vaddr % PAGESIZE;
			void* base_page_addr = (void*)(phdr->p_vaddr - base_page_offset);
			uint64_t mmap_size = PAGECEIL(phdr->p_memsz + base_page_offset);
			int flags = MAP_FIXED | MAP_PRIVATE;
			#ifndef NDEBUG
			printf("Called mmap(%p, 0x%lx, 0x%x, 0x%x, %i, 0x%lx)\n", base_page_addr, mmap_size, prot, MAP_FIXED | MAP_PRIVATE, progfd, PAGEFLOOR(phdr->p_offset));
			#endif
			void* pa = mmap(base_page_addr, mmap_size, PROT_WRITE, flags, progfd, PAGEFLOOR(phdr->p_offset));
			if (pa == MAP_FAILED) {
				err(EXIT_FAILURE, "Failed map: %i", errno);
			}
			// zero out the beginning offset and end offset
			explicit_bzero(pa, base_page_offset);
			explicit_bzero((char*)pa + base_page_offset + phdr->p_filesz, mmap_size - phdr->p_filesz - base_page_offset);
			// fix perms
			if (-1 == mprotect(pa, mmap_size, prot)) {
				err(EXIT_FAILURE, "Failed setting protection: %i", errno);
			}
		}
	}

	// for finding main
	void* main_location = NULL;
	// for finding main & relocating
	Elf64_Sym* symtab = NULL;
	// for relocating
	Elf64_Shdr* rela_shdr = NULL;
	Elf64_Rela* rela = NULL;
	uint64_t strtab_offset = -1;
	bool relocated = false;

	elf_shdr* shdr = section_headers;
	for (int i = 0; i < header.e_shnum; i++, shdr++) {
		if (i == SHN_UNDEF || (i > SHN_LORESERVE && i < SHN_HIRESERVE) || (i > SHN_LOPROC && i < SHN_HIPROC) || i == SHN_ABS || i == SHN_COMMON) {
			continue;
		}
		#ifndef NDEBUG
		printf("[%i] ", i);
		print_shdr(shdr, &header, progfd);
		#endif
		// Relocations which must be done (with a static exec)
		if (shdr->sh_type == SHT_RELA) {
			rela_shdr = shdr;
			rela = malloc(shdr->sh_size);
			if (-1 == lseek(progfd, shdr->sh_offset, SEEK_SET)) {
				err(EXIT_FAILURE, "Couldn't seek when searching for main symbol");
			}
			if (shdr->sh_size != read(progfd, rela, shdr->sh_size)) {
				err(EXIT_FAILURE, "Couldn't read when searching for main symbol");
			}
			relocated = relocate_syms(section_headers, rela_shdr, rela, symtab, progfd, strtab_offset);
		}
		// Retrieve the location of main
		if (shdr->sh_type == SHT_SYMTAB) {
			read_symtab(shdr, &symtab, progfd);
			Elf64_Sym* symbols = symtab;
			strtab_offset = section_headers[shdr->sh_link].sh_offset;
			char symbol_buf[6] = {0}; // can be small. i only care about main
			bool found = false;
			for (int i = 0; i < shdr->sh_size / sizeof(Elf64_Sym); i++, symbols++) {
				uint64_t loc = strtab_offset + symbols->st_name;
				if (-1 == lseek(progfd, loc, SEEK_SET)) {
					err(EXIT_FAILURE, "Couldn't seek when searching for main symbol");
				}
				if (0 >= read(progfd, symbol_buf, 6)) {
					err(EXIT_FAILURE, "Couldn't read when searching for main symbol");
				}
				printf("Symbol: %s\n", symbol_buf);
				if (strcmp(symbol_buf, "main") == 0) {
					main_location = (void*)symbols->st_value;
					break;
				}
			}
		}
	}
	if (rela && !relocated) {
		if (relocate_syms(section_headers, rela_shdr, rela, symtab, progfd, strtab_offset)) {
			relocated = true;
		} else {
			err(EXIT_FAILURE, "Could not relocate, no symbol table was found");
		}
	}

	assert(main_location);

	// Relocate all necessary symbols

	if (-1 == close(progfd)) {
		err(EXIT_FAILURE, "Problems closing??");
	}

	// We do not want to jump to the entry point - since this is the start
	// function which does libc initialization, resets the stack pointer, etc.
	// We don't want to mangle setup we've already done, so we must set up the
	// stack ourselves
	printf("Prepping to transfer control to loaded program\n");

	/* The stack at the end of this should look like so:
	auxv
	0
	envvars
	0
	argv
	argc
	retaddr
	*/

	// Here we begin copying over everything. Our main goal is to copy over
	// everything from argv+1 to the top of the auxiliary vectors. We also leave
	// 8 extra bytes of space for argc. After, we set argc and change the
	// pointers for everything.

	// The initial stack pointer will also be argc.
	void* initial_sp = argv - 1;
	int my_argc = *(int*)(initial_sp) - 1; // decrement to prep for new prog
	char** argv_1 = ((char**)initial_sp + 2); //
	char** ptr_env = ((char**)initial_sp + my_argc + 3);
	// Iterate until we get to the end of the auxiliary vectors
	// Help from: https://articles.manugarg.com/aboutelfauxiliaryvectors
	while (*ptr_env != NULL)  ptr_env++;
	// envvars are referenced via pointer and do not need to be copied
	Elf64_auxv_t* auxv = (Elf64_auxv_t*)(ptr_env+1);
	while (auxv->a_type != AT_NULL) auxv++;
	void* copy_top = auxv + 1;
	void* copy_bottom = argv_1;
	uint64_t space_required = (copy_top - copy_bottom) + 8 /* for argc */;
	uintptr_t offset;
	// an additional 8B are subtracted for the return address
	uintptr_t sp;
	char i; // iterator for memcpy

    // We now have everything we need. Create space on the stack
	__asm__ (
		//"push %%rbp;" // TODO: hardcoded to maintain alignment. fixme
		"sub %1, %%rsp;"
		"mov %%rsp, %0;"
		"push 8(%%rbp);" // for ret addr
		// 8B of nothing expected here
		: "=r" (sp) // this is not really SP at this point... the push was after the var assignment
		: "r" (space_required)
	);

	// Copy data over manually because dealing with function call semantics
	// messing with my bp makes me want to die. (a memcpy would reset our well
	// crafted rbp)
	for (i = 0; i < space_required - 8; i++) {
		*((uint8_t*)sp + i + 8) = *((uint8_t*)argv_1 + i);
	}

	// Set all values and edit all pointers. Remember that
	*(uint64_t*)sp = (uint64_t)my_argc; // set argc
	// offset = (uintptr_t)(argv) - (sp + 8);
	// iterate and update all argv pointers
	// i = 0;
	// while (*(argv_1 + i) != NULL) {
	// 	*((uintptr_t*)sp + (i + 1)) -= offset;
	// 	i += 1;
	// }

	// iterate and update all environment variable pointers
	// i += 1;
	// while (*(argv_1 + i) != NULL) {
	// 	*((uintptr_t*)sp + (i + 1)) -= offset;
	// 	i += 1;
	// }

	asm (
		// GPRs
	    //"xor %%rax,    %%rax;"
	    "xor %%rbx,    %%rbx;"
	    "xor %%rcx,    %%rcx;"
	    "xor %%rdx,    %%rdx;"
		// "mov (%%rsp),  %%edi;"  handled by args
		// "mov %%rsp,    %%rsi;"  this + below
		// "add $8,       %%rsi;"  handled by args
	    "xor %%r8,     %%r8; "
	    "xor %%r9,     %%r9; "
	    "xor %%r10,    %%r10;"
	    "xor %%r11,    %%r11;"
	    "xor %%r12,    %%r12;"
	    "xor %%r13,    %%r13;"
	    "xor %%r14,    %%r14;"
	    "xor %%r15,    %%r15;"
		"jmp *%0;"
		: /* output regs */
		: "r" (main_location), "D" (my_argc), "S" (sp+8)
	);
	//prep_regs();

	return 0xBABE; // Babe you really shouldn't be returning
}
