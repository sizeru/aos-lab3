#include <stdio.h>
#include <elf.h>
#define bool unsigned char
#define uint64_t unsigned long
#define true 1
#define false 0

void leave(int code);
void _start();
int main(int argc, char* argv[]);
void assert(bool result);
bool stack_check(void* top_of_stack, int argc, char** argv);

int main(int argc, char* argv[]) {
	puts("This is being printed from the checker program!\n");
	if (stack_check(argv - 1, argc, argv)) {
		puts("Stack is working great!\n");
		return 0;
	}
	return -1;
}

// This is implemented wrong... but equality is fine
int strcmp(const char *a, const char *b) {
	while (*a != 0 && *b != 0) {
		if (*a != *b) {
			return *a - *b;
		}
		a++; b++;
	}
	return *a - *b;
}


void assert(bool result) {
	if (!result) leave(-2);
}

bool stack_check(void* top_of_stack, int argc, char** argv) {
	// printf("----- stack check -----\n");

	assert(((uint64_t)top_of_stack) % 8 == 0);
	// printf("top of stack is 8-byte aligned\n");

	uint64_t* stack = top_of_stack;
	uint64_t actual_argc = *(stack++);
	// printf("argc: %lu\n", actual_argc);
	assert(actual_argc == argc);

	for (int i = 0; i < argc; i++) {
		char* argp = (char*)*(stack++);
		assert(strcmp(argp, argv[i]) == 0);
		// printf("arg %d: %s\n", i, argp);
	}
	// Argument list ends with null pointer
	assert(*(stack++) == 0);

	int envp_count = 0;
	while (*(stack++) != 0)
		envp_count++;

	// printf("env count: %d\n", envp_count);

	Elf64_auxv_t* auxv_start = (Elf64_auxv_t*)stack;
	Elf64_auxv_t* auxv_null = auxv_start;
	while (auxv_null->a_type != AT_NULL) {
		auxv_null++;
	}
	// printf("aux count: %lu\n", auxv_null - auxv_start);
	// printf("----- end stack check -----\n");
	return true;
}

void leave (int code) {
	// Exit
	asm (
    "mov $60, %%rax;" // This is the syscall number for exit
    "syscall;"
		:: "D" (code) // exit status lives in rdi
	);
}

void _start() {
	/* The stack as of right now */
	// sp + 32: argv
	// sp + 24: argc
	// sp + 16: Return address (saved ebp)
	char** argv; // sp + 8
							 // sp + 4 padding
	int argc; // sp


	// Retrieve stack from kernel
	asm (
			"mov 24(%%rsp), %0;"
			"mov %%rsp, %1;"
			"add $32, %1;"
			: "=r" (argc), "=r" (argv)
	);

	leave(main(argc, argv));
}
