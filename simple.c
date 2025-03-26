int atoi(const char* str);
unsigned long strlen(const char* str);
void _leave(int code);
void _start();

int main(int argc, char* argv[]) {
	// Argc and argv must be manually loaded int
	if (argc < 3) {
		return -1;
	}
	int x = atoi(argv[1]);
	int y = atoi(argv[2]);
	return x + y;
}

void _leave (int code) {
	// Exit
	asm (
    "mov $60, %%rax;" // This is the syscall number for exit
    "syscall;"
		:: "D" (code) // exit status lives in rdi
	);
}

unsigned long strlen(const char* str) {
	int len = 0;
	while (*str++) len++;
	return len;
}

int atoi(const char* str) {
	int len = strlen(str);
	const int base = 10;
	int place_value = 1;
	int val = 0;
	for (int i = len-1; i >= 0; i--) {
		int digit = *(str + i) - 0x30;
		if (digit < 0 || digit > 9) {
			_leave(-1);
		}
		val += digit * place_value;
		place_value *= base;
	}	
	return val;
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

	_leave(main(argc, argv));
}

