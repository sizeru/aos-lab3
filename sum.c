#include <stdio.h>
#include <stdlib.h>

int do_sum(int a, int b) {
	return a + b;
}

int main(int argc, char* argv[]) {
	const char* greeting = "We're in the child!";
	int i = do_sum(1, 3);
	int j = do_sum(5, 2);
	//printf(greeting);
	puts(greeting);
	int a = atoi(argv[1]);
	int b = atoi(argv[2]);
	int x = a + b + i + j;
	//printf("%d + %d = %d\n", a, b, x);
	return x;
	// return 0;
}
