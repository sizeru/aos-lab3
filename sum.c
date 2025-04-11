#include <stdio.h>
#include <stdlib.h>

int do_sum(int a, int b) {
	return a + b;
}

int main(int argc, char* argv[]) {
	const char* greeting = "We're in the child!";
	if (argc < 3) {
		return -1;
	}
	int a = atoi(argv[1]);
	int b = atoi(argv[2]);
	int x = a + b;
	printf("sum is: %i\n", x);
	//printf("%d + %d = %d\n", a, b, x);
	return x;
	// return 0;
}
