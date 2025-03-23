#include <stdio.h>
#include <stdlib.h>
int main(int argc, char* argv[]) {
	int a = atoi(argv[1]);
	int b = atoi(argv[2]);
	int x = a + b;
	printf("%d + %d = %d\n", a, b, x);
	return x;
}
