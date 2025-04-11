CFLAGS = -static
CC = gcc
LD = ld
LDFLAGS = -Telf_x86_64.x
TARGETS = apager sum simple check
#-Ttext-segment=0x800000
.PHONY: debug all check-gcc run_malloc_test

debug: CFLAGS += -g3
debug: $(TARGETS)

all: CFLAGS += -DNDEBUG
all: $(TARGETS)

apager: loader.c
	$(CC) $(CFLAGS) -o $@ $<

# sum.o : sum.c
# 	$(CC) -c $(CFLAGS) -o $@ $<

# sum: CC = musl-gcc
sum: sum.c
	$(CC) $< $(CFLAGS) -T elf_x86_64.x -o $@

# # Create a temp static executable. It will be stripped
# temp-sum: sum.c
# 	$(CC) $< $(CFLAGS) -T elf_x86_64.x -o $@

# # Get these dumbass dynamicly linked sectioned out of my static exec
# sum: temp-sum
# 	objcopy -R.got -R.plt $< $@

simple: simple.c
	$(CC) -o $@ $< -static -nostartfiles -nostdlib -g -e _start -T elf_x86_64.x

check: CC = musl-gcc
check: check.c
	$(CC) -o $@ $< $(CFLAGS) -nostartfiles -g -e _start -T elf_x86_64.x

clean:
	$(RM) sum apager simple check

mymalloc.so: mymalloc.c
	$(CC) -shared -fPIC -o $@ $<

malloc_test: malloc_test.c
	$(CC) $< -o $@

run_malloc_test: malloc_test mymalloc.so
	LD_PRELOAD=./mymalloc.so ./malloc_test
