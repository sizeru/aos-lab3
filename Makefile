CFLAGS = -static
CC = gcc
LD = ld
LDFLAGS = -Telf_x86_64.x
#-Ttext-segment=0x800000
.PHONY: debug

debug: CFLAGS += -g3
debug: apager sum

apager: loader.c
	$(CC) $(CFLAGS) -o $@ $<

# sum.o : sum.c
# 	$(CC) -c $(CFLAGS) -o $@ $<

# sum: sum.o
# 	$(LD) $< $(LDFLAGS) -o $@

sum: sum.c
	$(CC) $< $(CFLAGS) -T elf_x86_64.x -e main -o $@

clean:
	$(RM) sum apager
