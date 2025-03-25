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

sum: sum.c
	$(CC) $< $(CFLAGS) -T elf_x86_64.x -o $@

# # Create a temp static executable. It will be stripped
# temp-sum: sum.c
# 	$(CC) $< $(CFLAGS) -T elf_x86_64.x -o $@

# # Get these dumbass dynamicly linked sectioned out of my static exec
# sum: temp-sum
# 	objcopy -R.got -R.plt $< $@

clean:
	$(RM) sum apager
