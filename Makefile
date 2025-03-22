.PHONY: debug

debug: CFLAGS += -g3
debug: apager sum

apager: loader.c
	$(CC) $(CFLAGS) -o $@ $<

sum : sum.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(RM) sum apager
