#define _GNU_SOURCE
#define MAGIC 0xCC

#include <stdio.h>
#include <dlfcn.h>

static void* (*real_malloc)(size_t)=NULL;

static void find_real_malloc()
{
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    if (NULL == real_malloc) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
    }
}

void *malloc(size_t size)
{
    if(real_malloc==NULL) find_real_malloc();

    char *p = real_malloc(size);
    for (long i = 0; i < size; i++) {
    	p[i] = MAGIC;
    }
    return p;
}
