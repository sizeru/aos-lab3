# A Loader
This is a simple elf loader.

## Usage
To run the checker program
```
make all
./apager check
```

You may alternatively see debug output with `make debug`

## Potentail Bugs
This does not deep copy the auxiliary values, the environment variables,
or the argv strings. This is not necessary for correctness, as the stack
is still set up initially, but I am not sure whether one would expect to
find this array of strings in a particular place.

## Segmentation
Object files are are separated into [segments](https://en.wikipedia.org/wiki/Object_file#Segmentation). The name originates from memory segments, which was used before paging. The loader allocates various regions of memory to the program. In days of old this was at the segment granularity. Now, it is more useful to have per-page granularity.

## Program Headers vs Section Headers
A program header shows the memory that a program has access to. The section header shows which "section" of the program maps to which memory locations.

Program headers are at the page granularity and are for protection. Section headers are mapped?

Program headers create the address space and section headers memory map things into the right place.

A section is a contiguous region of a file.

It seems to me that the program headers are mainly for protection, while sections indicate where the parts of an executable live.

== Terms

Straght from [wikipedia]("https://en.wikipedia.org/wiki/VDSO") on vdso and vvar (vdso variable)
vDSO (virtual dynamic shared object) is a kernel mechanism for exporting a carefully selected set of kernel space routines to user space applications so that applications can call these kernel space routines in-process, without incurring the performance penalty of a mode switch from user mode to kernel mode that is inherent when calling these same kernel space routines by means of the system call interface.

## Weird stuff
I noticed there's still a GOT and linkage table in my executable. [Here's the culprit]("https://stackoverflow.com/questions/34850007/why-are-there-global-offset-tables-and-procedure-linkage-tables-in-statically-li")

## Support for static linking in static libc?
https://github.com/lattera/glibc/blob/master/elf/dl-support.c#L228

To get debug info on arch linux for glibc
https://wiki.archlinux.org/title/Debugging/Getting_traces#Install_debug_packages

## Building glibc with debug symbols

They're not included by default on Arch so I had to do the following:
- Follow this guide to clone the glibc arch linux repo [this guide]("https://wiki.archlinux.org/title/Arch_build_system")
- Follow [this guide]("https://wiki.archlinux.org/title/Debugging/Getting_traces#Installing_debug_packages") to add debug symbols to the install
- Use `makepkg -sr` to build the package. I'm guessing this is gonna take upwards of 30 minutes.
- Install with pacman -U <packagename.zst> or sumn like that

## Questions I need to answer

1. What is an ifunc? Why is initializing it important?
2. GLRO - Is this what does the relocation????
