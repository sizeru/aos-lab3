# A Loader
This is a simple elf loader.

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
