# A Loader
This is a simple elf loader.

## Segmentation
Object files are are separated into [segments](https://en.wikipedia.org/wiki/Object_file#Segmentation). The name originates from memory segments, which was used before paging. The loader allocates various regions of memory to the program. In days of old this was at the segment granularity. Now, it is more useful to have per-page granularity.

## Program Headers vs Section Headers
A program header shows the memory that a program has access to. The section header shows which "section" of the program maps to which memory locations.

Program headers are at the page granularity and are for protection. Section headers are mapped?

Program headers create the address space and section headers memory map things into the right place.

A section is a contiguous region of a file.
