#include "dis-asm.h"

#ifndef EIO
#define EIO 5
#endif

/* Get LENGTH bytes from info's buffer, at target address memaddr.
   Transfer them to myaddr.  */
int
buffer_read_memory(bfd_vma memaddr, bfd_byte* myaddr, int length,
    struct disassemble_info* info)
{
    if (memaddr < info->buffer_vma
        || memaddr + length > info->buffer_vma + info->buffer_length)
        /* Out of bounds.  Use EIO because GDB uses it.  */
        return EIO;
    memcpy(myaddr, info->buffer + (memaddr - info->buffer_vma), length);
    return 0;
}

/* Print an error message.  We can assume that this is in response to
   an error return from buffer_read_memory.  */
void
perror_memory(int status, bfd_vma memaddr, struct disassemble_info* info)
{
    if (status != EIO)
        /* Can't happen.  */
        (*info->fprintf_func) (info->stream, "Unknown error %d\n", status);
    else
        /* Actually, address between memaddr and memaddr + len was
           out of bounds.  */
        (*info->fprintf_func) (info->stream,
            "Address 0x%" PRIx64 " is out of bounds.\n", memaddr);
}

/* This could be in a separate file, to save miniscule amounts of space
   in statically linked executables.  */

   /* Just print the address is hex.  This is included for completeness even
      though both GDB and objdump provide their own (to print symbolic
      addresses).  */

void
generic_print_address(bfd_vma addr, struct disassemble_info* info)
{
    (*info->fprintf_func) (info->stream, "0x%" PRIx64, addr);
}

/* Just return the given address.  */

int
generic_symbol_at_address(bfd_vma addr, struct disassemble_info* info)
{
    return 1;
}

bfd_vma bfd_getl64(const bfd_byte* addr)
{
    unsigned long long v;

    v = (unsigned long long) addr[0];
    v |= (unsigned long long) addr[1] << 8;
    v |= (unsigned long long) addr[2] << 16;
    v |= (unsigned long long) addr[3] << 24;
    v |= (unsigned long long) addr[4] << 32;
    v |= (unsigned long long) addr[5] << 40;
    v |= (unsigned long long) addr[6] << 48;
    v |= (unsigned long long) addr[7] << 56;
    return (bfd_vma)v;
}

bfd_vma bfd_getl32(const bfd_byte* addr)
{
    unsigned long v;

    v = (unsigned long)addr[0];
    v |= (unsigned long)addr[1] << 8;
    v |= (unsigned long)addr[2] << 16;
    v |= (unsigned long)addr[3] << 24;
    return (bfd_vma)v;
}

bfd_vma bfd_getb32(const bfd_byte* addr)
{
    unsigned long v;

    v = (unsigned long)addr[0] << 24;
    v |= (unsigned long)addr[1] << 16;
    v |= (unsigned long)addr[2] << 8;
    v |= (unsigned long)addr[3];
    return (bfd_vma)v;
}

bfd_vma bfd_getl16(const bfd_byte* addr)
{
    unsigned long v;

    v = (unsigned long)addr[0];
    v |= (unsigned long)addr[1] << 8;
    return (bfd_vma)v;
}

bfd_vma bfd_getb16(const bfd_byte* addr)
{
    unsigned long v;

    v = (unsigned long)addr[0] << 24;
    v |= (unsigned long)addr[1] << 16;
    return (bfd_vma)v;
}
