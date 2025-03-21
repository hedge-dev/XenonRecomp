/* Interface between the opcode library and its callers.
   Written by Cygnus Support, 1993.

   The opcode library (libopcodes.a) provides instruction decoders for
   a large variety of instruction sets, callable with an identical
   interface, for making instruction-processing programs more independent
   of the instruction set being processed.  */

#ifndef DIS_ASM_H
#define DIS_ASM_H

#if defined __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#if defined __GNUC__
# if (__GNUC__ < 4) || \
     defined(__GNUC_MINOR__) && (__GNUC__ == 4) && (__GNUC_MINOR__ < 4)
   /* gcc versions before 4.4.x don't support gnu_printf, so use printf. */
#  define GCC_ATTR __attribute__((__unused__, format(printf, 1, 2)))
#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))
# else
   /* Use gnu_printf when supported (qemu uses standard format strings). */
#  define GCC_ATTR __attribute__((__unused__, format(gnu_printf, 1, 2)))
#  define GCC_FMT_ATTR(n, m) __attribute__((format(gnu_printf, n, m)))
# endif
#else
#define GCC_ATTR /**/
#define GCC_FMT_ATTR(n, m)
#endif

typedef int (*fprintf_function)(FILE* f, const char* fmt, ...) GCC_FMT_ATTR(2, 3);

typedef void *PTR;
typedef uint64_t bfd_vma;
typedef int64_t bfd_signed_vma;
typedef uint8_t bfd_byte;
#define sprintf_vma(s,x) sprintf (s, "%0" PRIx64, x)
#define snprintf_vma(s,ss,x) snprintf (s, ss, "%0" PRIx64, x)

#define BFD64

enum bfd_flavour {
  bfd_target_unknown_flavour,
  bfd_target_aout_flavour,
  bfd_target_coff_flavour,
  bfd_target_ecoff_flavour,
  bfd_target_elf_flavour,
  bfd_target_ieee_flavour,
  bfd_target_nlm_flavour,
  bfd_target_oasys_flavour,
  bfd_target_tekhex_flavour,
  bfd_target_srec_flavour,
  bfd_target_ihex_flavour,
  bfd_target_som_flavour,
  bfd_target_os9k_flavour,
  bfd_target_versados_flavour,
  bfd_target_msdos_flavour,
  bfd_target_evax_flavour
};

enum bfd_endian { BFD_ENDIAN_BIG, BFD_ENDIAN_LITTLE, BFD_ENDIAN_UNKNOWN };

enum bfd_architecture
{
  bfd_arch_unknown,    /* File arch not known */
  bfd_arch_obscure,    /* Arch known, not one of these */
  bfd_arch_m68k,       /* Motorola 68xxx */
#define bfd_mach_m68000 1
#define bfd_mach_m68008 2
#define bfd_mach_m68010 3
#define bfd_mach_m68020 4
#define bfd_mach_m68030 5
#define bfd_mach_m68040 6
#define bfd_mach_m68060 7
#define bfd_mach_cpu32  8
#define bfd_mach_mcf5200  9
#define bfd_mach_mcf5206e 10
#define bfd_mach_mcf5307  11
#define bfd_mach_mcf5407  12
#define bfd_mach_mcf528x  13
#define bfd_mach_mcfv4e   14
#define bfd_mach_mcf521x   15
#define bfd_mach_mcf5249   16
#define bfd_mach_mcf547x   17
#define bfd_mach_mcf548x   18
  bfd_arch_vax,        /* DEC Vax */
  bfd_arch_i960,       /* Intel 960 */
	 /* The order of the following is important.
	   lower number indicates a machine type that
	   only accepts a subset of the instructions
	   available to machines with higher numbers.
	   The exception is the "ca", which is
	   incompatible with all other machines except
	   "core". */

#define bfd_mach_i960_core      1
#define bfd_mach_i960_ka_sa     2
#define bfd_mach_i960_kb_sb     3
#define bfd_mach_i960_mc        4
#define bfd_mach_i960_xa        5
#define bfd_mach_i960_ca        6
#define bfd_mach_i960_jx        7
#define bfd_mach_i960_hx        8

  bfd_arch_a29k,       /* AMD 29000 */
  bfd_arch_sparc,      /* SPARC */
#define bfd_mach_sparc                 1
/* The difference between v8plus and v9 is that v9 is a true 64 bit env.  */
#define bfd_mach_sparc_sparclet        2
#define bfd_mach_sparc_sparclite       3
#define bfd_mach_sparc_v8plus          4
#define bfd_mach_sparc_v8plusa         5 /* with ultrasparc add'ns.  */
#define bfd_mach_sparc_sparclite_le    6
#define bfd_mach_sparc_v9              7
#define bfd_mach_sparc_v9a             8 /* with ultrasparc add'ns.  */
#define bfd_mach_sparc_v8plusb         9 /* with cheetah add'ns.  */
#define bfd_mach_sparc_v9b             10 /* with cheetah add'ns.  */
/* Nonzero if MACH has the v9 instruction set.  */
#define bfd_mach_sparc_v9_p(mach) \
  ((mach) >= bfd_mach_sparc_v8plus && (mach) <= bfd_mach_sparc_v9b \
   && (mach) != bfd_mach_sparc_sparclite_le)
  bfd_arch_mips,       /* MIPS Rxxxx */
#define bfd_mach_mips3000              3000
#define bfd_mach_mips3900              3900
#define bfd_mach_mips4000              4000
#define bfd_mach_mips4010              4010
#define bfd_mach_mips4100              4100
#define bfd_mach_mips4300              4300
#define bfd_mach_mips4400              4400
#define bfd_mach_mips4600              4600
#define bfd_mach_mips4650              4650
#define bfd_mach_mips5000              5000
#define bfd_mach_mips6000              6000
#define bfd_mach_mips8000              8000
#define bfd_mach_mips10000             10000
#define bfd_mach_mips16                16
  bfd_arch_i386,       /* Intel 386 */
#define bfd_mach_i386_i386 0
#define bfd_mach_i386_i8086 1
#define bfd_mach_i386_i386_intel_syntax 2
#define bfd_mach_x86_64 3
#define bfd_mach_x86_64_intel_syntax 4
  bfd_arch_we32k,      /* AT&T WE32xxx */
  bfd_arch_tahoe,      /* CCI/Harris Tahoe */
  bfd_arch_i860,       /* Intel 860 */
  bfd_arch_romp,       /* IBM ROMP PC/RT */
  bfd_arch_alliant,    /* Alliant */
  bfd_arch_convex,     /* Convex */
  bfd_arch_m88k,       /* Motorola 88xxx */
  bfd_arch_pyramid,    /* Pyramid Technology */
  bfd_arch_h8300,      /* Hitachi H8/300 */
#define bfd_mach_h8300   1
#define bfd_mach_h8300h  2
#define bfd_mach_h8300s  3
  bfd_arch_powerpc,    /* PowerPC */
#define bfd_mach_ppc           0
#define bfd_mach_ppc64         1
#define bfd_mach_ppc_403       403
#define bfd_mach_ppc_403gc     4030
#define bfd_mach_ppc_e500      500
#define bfd_mach_ppc_505       505
#define bfd_mach_ppc_601       601
#define bfd_mach_ppc_602       602
#define bfd_mach_ppc_603       603
#define bfd_mach_ppc_ec603e    6031
#define bfd_mach_ppc_604       604
#define bfd_mach_ppc_620       620
#define bfd_mach_ppc_630       630
#define bfd_mach_ppc_750       750
#define bfd_mach_ppc_860       860
#define bfd_mach_ppc_a35       35
#define bfd_mach_ppc_rs64ii    642
#define bfd_mach_ppc_rs64iii   643
#define bfd_mach_ppc_7400      7400
  bfd_arch_rs6000,     /* IBM RS/6000 */
  bfd_arch_hppa,       /* HP PA RISC */
#define bfd_mach_hppa10        10
#define bfd_mach_hppa11        11
#define bfd_mach_hppa20        20
#define bfd_mach_hppa20w       25
  bfd_arch_d10v,       /* Mitsubishi D10V */
  bfd_arch_z8k,        /* Zilog Z8000 */
#define bfd_mach_z8001         1
#define bfd_mach_z8002         2
  bfd_arch_h8500,      /* Hitachi H8/500 */
  bfd_arch_sh,         /* Hitachi SH */
#define bfd_mach_sh            1
#define bfd_mach_sh2        0x20
#define bfd_mach_sh_dsp     0x2d
#define bfd_mach_sh2a       0x2a
#define bfd_mach_sh2a_nofpu 0x2b
#define bfd_mach_sh2e       0x2e
#define bfd_mach_sh3        0x30
#define bfd_mach_sh3_nommu  0x31
#define bfd_mach_sh3_dsp    0x3d
#define bfd_mach_sh3e       0x3e
#define bfd_mach_sh4        0x40
#define bfd_mach_sh4_nofpu  0x41
#define bfd_mach_sh4_nommu_nofpu  0x42
#define bfd_mach_sh4a       0x4a
#define bfd_mach_sh4a_nofpu 0x4b
#define bfd_mach_sh4al_dsp  0x4d
#define bfd_mach_sh5        0x50
  bfd_arch_alpha,      /* Dec Alpha */
#define bfd_mach_alpha 1
#define bfd_mach_alpha_ev4  0x10
#define bfd_mach_alpha_ev5  0x20
#define bfd_mach_alpha_ev6  0x30
  bfd_arch_arm,        /* Advanced Risc Machines ARM */
#define bfd_mach_arm_unknown	0
#define bfd_mach_arm_2		1
#define bfd_mach_arm_2a		2
#define bfd_mach_arm_3		3
#define bfd_mach_arm_3M 	4
#define bfd_mach_arm_4 		5
#define bfd_mach_arm_4T 	6
#define bfd_mach_arm_5 		7
#define bfd_mach_arm_5T		8
#define bfd_mach_arm_5TE	9
#define bfd_mach_arm_XScale	10
#define bfd_mach_arm_ep9312	11
#define bfd_mach_arm_iWMMXt	12
#define bfd_mach_arm_iWMMXt2	13
  bfd_arch_ns32k,      /* National Semiconductors ns32000 */
  bfd_arch_w65,        /* WDC 65816 */
  bfd_arch_tic30,      /* Texas Instruments TMS320C30 */
  bfd_arch_v850,       /* NEC V850 */
#define bfd_mach_v850          0
  bfd_arch_arc,        /* Argonaut RISC Core */
#define bfd_mach_arc_base 0
  bfd_arch_m32r,       /* Mitsubishi M32R/D */
#define bfd_mach_m32r          0  /* backwards compatibility */
  bfd_arch_mn10200,    /* Matsushita MN10200 */
  bfd_arch_mn10300,    /* Matsushita MN10300 */
  bfd_arch_cris,       /* Axis CRIS */
#define bfd_mach_cris_v0_v10   255
#define bfd_mach_cris_v32      32
#define bfd_mach_cris_v10_v32  1032
  bfd_arch_microblaze, /* Xilinx MicroBlaze.  */
  bfd_arch_ia64,      /* HP/Intel ia64 */
#define bfd_mach_ia64_elf64    64
#define bfd_mach_ia64_elf32    32
  bfd_arch_last
  };
#define bfd_mach_s390_31 31
#define bfd_mach_s390_64 64

typedef struct symbol_cache_entry
{
	const char *name;
	union
	{
		PTR p;
		bfd_vma i;
	} udata;
} asymbol;

enum dis_insn_type {
  dis_noninsn,			/* Not a valid instruction */
  dis_nonbranch,		/* Not a branch instruction */
  dis_branch,			/* Unconditional branch */
  dis_condbranch,		/* Conditional branch */
  dis_jsr,			/* Jump to subroutine */
  dis_condjsr,			/* Conditional jump to subroutine */
  dis_dref,			/* Data reference instruction */
  dis_dref2			/* Two data references in instruction */
};

/* This struct is passed into the instruction decoding routine,
   and is passed back out into each callback.  The various fields are used
   for conveying information from your main routine into your callbacks,
   for passing information into the instruction decoders (such as the
   addresses of the callback functions), or for passing information
   back from the instruction decoders to their callers.

   It must be initialized before it is first passed; this can be done
   by hand, or using one of the initialization macros below.  */

typedef struct disassemble_info {
  fprintf_function fprintf_func;
  FILE *stream;
  PTR application_data;

  /* Target description.  We could replace this with a pointer to the bfd,
	 but that would require one.  There currently isn't any such requirement
	 so to avoid introducing one we record these explicitly.  */
  /* The bfd_flavour.  This can be bfd_target_unknown_flavour.  */
  enum bfd_flavour flavour;
  /* The bfd_arch value.  */
  enum bfd_architecture arch;
  /* The bfd_mach value.  */
  unsigned long mach;
  /* Endianness (for bi-endian cpus).  Mono-endian cpus can ignore this.  */
  enum bfd_endian endian;

  /* An array of pointers to symbols either at the location being disassembled
	 or at the start of the function being disassembled.  The array is sorted
	 so that the first symbol is intended to be the one used.  The others are
	 present for any misc. purposes.  This is not set reliably, but if it is
	 not NULL, it is correct.  */
  asymbol **symbols;
  /* Number of symbols in array.  */
  int num_symbols;

  /* For use by the disassembler.
	 The top 16 bits are reserved for public use (and are documented here).
	 The bottom 16 bits are for the internal use of the disassembler.  */
  unsigned long flags;
#define INSN_HAS_RELOC	0x80000000
  PTR private_data;

  /* Function used to get bytes to disassemble.  MEMADDR is the
	 address of the stuff to be disassembled, MYADDR is the address to
	 put the bytes in, and LENGTH is the number of bytes to read.
	 INFO is a pointer to this struct.
	 Returns an errno value or 0 for success.  */
  int (*read_memory_func)
	(bfd_vma memaddr, bfd_byte *myaddr, int length,
		 struct disassemble_info *info);

  /* Function which should be called if we get an error that we can't
	 recover from.  STATUS is the errno value from read_memory_func and
	 MEMADDR is the address that we were trying to read.  INFO is a
	 pointer to this struct.  */
  void (*memory_error_func)
	(int status, bfd_vma memaddr, struct disassemble_info *info);

  /* Function called to print ADDR.  */
  void (*print_address_func)
	(bfd_vma addr, struct disassemble_info *info);

  /* Function called to determine if there is a symbol at the given ADDR.
	 If there is, the function returns 1, otherwise it returns 0.
	 This is used by ports which support an overlay manager where
	 the overlay number is held in the top part of an address.  In
	 some circumstances we want to include the overlay number in the
	 address, (normally because there is a symbol associated with
	 that address), but sometimes we want to mask out the overlay bits.  */
  int (* symbol_at_address_func)
	(bfd_vma addr, struct disassemble_info * info);

  /* These are for buffer_read_memory.  */
  const bfd_byte *buffer;
  bfd_vma buffer_vma;
  int buffer_length;

  /* This variable may be set by the instruction decoder.  It suggests
	  the number of bytes objdump should display on a single line.  If
	  the instruction decoder sets this, it should always set it to
	  the same value in order to get reasonable looking output.  */
  int bytes_per_line;

  /* the next two variables control the way objdump displays the raw data */
  /* For example, if bytes_per_line is 8 and bytes_per_chunk is 4, the */
  /* output will look like this:
	 00:   00000000 00000000
	 with the chunks displayed according to "display_endian". */
  int bytes_per_chunk;
  enum bfd_endian display_endian;

  /* Results from instruction decoders.  Not all decoders yet support
	 this information.  This info is set each time an instruction is
	 decoded, and is only valid for the last such instruction.

	 To determine whether this decoder supports this information, set
	 insn_info_valid to 0, decode an instruction, then check it.  */

  char insn_info_valid;		/* Branch info has been set. */
  char branch_delay_insns;	/* How many sequential insn's will run before
				   a branch takes effect.  (0 = normal) */
  char data_size;		/* Size of data reference in insn, in bytes */
  enum dis_insn_type insn_type;	/* Type of instruction */
  bfd_vma target;		/* Target address of branch or dref, if known;
				   zero if unknown.  */
  bfd_vma target2;		/* Second target address for dref2 */

  /* Command line options specific to the target disassembler.  */
  const char * disassembler_options;

} disassemble_info;

typedef struct powerpc_opcode
{
    /* The opcode name.  */
    const char* name;

    /* The opcode itself.  Those bits which will be filled in with
       operands are zeroes.  */
    unsigned long opcode;

    /* The opcode mask.  This is used by the disassembler.  This is a
       mask containing ones indicating those bits which must match the
       opcode field, and zeroes indicating those bits which need not
       match (and are presumably filled in by operands).  */
    unsigned long mask;

    /* One bit flags for the opcode.  These are used to indicate which
       specific processors support the instructions.  The defined values
       are listed below.  */
    unsigned long flags;

    /* An array of operand codes.  Each code is an index into the
       operand table.  They appear in the order which the operands must
       appear in assembly code, and are terminated by a zero.  */
    unsigned char operands[8];

    /* The opcode ID. */
    int id;
} powerpc_opcode;

typedef struct ppc_insn
{
    const powerpc_opcode* opcode;
    uint32_t instruction;
    uint32_t operands[8];
    char op_str[160];
} ppc_insn;

/* Standard disassemblers.  Disassemble one instruction at the given
   target address.  Return number of bytes processed.  */
typedef int (*disassembler_ftype) (bfd_vma, disassemble_info *);

int print_insn_big_mips         (bfd_vma, disassemble_info*);
int print_insn_little_mips      (bfd_vma, disassemble_info*);
int print_insn_i386             (bfd_vma, disassemble_info*);
int print_insn_m68k             (bfd_vma, disassemble_info*);
int print_insn_z8001            (bfd_vma, disassemble_info*);
int print_insn_z8002            (bfd_vma, disassemble_info*);
int print_insn_h8300            (bfd_vma, disassemble_info*);
int print_insn_h8300h           (bfd_vma, disassemble_info*);
int print_insn_h8300s           (bfd_vma, disassemble_info*);
int print_insn_h8500            (bfd_vma, disassemble_info*);
int print_insn_alpha            (bfd_vma, disassemble_info*);
disassembler_ftype arc_get_disassembler (int, int);
int print_insn_arm              (bfd_vma, disassemble_info*);
int print_insn_sparc            (bfd_vma, disassemble_info*);
int print_insn_big_a29k         (bfd_vma, disassemble_info*);
int print_insn_little_a29k      (bfd_vma, disassemble_info*);
int print_insn_i960             (bfd_vma, disassemble_info*);
int print_insn_sh               (bfd_vma, disassemble_info*);
int print_insn_shl              (bfd_vma, disassemble_info*);
int print_insn_hppa             (bfd_vma, disassemble_info*);
int print_insn_m32r             (bfd_vma, disassemble_info*);
int print_insn_m88k             (bfd_vma, disassemble_info*);
int print_insn_mn10200          (bfd_vma, disassemble_info*);
int print_insn_mn10300          (bfd_vma, disassemble_info*);
int print_insn_ns32k            (bfd_vma, disassemble_info*);
int print_insn_big_powerpc      (bfd_vma, disassemble_info*);
int print_insn_little_powerpc   (bfd_vma, disassemble_info*);
int print_insn_rs6000           (bfd_vma, disassemble_info*);
int print_insn_w65              (bfd_vma, disassemble_info*);
int print_insn_d10v             (bfd_vma, disassemble_info*);
int print_insn_v850             (bfd_vma, disassemble_info*);
int print_insn_tic30            (bfd_vma, disassemble_info*);
int print_insn_ppc              (bfd_vma, disassemble_info*);
int print_insn_s390             (bfd_vma, disassemble_info*);
int print_insn_crisv32          (bfd_vma, disassemble_info*);
int print_insn_crisv10          (bfd_vma, disassemble_info*);
int print_insn_microblaze       (bfd_vma, disassemble_info*);
int print_insn_ia64             (bfd_vma, disassemble_info*);

int decode_insn_ppc(bfd_vma, disassemble_info*, ppc_insn*);

#if 0
/* Fetch the disassembler for a given BFD, if that support is available.  */
disassembler_ftype disassembler(bfd *);
#endif

/* This block of definitions is for particular callers who read instructions
   into a buffer before calling the instruction decoder.  */

/* Here is a function which callers may wish to use for read_memory_func.
   It gets bytes from a buffer.  */
int buffer_read_memory(bfd_vma, bfd_byte *, int, struct disassemble_info *);

/* This function goes with buffer_read_memory.
   It prints a message using info->fprintf_func and info->stream.  */
void perror_memory(int, bfd_vma, struct disassemble_info *);


/* Just print the address in hex.  This is included for completeness even
   though both GDB and objdump provide their own (to print symbolic
   addresses).  */
void generic_print_address(bfd_vma, struct disassemble_info *);

/* Always true.  */
int generic_symbol_at_address(bfd_vma, struct disassemble_info *);

/* Macro to initialize a disassemble_info struct.  This should be called
   by all applications creating such a struct.  */
#define INIT_DISASSEMBLE_INFO(INFO, STREAM, FPRINTF_FUNC) \
  (INFO).flavour = bfd_target_unknown_flavour, \
  (INFO).arch = bfd_arch_unknown, \
  (INFO).mach = 0, \
  (INFO).endian = BFD_ENDIAN_UNKNOWN, \
  INIT_DISASSEMBLE_INFO_NO_ARCH(INFO, STREAM, FPRINTF_FUNC)

/* Call this macro to initialize only the internal variables for the
   disassembler.  Architecture dependent things such as byte order, or machine
   variant are not touched by this macro.  This makes things much easier for
   GDB which must initialize these things separately.  */

#define INIT_DISASSEMBLE_INFO_NO_ARCH(INFO, STREAM, FPRINTF_FUNC) \
  (INFO).fprintf_func = (FPRINTF_FUNC), \
  (INFO).stream = (STREAM), \
  (INFO).symbols = NULL, \
  (INFO).num_symbols = 0, \
  (INFO).private_data = NULL, \
  (INFO).buffer = NULL, \
  (INFO).buffer_vma = 0, \
  (INFO).buffer_length = 0, \
  (INFO).read_memory_func = buffer_read_memory, \
  (INFO).memory_error_func = perror_memory, \
  (INFO).print_address_func = generic_print_address, \
  (INFO).symbol_at_address_func = generic_symbol_at_address, \
  (INFO).flags = 0, \
  (INFO).bytes_per_line = 0, \
  (INFO).bytes_per_chunk = 0, \
  (INFO).display_endian = BFD_ENDIAN_UNKNOWN, \
  (INFO).disassembler_options = NULL, \
  (INFO).insn_info_valid = 0

#define _(x) x

#if defined __GNUC__
#define ATTRIBUTE_UNUSED __attribute__((unused))
#else
#define ATTRIBUTE_UNUSED
#endif
/* from libbfd */

bfd_vma bfd_getl64 (const bfd_byte *addr);
bfd_vma bfd_getl32 (const bfd_byte *addr);
bfd_vma bfd_getb32 (const bfd_byte *addr);
bfd_vma bfd_getl16 (const bfd_byte *addr);
bfd_vma bfd_getb16 (const bfd_byte *addr);
typedef bool bfd_boolean;

#if defined __cplusplus
}
#endif

#endif /* ! defined (DIS_ASM_H) */
