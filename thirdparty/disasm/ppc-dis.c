/* ppc-dis.c -- Disassemble PowerPC instructions
   Copyright 1994, 1995, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
   Free Software Foundation, Inc.
   Written by Ian Lance Taylor, Cygnus Support

This file is part of GDB, GAS, and the GNU binutils.

GDB, GAS, and the GNU binutils are free software; you can redistribute
them and/or modify them under the terms of the GNU General Public
License as published by the Free Software Foundation; either version
2, or (at your option) any later version.

GDB, GAS, and the GNU binutils are distributed in the hope that they
will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this file; see the file COPYING.  If not,
see <http://www.gnu.org/licenses/>.  */
#include "dis-asm.h"
#include "ppc.h"

#define BFD_DEFAULT_TARGET_SIZE 64

/* ppc.h -- Header file for PowerPC opcode table
   Copyright 1994, 1995, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
   2007 Free Software Foundation, Inc.
   Written by Ian Lance Taylor, Cygnus Support

This file is part of GDB, GAS, and the GNU binutils.

GDB, GAS, and the GNU binutils are free software; you can redistribute
them and/or modify them under the terms of the GNU General Public
License as published by the Free Software Foundation; either version
1, or (at your option) any later version.

GDB, GAS, and the GNU binutils are distributed in the hope that they
will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this file; see the file COPYING.  If not,
see <http://www.gnu.org/licenses/>.  */

/* The opcode table is an array of struct powerpc_opcode.  */

/* The table itself is sorted by major opcode number, and is otherwise
   in the order in which the disassembler should consider
   instructions.  */
extern const struct powerpc_opcode powerpc_opcodes[];
extern const int powerpc_num_opcodes;

/* Values defined for the flags field of a struct powerpc_opcode.  */

/* Opcode is defined for the PowerPC architecture.  */
#define PPC_OPCODE_PPC			 1

/* Opcode is defined for the POWER (RS/6000) architecture.  */
#define PPC_OPCODE_POWER		 2

/* Opcode is defined for the POWER2 (Rios 2) architecture.  */
#define PPC_OPCODE_POWER2		 4

/* Opcode is only defined on 32 bit architectures.  */
#define PPC_OPCODE_32			 8

/* Opcode is only defined on 64 bit architectures.  */
#define PPC_OPCODE_64		      0x10

/* Opcode is supported by the Motorola PowerPC 601 processor.  The 601
   is assumed to support all PowerPC (PPC_OPCODE_PPC) instructions,
   but it also supports many additional POWER instructions.  */
#define PPC_OPCODE_601		      0x20

   /* Opcode is supported in both the Power and PowerPC architectures
      (ie, compiler's -mcpu=common or assembler's -mcom).  */
#define PPC_OPCODE_COMMON	      0x40

      /* Opcode is supported for any Power or PowerPC platform (this is
         for the assembler's -many option, and it eliminates duplicates).  */
#define PPC_OPCODE_ANY		      0x80

         /* Opcode is supported as part of the 64-bit bridge.  */
#define PPC_OPCODE_64_BRIDGE	     0x100

/* Opcode is supported by Altivec Vector Unit */
#define PPC_OPCODE_ALTIVEC	     0x200

/* Opcode is supported by VMX128 Vector Extension */
#define PPC_OPCODE_VMX_128	  0x1000000

/* Opcode is supported by PowerPC 403 processor.  */
#define PPC_OPCODE_403		     0x400

/* Opcode is supported by PowerPC BookE processor.  */
#define PPC_OPCODE_BOOKE	     0x800

/* Opcode is only supported by 64-bit PowerPC BookE processor.  */
#define PPC_OPCODE_BOOKE64	    0x1000

/* Opcode is supported by PowerPC 440 processor.  */
#define PPC_OPCODE_440		    0x2000

/* Opcode is only supported by Power4 architecture.  */
#define PPC_OPCODE_POWER4	    0x4000

/* Opcode isn't supported by Power4 architecture.  */
#define PPC_OPCODE_NOPOWER4	    0x8000

/* Opcode is only supported by POWERPC Classic architecture.  */
#define PPC_OPCODE_CLASSIC	   0x10000

/* Opcode is only supported by e500x2 Core.  */
#define PPC_OPCODE_SPE		   0x20000

/* Opcode is supported by e500x2 Integer select APU.  */
#define PPC_OPCODE_ISEL		   0x40000

/* Opcode is an e500 SPE floating point instruction.  */
#define PPC_OPCODE_EFS		   0x80000

/* Opcode is supported by branch locking APU.  */
#define PPC_OPCODE_BRLOCK	  0x100000

/* Opcode is supported by performance monitor APU.  */
#define PPC_OPCODE_PMR		  0x200000

/* Opcode is supported by cache locking APU.  */
#define PPC_OPCODE_CACHELCK	  0x400000

/* Opcode is supported by machine check APU.  */
#define PPC_OPCODE_RFMCI	  0x800000

/* Opcode is only supported by Power5 architecture.  */
#define PPC_OPCODE_POWER5	 0x1000000

/* Opcode is supported by PowerPC e300 family.  */
#define PPC_OPCODE_E300          0x2000000

/* Opcode is only supported by Power6 architecture.  */
#define PPC_OPCODE_POWER6	 0x4000000

/* Opcode is only supported by PowerPC Cell family.  */
#define PPC_OPCODE_CELL		 0x8000000

/* The operands table is an array of struct powerpc_operand.  */

struct powerpc_operand
{
    /* A bitmask of bits in the operand.  */
    unsigned int bitm;

    /* How far the operand is left shifted in the instruction.
       -1 to indicate that BITM and SHIFT cannot be used to determine
       where the operand goes in the insn.  */
    int shift;

    /* Insertion function.  This is used by the assembler.  To insert an
       operand value into an instruction, check this field.

       If it is NULL, execute
       i |= (op & o->bitm) << o->shift;
       (i is the instruction which we are filling in, o is a pointer to
       this structure, and op is the operand value).

       If this field is not NULL, then simply call it with the
       instruction and the operand value.  It will return the new value
       of the instruction.  If the ERRMSG argument is not NULL, then if
       the operand value is illegal, *ERRMSG will be set to a warning
       string (the operand will be inserted in any case).  If the
       operand value is legal, *ERRMSG will be unchanged (most operands
       can accept any value).  */
    unsigned long (*insert)
        (unsigned long instruction, long op, int dialect, const char** errmsg);

    /* Extraction function.  This is used by the disassembler.  To
       extract this operand type from an instruction, check this field.

       If it is NULL, compute
       op = (i >> o->shift) & o->bitm;
       if ((o->flags & PPC_OPERAND_SIGNED) != 0)
         sign_extend (op);
       (i is the instruction, o is a pointer to this structure, and op
       is the result).

       If this field is not NULL, then simply call it with the
       instruction value.  It will return the value of the operand.  If
       the INVALID argument is not NULL, *INVALID will be set to
       non-zero if this operand type can not actually be extracted from
       this operand (i.e., the instruction does not match).  If the
       operand is valid, *INVALID will not be changed.  */
    long (*extract) (unsigned long instruction, int dialect, int* invalid);

    /* One bit syntax flags.  */
    unsigned long flags;
};

/* Elements in the table are retrieved by indexing with values from
   the operands field of the powerpc_opcodes table.  */

extern const struct powerpc_operand powerpc_operands[];
extern const unsigned int num_powerpc_operands;

/* Values defined for the flags field of a struct powerpc_operand.  */

/* This operand takes signed values.  */
#define PPC_OPERAND_SIGNED (0x1)

/* This operand takes signed values, but also accepts a full positive
   range of values when running in 32 bit mode.  That is, if bits is
   16, it takes any value from -0x8000 to 0xffff.  In 64 bit mode,
   this flag is ignored.  */
#define PPC_OPERAND_SIGNOPT (0x2)

   /* This operand does not actually exist in the assembler input.  This
      is used to support extended mnemonics such as mr, for which two
      operands fields are identical.  The assembler should call the
      insert function with any op value.  The disassembler should call
      the extract function, ignore the return value, and check the value
      placed in the valid argument.  */
#define PPC_OPERAND_FAKE (0x4)

      /* The next operand should be wrapped in parentheses rather than
         separated from this one by a comma.  This is used for the load and
         store instructions which want their operands to look like
             reg,displacement(reg)
         */
#define PPC_OPERAND_PARENS (0x8)

         /* This operand may use the symbolic names for the CR fields, which
            are
                lt  0	gt  1	eq  2	so  3	un  3
                cr0 0	cr1 1	cr2 2	cr3 3
                cr4 4	cr5 5	cr6 6	cr7 7
            These may be combined arithmetically, as in cr2*4+gt.  These are
            only supported on the PowerPC, not the POWER.  */
#define PPC_OPERAND_CR (0x10)

            /* This operand names a register.  The disassembler uses this to print
               register names with a leading 'r'.  */
#define PPC_OPERAND_GPR (0x20)

               /* Like PPC_OPERAND_GPR, but don't print a leading 'r' for r0.  */
#define PPC_OPERAND_GPR_0 (0x40)

/* This operand names a floating point register.  The disassembler
   prints these with a leading 'f'.  */
#define PPC_OPERAND_FPR (0x80)

   /* This operand is a relative branch displacement.  The disassembler
      prints these symbolically if possible.  */
#define PPC_OPERAND_RELATIVE (0x100)

      /* This operand is an absolute branch address.  The disassembler
         prints these symbolically if possible.  */
#define PPC_OPERAND_ABSOLUTE (0x200)

         /* This operand is optional, and is zero if omitted.  This is used for
            example, in the optional BF field in the comparison instructions.  The
            assembler must count the number of operands remaining on the line,
            and the number of operands remaining for the opcode, and decide
            whether this operand is present or not.  The disassembler should
            print this operand out only if it is not zero.  */
#define PPC_OPERAND_OPTIONAL (0x400)

            /* This flag is only used with PPC_OPERAND_OPTIONAL.  If this operand
               is omitted, then for the next operand use this operand value plus
               1, ignoring the next operand field for the opcode.  This wretched
               hack is needed because the Power rotate instructions can take
               either 4 or 5 operands.  The disassembler should print this operand
               out regardless of the PPC_OPERAND_OPTIONAL field.  */
#define PPC_OPERAND_NEXT (0x800)

               /* This operand should be regarded as a negative number for the
                  purposes of overflow checking (i.e., the normal most negative
                  number is disallowed and one more than the normal most positive
                  number is allowed).  This flag will only be set for a signed
                  operand.  */
#define PPC_OPERAND_NEGATIVE (0x1000)

                  /* This operand names a vector unit register.  The disassembler
                     prints these with a leading 'v'.  */
#define PPC_OPERAND_VR (0x2000)

                     /* This operand is for the DS field in a DS form instruction.  */
#define PPC_OPERAND_DS (0x4000)

/* This operand is for the DQ field in a DQ form instruction.  */
#define PPC_OPERAND_DQ (0x8000)

/* Valid range of operand is 0..n rather than 0..n-1.  */
#define PPC_OPERAND_PLUS1 (0x10000)

/* The POWER and PowerPC assemblers use a few macros.  We keep them
   with the operands table for simplicity.  The macro table is an
   array of struct powerpc_macro.  */

struct powerpc_macro
{
    /* The macro name.  */
    const char* name;

    /* The number of operands the macro takes.  */
    unsigned int operands;

    /* One bit flags for the opcode.  These are used to indicate which
       specific processors support the instructions.  The values are the
       same as those for the struct powerpc_opcode flags field.  */
    unsigned long flags;

    /* A format string to turn the macro into a normal instruction.
       Each %N in the string is replaced with operand number N (zero
       based).  */
    const char* format;
};

extern const struct powerpc_macro powerpc_macros[];
extern const int powerpc_num_macros;

/* ppc-opc.c -- PowerPC opcode list
   Copyright 1994, 1995, 1996, 1997, 1998, 2000, 2001, 2002, 2003, 2004,
   2005, 2006, 2007 Free Software Foundation, Inc.
   Written by Ian Lance Taylor, Cygnus Support

   This file is part of GDB, GAS, and the GNU binutils.

   GDB, GAS, and the GNU binutils are free software; you can redistribute
   them and/or modify them under the terms of the GNU General Public
   License as published by the Free Software Foundation; either version
   2, or (at your option) any later version.

   GDB, GAS, and the GNU binutils are distributed in the hope that they
   will be useful, but WITHOUT ANY WARRANTY; without even the implied
   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
   the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this file; see the file COPYING.
   If not, see <http://www.gnu.org/licenses/>.  */

   /* This file holds the PowerPC opcode table.  The opcode table
      includes almost all of the extended instruction mnemonics.  This
      permits the disassembler to use them, and simplifies the assembler
      logic, at the cost of increasing the table size.  The table is
      strictly constant data, so the compiler should be able to put it in
      the .text section.

      This file also holds the operand table.  All knowledge about
      inserting operands into instructions and vice-versa is kept in this
      file.  */

      /* Local insertion and extraction functions.  */

static unsigned long insert_bat(unsigned long, long, int, const char**);
static long extract_bat(unsigned long, int, int*);
static unsigned long insert_bba(unsigned long, long, int, const char**);
static long extract_bba(unsigned long, int, int*);
static unsigned long insert_bdm(unsigned long, long, int, const char**);
static long extract_bdm(unsigned long, int, int*);
static unsigned long insert_bdp(unsigned long, long, int, const char**);
static long extract_bdp(unsigned long, int, int*);
static unsigned long insert_bo(unsigned long, long, int, const char**);
static long extract_bo(unsigned long, int, int*);
static unsigned long insert_boe(unsigned long, long, int, const char**);
static long extract_boe(unsigned long, int, int*);
static unsigned long insert_fxm(unsigned long, long, int, const char**);
static long extract_fxm(unsigned long, int, int*);
static unsigned long insert_mbe(unsigned long, long, int, const char**);
static long extract_mbe(unsigned long, int, int*);
static unsigned long insert_mb6(unsigned long, long, int, const char**);
static long extract_mb6(unsigned long, int, int*);
static long extract_nb(unsigned long, int, int*);
static unsigned long insert_nsi(unsigned long, long, int, const char**);
static long extract_nsi(unsigned long, int, int*);
static unsigned long insert_ral(unsigned long, long, int, const char**);
static unsigned long insert_ram(unsigned long, long, int, const char**);
static unsigned long insert_raq(unsigned long, long, int, const char**);
static unsigned long insert_ras(unsigned long, long, int, const char**);
static unsigned long insert_rbs(unsigned long, long, int, const char**);
static long extract_rbs(unsigned long, int, int*);
static unsigned long insert_sh6(unsigned long, long, int, const char**);
static long extract_sh6(unsigned long, int, int*);
static unsigned long insert_spr(unsigned long, long, int, const char**);
static long extract_spr(unsigned long, int, int*);
static unsigned long insert_sprg(unsigned long, long, int, const char**);
static long extract_sprg(unsigned long, int, int*);
static unsigned long insert_tbr(unsigned long, long, int, const char**);
static long extract_tbr(unsigned long, int, int*);
static unsigned long insert_vds128(unsigned long, long, int, const char**);
static long extract_vds128(unsigned long, int, int*);
static unsigned long insert_va128(unsigned long, long, int, const char**);
static long extract_va128(unsigned long, int, int*);
static unsigned long insert_vb128(unsigned long, long, int, const char**);
static long extract_vb128(unsigned long, int, int*);
static unsigned long insert_vperm(unsigned long, long, int, const char**);
static long extract_vperm(unsigned long, int, int*);

/* The operands table.

   The fields are bitm, shift, insert, extract, flags.

   We used to put parens around the various additions, like the one
   for BA just below.  However, that caused trouble with feeble
   compilers with a limit on depth of a parenthesized expression, like
   (reportedly) the compiler in Microsoft Developer Studio 5.  So we
   omit the parens, since the macros are never used in a context where
   the addition will be ambiguous.  */

const struct powerpc_operand powerpc_operands[] =
{
    /* The zero index is used to indicate the end of the list of
       operands.  */
  #define UNUSED 0
    { 0, 0, NULL, NULL, 0 },

    /* The BA field in an XL form instruction.  */
  #define BA UNUSED + 1
    /* The BI field in a B form or XL form instruction.  */
  #define BI BA
  #define BI_MASK (0x1f << 16)
    { 0x1f, 16, NULL, NULL, PPC_OPERAND_CR },

    /* The BA field in an XL form instruction when it must be the same
       as the BT field in the same instruction.  */
  #define BAT BA + 1
    { 0x1f, 16, insert_bat, extract_bat, PPC_OPERAND_FAKE },

    /* The BB field in an XL form instruction.  */
  #define BB BAT + 1
  #define BB_MASK (0x1f << 11)
    { 0x1f, 11, NULL, NULL, PPC_OPERAND_CR },

    /* The BB field in an XL form instruction when it must be the same
       as the BA field in the same instruction.  */
  #define BBA BB + 1
    { 0x1f, 11, insert_bba, extract_bba, PPC_OPERAND_FAKE },

    /* The BD field in a B form instruction.  The lower two bits are
       forced to zero.  */
  #define BD BBA + 1
    { 0xfffc, 0, NULL, NULL, PPC_OPERAND_RELATIVE | PPC_OPERAND_SIGNED },

    /* The BD field in a B form instruction when absolute addressing is
       used.  */
  #define BDA BD + 1
    { 0xfffc, 0, NULL, NULL, PPC_OPERAND_ABSOLUTE | PPC_OPERAND_SIGNED },

    /* The BD field in a B form instruction when the - modifier is used.
       This sets the y bit of the BO field appropriately.  */
  #define BDM BDA + 1
    { 0xfffc, 0, insert_bdm, extract_bdm,
        PPC_OPERAND_RELATIVE | PPC_OPERAND_SIGNED },

        /* The BD field in a B form instruction when the - modifier is used
           and absolute address is used.  */
      #define BDMA BDM + 1
        { 0xfffc, 0, insert_bdm, extract_bdm,
            PPC_OPERAND_ABSOLUTE | PPC_OPERAND_SIGNED },

            /* The BD field in a B form instruction when the + modifier is used.
               This sets the y bit of the BO field appropriately.  */
          #define BDP BDMA + 1
            { 0xfffc, 0, insert_bdp, extract_bdp,
                PPC_OPERAND_RELATIVE | PPC_OPERAND_SIGNED },

                /* The BD field in a B form instruction when the + modifier is used
                   and absolute addressing is used.  */
              #define BDPA BDP + 1
                { 0xfffc, 0, insert_bdp, extract_bdp,
                    PPC_OPERAND_ABSOLUTE | PPC_OPERAND_SIGNED },

                    /* The BF field in an X or XL form instruction.  */
                  #define BF BDPA + 1
                    /* The CRFD field in an X form instruction.  */
                  #define CRFD BF
                    { 0x7, 23, NULL, NULL, PPC_OPERAND_CR },

                    /* The BF field in an X or XL form instruction.  */
                  #define BFF BF + 1
                    { 0x7, 23, NULL, NULL, 0 },

                    /* An optional BF field.  This is used for comparison instructions,
                       in which an omitted BF field is taken as zero.  */
                  #define OBF BFF + 1
                    { 0x7, 23, NULL, NULL, PPC_OPERAND_CR | PPC_OPERAND_OPTIONAL },

                    /* The BFA field in an X or XL form instruction.  */
                  #define BFA OBF + 1
                    { 0x7, 18, NULL, NULL, PPC_OPERAND_CR },

                    /* The BO field in a B form instruction.  Certain values are
                       illegal.  */
                  #define BO BFA + 1
                  #define BO_MASK (0x1f << 21)
                    { 0x1f, 21, insert_bo, extract_bo, 0 },

                    /* The BO field in a B form instruction when the + or - modifier is
                       used.  This is like the BO field, but it must be even.  */
                  #define BOE BO + 1
                    { 0x1e, 21, insert_boe, extract_boe, 0 },

                  #define BH BOE + 1
                    { 0x3, 11, NULL, NULL, PPC_OPERAND_OPTIONAL },

                    /* The BT field in an X or XL form instruction.  */
                  #define BT BH + 1
                    { 0x1f, 21, NULL, NULL, PPC_OPERAND_CR },

                    /* The condition register number portion of the BI field in a B form
                       or XL form instruction.  This is used for the extended
                       conditional branch mnemonics, which set the lower two bits of the
                       BI field.  This field is optional.  */
                  #define CR BT + 1
                    { 0x7, 18, NULL, NULL, PPC_OPERAND_CR | PPC_OPERAND_OPTIONAL },

                    /* The CRB field in an X form instruction.  */
                  #define CRB CR + 1
                    /* The MB field in an M form instruction.  */
                  #define MB CRB
                  #define MB_MASK (0x1f << 6)
                    { 0x1f, 6, NULL, NULL, 0 },

                    /* The CRFS field in an X form instruction.  */
                  #define CRFS CRB + 1
                    { 0x7, 0, NULL, NULL, PPC_OPERAND_CR },

                    /* The CT field in an X form instruction.  */
                  #define CT CRFS + 1
                    /* The MO field in an mbar instruction.  */
                  #define MO CT
                    { 0x1f, 21, NULL, NULL, PPC_OPERAND_OPTIONAL },

                    /* The D field in a D form instruction.  This is a displacement off
                       a register, and implies that the next operand is a register in
                       parentheses.  */
                  #define D CT + 1
                    { 0xffff, 0, NULL, NULL, PPC_OPERAND_PARENS | PPC_OPERAND_SIGNED },

                    /* The DE field in a DE form instruction.  This is like D, but is 12
                       bits only.  */
                  #define DE D + 1
                    { 0xfff, 4, NULL, NULL, PPC_OPERAND_PARENS | PPC_OPERAND_SIGNED },

                    /* The DES field in a DES form instruction.  This is like DS, but is 14
                       bits only (12 stored.)  */
                  #define DES DE + 1
                    { 0x3ffc, 2, NULL, NULL, PPC_OPERAND_PARENS | PPC_OPERAND_SIGNED },

                    /* The DQ field in a DQ form instruction.  This is like D, but the
                       lower four bits are forced to zero. */
                  #define DQ DES + 1
                    { 0xfff0, 0, NULL, NULL,
                      PPC_OPERAND_PARENS | PPC_OPERAND_SIGNED | PPC_OPERAND_DQ },

                      /* The DS field in a DS form instruction.  This is like D, but the
                         lower two bits are forced to zero.  */
                    #undef DS
                    #define DS DQ + 1
                      { 0xfffc, 0, NULL, NULL,
                        PPC_OPERAND_PARENS | PPC_OPERAND_SIGNED | PPC_OPERAND_DS },

                        /* The E field in a wrteei instruction.  */
                      #define E DS + 1
                        { 0x1, 15, NULL, NULL, 0 },

                        /* The FL1 field in a POWER SC form instruction.  */
                      #define FL1 E + 1
                        /* The U field in an X form instruction.  */
                      #define U FL1
                        { 0xf, 12, NULL, NULL, 0 },

                        /* The FL2 field in a POWER SC form instruction.  */
                      #define FL2 FL1 + 1
                        { 0x7, 2, NULL, NULL, 0 },

                        /* The FLM field in an XFL form instruction.  */
                      #define FLM FL2 + 1
                        { 0xff, 17, NULL, NULL, 0 },

                        /* The FRA field in an X or A form instruction.  */
                      #define FRA FLM + 1
                      #define FRA_MASK (0x1f << 16)
                        { 0x1f, 16, NULL, NULL, PPC_OPERAND_FPR },

                        /* The FRB field in an X or A form instruction.  */
                      #define FRB FRA + 1
                      #define FRB_MASK (0x1f << 11)
                        { 0x1f, 11, NULL, NULL, PPC_OPERAND_FPR },

                        /* The FRC field in an A form instruction.  */
                      #define FRC FRB + 1
                      #define FRC_MASK (0x1f << 6)
                        { 0x1f, 6, NULL, NULL, PPC_OPERAND_FPR },

                        /* The FRS field in an X form instruction or the FRT field in a D, X
                           or A form instruction.  */
                      #define FRS FRC + 1
                      #define FRT FRS
                        { 0x1f, 21, NULL, NULL, PPC_OPERAND_FPR },

                        /* The FXM field in an XFX instruction.  */
                      #define FXM FRS + 1
                        { 0xff, 12, insert_fxm, extract_fxm, 0 },

                        /* Power4 version for mfcr.  */
                      #define FXM4 FXM + 1
                        { 0xff, 12, insert_fxm, extract_fxm, PPC_OPERAND_OPTIONAL },

                        /* The L field in a D or X form instruction.  */
                      #define L FXM4 + 1
                        { 0x1, 21, NULL, NULL, PPC_OPERAND_OPTIONAL },

                        /* The LEV field in a POWER SVC form instruction.  */
                      #define SVC_LEV L + 1
                        { 0x7f, 5, NULL, NULL, 0 },

                        /* The LEV field in an SC form instruction.  */
                      #define LEV SVC_LEV + 1
                        { 0x7f, 5, NULL, NULL, PPC_OPERAND_OPTIONAL },

                        /* The LI field in an I form instruction.  The lower two bits are
                           forced to zero.  */
                      #define LI LEV + 1
                        { 0x3fffffc, 0, NULL, NULL, PPC_OPERAND_RELATIVE | PPC_OPERAND_SIGNED },

                        /* The LI field in an I form instruction when used as an absolute
                           address.  */
                      #define LIA LI + 1
                        { 0x3fffffc, 0, NULL, NULL, PPC_OPERAND_ABSOLUTE | PPC_OPERAND_SIGNED },

                        /* The LS field in an X (sync) form instruction.  */
                      #define LS LIA + 1
                        { 0x3, 21, NULL, NULL, PPC_OPERAND_OPTIONAL },

                        /* The ME field in an M form instruction.  */
                      #define ME LS + 1
                      #define ME_MASK (0x1f << 1)
                        { 0x1f, 1, NULL, NULL, 0 },

                        /* The MB and ME fields in an M form instruction expressed a single
                           operand which is a bitmask indicating which bits to select.  This
                           is a two operand form using PPC_OPERAND_NEXT.  See the
                           description in opcode/ppc.h for what this means.  */
                      #define MBE ME + 1
                        { 0x1f, 6, NULL, NULL, PPC_OPERAND_OPTIONAL | PPC_OPERAND_NEXT },
                        { -1, 0, insert_mbe, extract_mbe, 0 },

                        /* The MB or ME field in an MD or MDS form instruction.  The high
                           bit is wrapped to the low end.  */
                      #define MB6 MBE + 2
                      #define ME6 MB6
                      #define MB6_MASK (0x3f << 5)
                        { 0x3f, 5, insert_mb6, extract_mb6, 0 },

                        /* The NB field in an X form instruction.  The value 32 is stored as
                           0.  */
                      #define NB MB6 + 1
                        { 0x1f, 11, NULL, extract_nb, PPC_OPERAND_PLUS1 },

                        /* The NSI field in a D form instruction.  This is the same as the
                           SI field, only negated.  */
                      #define NSI NB + 1
                        { 0xffff, 0, insert_nsi, extract_nsi,
                            PPC_OPERAND_NEGATIVE | PPC_OPERAND_SIGNED },

                            /* The RA field in an D, DS, DQ, X, XO, M, or MDS form instruction.  */
                          #define RA NSI + 1
                          #define RA_MASK (0x1f << 16)
                            { 0x1f, 16, NULL, NULL, PPC_OPERAND_GPR },

                            /* As above, but 0 in the RA field means zero, not r0.  */
                          #define RA0 RA + 1
                            { 0x1f, 16, NULL, NULL, PPC_OPERAND_GPR_0 },

                            /* The RA field in the DQ form lq instruction, which has special
                               value restrictions.  */
                          #define RAQ RA0 + 1
                            { 0x1f, 16, insert_raq, NULL, PPC_OPERAND_GPR_0 },

                            /* The RA field in a D or X form instruction which is an updating
                               load, which means that the RA field may not be zero and may not
                               equal the RT field.  */
                          #define RAL RAQ + 1
                            { 0x1f, 16, insert_ral, NULL, PPC_OPERAND_GPR_0 },

                            /* The RA field in an lmw instruction, which has special value
                               restrictions.  */
                          #define RAM RAL + 1
                            { 0x1f, 16, insert_ram, NULL, PPC_OPERAND_GPR_0 },

                            /* The RA field in a D or X form instruction which is an updating
                               store or an updating floating point load, which means that the RA
                               field may not be zero.  */
                          #define RAS RAM + 1
                            { 0x1f, 16, insert_ras, NULL, PPC_OPERAND_GPR_0 },

                            /* The RA field of the tlbwe instruction, which is optional.  */
                          #define RAOPT RAS + 1
                            { 0x1f, 16, NULL, NULL, PPC_OPERAND_GPR | PPC_OPERAND_OPTIONAL },

                            /* The RB field in an X, XO, M, or MDS form instruction.  */
                          #define RB RAOPT + 1
                          #define RB_MASK (0x1f << 11)
                            { 0x1f, 11, NULL, NULL, PPC_OPERAND_GPR },

                            /* The RB field in an X form instruction when it must be the same as
                               the RS field in the instruction.  This is used for extended
                               mnemonics like mr.  */
                          #define RBS RB + 1
                            { 0x1f, 11, insert_rbs, extract_rbs, PPC_OPERAND_FAKE },

                            /* The RS field in a D, DS, X, XFX, XS, M, MD or MDS form
                               instruction or the RT field in a D, DS, X, XFX or XO form
                               instruction.  */
                          #define RS RBS + 1
                          #define RT RS
                          #define RT_MASK (0x1f << 21)
                            { 0x1f, 21, NULL, NULL, PPC_OPERAND_GPR },

                            /* The RS and RT fields of the DS form stq instruction, which have
                               special value restrictions.  */
                          #define RSQ RS + 1
                          #define RTQ RSQ
                            { 0x1e, 21, NULL, NULL, PPC_OPERAND_GPR_0 },

                            /* The RS field of the tlbwe instruction, which is optional.  */
                          #define RSO RSQ + 1
                          #define RTO RSO
                            { 0x1f, 21, NULL, NULL, PPC_OPERAND_GPR | PPC_OPERAND_OPTIONAL },

                            /* The SH field in an X or M form instruction.  */
                          #define SH RSO + 1
                          #define SH_MASK (0x1f << 11)
                            /* The other UIMM field in a EVX form instruction.  */
                          #define EVUIMM SH
                            { 0x1f, 11, NULL, NULL, 0 },

                            /* The SH field in an MD form instruction.  This is split.  */
                          #define SH6 SH + 1
                          #define SH6_MASK ((0x1f << 11) | (1 << 1))
                            { 0x3f, -1, insert_sh6, extract_sh6, 0 },

                            /* The SH field of the tlbwe instruction, which is optional.  */
                          #define SHO SH6 + 1
                            { 0x1f, 11, NULL, NULL, PPC_OPERAND_OPTIONAL },

                            /* The SI field in a D form instruction.  */
                          #define SI SHO + 1
                            { 0xffff, 0, NULL, NULL, PPC_OPERAND_SIGNED },

                            /* The SI field in a D form instruction when we accept a wide range
                               of positive values.  */
                          #define SISIGNOPT SI + 1
                            { 0xffff, 0, NULL, NULL, PPC_OPERAND_SIGNED | PPC_OPERAND_SIGNOPT },

                            /* The SPR field in an XFX form instruction.  This is flipped--the
                               lower 5 bits are stored in the upper 5 and vice- versa.  */
                          #define SPR SISIGNOPT + 1
                          #define PMR SPR
                          #define SPR_MASK (0x3ff << 11)
                            { 0x3ff, 11, insert_spr, extract_spr, 0 },

                            /* The BAT index number in an XFX form m[ft]ibat[lu] instruction.  */
                          #define SPRBAT SPR + 1
                          #define SPRBAT_MASK (0x3 << 17)
                            { 0x3, 17, NULL, NULL, 0 },

                            /* The SPRG register number in an XFX form m[ft]sprg instruction.  */
                          #define SPRG SPRBAT + 1
                            { 0x1f, 16, insert_sprg, extract_sprg, 0 },

                            /* The SR field in an X form instruction.  */
                          #define SR SPRG + 1
                            { 0xf, 16, NULL, NULL, 0 },

                            /* The STRM field in an X AltiVec form instruction.  */
                          #define STRM SR + 1
                            { 0x3, 21, NULL, NULL, 0 },

                            /* The SV field in a POWER SC form instruction.  */
                          #define SV STRM + 1
                            { 0x3fff, 2, NULL, NULL, 0 },

                            /* The TBR field in an XFX form instruction.  This is like the SPR
                               field, but it is optional.  */
                          #define TBR SV + 1
                            { 0x3ff, 11, insert_tbr, extract_tbr, PPC_OPERAND_OPTIONAL },

                            /* The TO field in a D or X form instruction.  */
                          #define TO TBR + 1
                          #define TO_MASK (0x1f << 21)
                            { 0x1f, 21, NULL, NULL, 0 },

                            /* The UI field in a D form instruction.  */
                          #define UI TO + 1
                            { 0xffff, 0, NULL, NULL, 0 },

                            /* The VA field in a VA, VX or VXR form instruction.  */
                          #define VA UI + 1
                            { 0x1f, 16, NULL, NULL, PPC_OPERAND_VR },

                            /* The VB field in a VA, VX or VXR form instruction.  */
                          #define VB VA + 1
                            { 0x1f, 11, NULL, NULL, PPC_OPERAND_VR },

                            /* The VC field in a VA form instruction.  */
                          #define VC VB + 1
                            { 0x1f, 6, NULL, NULL, PPC_OPERAND_VR },

                            /* The VD or VS field in a VA, VX, VXR or X form instruction.  */
                          #define VD VC + 1
                          #define VS VD
                            { 0x1f, 21, NULL, NULL, PPC_OPERAND_VR },

                          #define VD128 VD + 1
                           #define VS128 VD128
                           #define VD128_MASK (0x1f << 21)
                           { 7, 0, insert_vds128, extract_vds128, PPC_OPERAND_VR },
                          
                            /* The VA128 field in a VA, VX, VXR or X form instruction. */
                          #define VA128 VD128 + 1
                           #define VA128_MASK (0x1f << 21)
                           { 7, 0, insert_va128, extract_va128, PPC_OPERAND_VR },
                          
                            /* The VB128 field in a VA, VX, VXR or X form instruction. */
                          #define VB128 VA128 + 1
                           #define VB128_MASK (0x1f << 21)
                           { 7, 0, insert_vb128, extract_vb128, PPC_OPERAND_VR },
                          
                            /* The VC128 field in a VA, VX, VXR or X form instruction. */
                          #define VC128 VB128 + 1
                           #define VC128_MASK (0x1f << 21)
                           { 7, 6, NULL, NULL, PPC_OPERAND_VR },
                          
                            /* The VPERM field in a VPERM128 form instruction. */
                          #define VPERM128 VC128 + 1
                           #define VPERM_MASK (0x1f << 21)
                           { 8, 0, insert_vperm, extract_vperm, 0 },
                          
                          #define VD3D0 VPERM128 + 1
                           { 7, 18, NULL, NULL, 0 },
                          
                          #define VD3D1 VD3D0 + 1
                           { 3, 16, NULL, NULL, 0 },
                          
                          #define VD3D2 VD3D1 + 1
                           { 3, 6, NULL, NULL, 0 },

                            /* The SIMM field in a VX form instruction.  */
                          #define SIMM VD3D2 + 1
                            { 0x1f, 16, NULL, NULL, PPC_OPERAND_SIGNED},

                            /* The UIMM field in a VX form instruction, and TE in Z form.  */
                          #define UIMM SIMM + 1
                          #define TE UIMM
                            { 0x1f, 16, NULL, NULL, 0 },

                            /* The SHB field in a VA form instruction.  */
                          #define SHB UIMM + 1
                            { 0xf, 6, NULL, NULL, 0 },

                            /* The other UIMM field in a half word EVX form instruction.  */
                          #define EVUIMM_2 SHB + 1
                            { 0x3e, 10, NULL, NULL, PPC_OPERAND_PARENS },

                            /* The other UIMM field in a word EVX form instruction.  */
                          #define EVUIMM_4 EVUIMM_2 + 1
                            { 0x7c, 9, NULL, NULL, PPC_OPERAND_PARENS },

                            /* The other UIMM field in a double EVX form instruction.  */
                          #define EVUIMM_8 EVUIMM_4 + 1
                            { 0xf8, 8, NULL, NULL, PPC_OPERAND_PARENS },

                            /* The WS field.  */
                          #define WS EVUIMM_8 + 1
                            { 0x7, 11, NULL, NULL, 0 },

                            /* The L field in an mtmsrd or A form instruction or W in an X form.  */
                          #define A_L WS + 1
                          #define W A_L
                            { 0x1, 16, NULL, NULL, PPC_OPERAND_OPTIONAL },

                          #define RMC A_L + 1
                            { 0x3, 9, NULL, NULL, 0 },

                          #define R RMC + 1
                            { 0x1, 16, NULL, NULL, 0 },

                          #define SP R + 1
                            { 0x3, 19, NULL, NULL, 0 },

                          #define S SP + 1
                            { 0x1, 20, NULL, NULL, 0 },

                            /* SH field starting at bit position 16.  */
                          #define SH16 S + 1
                            /* The DCM and DGM fields in a Z form instruction.  */
                          #define DCM SH16
                          #define DGM DCM
                            { 0x3f, 10, NULL, NULL, 0 },

                            /* The EH field in larx instruction.  */
                          #define EH SH16 + 1
                            { 0x1, 0, NULL, NULL, PPC_OPERAND_OPTIONAL },

                            /* The L field in an mtfsf or XFL form instruction.  */
                          #define XFL_L EH + 1
                            { 0x1, 25, NULL, NULL, PPC_OPERAND_OPTIONAL},
};

const unsigned int num_powerpc_operands = (sizeof(powerpc_operands)
    / sizeof(powerpc_operands[0]));

/* The functions used to insert and extract complicated operands.  */

/* The BA field in an XL form instruction when it must be the same as
   the BT field in the same instruction.  This operand is marked FAKE.
   The insertion function just copies the BT field into the BA field,
   and the extraction function just checks that the fields are the
   same.  */

static unsigned long
insert_bat(unsigned long insn,
    long value ATTRIBUTE_UNUSED,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg ATTRIBUTE_UNUSED)
{
    return insn | (((insn >> 21) & 0x1f) << 16);
}

static long
extract_bat(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid)
{
    if (((insn >> 21) & 0x1f) != ((insn >> 16) & 0x1f))
        *invalid = 1;
    return 0;
}

/* The BB field in an XL form instruction when it must be the same as
   the BA field in the same instruction.  This operand is marked FAKE.
   The insertion function just copies the BA field into the BB field,
   and the extraction function just checks that the fields are the
   same.  */

static unsigned long
insert_bba(unsigned long insn,
    long value ATTRIBUTE_UNUSED,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg ATTRIBUTE_UNUSED)
{
    return insn | (((insn >> 16) & 0x1f) << 11);
}

static long
extract_bba(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid)
{
    if (((insn >> 16) & 0x1f) != ((insn >> 11) & 0x1f))
        *invalid = 1;
    return 0;
}

/* The BD field in a B form instruction when the - modifier is used.
   This modifier means that the branch is not expected to be taken.
   For chips built to versions of the architecture prior to version 2
   (ie. not Power4 compatible), we set the y bit of the BO field to 1
   if the offset is negative.  When extracting, we require that the y
   bit be 1 and that the offset be positive, since if the y bit is 0
   we just want to print the normal form of the instruction.
   Power4 compatible targets use two bits, "a", and "t", instead of
   the "y" bit.  "at" == 00 => no hint, "at" == 01 => unpredictable,
   "at" == 10 => not taken, "at" == 11 => taken.  The "t" bit is 00001
   in BO field, the "a" bit is 00010 for branch on CR(BI) and 01000
   for branch on CTR.  We only handle the taken/not-taken hint here.
   Note that we don't relax the conditions tested here when
   disassembling with -Many because insns using extract_bdm and
   extract_bdp always occur in pairs.  One or the other will always
   be valid.  */

static unsigned long
insert_bdm(unsigned long insn,
    long value,
    int dialect,
    const char** errmsg ATTRIBUTE_UNUSED)
{
    if ((dialect & PPC_OPCODE_POWER4) == 0)
    {
        if ((value & 0x8000) != 0)
            insn |= 1 << 21;
    }
    else
    {
        if ((insn & (0x14 << 21)) == (0x04 << 21))
            insn |= 0x02 << 21;
        else if ((insn & (0x14 << 21)) == (0x10 << 21))
            insn |= 0x08 << 21;
    }
    return insn | (value & 0xfffc);
}

static long
extract_bdm(unsigned long insn,
    int dialect,
    int* invalid)
{
    if ((dialect & PPC_OPCODE_POWER4) == 0)
    {
        if (((insn & (1 << 21)) == 0) != ((insn & (1 << 15)) == 0))
            *invalid = 1;
    }
    else
    {
        if ((insn & (0x17 << 21)) != (0x06 << 21)
            && (insn & (0x1d << 21)) != (0x18 << 21))
            *invalid = 1;
    }

    return ((insn & 0xfffc) ^ 0x8000) - 0x8000;
}

/* The BD field in a B form instruction when the + modifier is used.
   This is like BDM, above, except that the branch is expected to be
   taken.  */

static unsigned long
insert_bdp(unsigned long insn,
    long value,
    int dialect,
    const char** errmsg ATTRIBUTE_UNUSED)
{
    if ((dialect & PPC_OPCODE_POWER4) == 0)
    {
        if ((value & 0x8000) == 0)
            insn |= 1 << 21;
    }
    else
    {
        if ((insn & (0x14 << 21)) == (0x04 << 21))
            insn |= 0x03 << 21;
        else if ((insn & (0x14 << 21)) == (0x10 << 21))
            insn |= 0x09 << 21;
    }
    return insn | (value & 0xfffc);
}

static long
extract_bdp(unsigned long insn,
    int dialect,
    int* invalid)
{
    if ((dialect & PPC_OPCODE_POWER4) == 0)
    {
        if (((insn & (1 << 21)) == 0) == ((insn & (1 << 15)) == 0))
            *invalid = 1;
    }
    else
    {
        if ((insn & (0x17 << 21)) != (0x07 << 21)
            && (insn & (0x1d << 21)) != (0x19 << 21))
            *invalid = 1;
    }

    return ((insn & 0xfffc) ^ 0x8000) - 0x8000;
}

/* Check for legal values of a BO field.  */

static int
valid_bo(long value, int dialect, int extract)
{
    if ((dialect & PPC_OPCODE_POWER4) == 0)
    {
        int valid;
        /* Certain encodings have bits that are required to be zero.
       These are (z must be zero, y may be anything):
           001zy
           011zy
           1z00y
           1z01y
           1z1zz
        */
        switch (value & 0x14)
        {
        default:
        case 0:
            valid = 1;
            break;
        case 0x4:
            valid = (value & 0x2) == 0;
            break;
        case 0x10:
            valid = (value & 0x8) == 0;
            break;
        case 0x14:
            valid = value == 0x14;
            break;
        }
        /* When disassembling with -Many, accept power4 encodings too.  */
        if (valid
            || (dialect & PPC_OPCODE_ANY) == 0
            || !extract)
            return valid;
    }

    /* Certain encodings have bits that are required to be zero.
       These are (z must be zero, a & t may be anything):
       0000z
       0001z
       0100z
       0101z
       001at
       011at
       1a00t
       1a01t
       1z1zz
    */
    if ((value & 0x14) == 0)
        return (value & 0x1) == 0;
    else if ((value & 0x14) == 0x14)
        return value == 0x14;
    else
        return 1;
}

/* The BO field in a B form instruction.  Warn about attempts to set
   the field to an illegal value.  */

static unsigned long
insert_bo(unsigned long insn,
    long value,
    int dialect,
    const char** errmsg)
{
    if (!valid_bo(value, dialect, 0))
        *errmsg = _("invalid conditional option");
    return insn | ((value & 0x1f) << 21);
}

static long
extract_bo(unsigned long insn,
    int dialect,
    int* invalid)
{
    long value;

    value = (insn >> 21) & 0x1f;
    if (!valid_bo(value, dialect, 1))
        *invalid = 1;
    return value;
}

/* The BO field in a B form instruction when the + or - modifier is
   used.  This is like the BO field, but it must be even.  When
   extracting it, we force it to be even.  */

static unsigned long
insert_boe(unsigned long insn,
    long value,
    int dialect,
    const char** errmsg)
{
    if (!valid_bo(value, dialect, 0))
        *errmsg = _("invalid conditional option");
    else if ((value & 1) != 0)
        *errmsg = _("attempt to set y bit when using + or - modifier");

    return insn | ((value & 0x1f) << 21);
}

static long
extract_boe(unsigned long insn,
    int dialect,
    int* invalid)
{
    long value;

    value = (insn >> 21) & 0x1f;
    if (!valid_bo(value, dialect, 1))
        *invalid = 1;
    return value & 0x1e;
}

/* FXM mask in mfcr and mtcrf instructions.  */

static unsigned long
insert_fxm(unsigned long insn,
    long value,
    int dialect,
    const char** errmsg)
{
    /* If we're handling the mfocrf and mtocrf insns ensure that exactly
       one bit of the mask field is set.  */
    if ((insn & (1 << 20)) != 0)
    {
        if (value == 0 || (value & -value) != value)
        {
            *errmsg = _("invalid mask field");
            value = 0;
        }
    }

    /* If the optional field on mfcr is missing that means we want to use
       the old form of the instruction that moves the whole cr.  In that
       case we'll have VALUE zero.  There doesn't seem to be a way to
       distinguish this from the case where someone writes mfcr %r3,0.  */
    else if (value == 0)
        ;

    /* If only one bit of the FXM field is set, we can use the new form
       of the instruction, which is faster.  Unlike the Power4 branch hint
       encoding, this is not backward compatible.  Do not generate the
       new form unless -mpower4 has been given, or -many and the two
       operand form of mfcr was used.  */
    else if ((value & -value) == value
        && ((dialect & PPC_OPCODE_POWER4) != 0
            || ((dialect & PPC_OPCODE_ANY) != 0
                && (insn & (0x3ff << 1)) == 19 << 1)))
        insn |= 1 << 20;

    /* Any other value on mfcr is an error.  */
    else if ((insn & (0x3ff << 1)) == 19 << 1)
    {
        *errmsg = _("ignoring invalid mfcr mask");
        value = 0;
    }

    return insn | ((value & 0xff) << 12);
}

static long
extract_fxm(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid)
{
    long mask = (insn >> 12) & 0xff;

    /* Is this a Power4 insn?  */
    if ((insn & (1 << 20)) != 0)
    {
        /* Exactly one bit of MASK should be set.  */
        if (mask == 0 || (mask & -mask) != mask)
            *invalid = 1;
    }

    /* Check that non-power4 form of mfcr has a zero MASK.  */
    else if ((insn & (0x3ff << 1)) == 19 << 1)
    {
        if (mask != 0)
            *invalid = 1;
    }

    return mask;
}

/* The MB and ME fields in an M form instruction expressed as a single
   operand which is itself a bitmask.  The extraction function always
   marks it as invalid, since we never want to recognize an
   instruction which uses a field of this type.  */

static unsigned long
insert_mbe(unsigned long insn,
    long value,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg)
{
    unsigned long uval, mask;
    int mb, me, mx, count, last;

    uval = value;

    if (uval == 0)
    {
        *errmsg = _("illegal bitmask");
        return insn;
    }

    mb = 0;
    me = 32;
    if ((uval & 1) != 0)
        last = 1;
    else
        last = 0;
    count = 0;

    /* mb: location of last 0->1 transition */
    /* me: location of last 1->0 transition */
    /* count: # transitions */

    for (mx = 0, mask = 1L << 31; mx < 32; ++mx, mask >>= 1)
    {
        if ((uval & mask) && !last)
        {
            ++count;
            mb = mx;
            last = 1;
        }
        else if (!(uval & mask) && last)
        {
            ++count;
            me = mx;
            last = 0;
        }
    }
    if (me == 0)
        me = 32;

    if (count != 2 && (count != 0 || !last))
        *errmsg = _("illegal bitmask");

    return insn | (mb << 6) | ((me - 1) << 1);
}

static long
extract_mbe(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid)
{
    long ret;
    int mb, me;
    int i;

    *invalid = 1;

    mb = (insn >> 6) & 0x1f;
    me = (insn >> 1) & 0x1f;
    if (mb < me + 1)
    {
        ret = 0;
        for (i = mb; i <= me; i++)
            ret |= 1L << (31 - i);
    }
    else if (mb == me + 1)
        ret = ~0;
    else /* (mb > me + 1) */
    {
        ret = ~0;
        for (i = me + 1; i < mb; i++)
            ret &= ~(1L << (31 - i));
    }
    return ret;
}

/* The MB or ME field in an MD or MDS form instruction.  The high bit
   is wrapped to the low end.  */

static unsigned long
insert_mb6(unsigned long insn,
    long value,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg ATTRIBUTE_UNUSED)
{
    return insn | ((value & 0x1f) << 6) | (value & 0x20);
}

static long
extract_mb6(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid ATTRIBUTE_UNUSED)
{
    return ((insn >> 6) & 0x1f) | (insn & 0x20);
}

/* The NB field in an X form instruction.  The value 32 is stored as
   0.  */

static long
extract_nb(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid ATTRIBUTE_UNUSED)
{
    long ret;

    ret = (insn >> 11) & 0x1f;
    if (ret == 0)
        ret = 32;
    return ret;
}

/* The NSI field in a D form instruction.  This is the same as the SI
   field, only negated.  The extraction function always marks it as
   invalid, since we never want to recognize an instruction which uses
   a field of this type.  */

static unsigned long
insert_nsi(unsigned long insn,
    long value,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg ATTRIBUTE_UNUSED)
{
    return insn | (-value & 0xffff);
}

static long
extract_nsi(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid)
{
    *invalid = 1;
    return -(((insn & 0xffff) ^ 0x8000) - 0x8000);
}

/* The RA field in a D or X form instruction which is an updating
   load, which means that the RA field may not be zero and may not
   equal the RT field.  */

static unsigned long
insert_ral(unsigned long insn,
    long value,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg)
{
    if (value == 0
        || (unsigned long)value == ((insn >> 21) & 0x1f))
        *errmsg = "invalid register operand when updating";
    return insn | ((value & 0x1f) << 16);
}

/* The RA field in an lmw instruction, which has special value
   restrictions.  */

static unsigned long
insert_ram(unsigned long insn,
    long value,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg)
{
    if ((unsigned long)value >= ((insn >> 21) & 0x1f))
        *errmsg = _("index register in load range");
    return insn | ((value & 0x1f) << 16);
}

/* The RA field in the DQ form lq instruction, which has special
   value restrictions.  */

static unsigned long
insert_raq(unsigned long insn,
    long value,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg)
{
    long rtvalue = (insn & RT_MASK) >> 21;

    if (value == rtvalue)
        *errmsg = _("source and target register operands must be different");
    return insn | ((value & 0x1f) << 16);
}

/* The RA field in a D or X form instruction which is an updating
   store or an updating floating point load, which means that the RA
   field may not be zero.  */

static unsigned long
insert_ras(unsigned long insn,
    long value,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg)
{
    if (value == 0)
        *errmsg = _("invalid register operand when updating");
    return insn | ((value & 0x1f) << 16);
}

/* The RB field in an X form instruction when it must be the same as
   the RS field in the instruction.  This is used for extended
   mnemonics like mr.  This operand is marked FAKE.  The insertion
   function just copies the BT field into the BA field, and the
   extraction function just checks that the fields are the same.  */

static unsigned long
insert_rbs(unsigned long insn,
    long value ATTRIBUTE_UNUSED,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg ATTRIBUTE_UNUSED)
{
    return insn | (((insn >> 21) & 0x1f) << 11);
}

static long
extract_rbs(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid)
{
    if (((insn >> 21) & 0x1f) != ((insn >> 11) & 0x1f))
        *invalid = 1;
    return 0;
}

/* The SH field in an MD form instruction.  This is split.  */

static unsigned long
insert_sh6(unsigned long insn,
    long value,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg ATTRIBUTE_UNUSED)
{
    return insn | ((value & 0x1f) << 11) | ((value & 0x20) >> 4);
}

static long
extract_sh6(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid ATTRIBUTE_UNUSED)
{
    return ((insn >> 11) & 0x1f) | ((insn << 4) & 0x20);
}

/* The SPR field in an XFX form instruction.  This is flipped--the
   lower 5 bits are stored in the upper 5 and vice- versa.  */

static unsigned long
insert_spr(unsigned long insn,
    long value,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg ATTRIBUTE_UNUSED)
{
    return insn | ((value & 0x1f) << 16) | ((value & 0x3e0) << 6);
}

static long
extract_spr(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid ATTRIBUTE_UNUSED)
{
    return ((insn >> 16) & 0x1f) | ((insn >> 6) & 0x3e0);
}

/* Some dialects have 8 SPRG registers instead of the standard 4.  */

static unsigned long
insert_sprg(unsigned long insn,
    long value,
    int dialect,
    const char** errmsg)
{
    /* This check uses PPC_OPCODE_403 because PPC405 is later defined
       as a synonym.  If ever a 405 specific dialect is added this
       check should use that instead.  */
    if (value > 7
        || (value > 3
            && (dialect & (PPC_OPCODE_BOOKE | PPC_OPCODE_403)) == 0))
        *errmsg = _("invalid sprg number");

    /* If this is mfsprg4..7 then use spr 260..263 which can be read in
       user mode.  Anything else must use spr 272..279.  */
    if (value <= 3 || (insn & 0x100) != 0)
        value |= 0x10;

    return insn | ((value & 0x17) << 16);
}

static long
extract_sprg(unsigned long insn,
    int dialect,
    int* invalid)
{
    unsigned long val = (insn >> 16) & 0x1f;

    /* mfsprg can use 260..263 and 272..279.  mtsprg only uses spr 272..279
       If not BOOKE or 405, then both use only 272..275.  */
    if (val <= 3
        || (val < 0x10 && (insn & 0x100) != 0)
        || (val - 0x10 > 3
            && (dialect & (PPC_OPCODE_BOOKE | PPC_OPCODE_403)) == 0))
        *invalid = 1;
    return val & 7;
}

/* The TBR field in an XFX instruction.  This is just like SPR, but it
   is optional.  When TBR is omitted, it must be inserted as 268 (the
   magic number of the TB register).  These functions treat 0
   (indicating an omitted optional operand) as 268.  This means that
   ``mftb 4,0'' is not handled correctly.  This does not matter very
   much, since the architecture manual does not define mftb as
   accepting any values other than 268 or 269.  */

#define TB (268)

static unsigned long
insert_tbr(unsigned long insn,
    long value,
    int dialect ATTRIBUTE_UNUSED,
    const char** errmsg ATTRIBUTE_UNUSED)
{
    if (value == 0)
        value = TB;
    return insn | ((value & 0x1f) << 16) | ((value & 0x3e0) << 6);
}

static long
extract_tbr(unsigned long insn,
    int dialect ATTRIBUTE_UNUSED,
    int* invalid ATTRIBUTE_UNUSED)
{
    long ret;

    ret = ((insn >> 16) & 0x1f) | ((insn >> 6) & 0x3e0);
    if (ret == TB)
        ret = 0;
    return ret;
}

/* The VD128 or VS128 field in an VX128 form instruction.  This is split.  */

static unsigned long
insert_vds128 (unsigned long insn,
       long value,
       int dialect ATTRIBUTE_UNUSED,
       const char **errmsg ATTRIBUTE_UNUSED)
{

  return insn | ((value & 0x60) >> 3) | ((value & 0x1f) << 21);
}

static long
extract_vds128 (unsigned long insn,
        int dialect ATTRIBUTE_UNUSED,
        int *invalid ATTRIBUTE_UNUSED)
{
  return ((insn << 3) & 0x60) | ((insn >> 21) & 0x1f);
}

/* The VA128 field in an VX128 form instruction.  This is split.  */

static unsigned long
insert_va128 (unsigned long insn,
       long value,
       int dialect ATTRIBUTE_UNUSED,
       const char **errmsg ATTRIBUTE_UNUSED)
{
  return insn | ((value & 0x40) << 4) | (value & 0x20) 
    | ((value & 0x1f) << 16);
}

static long
extract_va128 (unsigned long insn,
        int dialect ATTRIBUTE_UNUSED,
        int *invalid ATTRIBUTE_UNUSED)
{
  return ((insn >> 4) & 0x40) | (insn & 0x20) | ((insn >> 16) & 0x1f);
}

/* The VB128 field in an VX128 form instruction.  This is split.  */

static unsigned long
insert_vb128 (unsigned long insn,
       long value,
       int dialect ATTRIBUTE_UNUSED,
       const char **errmsg ATTRIBUTE_UNUSED)
{
  return insn | ((value & 0x60) >> 5) | ((value & 0x1f) << 11);
}

static long
extract_vb128 (unsigned long insn,
        int dialect ATTRIBUTE_UNUSED,
        int *invalid ATTRIBUTE_UNUSED)
{
  return ((insn << 5) & 0x60) | ((insn >> 11) & 0x1f);
}

/* The VPERM field in an VX128 form instruction.  This is split.  */

static unsigned long
insert_vperm (unsigned long insn,
       long value,
       int dialect ATTRIBUTE_UNUSED,
       const char **errmsg ATTRIBUTE_UNUSED)
{
  return insn | ((value & 0xe0) << 1) | ((value & 0x1f) << 16);
}

static long
extract_vperm (unsigned long insn,
        int dialect ATTRIBUTE_UNUSED,
        int *invalid ATTRIBUTE_UNUSED)
{
  return ((insn >> 1) & 0xe0) | ((insn >> 16) & 0x1f);
}


/* Macros used to form opcodes.  */

/* The main opcode.  */
#define OP(x) ((((unsigned long)(x)) & 0x3f) << 26)
#define OP_MASK OP (0x3f)

/* The main opcode combined with a trap code in the TO field of a D
   form instruction.  Used for extended mnemonics for the trap
   instructions.  */
#define OPTO(x,to) (OP (x) | ((((unsigned long)(to)) & 0x1f) << 21))
#define OPTO_MASK (OP_MASK | TO_MASK)

   /* The main opcode combined with a comparison size bit in the L field
      of a D form or X form instruction.  Used for extended mnemonics for
      the comparison instructions.  */
#define OPL(x,l) (OP (x) | ((((unsigned long)(l)) & 1) << 21))
#define OPL_MASK OPL (0x3f,1)

      /* An A form instruction.  */
#define A(op, xop, rc) (OP (op) | ((((unsigned long)(xop)) & 0x1f) << 1) | (((unsigned long)(rc)) & 1))
#define A_MASK A (0x3f, 0x1f, 1)

/* An A_MASK with the FRB field fixed.  */
#define AFRB_MASK (A_MASK | FRB_MASK)

/* An A_MASK with the FRC field fixed.  */
#define AFRC_MASK (A_MASK | FRC_MASK)

/* An A_MASK with the FRA and FRC fields fixed.  */
#define AFRAFRC_MASK (A_MASK | FRA_MASK | FRC_MASK)

/* An AFRAFRC_MASK, but with L bit clear.  */
#define AFRALFRC_MASK (AFRAFRC_MASK & ~((unsigned long) 1 << 16))

/* A B form instruction.  */
#define B(op, aa, lk) (OP (op) | ((((unsigned long)(aa)) & 1) << 1) | ((lk) & 1))
#define B_MASK B (0x3f, 1, 1)

/* A B form instruction setting the BO field.  */
#define BBO(op, bo, aa, lk) (B ((op), (aa), (lk)) | ((((unsigned long)(bo)) & 0x1f) << 21))
#define BBO_MASK BBO (0x3f, 0x1f, 1, 1)

/* A BBO_MASK with the y bit of the BO field removed.  This permits
   matching a conditional branch regardless of the setting of the y
   bit.  Similarly for the 'at' bits used for power4 branch hints.  */
#define Y_MASK   (((unsigned long) 1) << 21)
#define AT1_MASK (((unsigned long) 3) << 21)
#define AT2_MASK (((unsigned long) 9) << 21)
#define BBOY_MASK  (BBO_MASK &~ Y_MASK)
#define BBOAT_MASK (BBO_MASK &~ AT1_MASK)

   /* A B form instruction setting the BO field and the condition bits of
      the BI field.  */
#define BBOCB(op, bo, cb, aa, lk) \
  (BBO ((op), (bo), (aa), (lk)) | ((((unsigned long)(cb)) & 0x3) << 16))
#define BBOCB_MASK BBOCB (0x3f, 0x1f, 0x3, 1, 1)

      /* A BBOCB_MASK with the y bit of the BO field removed.  */
#define BBOYCB_MASK (BBOCB_MASK &~ Y_MASK)
#define BBOATCB_MASK (BBOCB_MASK &~ AT1_MASK)
#define BBOAT2CB_MASK (BBOCB_MASK &~ AT2_MASK)

/* A BBOYCB_MASK in which the BI field is fixed.  */
#define BBOYBI_MASK (BBOYCB_MASK | BI_MASK)
#define BBOATBI_MASK (BBOAT2CB_MASK | BI_MASK)

/* An Context form instruction.  */
#define CTX(op, xop)   (OP (op) | (((unsigned long)(xop)) & 0x7))
#define CTX_MASK CTX(0x3f, 0x7)

/* An User Context form instruction.  */
#define UCTX(op, xop)  (OP (op) | (((unsigned long)(xop)) & 0x1f))
#define UCTX_MASK UCTX(0x3f, 0x1f)

/* The main opcode mask with the RA field clear.  */
#define DRA_MASK (OP_MASK | RA_MASK)

/* A DS form instruction.  */
#define DSO(op, xop) (OP (op) | ((xop) & 0x3))
#define DS_MASK DSO (0x3f, 3)

/* A DE form instruction.  */
#define DEO(op, xop) (OP (op) | ((xop) & 0xf))
#define DE_MASK DEO (0x3e, 0xf)

/* An EVSEL form instruction.  */
#define EVSEL(op, xop) (OP (op) | (((unsigned long)(xop)) & 0xff) << 3)
#define EVSEL_MASK EVSEL(0x3f, 0xff)

/* An M form instruction.  */
#define M(op, rc) (OP (op) | ((rc) & 1))
#define M_MASK M (0x3f, 1)

/* An M form instruction with the ME field specified.  */
#define MME(op, me, rc) (M ((op), (rc)) | ((((unsigned long)(me)) & 0x1f) << 1))

/* An M_MASK with the MB and ME fields fixed.  */
#define MMBME_MASK (M_MASK | MB_MASK | ME_MASK)

/* An M_MASK with the SH and ME fields fixed.  */
#define MSHME_MASK (M_MASK | SH_MASK | ME_MASK)

/* An MD form instruction.  */
#define MD(op, xop, rc) (OP (op) | ((((unsigned long)(xop)) & 0x7) << 2) | ((rc) & 1))
#define MD_MASK MD (0x3f, 0x7, 1)

/* An MD_MASK with the MB field fixed.  */
#define MDMB_MASK (MD_MASK | MB6_MASK)

/* An MD_MASK with the SH field fixed.  */
#define MDSH_MASK (MD_MASK | SH6_MASK)

/* An MDS form instruction.  */
#define MDS(op, xop, rc) (OP (op) | ((((unsigned long)(xop)) & 0xf) << 1) | ((rc) & 1))
#define MDS_MASK MDS (0x3f, 0xf, 1)

/* An MDS_MASK with the MB field fixed.  */
#define MDSMB_MASK (MDS_MASK | MB6_MASK)

/* An SC form instruction.  */
#define SC(op, sa, lk) (OP (op) | ((((unsigned long)(sa)) & 1) << 1) | ((lk) & 1))
#define SC_MASK (OP_MASK | (((unsigned long)0x3ff) << 16) | (((unsigned long)1) << 1) | 1)

/* An VX form instruction.  */
#define VX(op, xop) (OP (op) | (((unsigned long)(xop)) & 0x7ff))

/* The mask for an VX form instruction.  */
#define VX_MASK	VX(0x3f, 0x7ff)

/* An VA form instruction.  */
#define VXA(op, xop) (OP (op) | (((unsigned long)(xop)) & 0x03f))

/* The mask for an VA form instruction.  */
#define VXA_MASK VXA(0x3f, 0x3f)

/* An VXR form instruction.  */
#define VXR(op, xop, rc) (OP (op) | (((rc) & 1) << 10) | (((unsigned long)(xop)) & 0x3ff))

/* The mask for a VXR form instruction.  */
#define VXR_MASK VXR(0x3f, 0x3ff, 1)

/* An VX128 form instruction. */
#define VX128(op, xop) (OP(op) | (((unsigned long)(xop)) & 0x3d0))

/* The mask for an VX form instruction. */
#define VX128_MASK	VX(0x3f, 0x3d0)

/* An VX128 form instruction. */
#define VX128_1(op, xop) (OP(op) | (((unsigned long)(xop)) & 0x7f3))

/* The mask for an VX form instruction. */
#define VX128_1_MASK	VX(0x3f, 0x7f3)

/* An VX128 form instruction. */
#define VX128_2(op, xop) (OP(op) | (((unsigned long)(xop)) & 0x210))

/* The mask for an VX form instruction. */
#define VX128_2_MASK	VX(0x3f, 0x210)

/* An VX128 form instruction. */
#define VX128_3(op, xop) (OP(op) | (((unsigned long)(xop)) & 0x7f0))

/* The mask for an VX form instruction. */
#define VX128_3_MASK	VX(0x3f, 0x7f0)

#define VX128_P(op, xop) (OP(op) | (((unsigned long)(xop)) & 0x630))
#define VX128_P_MASK	VX(0x3f, 0x630)

#define VX128_4(op, xop) (OP(op) | (((unsigned long)(xop)) & 0x730))
#define VX128_4_MASK	VX(0x3f, 0x730)

#define VX128_5(op, xop) (OP(op) | (((unsigned long)(xop)) & 0x10))
#define VX128_5_MASK	VX(0x3f, 0x10)

/* An X form instruction.  */
#define X(op, xop) (OP (op) | ((((unsigned long)(xop)) & 0x3ff) << 1))

/* A Z form instruction.  */
#define Z(op, xop) (OP (op) | ((((unsigned long)(xop)) & 0x1ff) << 1))

/* An X form instruction with the RC bit specified.  */
#define XRC(op, xop, rc) (X ((op), (xop)) | ((rc) & 1))

/* A Z form instruction with the RC bit specified.  */
#define ZRC(op, xop, rc) (Z ((op), (xop)) | ((rc) & 1))

/* The mask for an X form instruction.  */
#define X_MASK XRC (0x3f, 0x3ff, 1)

/* The mask for a Z form instruction.  */
#define Z_MASK ZRC (0x3f, 0x1ff, 1)
#define Z2_MASK ZRC (0x3f, 0xff, 1)

/* An X_MASK with the RA field fixed.  */
#define XRA_MASK (X_MASK | RA_MASK)

/* An XRA_MASK with the W field clear.  */
#define XWRA_MASK (XRA_MASK & ~((unsigned long) 1 << 16))

/* An X_MASK with the RB field fixed.  */
#define XRB_MASK (X_MASK | RB_MASK)

/* An X_MASK with the RT field fixed.  */
#define XRT_MASK (X_MASK | RT_MASK)

/* An XRT_MASK mask with the L bits clear.  */
#define XLRT_MASK (XRT_MASK & ~((unsigned long) 0x3 << 21))

/* An X_MASK with the RA and RB fields fixed.  */
#define XRARB_MASK (X_MASK | RA_MASK | RB_MASK)

/* An XRARB_MASK, but with the L bit clear.  */
#define XRLARB_MASK (XRARB_MASK & ~((unsigned long) 1 << 16))

/* An X_MASK with the RT and RA fields fixed.  */
#define XRTRA_MASK (X_MASK | RT_MASK | RA_MASK)

/* An XRTRA_MASK, but with L bit clear.  */
#define XRTLRA_MASK (XRTRA_MASK & ~((unsigned long) 1 << 21))

/* An X form instruction with the L bit specified.  */
#define XOPL(op, xop, l) (X ((op), (xop)) | ((((unsigned long)(l)) & 1) << 21))

/* The mask for an X form comparison instruction.  */
#define XCMP_MASK (X_MASK | (((unsigned long)1) << 22))

/* The mask for an X form comparison instruction with the L field
   fixed.  */
#define XCMPL_MASK (XCMP_MASK | (((unsigned long)1) << 21))

   /* An X form trap instruction with the TO field specified.  */
#define XTO(op, xop, to) (X ((op), (xop)) | ((((unsigned long)(to)) & 0x1f) << 21))
#define XTO_MASK (X_MASK | TO_MASK)

/* An X form tlb instruction with the SH field specified.  */
#define XTLB(op, xop, sh) (X ((op), (xop)) | ((((unsigned long)(sh)) & 0x1f) << 11))
#define XTLB_MASK (X_MASK | SH_MASK)

/* An X form sync instruction.  */
#define XSYNC(op, xop, l) (X ((op), (xop)) | ((((unsigned long)(l)) & 3) << 21))

/* An X form sync instruction with everything filled in except the LS field.  */
#define XSYNC_MASK (0xff9fffff)

/* An X_MASK, but with the EH bit clear.  */
#define XEH_MASK (X_MASK & ~((unsigned long )1))

/* An X form AltiVec dss instruction.  */
#define XDSS(op, xop, a) (X ((op), (xop)) | ((((unsigned long)(a)) & 1) << 25))
#define XDSS_MASK XDSS(0x3f, 0x3ff, 1)

/* An XFL form instruction.  */
#define XFL(op, xop, rc) (OP (op) | ((((unsigned long)(xop)) & 0x3ff) << 1) | (((unsigned long)(rc)) & 1))
#define XFL_MASK XFL (0x3f, 0x3ff, 1)

/* An X form isel instruction.  */
#define XISEL(op, xop)  (OP (op) | ((((unsigned long)(xop)) & 0x1f) << 1))
#define XISEL_MASK      XISEL(0x3f, 0x1f)

/* An XL form instruction with the LK field set to 0.  */
#define XL(op, xop) (OP (op) | ((((unsigned long)(xop)) & 0x3ff) << 1))

/* An XL form instruction which uses the LK field.  */
#define XLLK(op, xop, lk) (XL ((op), (xop)) | ((lk) & 1))

/* The mask for an XL form instruction.  */
#define XL_MASK XLLK (0x3f, 0x3ff, 1)

/* An XL form instruction which explicitly sets the BO field.  */
#define XLO(op, bo, xop, lk) \
  (XLLK ((op), (xop), (lk)) | ((((unsigned long)(bo)) & 0x1f) << 21))
#define XLO_MASK (XL_MASK | BO_MASK)

/* An XL form instruction which explicitly sets the y bit of the BO
   field.  */
#define XLYLK(op, xop, y, lk) (XLLK ((op), (xop), (lk)) | ((((unsigned long)(y)) & 1) << 21))
#define XLYLK_MASK (XL_MASK | Y_MASK)

   /* An XL form instruction which sets the BO field and the condition
      bits of the BI field.  */
#define XLOCB(op, bo, cb, xop, lk) \
  (XLO ((op), (bo), (xop), (lk)) | ((((unsigned long)(cb)) & 3) << 16))
#define XLOCB_MASK XLOCB (0x3f, 0x1f, 0x3, 0x3ff, 1)

      /* An XL_MASK or XLYLK_MASK or XLOCB_MASK with the BB field fixed.  */
#define XLBB_MASK (XL_MASK | BB_MASK)
#define XLYBB_MASK (XLYLK_MASK | BB_MASK)
#define XLBOCBBB_MASK (XLOCB_MASK | BB_MASK)

/* A mask for branch instructions using the BH field.  */
#define XLBH_MASK (XL_MASK | (0x1c << 11))

/* An XL_MASK with the BO and BB fields fixed.  */
#define XLBOBB_MASK (XL_MASK | BO_MASK | BB_MASK)

/* An XL_MASK with the BO, BI and BB fields fixed.  */
#define XLBOBIBB_MASK (XL_MASK | BO_MASK | BI_MASK | BB_MASK)

/* An XO form instruction.  */
#define XO(op, xop, oe, rc) \
  (OP (op) | ((((unsigned long)(xop)) & 0x1ff) << 1) | ((((unsigned long)(oe)) & 1) << 10) | (((unsigned long)(rc)) & 1))
#define XO_MASK XO (0x3f, 0x1ff, 1, 1)

/* An XO_MASK with the RB field fixed.  */
#define XORB_MASK (XO_MASK | RB_MASK)

/* An XS form instruction.  */
#define XS(op, xop, rc) (OP (op) | ((((unsigned long)(xop)) & 0x1ff) << 2) | (((unsigned long)(rc)) & 1))
#define XS_MASK XS (0x3f, 0x1ff, 1)

/* A mask for the FXM version of an XFX form instruction.  */
#define XFXFXM_MASK (X_MASK | (1 << 11) | (1 << 20))

/* An XFX form instruction with the FXM field filled in.  */
#define XFXM(op, xop, fxm, p4) \
  (X ((op), (xop)) | ((((unsigned long)(fxm)) & 0xff) << 12) \
   | ((unsigned long)(p4) << 20))

/* An XFX form instruction with the SPR field filled in.  */
#define XSPR(op, xop, spr) \
  (X ((op), (xop)) | ((((unsigned long)(spr)) & 0x1f) << 16) | ((((unsigned long)(spr)) & 0x3e0) << 6))
#define XSPR_MASK (X_MASK | SPR_MASK)

/* An XFX form instruction with the SPR field filled in except for the
   SPRBAT field.  */
#define XSPRBAT_MASK (XSPR_MASK &~ SPRBAT_MASK)

   /* An XFX form instruction with the SPR field filled in except for the
      SPRG field.  */
#define XSPRG_MASK (XSPR_MASK & ~(0x1f << 16))

      /* An X form instruction with everything filled in except the E field.  */
#define XE_MASK (0xffff7fff)

/* An X form user context instruction.  */
#define XUC(op, xop)  (OP (op) | (((unsigned long)(xop)) & 0x1f))
#define XUC_MASK      XUC(0x3f, 0x1f)

/* The BO encodings used in extended conditional branch mnemonics.  */
#define BODNZF	(0x0)
#define BODNZFP	(0x1)
#define BODZF	(0x2)
#define BODZFP	(0x3)
#define BODNZT	(0x8)
#define BODNZTP	(0x9)
#define BODZT	(0xa)
#define BODZTP	(0xb)

#define BOF	(0x4)
#define BOFP	(0x5)
#define BOFM4	(0x6)
#define BOFP4	(0x7)
#define BOT	(0xc)
#define BOTP	(0xd)
#define BOTM4	(0xe)
#define BOTP4	(0xf)

#define BODNZ	(0x10)
#define BODNZP	(0x11)
#define BODZ	(0x12)
#define BODZP	(0x13)
#define BODNZM4 (0x18)
#define BODNZP4 (0x19)
#define BODZM4	(0x1a)
#define BODZP4	(0x1b)

#define BOU	(0x14)

/* The BI condition bit encodings used in extended conditional branch
   mnemonics.  */
#define CBLT	(0)
#define CBGT	(1)
#define CBEQ	(2)
#define CBSO	(3)

   /* The TO encodings used in extended trap mnemonics.  */
#define TOLGT	(0x1)
#define TOLLT	(0x2)
#define TOEQ	(0x4)
#define TOLGE	(0x5)
#define TOLNL	(0x5)
#define TOLLE	(0x6)
#define TOLNG	(0x6)
#define TOGT	(0x8)
#define TOGE	(0xc)
#define TONL	(0xc)
#define TOLT	(0x10)
#define TOLE	(0x14)
#define TONG	(0x14)
#define TONE	(0x18)
#define TOU	(0x1f)

/* Smaller names for the flags so each entry in the opcodes table will
   fit on a single line.  */
#undef	PPC
#define PPC     PPC_OPCODE_PPC
#define PPCCOM	PPC_OPCODE_PPC | PPC_OPCODE_COMMON
#define NOPOWER4 PPC_OPCODE_NOPOWER4 | PPCCOM
#define POWER4	PPC_OPCODE_POWER4
#define POWER5	PPC_OPCODE_POWER5
#define POWER6	PPC_OPCODE_POWER6
#define CELL	PPC_OPCODE_CELL
#define PPC32   PPC_OPCODE_32 | PPC_OPCODE_PPC
#define PPC64   PPC_OPCODE_64 | PPC_OPCODE_PPC
#define PPC403	PPC_OPCODE_403
#define PPC405	PPC403
#define PPC440	PPC_OPCODE_440
#define PPC750	PPC
#define PPC860	PPC
#define PPCVEC	PPC_OPCODE_ALTIVEC
#define PPCVEC128 PPC_OPCODE_VMX_128
#define	POWER   PPC_OPCODE_POWER
#define	POWER2	PPC_OPCODE_POWER | PPC_OPCODE_POWER2
#define PPCPWR2	PPC_OPCODE_PPC | PPC_OPCODE_POWER | PPC_OPCODE_POWER2
#define	POWER32	PPC_OPCODE_POWER | PPC_OPCODE_32
#define	COM     PPC_OPCODE_POWER | PPC_OPCODE_PPC | PPC_OPCODE_COMMON
#define	COM32   PPC_OPCODE_POWER | PPC_OPCODE_PPC | PPC_OPCODE_COMMON | PPC_OPCODE_32
#define	M601    PPC_OPCODE_POWER | PPC_OPCODE_601
#define PWRCOM	PPC_OPCODE_POWER | PPC_OPCODE_601 | PPC_OPCODE_COMMON
#define	MFDEC1	PPC_OPCODE_POWER
#define	MFDEC2	PPC_OPCODE_PPC | PPC_OPCODE_601 | PPC_OPCODE_BOOKE
#define BOOKE	PPC_OPCODE_BOOKE
#define BOOKE64	PPC_OPCODE_BOOKE64
#define CLASSIC	PPC_OPCODE_CLASSIC
#define PPCE300 PPC_OPCODE_E300
#define PPCSPE	PPC_OPCODE_SPE
#define PPCISEL	PPC_OPCODE_ISEL
#define PPCEFS	PPC_OPCODE_EFS
#define PPCBRLK	PPC_OPCODE_BRLOCK
#define PPCPMR	PPC_OPCODE_PMR
#define PPCCHLK	PPC_OPCODE_CACHELCK
#define PPCCHLK64	PPC_OPCODE_CACHELCK | PPC_OPCODE_BOOKE64
#define PPCRFMCI	PPC_OPCODE_RFMCI

   /* The opcode table.

      The format of the opcode table is:

      NAME	     OPCODE	MASK		FLAGS		{ OPERANDS }

      NAME is the name of the instruction.
      OPCODE is the instruction opcode.
      MASK is the opcode mask; this is used to tell the disassembler
        which bits in the actual opcode must match OPCODE.
      FLAGS are flags indicated what processors support the instruction.
      OPERANDS is the list of operands.

      The disassembler reads the table in order and prints the first
      instruction which matches, so this table is sorted to put more
      specific instructions before more general instructions.  It is also
      sorted by major opcode.  */

const struct powerpc_opcode powerpc_opcodes[] = {
{ "attn",    X(0,256), X_MASK,		POWER4,		{ 0 }, PPC_INST_ATTN },
{ "tdlgti",  OPTO(2,TOLGT), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDLGTI },
{ "tdllti",  OPTO(2,TOLLT), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDLLTI },
{ "tdeqi",   OPTO(2,TOEQ), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDEQI },
{ "tdlgei",  OPTO(2,TOLGE), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDLGEI },
{ "tdlnli",  OPTO(2,TOLNL), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDLNLI },
{ "tdllei",  OPTO(2,TOLLE), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDLLEI },
{ "tdlngi",  OPTO(2,TOLNG), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDLNGI },
{ "tdgti",   OPTO(2,TOGT), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDGTI },
{ "tdgei",   OPTO(2,TOGE), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDGEI },
{ "tdnli",   OPTO(2,TONL), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDNLI },
{ "tdlti",   OPTO(2,TOLT), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDLTI },
{ "tdlei",   OPTO(2,TOLE), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDLEI },
{ "tdngi",   OPTO(2,TONG), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDNGI },
{ "tdnei",   OPTO(2,TONE), OPTO_MASK,	PPC64,		{ RA, SI }, PPC_INST_TDNEI },
{ "tdi",     OP(2),	OP_MASK,	PPC64,		{ TO, RA, SI }, PPC_INST_TDI },

{ "twlgti",  OPTO(3,TOLGT), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWLGTI },
{ "tlgti",   OPTO(3,TOLGT), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TLGTI },
{ "twllti",  OPTO(3,TOLLT), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWLLTI },
{ "tllti",   OPTO(3,TOLLT), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TLLTI },
{ "tweqi",   OPTO(3,TOEQ), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWEQI },
{ "teqi",    OPTO(3,TOEQ), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TEQI },
{ "twlgei",  OPTO(3,TOLGE), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWLGEI },
{ "tlgei",   OPTO(3,TOLGE), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TLGEI },
{ "twlnli",  OPTO(3,TOLNL), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWLNLI },
{ "tlnli",   OPTO(3,TOLNL), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TLNLI },
{ "twllei",  OPTO(3,TOLLE), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWLLEI },
{ "tllei",   OPTO(3,TOLLE), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TLLEI },
{ "twlngi",  OPTO(3,TOLNG), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWLNGI },
{ "tlngi",   OPTO(3,TOLNG), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TLNGI },
{ "twgti",   OPTO(3,TOGT), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWGTI },
{ "tgti",    OPTO(3,TOGT), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TGTI },
{ "twgei",   OPTO(3,TOGE), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWGEI },
{ "tgei",    OPTO(3,TOGE), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TGEI },
{ "twnli",   OPTO(3,TONL), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWNLI },
{ "tnli",    OPTO(3,TONL), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TNLI },
{ "twlti",   OPTO(3,TOLT), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWLTI },
{ "tlti",    OPTO(3,TOLT), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TLTI },
{ "twlei",   OPTO(3,TOLE), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWLEI },
{ "tlei",    OPTO(3,TOLE), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TLEI },
{ "twngi",   OPTO(3,TONG), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWNGI },
{ "tngi",    OPTO(3,TONG), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TNGI },
{ "twnei",   OPTO(3,TONE), OPTO_MASK,	PPCCOM,		{ RA, SI }, PPC_INST_TWNEI },
{ "tnei",    OPTO(3,TONE), OPTO_MASK,	PWRCOM,		{ RA, SI }, PPC_INST_TNEI },
{ "twi",     OP(3),	OP_MASK,	PPCCOM,		{ TO, RA, SI }, PPC_INST_TWI },
{ "ti",      OP(3),	OP_MASK,	PWRCOM,		{ TO, RA, SI }, PPC_INST_TI },

{ "macchw",	XO(4,172,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHW },
{ "macchw.",	XO(4,172,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHW },
{ "macchwo",	XO(4,172,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWO },
{ "macchwo.",	XO(4,172,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWO },
{ "macchws",	XO(4,236,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWS },
{ "macchws.",	XO(4,236,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWS },
{ "macchwso",	XO(4,236,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWSO },
{ "macchwso.",	XO(4,236,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWSO },
{ "macchwsu",	XO(4,204,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWSU },
{ "macchwsu.",	XO(4,204,0,1), XO_MASK, PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWSU },
{ "macchwsuo",	XO(4,204,1,0), XO_MASK, PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWSUO },
{ "macchwsuo.",	XO(4,204,1,1), XO_MASK, PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWSUO },
{ "macchwu",	XO(4,140,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWU },
{ "macchwu.",	XO(4,140,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWU },
{ "macchwuo",	XO(4,140,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWUO },
{ "macchwuo.",	XO(4,140,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACCHWUO },
{ "machhw",	XO(4,44,0,0),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHW },
{ "machhw.",	XO(4,44,0,1),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHW },
{ "machhwo",	XO(4,44,1,0),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWO },
{ "machhwo.",	XO(4,44,1,1),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWO },
{ "machhws",	XO(4,108,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWS },
{ "machhws.",	XO(4,108,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWS },
{ "machhwso",	XO(4,108,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWSO },
{ "machhwso.",	XO(4,108,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWSO },
{ "machhwsu",	XO(4,76,0,0),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWSU },
{ "machhwsu.",	XO(4,76,0,1),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWSU },
{ "machhwsuo",	XO(4,76,1,0),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWSUO },
{ "machhwsuo.",	XO(4,76,1,1),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWSUO },
{ "machhwu",	XO(4,12,0,0),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWU },
{ "machhwu.",	XO(4,12,0,1),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWU },
{ "machhwuo",	XO(4,12,1,0),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWUO },
{ "machhwuo.",	XO(4,12,1,1),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACHHWUO },
{ "maclhw",	XO(4,428,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHW },
{ "maclhw.",	XO(4,428,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHW },
{ "maclhwo",	XO(4,428,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWO },
{ "maclhwo.",	XO(4,428,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWO },
{ "maclhws",	XO(4,492,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWS },
{ "maclhws.",	XO(4,492,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWS },
{ "maclhwso",	XO(4,492,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWSO },
{ "maclhwso.",	XO(4,492,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWSO },
{ "maclhwsu",	XO(4,460,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWSU },
{ "maclhwsu.",	XO(4,460,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWSU },
{ "maclhwsuo",	XO(4,460,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWSUO },
{ "maclhwsuo.",	XO(4,460,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWSUO },
{ "maclhwu",	XO(4,396,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWU },
{ "maclhwu.",	XO(4,396,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWU },
{ "maclhwuo",	XO(4,396,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWUO },
{ "maclhwuo.",	XO(4,396,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MACLHWUO },
{ "mulchw",	XRC(4,168,0),  X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULCHW },
{ "mulchw.",	XRC(4,168,1),  X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULCHW },
//{ "mulchwu",	XRC(4,136,0),  X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULCHWU },
//{ "mulchwu.",	XRC(4,136,1),  X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULCHWU },
//{ "mulhhw",	XRC(4,40,0),   X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULHHW },
//{ "mulhhw.",	XRC(4,40,1),   X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULHHW },
{ "mulhhwu",	XRC(4,8,0),    X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULHHWU },
{ "mulhhwu.",	XRC(4,8,1),    X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULHHWU },
{ "mullhw",	XRC(4,424,0),  X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULLHW },
{ "mullhw.",	XRC(4,424,1),  X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULLHW },
{ "mullhwu",	XRC(4,392,0),  X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULLHWU },
{ "mullhwu.",	XRC(4,392,1),  X_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_MULLHWU },
{ "nmacchw",	XO(4,174,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACCHW },
{ "nmacchw.",	XO(4,174,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACCHW },
{ "nmacchwo",	XO(4,174,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACCHWO },
{ "nmacchwo.",	XO(4,174,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACCHWO },
{ "nmacchws",	XO(4,238,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACCHWS },
{ "nmacchws.",	XO(4,238,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACCHWS },
{ "nmacchwso",	XO(4,238,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACCHWSO },
{ "nmacchwso.",	XO(4,238,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACCHWSO },
{ "nmachhw",	XO(4,46,0,0),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACHHW },
{ "nmachhw.",	XO(4,46,0,1),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACHHW },
{ "nmachhwo",	XO(4,46,1,0),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACHHWO },
{ "nmachhwo.",	XO(4,46,1,1),  XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACHHWO },
{ "nmachhws",	XO(4,110,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACHHWS },
{ "nmachhws.",	XO(4,110,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACHHWS },
{ "nmachhwso",	XO(4,110,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACHHWSO },
{ "nmachhwso.",	XO(4,110,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACHHWSO },
{ "nmaclhw",	XO(4,430,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACLHW },
{ "nmaclhw.",	XO(4,430,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACLHW },
{ "nmaclhwo",	XO(4,430,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACLHWO },
{ "nmaclhwo.",	XO(4,430,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACLHWO },
{ "nmaclhws",	XO(4,494,0,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACLHWS },
{ "nmaclhws.",	XO(4,494,0,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACLHWS },
{ "nmaclhwso",	XO(4,494,1,0), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACLHWSO },
{ "nmaclhwso.",	XO(4,494,1,1), XO_MASK,	PPC405 | PPC440,	{ RT, RA, RB }, PPC_INST_NMACLHWSO },
{ "mfvscr",  VX(4, 1540), VX_MASK,	PPCVEC,		{ VD }, PPC_INST_MFVSCR },
{ "mtvscr",  VX(4, 1604), VX_MASK,	PPCVEC,		{ VB }, PPC_INST_MTVSCR },

/* Double-precision opcodes.  */
/* Some of these conflict with AltiVec, so move them before, since
   PPCVEC includes the PPC_OPCODE_PPC set.  */
{ "efscfd",   VX(4, 719), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCFD },
{ "efdabs",   VX(4, 740), VX_MASK,	PPCEFS,		{ RS, RA }, PPC_INST_EFDABS },
{ "efdnabs",  VX(4, 741), VX_MASK,	PPCEFS,		{ RS, RA }, PPC_INST_EFDNABS },
{ "efdneg",   VX(4, 742), VX_MASK,	PPCEFS,		{ RS, RA }, PPC_INST_EFDNEG },
{ "efdadd",   VX(4, 736), VX_MASK,	PPCEFS,		{ RS, RA, RB }, PPC_INST_EFDADD },
{ "efdsub",   VX(4, 737), VX_MASK,	PPCEFS,		{ RS, RA, RB }, PPC_INST_EFDSUB },
{ "efdmul",   VX(4, 744), VX_MASK,	PPCEFS,		{ RS, RA, RB }, PPC_INST_EFDMUL },
{ "efddiv",   VX(4, 745), VX_MASK,	PPCEFS,		{ RS, RA, RB }, PPC_INST_EFDDIV },
{ "efdcmpgt", VX(4, 748), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFDCMPGT },
{ "efdcmplt", VX(4, 749), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFDCMPLT },
{ "efdcmpeq", VX(4, 750), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFDCMPEQ },
{ "efdtstgt", VX(4, 764), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFDTSTGT },
{ "efdtstlt", VX(4, 765), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFDTSTLT },
{ "efdtsteq", VX(4, 766), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFDTSTEQ },
{ "efdcfsi",  VX(4, 753), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCFSI },
{ "efdcfsid", VX(4, 739), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCFSID },
{ "efdcfui",  VX(4, 752), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCFUI },
{ "efdcfuid", VX(4, 738), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCFUID },
{ "efdcfsf",  VX(4, 755), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCFSF },
{ "efdcfuf",  VX(4, 754), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCFUF },
{ "efdctsi",  VX(4, 757), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCTSI },
{ "efdctsidz",VX(4, 747), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCTSIDZ },
{ "efdctsiz", VX(4, 762), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCTSIZ },
{ "efdctui",  VX(4, 756), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCTUI },
{ "efdctuidz",VX(4, 746), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCTUIDZ },
{ "efdctuiz", VX(4, 760), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCTUIZ },
{ "efdctsf",  VX(4, 759), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCTSF },
{ "efdctuf",  VX(4, 758), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCTUF },
{ "efdcfs",   VX(4, 751), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFDCFS },
/* End of double-precision opcodes.  */

{ "vaddcuw", VX(4,  384), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDCUW },
{ "vaddfp",  VX(4,   10), VX_MASK, 	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDFP },
{ "vaddsbs", VX(4,  768), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDSBS },
{ "vaddshs", VX(4,  832), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDSHS },
{ "vaddsws", VX(4,  896), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDSWS },
{ "vaddubm", VX(4,    0), VX_MASK, 	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDUBM },
{ "vaddubs", VX(4,  512), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDUBS },
{ "vadduhm", VX(4,   64), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDUHM },
{ "vadduhs", VX(4,  576), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDUHS },
{ "vadduwm", VX(4,  128), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDUWM },
{ "vadduws", VX(4,  640), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VADDUWS },
{ "vand",    VX(4, 1028), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VAND },
{ "vandc",   VX(4, 1092), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VANDC },
{ "vavgsb",  VX(4, 1282), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VAVGSB },
{ "vavgsh",  VX(4, 1346), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VAVGSH },
{ "vavgsw",  VX(4, 1410), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VAVGSW },
{ "vavgub",  VX(4, 1026), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VAVGUB },
{ "vavguh",  VX(4, 1090), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VAVGUH },
{ "vavguw",  VX(4, 1154), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VAVGUW },
{ "vcfsx",   VX(4,  842), VX_MASK,	PPCVEC,		{ VD, VB, UIMM }, PPC_INST_VCFSX },
{ "vcfux",   VX(4,  778), VX_MASK,	PPCVEC,		{ VD, VB, UIMM }, PPC_INST_VCFUX },
{ "vcmpbfp",   VXR(4, 966, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPBFP },
{ "vcmpbfp.",  VXR(4, 966, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPBFP },
{ "vcmpeqfp",  VXR(4, 198, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPEQFP },
{ "vcmpeqfp.", VXR(4, 198, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPEQFP },
{ "vcmpequb",  VXR(4,   6, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPEQUB },
{ "vcmpequb.", VXR(4,   6, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPEQUB },
{ "vcmpequh",  VXR(4,  70, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPEQUH },
{ "vcmpequh.", VXR(4,  70, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPEQUH },
{ "vcmpequw",  VXR(4, 134, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPEQUW },
{ "vcmpequw.", VXR(4, 134, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPEQUW },
{ "vcmpgefp",  VXR(4, 454, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGEFP },
{ "vcmpgefp.", VXR(4, 454, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGEFP },
{ "vcmpgtfp",  VXR(4, 710, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTFP },
{ "vcmpgtfp.", VXR(4, 710, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTFP },
{ "vcmpgtsb",  VXR(4, 774, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTSB },
{ "vcmpgtsb.", VXR(4, 774, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTSB },
{ "vcmpgtsh",  VXR(4, 838, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTSH },
{ "vcmpgtsh.", VXR(4, 838, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTSH },
{ "vcmpgtsw",  VXR(4, 902, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTSW },
{ "vcmpgtsw.", VXR(4, 902, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTSW },
{ "vcmpgtub",  VXR(4, 518, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTUB },
{ "vcmpgtub.", VXR(4, 518, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTUB },
{ "vcmpgtuh",  VXR(4, 582, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTUH },
{ "vcmpgtuh.", VXR(4, 582, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTUH },
{ "vcmpgtuw",  VXR(4, 646, 0), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTUW },
{ "vcmpgtuw.", VXR(4, 646, 1), VXR_MASK, PPCVEC,	{ VD, VA, VB }, PPC_INST_VCMPGTUW },
{ "vctsxs",    VX(4,  970), VX_MASK,	PPCVEC,		{ VD, VB, UIMM }, PPC_INST_VCTSXS },
{ "vctuxs",    VX(4,  906), VX_MASK,	PPCVEC,		{ VD, VB, UIMM }, PPC_INST_VCTUXS },
{ "vexptefp",  VX(4,  394), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VEXPTEFP },
{ "vlogefp",   VX(4,  458), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VLOGEFP },
{ "vmaddfp",   VXA(4,  46), VXA_MASK,	PPCVEC,		{ VD, VA, VC, VB }, PPC_INST_VMADDFP },
{ "vmaxfp",    VX(4, 1034), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMAXFP },
{ "vmaxsb",    VX(4,  258), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMAXSB },
{ "vmaxsh",    VX(4,  322), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMAXSH },
{ "vmaxsw",    VX(4,  386), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMAXSW },
{ "vmaxub",    VX(4,    2), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMAXUB },
{ "vmaxuh",    VX(4,   66), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMAXUH },
{ "vmaxuw",    VX(4,  130), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMAXUW },
{ "vmhaddshs", VXA(4,  32), VXA_MASK,	PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VMHADDSHS },
{ "vmhraddshs", VXA(4, 33), VXA_MASK,	PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VMHRADDSHS },
{ "vminfp",    VX(4, 1098), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMINFP },
{ "vminsb",    VX(4,  770), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMINSB },
{ "vminsh",    VX(4,  834), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMINSH },
{ "vminsw",    VX(4,  898), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMINSW },
{ "vminub",    VX(4,  514), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMINUB },
{ "vminuh",    VX(4,  578), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMINUH },
{ "vminuw",    VX(4,  642), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMINUW },
{ "vmladduhm", VXA(4,  34), VXA_MASK,	PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VMLADDUHM },
{ "vmrghb",    VX(4,   12), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMRGHB },
{ "vmrghh",    VX(4,   76), VX_MASK,    PPCVEC,		{ VD, VA, VB }, PPC_INST_VMRGHH },
{ "vmrghw",    VX(4,  140), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMRGHW },
{ "vmrglb",    VX(4,  268), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMRGLB },
{ "vmrglh",    VX(4,  332), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMRGLH },
{ "vmrglw",    VX(4,  396), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMRGLW },
{ "vmsummbm",  VXA(4,  37), VXA_MASK,	PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VMSUMMBM },
{ "vmsumshm",  VXA(4,  40), VXA_MASK,	PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VMSUMSHM },
{ "vmsumshs",  VXA(4,  41), VXA_MASK,	PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VMSUMSHS },
{ "vmsumubm",  VXA(4,  36), VXA_MASK,   PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VMSUMUBM },
{ "vmsumuhm",  VXA(4,  38), VXA_MASK,   PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VMSUMUHM },
{ "vmsumuhs",  VXA(4,  39), VXA_MASK,   PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VMSUMUHS },
{ "vmulesb",   VX(4,  776), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMULESB },
{ "vmulesh",   VX(4,  840), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMULESH },
{ "vmuleub",   VX(4,  520), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMULEUB },
{ "vmuleuh",   VX(4,  584), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMULEUH },
{ "vmulosb",   VX(4,  264), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMULOSB },
{ "vmulosh",   VX(4,  328), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMULOSH },
{ "vmuloub",   VX(4,    8), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMULOUB },
{ "vmulouh",   VX(4,   72), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VMULOUH },
{ "vnmsubfp",  VXA(4,  47), VXA_MASK,	PPCVEC,		{ VD, VA, VC, VB }, PPC_INST_VNMSUBFP },
{ "vnor",      VX(4, 1284), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VNOR },
{ "vor",       VX(4, 1156), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VOR },
{ "vperm",     VXA(4,  43), VXA_MASK,	PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VPERM },
{ "vpkpx",     VX(4,  782), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VPKPX },
{ "vpkshss",   VX(4,  398), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VPKSHSS },
{ "vpkshus",   VX(4,  270), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VPKSHUS },
{ "vpkswss",   VX(4,  462), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VPKSWSS },
{ "vpkswus",   VX(4,  334), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VPKSWUS },
{ "vpkuhum",   VX(4,   14), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VPKUHUM },
{ "vpkuhus",   VX(4,  142), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VPKUHUS },
{ "vpkuwum",   VX(4,   78), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VPKUWUM },
{ "vpkuwus",   VX(4,  206), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VPKUWUS },
{ "vrefp",     VX(4,  266), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VREFP },
{ "vrfim",     VX(4,  714), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VRFIM },
{ "vrfin",     VX(4,  522), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VRFIN },
{ "vrfip",     VX(4,  650), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VRFIP },
{ "vrfiz",     VX(4,  586), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VRFIZ },
{ "vrlb",      VX(4,    4), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VRLB },
{ "vrlh",      VX(4,   68), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VRLH },
{ "vrlw",      VX(4,  132), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VRLW },
{ "vrsqrtefp", VX(4,  330), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VRSQRTEFP },
{ "vsel",      VXA(4,  42), VXA_MASK,	PPCVEC,		{ VD, VA, VB, VC }, PPC_INST_VSEL },
{ "vsl",       VX(4,  452), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSL },
{ "vslb",      VX(4,  260), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSLB },
{ "vsldoi",    VXA(4,  44), VXA_MASK,	PPCVEC,		{ VD, VA, VB, SHB }, PPC_INST_VSLDOI },
{ "vslh",      VX(4,  324), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSLH },
{ "vslo",      VX(4, 1036), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSLO },
{ "vslw",      VX(4,  388), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSLW },
{ "vspltb",    VX(4,  524), VX_MASK,	PPCVEC,		{ VD, VB, UIMM }, PPC_INST_VSPLTB },
{ "vsplth",    VX(4,  588), VX_MASK,	PPCVEC,		{ VD, VB, UIMM }, PPC_INST_VSPLTH },
{ "vspltisb",  VX(4,  780), VX_MASK,	PPCVEC,		{ VD, SIMM }, PPC_INST_VSPLTISB },
{ "vspltish",  VX(4,  844), VX_MASK,	PPCVEC,		{ VD, SIMM }, PPC_INST_VSPLTISH },
{ "vspltisw",  VX(4,  908), VX_MASK,	PPCVEC,		{ VD, SIMM }, PPC_INST_VSPLTISW },
{ "vspltw",    VX(4,  652), VX_MASK,	PPCVEC,		{ VD, VB, UIMM }, PPC_INST_VSPLTW },
{ "vsr",       VX(4,  708), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSR },
{ "vsrab",     VX(4,  772), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSRAB },
{ "vsrah",     VX(4,  836), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSRAH },
{ "vsraw",     VX(4,  900), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSRAW },
{ "vsrb",      VX(4,  516), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSRB },
{ "vsrh",      VX(4,  580), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSRH },
{ "vsro",      VX(4, 1100), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSRO },
{ "vsrw",      VX(4,  644), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSRW },
{ "vsubcuw",   VX(4, 1408), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBCUW },
{ "vsubfp",    VX(4,   74), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBFP },
{ "vsubsbs",   VX(4, 1792), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBSBS },
{ "vsubshs",   VX(4, 1856), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBSHS },
{ "vsubsws",   VX(4, 1920), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBSWS },
{ "vsububm",   VX(4, 1024), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBUBM },
{ "vsububs",   VX(4, 1536), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBUBS },
{ "vsubuhm",   VX(4, 1088), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBUHM },
{ "vsubuhs",   VX(4, 1600), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBUHS },
{ "vsubuwm",   VX(4, 1152), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBUWM },
{ "vsubuws",   VX(4, 1664), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUBUWS },
{ "vsumsws",   VX(4, 1928), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUMSWS },
{ "vsum2sws",  VX(4, 1672), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUM2SWS },
{ "vsum4sbs",  VX(4, 1800), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUM4SBS },
{ "vsum4shs",  VX(4, 1608), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUM4SHS },
{ "vsum4ubs",  VX(4, 1544), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VSUM4UBS },
{ "vupkhpx",   VX(4,  846), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VUPKHPX },
{ "vupkhsb",   VX(4,  526), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VUPKHSB },
{ "vupkhsh",   VX(4,  590), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VUPKHSH },
{ "vupklpx",   VX(4,  974), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VUPKLPX },
{ "vupklsb",   VX(4,  654), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VUPKLSB },
{ "vupklsh",   VX(4,  718), VX_MASK,	PPCVEC,		{ VD, VB }, PPC_INST_VUPKLSH },
{ "vxor",      VX(4, 1220), VX_MASK,	PPCVEC,		{ VD, VA, VB }, PPC_INST_VXOR },

{ "vsldoi128", VX128_5(4, 16), VX128_5_MASK, PPCVEC128, { VD128, VA128, VB128, SHB }, PPC_INST_VSLDOI128 },
{ "lvsl128", VX128_1(4, 3), VX128_1_MASK, PPCVEC128, { VD128, RA, RB }, PPC_INST_LVSL128 },
{ "lvsr128", VX128_1(4, 67), VX128_1_MASK, PPCVEC128, { VD128, RA, RB }, PPC_INST_LVSR128 },
{ "lvewx128", VX128_1(4, 131), VX128_1_MASK, PPCVEC128, { VD128, RA, RB }, PPC_INST_LVEWX128 },
{ "lvx128", VX128_1(4, 195), VX128_1_MASK, PPCVEC128, { VD128, RA, RB }, PPC_INST_LVX128 },
{ "stvewx128", VX128_1(4, 387), VX128_1_MASK, PPCVEC128, { VS128, RA, RB }, PPC_INST_STVEWX128 },
{ "stvx128", VX128_1(4, 451), VX128_1_MASK, PPCVEC128, { VS128, RA, RB }, PPC_INST_STVX128 },
{ "lvxl128", VX128_1(4, 707), VX128_1_MASK, PPCVEC128, { VD128, RA, RB }, PPC_INST_LVXL128 },
{ "stvxl128", VX128_1(4, 963), VX128_1_MASK, PPCVEC128, { VS128, RA, RB }, PPC_INST_STVXL128 },
{ "lvlx128", VX128_1(4, 1027), VX128_1_MASK, PPCVEC128, { VD128, RA, RB }, PPC_INST_LVLX128 },
{ "lvrx128", VX128_1(4, 1091), VX128_1_MASK, PPCVEC128, { VD128, RA, RB }, PPC_INST_LVRX128 },
{ "stvlx128", VX128_1(4, 1283), VX128_1_MASK, PPCVEC128, { VS128, RA, RB }, PPC_INST_STVLX128 },
{ "stvrx128", VX128_1(4, 1347), VX128_1_MASK, PPCVEC128, { VS128, RA, RB }, PPC_INST_STVRX128 },
{ "lvlxl128", VX128_1(4, 1539), VX128_1_MASK, PPCVEC128, { VD128, RA, RB }, PPC_INST_LVLXL128 },
{ "lvrxl128", VX128_1(4, 1603), VX128_1_MASK, PPCVEC128, { VD128, RA, RB }, PPC_INST_LVRXL128 },
{ "stvlxl128", VX128_1(4, 1795), VX128_1_MASK, PPCVEC128, { VS128, RA, RB }, PPC_INST_STVLXL128 },
{ "stvrxl128", VX128_1(4, 1859), VX128_1_MASK, PPCVEC128, { VS128, RA, RB }, PPC_INST_STVRXL128 },

{ "vperm128", VX128_2(5, 0), VX128_2_MASK, PPCVEC128, { VD128, VA128, VB128, VC128 }, PPC_INST_VPERM128 },
{ "vaddfp128", VX128(5, 16), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VADDFP128 },
{ "vsubfp128", VX128(5, 80), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VSUBFP128 },
{ "vmulfp128", VX128(5, 144), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VMULFP128 },
{ "vmaddfp128", VX128(5, 208), VX128_MASK, PPCVEC128, { VD128, VA128, VB128, VS128 }, PPC_INST_VMADDFP128 },
{ "vmaddcfp128", VX128(5, 272), VX128_MASK, PPCVEC128, { VD128, VA128, VS128, VB128 }, PPC_INST_VMADDCFP128 },
{ "vnmsubfp128", VX128(5, 336), VX128_MASK, PPCVEC128, { VD128, VA128, VB128, VS128 }, PPC_INST_VNMSUBFP128 },
{ "vmsum3fp128", VX128(5, 400), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VMSUM3FP128 },
{ "vmsum4fp128", VX128(5, 464), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VMSUM4FP128 },
{ "vpkshss128", VX128(5, 512), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VPKSHSS128 },
{ "vand128", VX128(5, 528), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VAND128 },
{ "vpkshus128", VX128(5, 576), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VPKSHUS128 },
{ "vandc128", VX128(5, 592), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VANDC128 },
{ "vpkswss128", VX128(5, 640), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VPKSWSS128 },
{ "vnor128", VX128(5, 656), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VNOR128 },
{ "vpkswus128", VX128(5, 704), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VPKSWUS128 },
{ "vor128", VX128(5, 720), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VOR128 },
{ "vpkuhum128", VX128(5, 768), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VPKUHUM128 },
{ "vxor128", VX128(5, 784), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VXOR128 },
{ "vpkuhus128", VX128(5, 832), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VPKUHUS128 },
{ "vsel128", VX128(5, 848), VX128_MASK, PPCVEC128, { VD128, VA128, VB128, VS128 }, PPC_INST_VSEL128 },
{ "vpkuwum128", VX128(5, 896), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VPKUWUM128 },
{ "vslo128", VX128(5, 912), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VSLO128 },
{ "vpkuwus128", VX128(5, 960), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VPKUWUS128 },
{ "vsro128", VX128(5, 976), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VSRO128 },

{ "vpermwi128", VX128_P(6, 528), VX128_P_MASK, PPCVEC128, { VD128, VB128, VPERM128 }, PPC_INST_VPERMWI128 },
{ "vcfpsxws128", VX128_3(6, 560), VX128_3_MASK, PPCVEC128, { VD128, VB128, UIMM }, PPC_INST_VCFPSXWS128 },
{ "vcfpuxws128", VX128_3(6, 624), VX128_3_MASK, PPCVEC128, { VD128, VB128, UIMM }, PPC_INST_VCFPUXWS128 },
{ "vcsxwfp128", VX128_3(6, 688), VX128_3_MASK, PPCVEC128, { VD128, VB128, UIMM }, PPC_INST_VCSXWFP128 },
{ "vcuxwfp128", VX128_3(6, 752), VX128_3_MASK, PPCVEC128, { VD128, VB128, UIMM }, PPC_INST_VCUXWFP128 },
{ "vrfim128", VX128_3(6, 816), VX128_3_MASK, PPCVEC128, { VD128, VB128 }, PPC_INST_VRFIM128 },
{ "vrfin128", VX128_3(6, 880), VX128_3_MASK, PPCVEC128, { VD128, VB128 }, PPC_INST_VRFIN128 },
{ "vrfip128", VX128_3(6, 944), VX128_3_MASK, PPCVEC128, { VD128, VB128 }, PPC_INST_VRFIP128 },
{ "vrfiz128", VX128_3(6, 1008), VX128_3_MASK, PPCVEC128, { VD128, VB128 }, PPC_INST_VRFIZ128 },
{ "vpkd3d128", VX128_4(6, 1552), VX128_4_MASK, PPCVEC128, { VD128, VB128, VD3D0, VD3D1, VD3D2 }, PPC_INST_VPKD3D128 },
{ "vrefp128", VX128_3(6, 1584), VX128_3_MASK, PPCVEC128, { VD128, VB128 }, PPC_INST_VREFP128 },
{ "vrsqrtefp128", VX128_3(6, 1648), VX128_3_MASK, PPCVEC128, { VD128, VB128 }, PPC_INST_VRSQRTEFP128 },
{ "vexptefp128", VX128_3(6, 1712), VX128_3_MASK, PPCVEC128, { VD128, VB128 }, PPC_INST_VEXPTEFP128 },
{ "vlogefp128", VX128_3(6, 1776), VX128_3_MASK, PPCVEC128, { VD128, VB128 }, PPC_INST_VLOGEFP128 },
{ "vrlimi128", VX128_4(6, 1808), VX128_4_MASK, PPCVEC128, { VD128, VB128, UIMM, VD3D2 }, PPC_INST_VRLIMI128 },
{ "vspltw128", VX128_3(6, 1840), VX128_3_MASK, PPCVEC128, { VD128, VB128, UIMM }, PPC_INST_VSPLTW128 },
{ "vspltisw128", VX128_3(6, 1904), VX128_3_MASK, PPCVEC128, { VD128, SIMM }, PPC_INST_VSPLTISW128 },
{ "vupkd3d128", VX128_3(6, 2032), VX128_3_MASK, PPCVEC128, { VD128, VB128, UIMM }, PPC_INST_VUPKD3D128 },
{ "vcmpeqfp128", VX128(6, 0), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VCMPEQFP128 },
{ "vcmpeqfp128.", VX128(6, 64), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VCMPEQFP128 },
{ "vrlw128", VX128(6, 80), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VRLW128 },
{ "vcmpgefp128", VX128(6, 128), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VCMPGEFP128 },
{ "vcmpgefp128.", VX128(6, 192), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VCMPGEFP128 },
{ "vslw128", VX128(6, 208), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VSLW128 },
{ "vcmpgtfp128", VX128(6, 256), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VCMPGTFP128 },
{ "vcmpgtfp128.", VX128(6, 320), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VCMPGTFP128 },
{ "vsraw128", VX128(6, 336), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VSRAW128 },
{ "vcmpbfp128", VX128(6, 384), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VCMPBFP128 },
{ "vcmpbfp128.", VX128(6, 448), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VCMPBFP128 },
{ "vsrw128", VX128(6, 464), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VSRW128 },
{ "vcmpequw128", VX128(6, 512), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VCMPEQUW128 },
{ "vcmpequw128.", VX128(6, 576), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VCMPEQUW128 },
{ "vmaxfp128", VX128(6, 640), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VMAXFP128 },
{ "vminfp128", VX128(6, 704), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VMINFP128 },
{ "vmrghw128", VX128(6, 768), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VMRGHW128 },
{ "vmrglw128", VX128(6, 832), VX128_MASK, PPCVEC128, { VD128, VA128, VB128 }, PPC_INST_VMRGLW128 },
{ "vupkhsb128", VX128(6, 896), VX128_MASK, PPCVEC128, { VD128, VB128, VA128 }, PPC_INST_VUPKHSB128 },
{ "vupklsb128", VX128(6, 960), VX128_MASK, PPCVEC128, { VD128, VB128, VA128 }, PPC_INST_VUPKLSB128 },
//{ "vupkhsh128", VX128(6, 1952), VX128_MASK, PPCVEC128, { VD128, VB128 }, PPC_INST_VUPKHSH128 },
//{ "vupklsh128", VX128(6, 2016), VX128_MASK, PPCVEC128, { VD128, VB128 }, PPC_INST_VUPKLSH128 },

{ "evaddw",    VX(4, 512), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVADDW },
{ "evaddiw",   VX(4, 514), VX_MASK,	PPCSPE,		{ RS, RB, UIMM }, PPC_INST_EVADDIW },
{ "evsubfw",   VX(4, 516), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSUBFW },
{ "evsubw",    VX(4, 516), VX_MASK,	PPCSPE,		{ RS, RB, RA }, PPC_INST_EVSUBW },
{ "evsubifw",  VX(4, 518), VX_MASK,	PPCSPE,		{ RS, UIMM, RB }, PPC_INST_EVSUBIFW },
{ "evsubiw",   VX(4, 518), VX_MASK,	PPCSPE,		{ RS, RB, UIMM }, PPC_INST_EVSUBIW },
{ "evabs",     VX(4, 520), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVABS },
{ "evneg",     VX(4, 521), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVNEG },
{ "evextsb",   VX(4, 522), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVEXTSB },
{ "evextsh",   VX(4, 523), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVEXTSH },
{ "evrndw",    VX(4, 524), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVRNDW },
{ "evcntlzw",  VX(4, 525), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVCNTLZW },
{ "evcntlsw",  VX(4, 526), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVCNTLSW },

{ "brinc",     VX(4, 527), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_BRINC },

{ "evand",     VX(4, 529), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVAND },
{ "evandc",    VX(4, 530), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVANDC },
{ "evmr",      VX(4, 535), VX_MASK,	PPCSPE,		{ RS, RA, BBA }, PPC_INST_EVMR },
{ "evor",      VX(4, 535), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVOR },
{ "evorc",     VX(4, 539), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVORC },
{ "evxor",     VX(4, 534), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVXOR },
{ "eveqv",     VX(4, 537), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVEQV },
{ "evnand",    VX(4, 542), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVNAND },
{ "evnot",     VX(4, 536), VX_MASK,	PPCSPE,		{ RS, RA, BBA }, PPC_INST_EVNOT },
{ "evnor",     VX(4, 536), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVNOR },

{ "evrlw",     VX(4, 552), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVRLW },
{ "evrlwi",    VX(4, 554), VX_MASK,	PPCSPE,		{ RS, RA, EVUIMM }, PPC_INST_EVRLWI },
{ "evslw",     VX(4, 548), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSLW },
{ "evslwi",    VX(4, 550), VX_MASK,	PPCSPE,		{ RS, RA, EVUIMM }, PPC_INST_EVSLWI },
{ "evsrws",    VX(4, 545), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSRWS },
{ "evsrwu",    VX(4, 544), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSRWU },
{ "evsrwis",   VX(4, 547), VX_MASK,	PPCSPE,		{ RS, RA, EVUIMM }, PPC_INST_EVSRWIS },
{ "evsrwiu",   VX(4, 546), VX_MASK,	PPCSPE,		{ RS, RA, EVUIMM }, PPC_INST_EVSRWIU },
{ "evsplati",  VX(4, 553), VX_MASK,	PPCSPE,		{ RS, SIMM }, PPC_INST_EVSPLATI },
{ "evsplatfi", VX(4, 555), VX_MASK,	PPCSPE,		{ RS, SIMM }, PPC_INST_EVSPLATFI },
{ "evmergehi", VX(4, 556), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMERGEHI },
{ "evmergelo", VX(4, 557), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMERGELO },
{ "evmergehilo",VX(4,558), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMERGEHILO },
{ "evmergelohi",VX(4,559), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMERGELOHI },

{ "evcmpgts",  VX(4, 561), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVCMPGTS },
{ "evcmpgtu",  VX(4, 560), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVCMPGTU },
{ "evcmplts",  VX(4, 563), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVCMPLTS },
{ "evcmpltu",  VX(4, 562), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVCMPLTU },
{ "evcmpeq",   VX(4, 564), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVCMPEQ },
{ "evsel",     EVSEL(4,79),EVSEL_MASK,	PPCSPE,		{ RS, RA, RB, CRFS }, PPC_INST_EVSEL },

{ "evldd",     VX(4, 769), VX_MASK,	PPCSPE,		{ RS, EVUIMM_8, RA }, PPC_INST_EVLDD },
{ "evlddx",    VX(4, 768), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLDDX },
{ "evldw",     VX(4, 771), VX_MASK,	PPCSPE,		{ RS, EVUIMM_8, RA }, PPC_INST_EVLDW },
{ "evldwx",    VX(4, 770), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLDWX },
{ "evldh",     VX(4, 773), VX_MASK,	PPCSPE,		{ RS, EVUIMM_8, RA }, PPC_INST_EVLDH },
{ "evldhx",    VX(4, 772), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLDHX },
{ "evlwhe",    VX(4, 785), VX_MASK,	PPCSPE,		{ RS, EVUIMM_4, RA }, PPC_INST_EVLWHE },
{ "evlwhex",   VX(4, 784), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLWHEX },
{ "evlwhou",   VX(4, 789), VX_MASK,	PPCSPE,		{ RS, EVUIMM_4, RA }, PPC_INST_EVLWHOU },
{ "evlwhoux",  VX(4, 788), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLWHOUX },
{ "evlwhos",   VX(4, 791), VX_MASK,	PPCSPE,		{ RS, EVUIMM_4, RA }, PPC_INST_EVLWHOS },
{ "evlwhosx",  VX(4, 790), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLWHOSX },
{ "evlwwsplat",VX(4, 793), VX_MASK,	PPCSPE,		{ RS, EVUIMM_4, RA }, PPC_INST_EVLWWSPLAT },
{ "evlwwsplatx",VX(4, 792), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLWWSPLATX },
{ "evlwhsplat",VX(4, 797), VX_MASK,	PPCSPE,		{ RS, EVUIMM_4, RA }, PPC_INST_EVLWHSPLAT },
{ "evlwhsplatx",VX(4, 796), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLWHSPLATX },
{ "evlhhesplat",VX(4, 777), VX_MASK,	PPCSPE,		{ RS, EVUIMM_2, RA }, PPC_INST_EVLHHESPLAT },
{ "evlhhesplatx",VX(4, 776), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLHHESPLATX },
{ "evlhhousplat",VX(4, 781), VX_MASK,	PPCSPE,		{ RS, EVUIMM_2, RA }, PPC_INST_EVLHHOUSPLAT },
{ "evlhhousplatx",VX(4, 780), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLHHOUSPLATX },
{ "evlhhossplat",VX(4, 783), VX_MASK,	PPCSPE,		{ RS, EVUIMM_2, RA }, PPC_INST_EVLHHOSSPLAT },
{ "evlhhossplatx",VX(4, 782), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVLHHOSSPLATX },

{ "evstdd",    VX(4, 801), VX_MASK,	PPCSPE,		{ RS, EVUIMM_8, RA }, PPC_INST_EVSTDD },
{ "evstddx",   VX(4, 800), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSTDDX },
{ "evstdw",    VX(4, 803), VX_MASK,	PPCSPE,		{ RS, EVUIMM_8, RA }, PPC_INST_EVSTDW },
{ "evstdwx",   VX(4, 802), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSTDWX },
{ "evstdh",    VX(4, 805), VX_MASK,	PPCSPE,		{ RS, EVUIMM_8, RA }, PPC_INST_EVSTDH },
{ "evstdhx",   VX(4, 804), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSTDHX },
{ "evstwwe",   VX(4, 825), VX_MASK,	PPCSPE,		{ RS, EVUIMM_4, RA }, PPC_INST_EVSTWWE },
{ "evstwwex",  VX(4, 824), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSTWWEX },
{ "evstwwo",   VX(4, 829), VX_MASK,	PPCSPE,		{ RS, EVUIMM_4, RA }, PPC_INST_EVSTWWO },
{ "evstwwox",  VX(4, 828), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSTWWOX },
{ "evstwhe",   VX(4, 817), VX_MASK,	PPCSPE,		{ RS, EVUIMM_4, RA }, PPC_INST_EVSTWHE },
{ "evstwhex",  VX(4, 816), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSTWHEX },
{ "evstwho",   VX(4, 821), VX_MASK,	PPCSPE,		{ RS, EVUIMM_4, RA }, PPC_INST_EVSTWHO },
{ "evstwhox",  VX(4, 820), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVSTWHOX },

{ "evfsabs",   VX(4, 644), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVFSABS },
{ "evfsnabs",  VX(4, 645), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVFSNABS },
{ "evfsneg",   VX(4, 646), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVFSNEG },
{ "evfsadd",   VX(4, 640), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVFSADD },
{ "evfssub",   VX(4, 641), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVFSSUB },
{ "evfsmul",   VX(4, 648), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVFSMUL },
{ "evfsdiv",   VX(4, 649), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVFSDIV },
{ "evfscmpgt", VX(4, 652), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVFSCMPGT },
{ "evfscmplt", VX(4, 653), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVFSCMPLT },
{ "evfscmpeq", VX(4, 654), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVFSCMPEQ },
{ "evfststgt", VX(4, 668), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVFSTSTGT },
{ "evfststlt", VX(4, 669), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVFSTSTLT },
{ "evfststeq", VX(4, 670), VX_MASK,	PPCSPE,		{ CRFD, RA, RB }, PPC_INST_EVFSTSTEQ },
{ "evfscfui",  VX(4, 656), VX_MASK,	PPCSPE,		{ RS, RB }, PPC_INST_EVFSCFUI },
{ "evfsctuiz", VX(4, 664), VX_MASK,	PPCSPE,		{ RS, RB }, PPC_INST_EVFSCTUIZ },
{ "evfscfsi",  VX(4, 657), VX_MASK,	PPCSPE,		{ RS, RB }, PPC_INST_EVFSCFSI },
{ "evfscfuf",  VX(4, 658), VX_MASK,	PPCSPE,		{ RS, RB }, PPC_INST_EVFSCFUF },
{ "evfscfsf",  VX(4, 659), VX_MASK,	PPCSPE,		{ RS, RB }, PPC_INST_EVFSCFSF },
{ "evfsctui",  VX(4, 660), VX_MASK,	PPCSPE,		{ RS, RB }, PPC_INST_EVFSCTUI },
{ "evfsctsi",  VX(4, 661), VX_MASK,	PPCSPE,		{ RS, RB }, PPC_INST_EVFSCTSI },
{ "evfsctsiz", VX(4, 666), VX_MASK,	PPCSPE,		{ RS, RB }, PPC_INST_EVFSCTSIZ },
{ "evfsctuf",  VX(4, 662), VX_MASK,	PPCSPE,		{ RS, RB }, PPC_INST_EVFSCTUF },
{ "evfsctsf",  VX(4, 663), VX_MASK,	PPCSPE,		{ RS, RB }, PPC_INST_EVFSCTSF },

{ "efsabs",   VX(4, 708), VX_MASK,	PPCEFS,		{ RS, RA }, PPC_INST_EFSABS },
{ "efsnabs",  VX(4, 709), VX_MASK,	PPCEFS,		{ RS, RA }, PPC_INST_EFSNABS },
{ "efsneg",   VX(4, 710), VX_MASK,	PPCEFS,		{ RS, RA }, PPC_INST_EFSNEG },
{ "efsadd",   VX(4, 704), VX_MASK,	PPCEFS,		{ RS, RA, RB }, PPC_INST_EFSADD },
{ "efssub",   VX(4, 705), VX_MASK,	PPCEFS,		{ RS, RA, RB }, PPC_INST_EFSSUB },
{ "efsmul",   VX(4, 712), VX_MASK,	PPCEFS,		{ RS, RA, RB }, PPC_INST_EFSMUL },
{ "efsdiv",   VX(4, 713), VX_MASK,	PPCEFS,		{ RS, RA, RB }, PPC_INST_EFSDIV },
{ "efscmpgt", VX(4, 716), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFSCMPGT },
{ "efscmplt", VX(4, 717), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFSCMPLT },
{ "efscmpeq", VX(4, 718), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFSCMPEQ },
{ "efststgt", VX(4, 732), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFSTSTGT },
{ "efststlt", VX(4, 733), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFSTSTLT },
{ "efststeq", VX(4, 734), VX_MASK,	PPCEFS,		{ CRFD, RA, RB }, PPC_INST_EFSTSTEQ },
{ "efscfui",  VX(4, 720), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCFUI },
{ "efsctuiz", VX(4, 728), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCTUIZ },
{ "efscfsi",  VX(4, 721), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCFSI },
{ "efscfuf",  VX(4, 722), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCFUF },
{ "efscfsf",  VX(4, 723), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCFSF },
{ "efsctui",  VX(4, 724), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCTUI },
{ "efsctsi",  VX(4, 725), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCTSI },
{ "efsctsiz", VX(4, 730), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCTSIZ },
{ "efsctuf",  VX(4, 726), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCTUF },
{ "efsctsf",  VX(4, 727), VX_MASK,	PPCEFS,		{ RS, RB }, PPC_INST_EFSCTSF },

{ "evmhossf",  VX(4, 1031), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSSF },
{ "evmhossfa", VX(4, 1063), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSSFA },
{ "evmhosmf",  VX(4, 1039), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSMF },
{ "evmhosmfa", VX(4, 1071), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSMFA },
{ "evmhosmi",  VX(4, 1037), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSMI },
{ "evmhosmia", VX(4, 1069), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSMIA },
{ "evmhoumi",  VX(4, 1036), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOUMI },
{ "evmhoumia", VX(4, 1068), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOUMIA },
{ "evmhessf",  VX(4, 1027), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESSF },
{ "evmhessfa", VX(4, 1059), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESSFA },
{ "evmhesmf",  VX(4, 1035), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESMF },
{ "evmhesmfa", VX(4, 1067), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESMFA },
{ "evmhesmi",  VX(4, 1033), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESMI },
{ "evmhesmia", VX(4, 1065), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESMIA },
{ "evmheumi",  VX(4, 1032), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEUMI },
{ "evmheumia", VX(4, 1064), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEUMIA },

{ "evmhossfaaw",VX(4, 1287), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSSFAAW },
{ "evmhossiaaw",VX(4, 1285), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSSIAAW },
{ "evmhosmfaaw",VX(4, 1295), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSMFAAW },
{ "evmhosmiaaw",VX(4, 1293), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSMIAAW },
{ "evmhousiaaw",VX(4, 1284), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOUSIAAW },
{ "evmhoumiaaw",VX(4, 1292), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOUMIAAW },
{ "evmhessfaaw",VX(4, 1283), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESSFAAW },
{ "evmhessiaaw",VX(4, 1281), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESSIAAW },
{ "evmhesmfaaw",VX(4, 1291), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESMFAAW },
{ "evmhesmiaaw",VX(4, 1289), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESMIAAW },
{ "evmheusiaaw",VX(4, 1280), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEUSIAAW },
{ "evmheumiaaw",VX(4, 1288), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEUMIAAW },

{ "evmhossfanw",VX(4, 1415), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSSFANW },
{ "evmhossianw",VX(4, 1413), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSSIANW },
{ "evmhosmfanw",VX(4, 1423), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSMFANW },
{ "evmhosmianw",VX(4, 1421), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOSMIANW },
{ "evmhousianw",VX(4, 1412), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOUSIANW },
{ "evmhoumianw",VX(4, 1420), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOUMIANW },
{ "evmhessfanw",VX(4, 1411), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESSFANW },
{ "evmhessianw",VX(4, 1409), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESSIANW },
{ "evmhesmfanw",VX(4, 1419), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESMFANW },
{ "evmhesmianw",VX(4, 1417), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHESMIANW },
{ "evmheusianw",VX(4, 1408), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEUSIANW },
{ "evmheumianw",VX(4, 1416), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEUMIANW },

{ "evmhogsmfaa",VX(4, 1327), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOGSMFAA },
{ "evmhogsmiaa",VX(4, 1325), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOGSMIAA },
{ "evmhogumiaa",VX(4, 1324), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOGUMIAA },
{ "evmhegsmfaa",VX(4, 1323), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEGSMFAA },
{ "evmhegsmiaa",VX(4, 1321), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEGSMIAA },
{ "evmhegumiaa",VX(4, 1320), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEGUMIAA },

{ "evmhogsmfan",VX(4, 1455), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOGSMFAN },
{ "evmhogsmian",VX(4, 1453), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOGSMIAN },
{ "evmhogumian",VX(4, 1452), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHOGUMIAN },
{ "evmhegsmfan",VX(4, 1451), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEGSMFAN },
{ "evmhegsmian",VX(4, 1449), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEGSMIAN },
{ "evmhegumian",VX(4, 1448), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMHEGUMIAN },

{ "evmwhssf",  VX(4, 1095), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWHSSF },
{ "evmwhssfa", VX(4, 1127), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWHSSFA },
{ "evmwhsmf",  VX(4, 1103), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWHSMF },
{ "evmwhsmfa", VX(4, 1135), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWHSMFA },
{ "evmwhsmi",  VX(4, 1101), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWHSMI },
{ "evmwhsmia", VX(4, 1133), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWHSMIA },
{ "evmwhumi",  VX(4, 1100), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWHUMI },
{ "evmwhumia", VX(4, 1132), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWHUMIA },

{ "evmwlumi",  VX(4, 1096), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWLUMI },
{ "evmwlumia", VX(4, 1128), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWLUMIA },

{ "evmwlssiaaw",VX(4, 1345), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWLSSIAAW },
{ "evmwlsmiaaw",VX(4, 1353), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWLSMIAAW },
{ "evmwlusiaaw",VX(4, 1344), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWLUSIAAW },
{ "evmwlumiaaw",VX(4, 1352), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWLUMIAAW },

{ "evmwlssianw",VX(4, 1473), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWLSSIANW },
{ "evmwlsmianw",VX(4, 1481), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWLSMIANW },
{ "evmwlusianw",VX(4, 1472), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWLUSIANW },
{ "evmwlumianw",VX(4, 1480), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWLUMIANW },

{ "evmwssf",   VX(4, 1107), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSSF },
{ "evmwssfa",  VX(4, 1139), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSSFA },
{ "evmwsmf",   VX(4, 1115), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSMF },
{ "evmwsmfa",  VX(4, 1147), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSMFA },
{ "evmwsmi",   VX(4, 1113), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSMI },
{ "evmwsmia",  VX(4, 1145), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSMIA },
{ "evmwumi",   VX(4, 1112), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWUMI },
{ "evmwumia",  VX(4, 1144), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWUMIA },

{ "evmwssfaa", VX(4, 1363), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSSFAA },
{ "evmwsmfaa", VX(4, 1371), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSMFAA },
{ "evmwsmiaa", VX(4, 1369), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSMIAA },
{ "evmwumiaa", VX(4, 1368), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWUMIAA },

{ "evmwssfan", VX(4, 1491), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSSFAN },
{ "evmwsmfan", VX(4, 1499), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSMFAN },
{ "evmwsmian", VX(4, 1497), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWSMIAN },
{ "evmwumian", VX(4, 1496), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVMWUMIAN },

{ "evaddssiaaw",VX(4, 1217), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVADDSSIAAW },
{ "evaddsmiaaw",VX(4, 1225), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVADDSMIAAW },
{ "evaddusiaaw",VX(4, 1216), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVADDUSIAAW },
{ "evaddumiaaw",VX(4, 1224), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVADDUMIAAW },

{ "evsubfssiaaw",VX(4, 1219), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVSUBFSSIAAW },
{ "evsubfsmiaaw",VX(4, 1227), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVSUBFSMIAAW },
{ "evsubfusiaaw",VX(4, 1218), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVSUBFUSIAAW },
{ "evsubfumiaaw",VX(4, 1226), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVSUBFUMIAAW },

{ "evmra",    VX(4, 1220), VX_MASK,	PPCSPE,		{ RS, RA }, PPC_INST_EVMRA },

{ "evdivws",  VX(4, 1222), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVDIVWS },
{ "evdivwu",  VX(4, 1223), VX_MASK,	PPCSPE,		{ RS, RA, RB }, PPC_INST_EVDIVWU },

{ "mulli",   OP(7),	OP_MASK,	PPCCOM,		{ RT, RA, SI }, PPC_INST_MULLI },
{ "muli",    OP(7),	OP_MASK,	PWRCOM,		{ RT, RA, SI }, PPC_INST_MULI },

{ "subfic",  OP(8),	OP_MASK,	PPCCOM,		{ RT, RA, SI }, PPC_INST_SUBFIC },
{ "sfi",     OP(8),	OP_MASK,	PWRCOM,		{ RT, RA, SI }, PPC_INST_SFI },

{ "dozi",    OP(9),	OP_MASK,	M601,		{ RT, RA, SI }, PPC_INST_DOZI },

{ "bce",     B(9,0,0),	B_MASK,		BOOKE64,	{ BO, BI, BD }, PPC_INST_BCE },
{ "bcel",    B(9,0,1),	B_MASK,		BOOKE64,	{ BO, BI, BD }, PPC_INST_BCEL },
{ "bcea",    B(9,1,0),	B_MASK,		BOOKE64,	{ BO, BI, BDA }, PPC_INST_BCEA },
{ "bcela",   B(9,1,1),	B_MASK,		BOOKE64,	{ BO, BI, BDA }, PPC_INST_BCELA },

{ "cmplwi",  OPL(10,0),	OPL_MASK,	PPCCOM,		{ OBF, RA, UI }, PPC_INST_CMPLWI },
{ "cmpldi",  OPL(10,1), OPL_MASK,	PPC64,		{ OBF, RA, UI }, PPC_INST_CMPLDI },
{ "cmpli",   OP(10),	OP_MASK,	PPC,		{ BF, L, RA, UI }, PPC_INST_CMPLI },
{ "cmpli",   OP(10),	OP_MASK,	PWRCOM,		{ BF, RA, UI }, PPC_INST_CMPLI },

{ "cmpwi",   OPL(11,0),	OPL_MASK,	PPCCOM,		{ OBF, RA, SI }, PPC_INST_CMPWI },
{ "cmpdi",   OPL(11,1),	OPL_MASK,	PPC64,		{ OBF, RA, SI }, PPC_INST_CMPDI },
{ "cmpi",    OP(11),	OP_MASK,	PPC,		{ BF, L, RA, SI }, PPC_INST_CMPI },
{ "cmpi",    OP(11),	OP_MASK,	PWRCOM,		{ BF, RA, SI }, PPC_INST_CMPI },

{ "addic",   OP(12),	OP_MASK,	PPCCOM,		{ RT, RA, SI }, PPC_INST_ADDIC },
{ "ai",	     OP(12),	OP_MASK,	PWRCOM,		{ RT, RA, SI }, PPC_INST_AI },
{ "subic",   OP(12),	OP_MASK,	PPCCOM,		{ RT, RA, NSI }, PPC_INST_SUBIC },

{ "addic.",  OP(13),	OP_MASK,	PPCCOM,		{ RT, RA, SI }, PPC_INST_ADDIC },
{ "ai.",     OP(13),	OP_MASK,	PWRCOM,		{ RT, RA, SI }, PPC_INST_AI },
{ "subic.",  OP(13),	OP_MASK,	PPCCOM,		{ RT, RA, NSI }, PPC_INST_SUBIC },

{ "li",	     OP(14),	DRA_MASK,	PPCCOM,		{ RT, SI }, PPC_INST_LI },
{ "lil",     OP(14),	DRA_MASK,	PWRCOM,		{ RT, SI }, PPC_INST_LIL },
{ "addi",    OP(14),	OP_MASK,	PPCCOM,		{ RT, RA0, SI }, PPC_INST_ADDI },
{ "cal",     OP(14),	OP_MASK,	PWRCOM,		{ RT, D, RA0 }, PPC_INST_CAL },
{ "subi",    OP(14),	OP_MASK,	PPCCOM,		{ RT, RA0, NSI }, PPC_INST_SUBI },
{ "la",	     OP(14),	OP_MASK,	PPCCOM,		{ RT, D, RA0 }, PPC_INST_LA },

{ "lis",     OP(15),	DRA_MASK,	PPCCOM,		{ RT, SISIGNOPT }, PPC_INST_LIS },
{ "liu",     OP(15),	DRA_MASK,	PWRCOM,		{ RT, SISIGNOPT }, PPC_INST_LIU },
{ "addis",   OP(15),	OP_MASK,	PPCCOM,		{ RT,RA0,SISIGNOPT }, PPC_INST_ADDIS },
{ "cau",     OP(15),	OP_MASK,	PWRCOM,		{ RT,RA0,SISIGNOPT }, PPC_INST_CAU },
{ "subis",   OP(15),	OP_MASK,	PPCCOM,		{ RT, RA0, NSI }, PPC_INST_SUBIS },

{ "bdnz-",   BBO(16,BODNZ,0,0),      BBOATBI_MASK, PPCCOM,	{ BDM }, PPC_INST_BDNZ },
{ "bdnz+",   BBO(16,BODNZ,0,0),      BBOATBI_MASK, PPCCOM,	{ BDP }, PPC_INST_BDNZ },
{ "bdnz",    BBO(16,BODNZ,0,0),      BBOATBI_MASK, PPCCOM,	{ BD }, PPC_INST_BDNZ },
{ "bdn",     BBO(16,BODNZ,0,0),      BBOATBI_MASK, PWRCOM,	{ BD }, PPC_INST_BDN },
{ "bdnzl-",  BBO(16,BODNZ,0,1),      BBOATBI_MASK, PPCCOM,	{ BDM }, PPC_INST_BDNZL },
{ "bdnzl+",  BBO(16,BODNZ,0,1),      BBOATBI_MASK, PPCCOM,	{ BDP }, PPC_INST_BDNZL },
{ "bdnzl",   BBO(16,BODNZ,0,1),      BBOATBI_MASK, PPCCOM,	{ BD }, PPC_INST_BDNZL },
{ "bdnl",    BBO(16,BODNZ,0,1),      BBOATBI_MASK, PWRCOM,	{ BD }, PPC_INST_BDNL },
{ "bdnza-",  BBO(16,BODNZ,1,0),      BBOATBI_MASK, PPCCOM,	{ BDMA }, PPC_INST_BDNZA },
{ "bdnza+",  BBO(16,BODNZ,1,0),      BBOATBI_MASK, PPCCOM,	{ BDPA }, PPC_INST_BDNZA },
{ "bdnza",   BBO(16,BODNZ,1,0),      BBOATBI_MASK, PPCCOM,	{ BDA }, PPC_INST_BDNZA },
{ "bdna",    BBO(16,BODNZ,1,0),      BBOATBI_MASK, PWRCOM,	{ BDA }, PPC_INST_BDNA },
{ "bdnzla-", BBO(16,BODNZ,1,1),      BBOATBI_MASK, PPCCOM,	{ BDMA }, PPC_INST_BDNZLA },
{ "bdnzla+", BBO(16,BODNZ,1,1),      BBOATBI_MASK, PPCCOM,	{ BDPA }, PPC_INST_BDNZLA },
{ "bdnzla",  BBO(16,BODNZ,1,1),      BBOATBI_MASK, PPCCOM,	{ BDA }, PPC_INST_BDNZLA },
{ "bdnla",   BBO(16,BODNZ,1,1),      BBOATBI_MASK, PWRCOM,	{ BDA }, PPC_INST_BDNLA },
{ "bdz-",    BBO(16,BODZ,0,0),       BBOATBI_MASK, PPCCOM,	{ BDM }, PPC_INST_BDZ },
{ "bdz+",    BBO(16,BODZ,0,0),       BBOATBI_MASK, PPCCOM,	{ BDP }, PPC_INST_BDZ },
{ "bdz",     BBO(16,BODZ,0,0),       BBOATBI_MASK, COM,		{ BD }, PPC_INST_BDZ },
{ "bdzl-",   BBO(16,BODZ,0,1),       BBOATBI_MASK, PPCCOM,	{ BDM }, PPC_INST_BDZL },
{ "bdzl+",   BBO(16,BODZ,0,1),       BBOATBI_MASK, PPCCOM,	{ BDP }, PPC_INST_BDZL },
{ "bdzl",    BBO(16,BODZ,0,1),       BBOATBI_MASK, COM,		{ BD }, PPC_INST_BDZL },
{ "bdza-",   BBO(16,BODZ,1,0),       BBOATBI_MASK, PPCCOM,	{ BDMA }, PPC_INST_BDZA },
{ "bdza+",   BBO(16,BODZ,1,0),       BBOATBI_MASK, PPCCOM,	{ BDPA }, PPC_INST_BDZA },
{ "bdza",    BBO(16,BODZ,1,0),       BBOATBI_MASK, COM,		{ BDA }, PPC_INST_BDZA },
{ "bdzla-",  BBO(16,BODZ,1,1),       BBOATBI_MASK, PPCCOM,	{ BDMA }, PPC_INST_BDZLA },
{ "bdzla+",  BBO(16,BODZ,1,1),       BBOATBI_MASK, PPCCOM,	{ BDPA }, PPC_INST_BDZLA },
{ "bdzla",   BBO(16,BODZ,1,1),       BBOATBI_MASK, COM,		{ BDA }, PPC_INST_BDZLA },
{ "blt-",    BBOCB(16,BOT,CBLT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BLT },
{ "blt+",    BBOCB(16,BOT,CBLT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BLT },
{ "blt",     BBOCB(16,BOT,CBLT,0,0), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BLT },
{ "bltl-",   BBOCB(16,BOT,CBLT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BLTL },
{ "bltl+",   BBOCB(16,BOT,CBLT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BLTL },
{ "bltl",    BBOCB(16,BOT,CBLT,0,1), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BLTL },
{ "blta-",   BBOCB(16,BOT,CBLT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BLTA },
{ "blta+",   BBOCB(16,BOT,CBLT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BLTA },
{ "blta",    BBOCB(16,BOT,CBLT,1,0), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BLTA },
{ "bltla-",  BBOCB(16,BOT,CBLT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BLTLA },
{ "bltla+",  BBOCB(16,BOT,CBLT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BLTLA },
{ "bltla",   BBOCB(16,BOT,CBLT,1,1), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BLTLA },
{ "bgt-",    BBOCB(16,BOT,CBGT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BGT },
{ "bgt+",    BBOCB(16,BOT,CBGT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BGT },
{ "bgt",     BBOCB(16,BOT,CBGT,0,0), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BGT },
{ "bgtl-",   BBOCB(16,BOT,CBGT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BGTL },
{ "bgtl+",   BBOCB(16,BOT,CBGT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BGTL },
{ "bgtl",    BBOCB(16,BOT,CBGT,0,1), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BGTL },
{ "bgta-",   BBOCB(16,BOT,CBGT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BGTA },
{ "bgta+",   BBOCB(16,BOT,CBGT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BGTA },
{ "bgta",    BBOCB(16,BOT,CBGT,1,0), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BGTA },
{ "bgtla-",  BBOCB(16,BOT,CBGT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BGTLA },
{ "bgtla+",  BBOCB(16,BOT,CBGT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BGTLA },
{ "bgtla",   BBOCB(16,BOT,CBGT,1,1), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BGTLA },
{ "beq-",    BBOCB(16,BOT,CBEQ,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BEQ },
{ "beq+",    BBOCB(16,BOT,CBEQ,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BEQ },
{ "beq",     BBOCB(16,BOT,CBEQ,0,0), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BEQ },
{ "beql-",   BBOCB(16,BOT,CBEQ,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BEQL },
{ "beql+",   BBOCB(16,BOT,CBEQ,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BEQL },
{ "beql",    BBOCB(16,BOT,CBEQ,0,1), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BEQL },
{ "beqa-",   BBOCB(16,BOT,CBEQ,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BEQA },
{ "beqa+",   BBOCB(16,BOT,CBEQ,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BEQA },
{ "beqa",    BBOCB(16,BOT,CBEQ,1,0), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BEQA },
{ "beqla-",  BBOCB(16,BOT,CBEQ,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BEQLA },
{ "beqla+",  BBOCB(16,BOT,CBEQ,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BEQLA },
{ "beqla",   BBOCB(16,BOT,CBEQ,1,1), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BEQLA },
{ "bso-",    BBOCB(16,BOT,CBSO,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BSO },
{ "bso+",    BBOCB(16,BOT,CBSO,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BSO },
{ "bso",     BBOCB(16,BOT,CBSO,0,0), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BSO },
{ "bsol-",   BBOCB(16,BOT,CBSO,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BSOL },
{ "bsol+",   BBOCB(16,BOT,CBSO,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BSOL },
{ "bsol",    BBOCB(16,BOT,CBSO,0,1), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BSOL },
{ "bsoa-",   BBOCB(16,BOT,CBSO,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BSOA },
{ "bsoa+",   BBOCB(16,BOT,CBSO,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BSOA },
{ "bsoa",    BBOCB(16,BOT,CBSO,1,0), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BSOA },
{ "bsola-",  BBOCB(16,BOT,CBSO,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BSOLA },
{ "bsola+",  BBOCB(16,BOT,CBSO,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BSOLA },
{ "bsola",   BBOCB(16,BOT,CBSO,1,1), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BSOLA },
{ "bun-",    BBOCB(16,BOT,CBSO,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BUN },
{ "bun+",    BBOCB(16,BOT,CBSO,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BUN },
{ "bun",     BBOCB(16,BOT,CBSO,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BD }, PPC_INST_BUN },
{ "bunl-",   BBOCB(16,BOT,CBSO,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BUNL },
{ "bunl+",   BBOCB(16,BOT,CBSO,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BUNL },
{ "bunl",    BBOCB(16,BOT,CBSO,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BD }, PPC_INST_BUNL },
{ "buna-",   BBOCB(16,BOT,CBSO,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BUNA },
{ "buna+",   BBOCB(16,BOT,CBSO,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BUNA },
{ "buna",    BBOCB(16,BOT,CBSO,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDA }, PPC_INST_BUNA },
{ "bunla-",  BBOCB(16,BOT,CBSO,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BUNLA },
{ "bunla+",  BBOCB(16,BOT,CBSO,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BUNLA },
{ "bunla",   BBOCB(16,BOT,CBSO,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDA }, PPC_INST_BUNLA },
{ "bge-",    BBOCB(16,BOF,CBLT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BGE },
{ "bge+",    BBOCB(16,BOF,CBLT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BGE },
{ "bge",     BBOCB(16,BOF,CBLT,0,0), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BGE },
{ "bgel-",   BBOCB(16,BOF,CBLT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BGEL },
{ "bgel+",   BBOCB(16,BOF,CBLT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BGEL },
{ "bgel",    BBOCB(16,BOF,CBLT,0,1), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BGEL },
{ "bgea-",   BBOCB(16,BOF,CBLT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BGEA },
{ "bgea+",   BBOCB(16,BOF,CBLT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BGEA },
{ "bgea",    BBOCB(16,BOF,CBLT,1,0), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BGEA },
{ "bgela-",  BBOCB(16,BOF,CBLT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BGELA },
{ "bgela+",  BBOCB(16,BOF,CBLT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BGELA },
{ "bgela",   BBOCB(16,BOF,CBLT,1,1), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BGELA },
{ "bnl-",    BBOCB(16,BOF,CBLT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BNL },
{ "bnl+",    BBOCB(16,BOF,CBLT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BNL },
{ "bnl",     BBOCB(16,BOF,CBLT,0,0), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BNL },
{ "bnll-",   BBOCB(16,BOF,CBLT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BNLL },
{ "bnll+",   BBOCB(16,BOF,CBLT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BNLL },
{ "bnll",    BBOCB(16,BOF,CBLT,0,1), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BNLL },
{ "bnla-",   BBOCB(16,BOF,CBLT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BNLA },
{ "bnla+",   BBOCB(16,BOF,CBLT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BNLA },
{ "bnla",    BBOCB(16,BOF,CBLT,1,0), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BNLA },
{ "bnlla-",  BBOCB(16,BOF,CBLT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BNLLA },
{ "bnlla+",  BBOCB(16,BOF,CBLT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BNLLA },
{ "bnlla",   BBOCB(16,BOF,CBLT,1,1), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BNLLA },
{ "ble-",    BBOCB(16,BOF,CBGT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BLE },
{ "ble+",    BBOCB(16,BOF,CBGT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BLE },
{ "ble",     BBOCB(16,BOF,CBGT,0,0), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BLE },
{ "blel-",   BBOCB(16,BOF,CBGT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BLEL },
{ "blel+",   BBOCB(16,BOF,CBGT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BLEL },
{ "blel",    BBOCB(16,BOF,CBGT,0,1), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BLEL },
{ "blea-",   BBOCB(16,BOF,CBGT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BLEA },
{ "blea+",   BBOCB(16,BOF,CBGT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BLEA },
{ "blea",    BBOCB(16,BOF,CBGT,1,0), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BLEA },
{ "blela-",  BBOCB(16,BOF,CBGT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BLELA },
{ "blela+",  BBOCB(16,BOF,CBGT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BLELA },
{ "blela",   BBOCB(16,BOF,CBGT,1,1), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BLELA },
{ "bng-",    BBOCB(16,BOF,CBGT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BNG },
{ "bng+",    BBOCB(16,BOF,CBGT,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BNG },
{ "bng",     BBOCB(16,BOF,CBGT,0,0), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BNG },
{ "bngl-",   BBOCB(16,BOF,CBGT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BNGL },
{ "bngl+",   BBOCB(16,BOF,CBGT,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BNGL },
{ "bngl",    BBOCB(16,BOF,CBGT,0,1), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BNGL },
{ "bnga-",   BBOCB(16,BOF,CBGT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BNGA },
{ "bnga+",   BBOCB(16,BOF,CBGT,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BNGA },
{ "bnga",    BBOCB(16,BOF,CBGT,1,0), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BNGA },
{ "bngla-",  BBOCB(16,BOF,CBGT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BNGLA },
{ "bngla+",  BBOCB(16,BOF,CBGT,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BNGLA },
{ "bngla",   BBOCB(16,BOF,CBGT,1,1), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BNGLA },
{ "bne-",    BBOCB(16,BOF,CBEQ,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BNE },
{ "bne+",    BBOCB(16,BOF,CBEQ,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BNE },
{ "bne",     BBOCB(16,BOF,CBEQ,0,0), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BNE },
{ "bnel-",   BBOCB(16,BOF,CBEQ,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BNEL },
{ "bnel+",   BBOCB(16,BOF,CBEQ,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BNEL },
{ "bnel",    BBOCB(16,BOF,CBEQ,0,1), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BNEL },
{ "bnea-",   BBOCB(16,BOF,CBEQ,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BNEA },
{ "bnea+",   BBOCB(16,BOF,CBEQ,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BNEA },
{ "bnea",    BBOCB(16,BOF,CBEQ,1,0), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BNEA },
{ "bnela-",  BBOCB(16,BOF,CBEQ,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BNELA },
{ "bnela+",  BBOCB(16,BOF,CBEQ,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BNELA },
{ "bnela",   BBOCB(16,BOF,CBEQ,1,1), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BNELA },
{ "bns-",    BBOCB(16,BOF,CBSO,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BNS },
{ "bns+",    BBOCB(16,BOF,CBSO,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BNS },
{ "bns",     BBOCB(16,BOF,CBSO,0,0), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BNS },
{ "bnsl-",   BBOCB(16,BOF,CBSO,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BNSL },
{ "bnsl+",   BBOCB(16,BOF,CBSO,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BNSL },
{ "bnsl",    BBOCB(16,BOF,CBSO,0,1), BBOATCB_MASK, COM,		{ CR, BD }, PPC_INST_BNSL },
{ "bnsa-",   BBOCB(16,BOF,CBSO,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BNSA },
{ "bnsa+",   BBOCB(16,BOF,CBSO,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BNSA },
{ "bnsa",    BBOCB(16,BOF,CBSO,1,0), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BNSA },
{ "bnsla-",  BBOCB(16,BOF,CBSO,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BNSLA },
{ "bnsla+",  BBOCB(16,BOF,CBSO,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BNSLA },
{ "bnsla",   BBOCB(16,BOF,CBSO,1,1), BBOATCB_MASK, COM,		{ CR, BDA }, PPC_INST_BNSLA },
{ "bnu-",    BBOCB(16,BOF,CBSO,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BNU },
{ "bnu+",    BBOCB(16,BOF,CBSO,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BNU },
{ "bnu",     BBOCB(16,BOF,CBSO,0,0), BBOATCB_MASK, PPCCOM,	{ CR, BD }, PPC_INST_BNU },
{ "bnul-",   BBOCB(16,BOF,CBSO,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDM }, PPC_INST_BNUL },
{ "bnul+",   BBOCB(16,BOF,CBSO,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BDP }, PPC_INST_BNUL },
{ "bnul",    BBOCB(16,BOF,CBSO,0,1), BBOATCB_MASK, PPCCOM,	{ CR, BD }, PPC_INST_BNUL },
{ "bnua-",   BBOCB(16,BOF,CBSO,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BNUA },
{ "bnua+",   BBOCB(16,BOF,CBSO,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BNUA },
{ "bnua",    BBOCB(16,BOF,CBSO,1,0), BBOATCB_MASK, PPCCOM,	{ CR, BDA }, PPC_INST_BNUA },
{ "bnula-",  BBOCB(16,BOF,CBSO,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDMA }, PPC_INST_BNULA },
{ "bnula+",  BBOCB(16,BOF,CBSO,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDPA }, PPC_INST_BNULA },
{ "bnula",   BBOCB(16,BOF,CBSO,1,1), BBOATCB_MASK, PPCCOM,	{ CR, BDA }, PPC_INST_BNULA },
{ "bdnzt-",  BBO(16,BODNZT,0,0), BBOY_MASK, NOPOWER4,	{ BI, BDM }, PPC_INST_BDNZT },
{ "bdnzt+",  BBO(16,BODNZT,0,0), BBOY_MASK, NOPOWER4,	{ BI, BDP }, PPC_INST_BDNZT },
{ "bdnzt",   BBO(16,BODNZT,0,0), BBOY_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BDNZT },
{ "bdnztl-", BBO(16,BODNZT,0,1), BBOY_MASK, NOPOWER4,	{ BI, BDM }, PPC_INST_BDNZTL },
{ "bdnztl+", BBO(16,BODNZT,0,1), BBOY_MASK, NOPOWER4,	{ BI, BDP }, PPC_INST_BDNZTL },
{ "bdnztl",  BBO(16,BODNZT,0,1), BBOY_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BDNZTL },
{ "bdnzta-", BBO(16,BODNZT,1,0), BBOY_MASK, NOPOWER4,	{ BI, BDMA }, PPC_INST_BDNZTA },
{ "bdnzta+", BBO(16,BODNZT,1,0), BBOY_MASK, NOPOWER4,	{ BI, BDPA }, PPC_INST_BDNZTA },
{ "bdnzta",  BBO(16,BODNZT,1,0), BBOY_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BDNZTA },
{ "bdnztla-",BBO(16,BODNZT,1,1), BBOY_MASK, NOPOWER4,	{ BI, BDMA }, PPC_INST_BDNZTLA },
{ "bdnztla+",BBO(16,BODNZT,1,1), BBOY_MASK, NOPOWER4,	{ BI, BDPA }, PPC_INST_BDNZTLA },
{ "bdnztla", BBO(16,BODNZT,1,1), BBOY_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BDNZTLA },
{ "bdnzf-",  BBO(16,BODNZF,0,0), BBOY_MASK, NOPOWER4,	{ BI, BDM }, PPC_INST_BDNZF },
{ "bdnzf+",  BBO(16,BODNZF,0,0), BBOY_MASK, NOPOWER4,	{ BI, BDP }, PPC_INST_BDNZF },
{ "bdnzf",   BBO(16,BODNZF,0,0), BBOY_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BDNZF },
{ "bdnzfl-", BBO(16,BODNZF,0,1), BBOY_MASK, NOPOWER4,	{ BI, BDM }, PPC_INST_BDNZFL },
{ "bdnzfl+", BBO(16,BODNZF,0,1), BBOY_MASK, NOPOWER4,	{ BI, BDP }, PPC_INST_BDNZFL },
{ "bdnzfl",  BBO(16,BODNZF,0,1), BBOY_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BDNZFL },
{ "bdnzfa-", BBO(16,BODNZF,1,0), BBOY_MASK, NOPOWER4,	{ BI, BDMA }, PPC_INST_BDNZFA },
{ "bdnzfa+", BBO(16,BODNZF,1,0), BBOY_MASK, NOPOWER4,	{ BI, BDPA }, PPC_INST_BDNZFA },
{ "bdnzfa",  BBO(16,BODNZF,1,0), BBOY_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BDNZFA },
{ "bdnzfla-",BBO(16,BODNZF,1,1), BBOY_MASK, NOPOWER4,	{ BI, BDMA }, PPC_INST_BDNZFLA },
{ "bdnzfla+",BBO(16,BODNZF,1,1), BBOY_MASK, NOPOWER4,	{ BI, BDPA }, PPC_INST_BDNZFLA },
{ "bdnzfla", BBO(16,BODNZF,1,1), BBOY_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BDNZFLA },
{ "bt-",     BBO(16,BOT,0,0), BBOAT_MASK, PPCCOM,	{ BI, BDM }, PPC_INST_BT },
{ "bt+",     BBO(16,BOT,0,0), BBOAT_MASK, PPCCOM,	{ BI, BDP }, PPC_INST_BT },
{ "bt",	     BBO(16,BOT,0,0), BBOAT_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BT },
{ "bbt",     BBO(16,BOT,0,0), BBOAT_MASK, PWRCOM,	{ BI, BD }, PPC_INST_BBT },
{ "btl-",    BBO(16,BOT,0,1), BBOAT_MASK, PPCCOM,	{ BI, BDM }, PPC_INST_BTL },
{ "btl+",    BBO(16,BOT,0,1), BBOAT_MASK, PPCCOM,	{ BI, BDP }, PPC_INST_BTL },
{ "btl",     BBO(16,BOT,0,1), BBOAT_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BTL },
{ "bbtl",    BBO(16,BOT,0,1), BBOAT_MASK, PWRCOM,	{ BI, BD }, PPC_INST_BBTL },
{ "bta-",    BBO(16,BOT,1,0), BBOAT_MASK, PPCCOM,	{ BI, BDMA }, PPC_INST_BTA },
{ "bta+",    BBO(16,BOT,1,0), BBOAT_MASK, PPCCOM,	{ BI, BDPA }, PPC_INST_BTA },
{ "bta",     BBO(16,BOT,1,0), BBOAT_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BTA },
{ "bbta",    BBO(16,BOT,1,0), BBOAT_MASK, PWRCOM,	{ BI, BDA }, PPC_INST_BBTA },
{ "btla-",   BBO(16,BOT,1,1), BBOAT_MASK, PPCCOM,	{ BI, BDMA }, PPC_INST_BTLA },
{ "btla+",   BBO(16,BOT,1,1), BBOAT_MASK, PPCCOM,	{ BI, BDPA }, PPC_INST_BTLA },
{ "btla",    BBO(16,BOT,1,1), BBOAT_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BTLA },
{ "bbtla",   BBO(16,BOT,1,1), BBOAT_MASK, PWRCOM,	{ BI, BDA }, PPC_INST_BBTLA },
{ "bf-",     BBO(16,BOF,0,0), BBOAT_MASK, PPCCOM,	{ BI, BDM }, PPC_INST_BF },
{ "bf+",     BBO(16,BOF,0,0), BBOAT_MASK, PPCCOM,	{ BI, BDP }, PPC_INST_BF },
{ "bf",	     BBO(16,BOF,0,0), BBOAT_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BF },
{ "bbf",     BBO(16,BOF,0,0), BBOAT_MASK, PWRCOM,	{ BI, BD }, PPC_INST_BBF },
{ "bfl-",    BBO(16,BOF,0,1), BBOAT_MASK, PPCCOM,	{ BI, BDM }, PPC_INST_BFL },
{ "bfl+",    BBO(16,BOF,0,1), BBOAT_MASK, PPCCOM,	{ BI, BDP }, PPC_INST_BFL },
{ "bfl",     BBO(16,BOF,0,1), BBOAT_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BFL },
{ "bbfl",    BBO(16,BOF,0,1), BBOAT_MASK, PWRCOM,	{ BI, BD }, PPC_INST_BBFL },
{ "bfa-",    BBO(16,BOF,1,0), BBOAT_MASK, PPCCOM,	{ BI, BDMA }, PPC_INST_BFA },
{ "bfa+",    BBO(16,BOF,1,0), BBOAT_MASK, PPCCOM,	{ BI, BDPA }, PPC_INST_BFA },
{ "bfa",     BBO(16,BOF,1,0), BBOAT_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BFA },
{ "bbfa",    BBO(16,BOF,1,0), BBOAT_MASK, PWRCOM,	{ BI, BDA }, PPC_INST_BBFA },
{ "bfla-",   BBO(16,BOF,1,1), BBOAT_MASK, PPCCOM,	{ BI, BDMA }, PPC_INST_BFLA },
{ "bfla+",   BBO(16,BOF,1,1), BBOAT_MASK, PPCCOM,	{ BI, BDPA }, PPC_INST_BFLA },
{ "bfla",    BBO(16,BOF,1,1), BBOAT_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BFLA },
{ "bbfla",   BBO(16,BOF,1,1), BBOAT_MASK, PWRCOM,	{ BI, BDA }, PPC_INST_BBFLA },
{ "bdzt-",   BBO(16,BODZT,0,0), BBOY_MASK, NOPOWER4,	{ BI, BDM }, PPC_INST_BDZT },
{ "bdzt+",   BBO(16,BODZT,0,0), BBOY_MASK, NOPOWER4,	{ BI, BDP }, PPC_INST_BDZT },
{ "bdzt",    BBO(16,BODZT,0,0), BBOY_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BDZT },
{ "bdztl-",  BBO(16,BODZT,0,1), BBOY_MASK, NOPOWER4,	{ BI, BDM }, PPC_INST_BDZTL },
{ "bdztl+",  BBO(16,BODZT,0,1), BBOY_MASK, NOPOWER4,	{ BI, BDP }, PPC_INST_BDZTL },
{ "bdztl",   BBO(16,BODZT,0,1), BBOY_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BDZTL },
{ "bdzta-",  BBO(16,BODZT,1,0), BBOY_MASK, NOPOWER4,	{ BI, BDMA }, PPC_INST_BDZTA },
{ "bdzta+",  BBO(16,BODZT,1,0), BBOY_MASK, NOPOWER4,	{ BI, BDPA }, PPC_INST_BDZTA },
{ "bdzta",   BBO(16,BODZT,1,0), BBOY_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BDZTA },
{ "bdztla-", BBO(16,BODZT,1,1), BBOY_MASK, NOPOWER4,	{ BI, BDMA }, PPC_INST_BDZTLA },
{ "bdztla+", BBO(16,BODZT,1,1), BBOY_MASK, NOPOWER4,	{ BI, BDPA }, PPC_INST_BDZTLA },
{ "bdztla",  BBO(16,BODZT,1,1), BBOY_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BDZTLA },
{ "bdzf-",   BBO(16,BODZF,0,0), BBOY_MASK, NOPOWER4,	{ BI, BDM }, PPC_INST_BDZF },
{ "bdzf+",   BBO(16,BODZF,0,0), BBOY_MASK, NOPOWER4,	{ BI, BDP }, PPC_INST_BDZF },
{ "bdzf",    BBO(16,BODZF,0,0), BBOY_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BDZF },
{ "bdzfl-",  BBO(16,BODZF,0,1), BBOY_MASK, NOPOWER4,	{ BI, BDM }, PPC_INST_BDZFL },
{ "bdzfl+",  BBO(16,BODZF,0,1), BBOY_MASK, NOPOWER4,	{ BI, BDP }, PPC_INST_BDZFL },
{ "bdzfl",   BBO(16,BODZF,0,1), BBOY_MASK, PPCCOM,	{ BI, BD }, PPC_INST_BDZFL },
{ "bdzfa-",  BBO(16,BODZF,1,0), BBOY_MASK, NOPOWER4,	{ BI, BDMA }, PPC_INST_BDZFA },
{ "bdzfa+",  BBO(16,BODZF,1,0), BBOY_MASK, NOPOWER4,	{ BI, BDPA }, PPC_INST_BDZFA },
{ "bdzfa",   BBO(16,BODZF,1,0), BBOY_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BDZFA },
{ "bdzfla-", BBO(16,BODZF,1,1), BBOY_MASK, NOPOWER4,	{ BI, BDMA }, PPC_INST_BDZFLA },
{ "bdzfla+", BBO(16,BODZF,1,1), BBOY_MASK, NOPOWER4,	{ BI, BDPA }, PPC_INST_BDZFLA },
{ "bdzfla",  BBO(16,BODZF,1,1), BBOY_MASK, PPCCOM,	{ BI, BDA }, PPC_INST_BDZFLA },
{ "bc-",     B(16,0,0),	B_MASK,		PPCCOM,		{ BOE, BI, BDM }, PPC_INST_BC },
{ "bc+",     B(16,0,0),	B_MASK,		PPCCOM,		{ BOE, BI, BDP }, PPC_INST_BC },
{ "bc",	     B(16,0,0),	B_MASK,		COM,		{ BO, BI, BD }, PPC_INST_BC },
{ "bcl-",    B(16,0,1),	B_MASK,		PPCCOM,		{ BOE, BI, BDM }, PPC_INST_BCL },
{ "bcl+",    B(16,0,1),	B_MASK,		PPCCOM,		{ BOE, BI, BDP }, PPC_INST_BCL },
{ "bcl",     B(16,0,1),	B_MASK,		COM,		{ BO, BI, BD }, PPC_INST_BCL },
{ "bca-",    B(16,1,0),	B_MASK,		PPCCOM,		{ BOE, BI, BDMA }, PPC_INST_BCA },
{ "bca+",    B(16,1,0),	B_MASK,		PPCCOM,		{ BOE, BI, BDPA }, PPC_INST_BCA },
{ "bca",     B(16,1,0),	B_MASK,		COM,		{ BO, BI, BDA }, PPC_INST_BCA },
{ "bcla-",   B(16,1,1),	B_MASK,		PPCCOM,		{ BOE, BI, BDMA }, PPC_INST_BCLA },
{ "bcla+",   B(16,1,1),	B_MASK,		PPCCOM,		{ BOE, BI, BDPA }, PPC_INST_BCLA },
{ "bcla",    B(16,1,1),	B_MASK,		COM,		{ BO, BI, BDA }, PPC_INST_BCLA },

{ "sc",      SC(17,1,0), SC_MASK,	PPC,		{ LEV }, PPC_INST_SC },
{ "svc",     SC(17,0,0), SC_MASK,	POWER,		{ SVC_LEV, FL1, FL2 }, PPC_INST_SVC },
{ "svcl",    SC(17,0,1), SC_MASK,	POWER,		{ SVC_LEV, FL1, FL2 }, PPC_INST_SVCL },
{ "svca",    SC(17,1,0), SC_MASK,	PWRCOM,		{ SV }, PPC_INST_SVCA },
{ "svcla",   SC(17,1,1), SC_MASK,	POWER,		{ SV }, PPC_INST_SVCLA },

{ "b",	     B(18,0,0),	B_MASK,		COM,		{ LI }, PPC_INST_B },
{ "bl",      B(18,0,1),	B_MASK,		COM,		{ LI }, PPC_INST_BL },
{ "ba",      B(18,1,0),	B_MASK,		COM,		{ LIA }, PPC_INST_BA },
{ "bla",     B(18,1,1),	B_MASK,		COM,		{ LIA }, PPC_INST_BLA },

{ "mcrf",    XL(19,0),	XLBB_MASK | (3 << 21) | (3 << 16), COM,	{ BF, BFA }, PPC_INST_MCRF },

{ "blr",     XLO(19,BOU,16,0), XLBOBIBB_MASK, PPCCOM,	{ 0 }, PPC_INST_BLR },
{ "br",      XLO(19,BOU,16,0), XLBOBIBB_MASK, PWRCOM,	{ 0 }, PPC_INST_BR },
{ "blrl",    XLO(19,BOU,16,1), XLBOBIBB_MASK, PPCCOM,	{ 0 }, PPC_INST_BLRL },
{ "brl",     XLO(19,BOU,16,1), XLBOBIBB_MASK, PWRCOM,	{ 0 }, PPC_INST_BRL },
{ "bdnzlr",  XLO(19,BODNZ,16,0), XLBOBIBB_MASK, PPCCOM,	{ 0 }, PPC_INST_BDNZLR },
{ "bdnzlr-", XLO(19,BODNZ,16,0), XLBOBIBB_MASK, NOPOWER4,	{ 0 }, PPC_INST_BDNZLR },
{ "bdnzlr-", XLO(19,BODNZM4,16,0), XLBOBIBB_MASK, POWER4,	{ 0 }, PPC_INST_BDNZLR },
{ "bdnzlr+", XLO(19,BODNZP,16,0), XLBOBIBB_MASK, NOPOWER4,	{ 0 }, PPC_INST_BDNZLR },
{ "bdnzlr+", XLO(19,BODNZP4,16,0), XLBOBIBB_MASK, POWER4,	{ 0 }, PPC_INST_BDNZLR },
{ "bdnzlrl", XLO(19,BODNZ,16,1), XLBOBIBB_MASK, PPCCOM,	{ 0 }, PPC_INST_BDNZLRL },
{ "bdnzlrl-",XLO(19,BODNZ,16,1), XLBOBIBB_MASK, NOPOWER4,	{ 0 }, PPC_INST_BDNZLRL },
{ "bdnzlrl-",XLO(19,BODNZM4,16,1), XLBOBIBB_MASK, POWER4,	{ 0 }, PPC_INST_BDNZLRL },
{ "bdnzlrl+",XLO(19,BODNZP,16,1), XLBOBIBB_MASK, NOPOWER4,	{ 0 }, PPC_INST_BDNZLRL },
{ "bdnzlrl+",XLO(19,BODNZP4,16,1), XLBOBIBB_MASK, POWER4,	{ 0 }, PPC_INST_BDNZLRL },
{ "bdzlr",   XLO(19,BODZ,16,0), XLBOBIBB_MASK, PPCCOM,	{ 0 }, PPC_INST_BDZLR },
{ "bdzlr-",  XLO(19,BODZ,16,0), XLBOBIBB_MASK, NOPOWER4,	{ 0 }, PPC_INST_BDZLR },
{ "bdzlr-",  XLO(19,BODZM4,16,0), XLBOBIBB_MASK, POWER4,	{ 0 }, PPC_INST_BDZLR },
{ "bdzlr+",  XLO(19,BODZP,16,0), XLBOBIBB_MASK, NOPOWER4,	{ 0 }, PPC_INST_BDZLR },
{ "bdzlr+",  XLO(19,BODZP4,16,0), XLBOBIBB_MASK, POWER4,	{ 0 }, PPC_INST_BDZLR },
{ "bdzlrl",  XLO(19,BODZ,16,1), XLBOBIBB_MASK, PPCCOM,	{ 0 }, PPC_INST_BDZLRL },
{ "bdzlrl-", XLO(19,BODZ,16,1), XLBOBIBB_MASK, NOPOWER4,	{ 0 }, PPC_INST_BDZLRL },
{ "bdzlrl-", XLO(19,BODZM4,16,1), XLBOBIBB_MASK, POWER4,	{ 0 }, PPC_INST_BDZLRL },
{ "bdzlrl+", XLO(19,BODZP,16,1), XLBOBIBB_MASK, NOPOWER4,	{ 0 }, PPC_INST_BDZLRL },
{ "bdzlrl+", XLO(19,BODZP4,16,1), XLBOBIBB_MASK, POWER4,	{ 0 }, PPC_INST_BDZLRL },
{ "bltlr",   XLOCB(19,BOT,CBLT,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BLTLR },
{ "bltlr-",  XLOCB(19,BOT,CBLT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLTLR },
{ "bltlr-",  XLOCB(19,BOTM4,CBLT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLTLR },
{ "bltlr+",  XLOCB(19,BOTP,CBLT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLTLR },
{ "bltlr+",  XLOCB(19,BOTP4,CBLT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLTLR },
{ "bltr",    XLOCB(19,BOT,CBLT,16,0), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BLTR },
{ "bltlrl",  XLOCB(19,BOT,CBLT,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BLTLRL },
{ "bltlrl-", XLOCB(19,BOT,CBLT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLTLRL },
{ "bltlrl-", XLOCB(19,BOTM4,CBLT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLTLRL },
{ "bltlrl+", XLOCB(19,BOTP,CBLT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLTLRL },
{ "bltlrl+", XLOCB(19,BOTP4,CBLT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLTLRL },
{ "bltrl",   XLOCB(19,BOT,CBLT,16,1), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BLTRL },
{ "bgtlr",   XLOCB(19,BOT,CBGT,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BGTLR },
{ "bgtlr-",  XLOCB(19,BOT,CBGT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGTLR },
{ "bgtlr-",  XLOCB(19,BOTM4,CBGT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGTLR },
{ "bgtlr+",  XLOCB(19,BOTP,CBGT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGTLR },
{ "bgtlr+",  XLOCB(19,BOTP4,CBGT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGTLR },
{ "bgtr",    XLOCB(19,BOT,CBGT,16,0), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BGTR },
{ "bgtlrl",  XLOCB(19,BOT,CBGT,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BGTLRL },
{ "bgtlrl-", XLOCB(19,BOT,CBGT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGTLRL },
{ "bgtlrl-", XLOCB(19,BOTM4,CBGT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGTLRL },
{ "bgtlrl+", XLOCB(19,BOTP,CBGT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGTLRL },
{ "bgtlrl+", XLOCB(19,BOTP4,CBGT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGTLRL },
{ "bgtrl",   XLOCB(19,BOT,CBGT,16,1), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BGTRL },
{ "beqlr",   XLOCB(19,BOT,CBEQ,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BEQLR },
{ "beqlr-",  XLOCB(19,BOT,CBEQ,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BEQLR },
{ "beqlr-",  XLOCB(19,BOTM4,CBEQ,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BEQLR },
{ "beqlr+",  XLOCB(19,BOTP,CBEQ,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BEQLR },
{ "beqlr+",  XLOCB(19,BOTP4,CBEQ,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BEQLR },
{ "beqr",    XLOCB(19,BOT,CBEQ,16,0), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BEQR },
{ "beqlrl",  XLOCB(19,BOT,CBEQ,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BEQLRL },
{ "beqlrl-", XLOCB(19,BOT,CBEQ,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BEQLRL },
{ "beqlrl-", XLOCB(19,BOTM4,CBEQ,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BEQLRL },
{ "beqlrl+", XLOCB(19,BOTP,CBEQ,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BEQLRL },
{ "beqlrl+", XLOCB(19,BOTP4,CBEQ,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BEQLRL },
{ "beqrl",   XLOCB(19,BOT,CBEQ,16,1), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BEQRL },
{ "bsolr",   XLOCB(19,BOT,CBSO,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BSOLR },
{ "bsolr-",  XLOCB(19,BOT,CBSO,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BSOLR },
{ "bsolr-",  XLOCB(19,BOTM4,CBSO,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BSOLR },
{ "bsolr+",  XLOCB(19,BOTP,CBSO,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BSOLR },
{ "bsolr+",  XLOCB(19,BOTP4,CBSO,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BSOLR },
{ "bsor",    XLOCB(19,BOT,CBSO,16,0), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BSOR },
{ "bsolrl",  XLOCB(19,BOT,CBSO,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BSOLRL },
{ "bsolrl-", XLOCB(19,BOT,CBSO,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BSOLRL },
{ "bsolrl-", XLOCB(19,BOTM4,CBSO,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BSOLRL },
{ "bsolrl+", XLOCB(19,BOTP,CBSO,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BSOLRL },
{ "bsolrl+", XLOCB(19,BOTP4,CBSO,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BSOLRL },
{ "bsorl",   XLOCB(19,BOT,CBSO,16,1), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BSORL },
{ "bunlr",   XLOCB(19,BOT,CBSO,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BUNLR },
{ "bunlr-",  XLOCB(19,BOT,CBSO,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BUNLR },
{ "bunlr-",  XLOCB(19,BOTM4,CBSO,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BUNLR },
{ "bunlr+",  XLOCB(19,BOTP,CBSO,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BUNLR },
{ "bunlr+",  XLOCB(19,BOTP4,CBSO,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BUNLR },
{ "bunlrl",  XLOCB(19,BOT,CBSO,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BUNLRL },
{ "bunlrl-", XLOCB(19,BOT,CBSO,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BUNLRL },
{ "bunlrl-", XLOCB(19,BOTM4,CBSO,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BUNLRL },
{ "bunlrl+", XLOCB(19,BOTP,CBSO,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BUNLRL },
{ "bunlrl+", XLOCB(19,BOTP4,CBSO,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BUNLRL },
{ "bgelr",   XLOCB(19,BOF,CBLT,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BGELR },
{ "bgelr-",  XLOCB(19,BOF,CBLT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGELR },
{ "bgelr-",  XLOCB(19,BOFM4,CBLT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGELR },
{ "bgelr+",  XLOCB(19,BOFP,CBLT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGELR },
{ "bgelr+",  XLOCB(19,BOFP4,CBLT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGELR },
{ "bger",    XLOCB(19,BOF,CBLT,16,0), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BGER },
{ "bgelrl",  XLOCB(19,BOF,CBLT,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BGELRL },
{ "bgelrl-", XLOCB(19,BOF,CBLT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGELRL },
{ "bgelrl-", XLOCB(19,BOFM4,CBLT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGELRL },
{ "bgelrl+", XLOCB(19,BOFP,CBLT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGELRL },
{ "bgelrl+", XLOCB(19,BOFP4,CBLT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGELRL },
{ "bgerl",   XLOCB(19,BOF,CBLT,16,1), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BGERL },
{ "bnllr",   XLOCB(19,BOF,CBLT,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BNLLR },
{ "bnllr-",  XLOCB(19,BOF,CBLT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNLLR },
{ "bnllr-",  XLOCB(19,BOFM4,CBLT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNLLR },
{ "bnllr+",  XLOCB(19,BOFP,CBLT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNLLR },
{ "bnllr+",  XLOCB(19,BOFP4,CBLT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNLLR },
{ "bnlr",    XLOCB(19,BOF,CBLT,16,0), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BNLR },
{ "bnllrl",  XLOCB(19,BOF,CBLT,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BNLLRL },
{ "bnllrl-", XLOCB(19,BOF,CBLT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNLLRL },
{ "bnllrl-", XLOCB(19,BOFM4,CBLT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNLLRL },
{ "bnllrl+", XLOCB(19,BOFP,CBLT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNLLRL },
{ "bnllrl+", XLOCB(19,BOFP4,CBLT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNLLRL },
{ "bnlrl",   XLOCB(19,BOF,CBLT,16,1), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BNLRL },
{ "blelr",   XLOCB(19,BOF,CBGT,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BLELR },
{ "blelr-",  XLOCB(19,BOF,CBGT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLELR },
{ "blelr-",  XLOCB(19,BOFM4,CBGT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLELR },
{ "blelr+",  XLOCB(19,BOFP,CBGT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLELR },
{ "blelr+",  XLOCB(19,BOFP4,CBGT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLELR },
{ "bler",    XLOCB(19,BOF,CBGT,16,0), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BLER },
{ "blelrl",  XLOCB(19,BOF,CBGT,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BLELRL },
{ "blelrl-", XLOCB(19,BOF,CBGT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLELRL },
{ "blelrl-", XLOCB(19,BOFM4,CBGT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLELRL },
{ "blelrl+", XLOCB(19,BOFP,CBGT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLELRL },
{ "blelrl+", XLOCB(19,BOFP4,CBGT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLELRL },
{ "blerl",   XLOCB(19,BOF,CBGT,16,1), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BLERL },
{ "bnglr",   XLOCB(19,BOF,CBGT,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BNGLR },
{ "bnglr-",  XLOCB(19,BOF,CBGT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNGLR },
{ "bnglr-",  XLOCB(19,BOFM4,CBGT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNGLR },
{ "bnglr+",  XLOCB(19,BOFP,CBGT,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNGLR },
{ "bnglr+",  XLOCB(19,BOFP4,CBGT,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNGLR },
{ "bngr",    XLOCB(19,BOF,CBGT,16,0), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BNGR },
{ "bnglrl",  XLOCB(19,BOF,CBGT,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BNGLRL },
{ "bnglrl-", XLOCB(19,BOF,CBGT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNGLRL },
{ "bnglrl-", XLOCB(19,BOFM4,CBGT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNGLRL },
{ "bnglrl+", XLOCB(19,BOFP,CBGT,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNGLRL },
{ "bnglrl+", XLOCB(19,BOFP4,CBGT,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNGLRL },
{ "bngrl",   XLOCB(19,BOF,CBGT,16,1), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BNGRL },
{ "bnelr",   XLOCB(19,BOF,CBEQ,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BNELR },
{ "bnelr-",  XLOCB(19,BOF,CBEQ,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNELR },
{ "bnelr-",  XLOCB(19,BOFM4,CBEQ,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNELR },
{ "bnelr+",  XLOCB(19,BOFP,CBEQ,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNELR },
{ "bnelr+",  XLOCB(19,BOFP4,CBEQ,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNELR },
{ "bner",    XLOCB(19,BOF,CBEQ,16,0), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BNER },
{ "bnelrl",  XLOCB(19,BOF,CBEQ,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BNELRL },
{ "bnelrl-", XLOCB(19,BOF,CBEQ,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNELRL },
{ "bnelrl-", XLOCB(19,BOFM4,CBEQ,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNELRL },
{ "bnelrl+", XLOCB(19,BOFP,CBEQ,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNELRL },
{ "bnelrl+", XLOCB(19,BOFP4,CBEQ,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNELRL },
{ "bnerl",   XLOCB(19,BOF,CBEQ,16,1), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BNERL },
{ "bnslr",   XLOCB(19,BOF,CBSO,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BNSLR },
{ "bnslr-",  XLOCB(19,BOF,CBSO,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNSLR },
{ "bnslr-",  XLOCB(19,BOFM4,CBSO,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNSLR },
{ "bnslr+",  XLOCB(19,BOFP,CBSO,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNSLR },
{ "bnslr+",  XLOCB(19,BOFP4,CBSO,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNSLR },
{ "bnsr",    XLOCB(19,BOF,CBSO,16,0), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BNSR },
{ "bnslrl",  XLOCB(19,BOF,CBSO,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BNSLRL },
{ "bnslrl-", XLOCB(19,BOF,CBSO,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNSLRL },
{ "bnslrl-", XLOCB(19,BOFM4,CBSO,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNSLRL },
{ "bnslrl+", XLOCB(19,BOFP,CBSO,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNSLRL },
{ "bnslrl+", XLOCB(19,BOFP4,CBSO,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNSLRL },
{ "bnsrl",   XLOCB(19,BOF,CBSO,16,1), XLBOCBBB_MASK, PWRCOM, { CR }, PPC_INST_BNSRL },
{ "bnulr",   XLOCB(19,BOF,CBSO,16,0), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BNULR },
{ "bnulr-",  XLOCB(19,BOF,CBSO,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNULR },
{ "bnulr-",  XLOCB(19,BOFM4,CBSO,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNULR },
{ "bnulr+",  XLOCB(19,BOFP,CBSO,16,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNULR },
{ "bnulr+",  XLOCB(19,BOFP4,CBSO,16,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNULR },
{ "bnulrl",  XLOCB(19,BOF,CBSO,16,1), XLBOCBBB_MASK, PPCCOM, { CR }, PPC_INST_BNULRL },
{ "bnulrl-", XLOCB(19,BOF,CBSO,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNULRL },
{ "bnulrl-", XLOCB(19,BOFM4,CBSO,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNULRL },
{ "bnulrl+", XLOCB(19,BOFP,CBSO,16,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNULRL },
{ "bnulrl+", XLOCB(19,BOFP4,CBSO,16,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNULRL },
{ "btlr",    XLO(19,BOT,16,0), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BTLR },
{ "btlr-",   XLO(19,BOT,16,0), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BTLR },
{ "btlr-",   XLO(19,BOTM4,16,0), XLBOBB_MASK, POWER4,	{ BI }, PPC_INST_BTLR },
{ "btlr+",   XLO(19,BOTP,16,0), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BTLR },
{ "btlr+",   XLO(19,BOTP4,16,0), XLBOBB_MASK, POWER4,	{ BI }, PPC_INST_BTLR },
{ "bbtr",    XLO(19,BOT,16,0), XLBOBB_MASK, PWRCOM,	{ BI }, PPC_INST_BBTR },
{ "btlrl",   XLO(19,BOT,16,1), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BTLRL },
{ "btlrl-",  XLO(19,BOT,16,1), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BTLRL },
{ "btlrl-",  XLO(19,BOTM4,16,1), XLBOBB_MASK, POWER4,	{ BI }, PPC_INST_BTLRL },
{ "btlrl+",  XLO(19,BOTP,16,1), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BTLRL },
{ "btlrl+",  XLO(19,BOTP4,16,1), XLBOBB_MASK, POWER4,	{ BI }, PPC_INST_BTLRL },
{ "bbtrl",   XLO(19,BOT,16,1), XLBOBB_MASK, PWRCOM,	{ BI }, PPC_INST_BBTRL },
{ "bflr",    XLO(19,BOF,16,0), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BFLR },
{ "bflr-",   XLO(19,BOF,16,0), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BFLR },
{ "bflr-",   XLO(19,BOFM4,16,0), XLBOBB_MASK, POWER4,	{ BI }, PPC_INST_BFLR },
{ "bflr+",   XLO(19,BOFP,16,0), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BFLR },
{ "bflr+",   XLO(19,BOFP4,16,0), XLBOBB_MASK, POWER4,	{ BI }, PPC_INST_BFLR },
{ "bbfr",    XLO(19,BOF,16,0), XLBOBB_MASK, PWRCOM,	{ BI }, PPC_INST_BBFR },
{ "bflrl",   XLO(19,BOF,16,1), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BFLRL },
{ "bflrl-",  XLO(19,BOF,16,1), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BFLRL },
{ "bflrl-",  XLO(19,BOFM4,16,1), XLBOBB_MASK, POWER4,	{ BI }, PPC_INST_BFLRL },
{ "bflrl+",  XLO(19,BOFP,16,1), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BFLRL },
{ "bflrl+",  XLO(19,BOFP4,16,1), XLBOBB_MASK, POWER4,	{ BI }, PPC_INST_BFLRL },
{ "bbfrl",   XLO(19,BOF,16,1), XLBOBB_MASK, PWRCOM,	{ BI }, PPC_INST_BBFRL },
{ "bdnztlr", XLO(19,BODNZT,16,0), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BDNZTLR },
{ "bdnztlr-",XLO(19,BODNZT,16,0), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDNZTLR },
{ "bdnztlr+",XLO(19,BODNZTP,16,0), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDNZTLR },
{ "bdnztlrl",XLO(19,BODNZT,16,1), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BDNZTLRL },
{ "bdnztlrl-",XLO(19,BODNZT,16,1), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDNZTLRL },
{ "bdnztlrl+",XLO(19,BODNZTP,16,1), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDNZTLRL },
{ "bdnzflr", XLO(19,BODNZF,16,0), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BDNZFLR },
{ "bdnzflr-",XLO(19,BODNZF,16,0), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDNZFLR },
{ "bdnzflr+",XLO(19,BODNZFP,16,0), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDNZFLR },
{ "bdnzflrl",XLO(19,BODNZF,16,1), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BDNZFLRL },
{ "bdnzflrl-",XLO(19,BODNZF,16,1), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDNZFLRL },
{ "bdnzflrl+",XLO(19,BODNZFP,16,1), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDNZFLRL },
{ "bdztlr",  XLO(19,BODZT,16,0), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BDZTLR },
{ "bdztlr-", XLO(19,BODZT,16,0), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BDZTLR },
{ "bdztlr+", XLO(19,BODZTP,16,0), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDZTLR },
{ "bdztlrl", XLO(19,BODZT,16,1), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BDZTLRL },
{ "bdztlrl-",XLO(19,BODZT,16,1), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BDZTLRL },
{ "bdztlrl+",XLO(19,BODZTP,16,1), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDZTLRL },
{ "bdzflr",  XLO(19,BODZF,16,0), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BDZFLR },
{ "bdzflr-", XLO(19,BODZF,16,0), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BDZFLR },
{ "bdzflr+", XLO(19,BODZFP,16,0), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDZFLR },
{ "bdzflrl", XLO(19,BODZF,16,1), XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BDZFLRL },
{ "bdzflrl-",XLO(19,BODZF,16,1), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BDZFLRL },
{ "bdzflrl+",XLO(19,BODZFP,16,1), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BDZFLRL },
{ "bclr+",   XLYLK(19,16,1,0), XLYBB_MASK, PPCCOM,	{ BOE, BI }, PPC_INST_BCLR },
{ "bclrl+",  XLYLK(19,16,1,1), XLYBB_MASK, PPCCOM,	{ BOE, BI }, PPC_INST_BCLRL },
{ "bclr-",   XLYLK(19,16,0,0), XLYBB_MASK, PPCCOM,	{ BOE, BI }, PPC_INST_BCLR },
{ "bclrl-",  XLYLK(19,16,0,1), XLYBB_MASK, PPCCOM,	{ BOE, BI }, PPC_INST_BCLRL },
{ "bclr",    XLLK(19,16,0), XLBH_MASK,	PPCCOM,		{ BO, BI, BH }, PPC_INST_BCLR },
{ "bclrl",   XLLK(19,16,1), XLBH_MASK,	PPCCOM,		{ BO, BI, BH }, PPC_INST_BCLRL },
{ "bcr",     XLLK(19,16,0), XLBB_MASK,	PWRCOM,		{ BO, BI }, PPC_INST_BCR },
{ "bcrl",    XLLK(19,16,1), XLBB_MASK,	PWRCOM,		{ BO, BI }, PPC_INST_BCRL },
{ "bclre",   XLLK(19,17,0), XLBB_MASK,	BOOKE64,	{ BO, BI }, PPC_INST_BCLRE },
{ "bclrel",  XLLK(19,17,1), XLBB_MASK,	BOOKE64,	{ BO, BI }, PPC_INST_BCLREL },

{ "rfid",    XL(19,18),	0xffffffff,	PPC64,		{ 0 }, PPC_INST_RFID },

{ "crnot",   XL(19,33), XL_MASK,	PPCCOM,		{ BT, BA, BBA }, PPC_INST_CRNOT },
{ "crnor",   XL(19,33),	XL_MASK,	COM,		{ BT, BA, BB }, PPC_INST_CRNOR },
{ "rfmci",    X(19,38), 0xffffffff,	PPCRFMCI,	{ 0 }, PPC_INST_RFMCI },

{ "rfi",     XL(19,50),	0xffffffff,	COM,		{ 0 }, PPC_INST_RFI },
{ "rfci",    XL(19,51),	0xffffffff,	PPC403 | BOOKE,	{ 0 }, PPC_INST_RFCI },

{ "rfsvc",   XL(19,82),	0xffffffff,	POWER,		{ 0 }, PPC_INST_RFSVC },

{ "crandc",  XL(19,129), XL_MASK,	COM,		{ BT, BA, BB }, PPC_INST_CRANDC },

{ "isync",   XL(19,150), 0xffffffff,	PPCCOM,		{ 0 }, PPC_INST_ISYNC },
{ "ics",     XL(19,150), 0xffffffff,	PWRCOM,		{ 0 }, PPC_INST_ICS },

{ "crclr",   XL(19,193), XL_MASK,	PPCCOM,		{ BT, BAT, BBA }, PPC_INST_CRCLR },
{ "crxor",   XL(19,193), XL_MASK,	COM,		{ BT, BA, BB }, PPC_INST_CRXOR },

{ "crnand",  XL(19,225), XL_MASK,	COM,		{ BT, BA, BB }, PPC_INST_CRNAND },

{ "crand",   XL(19,257), XL_MASK,	COM,		{ BT, BA, BB }, PPC_INST_CRAND },

{ "hrfid",   XL(19,274), 0xffffffff,	POWER5 | CELL,	{ 0 }, PPC_INST_HRFID },

{ "crset",   XL(19,289), XL_MASK,	PPCCOM,		{ BT, BAT, BBA }, PPC_INST_CRSET },
{ "creqv",   XL(19,289), XL_MASK,	COM,		{ BT, BA, BB }, PPC_INST_CREQV },

{ "doze",    XL(19,402), 0xffffffff,	POWER6,		{ 0 }, PPC_INST_DOZE },

{ "crorc",   XL(19,417), XL_MASK,	COM,		{ BT, BA, BB }, PPC_INST_CRORC },

{ "nap",     XL(19,434), 0xffffffff,	POWER6,		{ 0 }, PPC_INST_NAP },

{ "crmove",  XL(19,449), XL_MASK,	PPCCOM,		{ BT, BA, BBA }, PPC_INST_CRMOVE },
{ "cror",    XL(19,449), XL_MASK,	COM,		{ BT, BA, BB }, PPC_INST_CROR },

{ "sleep",   XL(19,466), 0xffffffff,	POWER6,		{ 0 }, PPC_INST_SLEEP },
{ "rvwinkle", XL(19,498), 0xffffffff,	POWER6,		{ 0 }, PPC_INST_RVWINKLE },

{ "bctr",    XLO(19,BOU,528,0), XLBOBIBB_MASK, COM,	{ 0 }, PPC_INST_BCTR },
{ "bctrl",   XLO(19,BOU,528,1), XLBOBIBB_MASK, COM,	{ 0 }, PPC_INST_BCTRL },
{ "bltctr",  XLOCB(19,BOT,CBLT,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BLTCTR },
{ "bltctr-", XLOCB(19,BOT,CBLT,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLTCTR },
{ "bltctr-", XLOCB(19,BOTM4,CBLT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLTCTR },
{ "bltctr+", XLOCB(19,BOTP,CBLT,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLTCTR },
{ "bltctr+", XLOCB(19,BOTP4,CBLT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLTCTR },
{ "bltctrl", XLOCB(19,BOT,CBLT,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BLTCTRL },
{ "bltctrl-",XLOCB(19,BOT,CBLT,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLTCTRL },
{ "bltctrl-",XLOCB(19,BOTM4,CBLT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLTCTRL },
{ "bltctrl+",XLOCB(19,BOTP,CBLT,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLTCTRL },
{ "bltctrl+",XLOCB(19,BOTP4,CBLT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLTCTRL },
{ "bgtctr",  XLOCB(19,BOT,CBGT,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BGTCTR },
{ "bgtctr-", XLOCB(19,BOT,CBGT,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGTCTR },
{ "bgtctr-", XLOCB(19,BOTM4,CBGT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGTCTR },
{ "bgtctr+", XLOCB(19,BOTP,CBGT,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGTCTR },
{ "bgtctr+", XLOCB(19,BOTP4,CBGT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGTCTR },
{ "bgtctrl", XLOCB(19,BOT,CBGT,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BGTCTRL },
{ "bgtctrl-",XLOCB(19,BOT,CBGT,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGTCTRL },
{ "bgtctrl-",XLOCB(19,BOTM4,CBGT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGTCTRL },
{ "bgtctrl+",XLOCB(19,BOTP,CBGT,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGTCTRL },
{ "bgtctrl+",XLOCB(19,BOTP4,CBGT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGTCTRL },
{ "beqctr",  XLOCB(19,BOT,CBEQ,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BEQCTR },
{ "beqctr-", XLOCB(19,BOT,CBEQ,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BEQCTR },
{ "beqctr-", XLOCB(19,BOTM4,CBEQ,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BEQCTR },
{ "beqctr+", XLOCB(19,BOTP,CBEQ,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BEQCTR },
{ "beqctr+", XLOCB(19,BOTP4,CBEQ,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BEQCTR },
{ "beqctrl", XLOCB(19,BOT,CBEQ,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BEQCTRL },
{ "beqctrl-",XLOCB(19,BOT,CBEQ,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BEQCTRL },
{ "beqctrl-",XLOCB(19,BOTM4,CBEQ,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BEQCTRL },
{ "beqctrl+",XLOCB(19,BOTP,CBEQ,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BEQCTRL },
{ "beqctrl+",XLOCB(19,BOTP4,CBEQ,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BEQCTRL },
{ "bsoctr",  XLOCB(19,BOT,CBSO,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BSOCTR },
{ "bsoctr-", XLOCB(19,BOT,CBSO,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BSOCTR },
{ "bsoctr-", XLOCB(19,BOTM4,CBSO,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BSOCTR },
{ "bsoctr+", XLOCB(19,BOTP,CBSO,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BSOCTR },
{ "bsoctr+", XLOCB(19,BOTP4,CBSO,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BSOCTR },
{ "bsoctrl", XLOCB(19,BOT,CBSO,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BSOCTRL },
{ "bsoctrl-",XLOCB(19,BOT,CBSO,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BSOCTRL },
{ "bsoctrl-",XLOCB(19,BOTM4,CBSO,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BSOCTRL },
{ "bsoctrl+",XLOCB(19,BOTP,CBSO,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BSOCTRL },
{ "bsoctrl+",XLOCB(19,BOTP4,CBSO,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BSOCTRL },
{ "bunctr",  XLOCB(19,BOT,CBSO,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BUNCTR },
{ "bunctr-", XLOCB(19,BOT,CBSO,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BUNCTR },
{ "bunctr-", XLOCB(19,BOTM4,CBSO,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BUNCTR },
{ "bunctr+", XLOCB(19,BOTP,CBSO,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BUNCTR },
{ "bunctr+", XLOCB(19,BOTP4,CBSO,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BUNCTR },
{ "bunctrl", XLOCB(19,BOT,CBSO,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BUNCTRL },
{ "bunctrl-",XLOCB(19,BOT,CBSO,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BUNCTRL },
{ "bunctrl-",XLOCB(19,BOTM4,CBSO,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BUNCTRL },
{ "bunctrl+",XLOCB(19,BOTP,CBSO,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BUNCTRL },
{ "bunctrl+",XLOCB(19,BOTP4,CBSO,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BUNCTRL },
{ "bgectr",  XLOCB(19,BOF,CBLT,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BGECTR },
{ "bgectr-", XLOCB(19,BOF,CBLT,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGECTR },
{ "bgectr-", XLOCB(19,BOFM4,CBLT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGECTR },
{ "bgectr+", XLOCB(19,BOFP,CBLT,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGECTR },
{ "bgectr+", XLOCB(19,BOFP4,CBLT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGECTR },
{ "bgectrl", XLOCB(19,BOF,CBLT,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BGECTRL },
{ "bgectrl-",XLOCB(19,BOF,CBLT,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGECTRL },
{ "bgectrl-",XLOCB(19,BOFM4,CBLT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGECTRL },
{ "bgectrl+",XLOCB(19,BOFP,CBLT,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BGECTRL },
{ "bgectrl+",XLOCB(19,BOFP4,CBLT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BGECTRL },
{ "bnlctr",  XLOCB(19,BOF,CBLT,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BNLCTR },
{ "bnlctr-", XLOCB(19,BOF,CBLT,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNLCTR },
{ "bnlctr-", XLOCB(19,BOFM4,CBLT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNLCTR },
{ "bnlctr+", XLOCB(19,BOFP,CBLT,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNLCTR },
{ "bnlctr+", XLOCB(19,BOFP4,CBLT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNLCTR },
{ "bnlctrl", XLOCB(19,BOF,CBLT,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BNLCTRL },
{ "bnlctrl-",XLOCB(19,BOF,CBLT,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNLCTRL },
{ "bnlctrl-",XLOCB(19,BOFM4,CBLT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNLCTRL },
{ "bnlctrl+",XLOCB(19,BOFP,CBLT,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNLCTRL },
{ "bnlctrl+",XLOCB(19,BOFP4,CBLT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNLCTRL },
{ "blectr",  XLOCB(19,BOF,CBGT,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BLECTR },
{ "blectr-", XLOCB(19,BOF,CBGT,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLECTR },
{ "blectr-", XLOCB(19,BOFM4,CBGT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLECTR },
{ "blectr+", XLOCB(19,BOFP,CBGT,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLECTR },
{ "blectr+", XLOCB(19,BOFP4,CBGT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLECTR },
{ "blectrl", XLOCB(19,BOF,CBGT,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BLECTRL },
{ "blectrl-",XLOCB(19,BOF,CBGT,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLECTRL },
{ "blectrl-",XLOCB(19,BOFM4,CBGT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLECTRL },
{ "blectrl+",XLOCB(19,BOFP,CBGT,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BLECTRL },
{ "blectrl+",XLOCB(19,BOFP4,CBGT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BLECTRL },
{ "bngctr",  XLOCB(19,BOF,CBGT,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BNGCTR },
{ "bngctr-", XLOCB(19,BOF,CBGT,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNGCTR },
{ "bngctr-", XLOCB(19,BOFM4,CBGT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNGCTR },
{ "bngctr+", XLOCB(19,BOFP,CBGT,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNGCTR },
{ "bngctr+", XLOCB(19,BOFP4,CBGT,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNGCTR },
{ "bngctrl", XLOCB(19,BOF,CBGT,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BNGCTRL },
{ "bngctrl-",XLOCB(19,BOF,CBGT,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNGCTRL },
{ "bngctrl-",XLOCB(19,BOFM4,CBGT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNGCTRL },
{ "bngctrl+",XLOCB(19,BOFP,CBGT,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNGCTRL },
{ "bngctrl+",XLOCB(19,BOFP4,CBGT,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNGCTRL },
{ "bnectr",  XLOCB(19,BOF,CBEQ,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BNECTR },
{ "bnectr-", XLOCB(19,BOF,CBEQ,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNECTR },
{ "bnectr-", XLOCB(19,BOFM4,CBEQ,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNECTR },
{ "bnectr+", XLOCB(19,BOFP,CBEQ,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNECTR },
{ "bnectr+", XLOCB(19,BOFP4,CBEQ,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNECTR },
{ "bnectrl", XLOCB(19,BOF,CBEQ,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BNECTRL },
{ "bnectrl-",XLOCB(19,BOF,CBEQ,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNECTRL },
{ "bnectrl-",XLOCB(19,BOFM4,CBEQ,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNECTRL },
{ "bnectrl+",XLOCB(19,BOFP,CBEQ,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNECTRL },
{ "bnectrl+",XLOCB(19,BOFP4,CBEQ,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNECTRL },
{ "bnsctr",  XLOCB(19,BOF,CBSO,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BNSCTR },
{ "bnsctr-", XLOCB(19,BOF,CBSO,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNSCTR },
{ "bnsctr-", XLOCB(19,BOFM4,CBSO,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNSCTR },
{ "bnsctr+", XLOCB(19,BOFP,CBSO,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNSCTR },
{ "bnsctr+", XLOCB(19,BOFP4,CBSO,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNSCTR },
{ "bnsctrl", XLOCB(19,BOF,CBSO,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BNSCTRL },
{ "bnsctrl-",XLOCB(19,BOF,CBSO,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNSCTRL },
{ "bnsctrl-",XLOCB(19,BOFM4,CBSO,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNSCTRL },
{ "bnsctrl+",XLOCB(19,BOFP,CBSO,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNSCTRL },
{ "bnsctrl+",XLOCB(19,BOFP4,CBSO,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNSCTRL },
{ "bnuctr",  XLOCB(19,BOF,CBSO,528,0),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BNUCTR },
{ "bnuctr-", XLOCB(19,BOF,CBSO,528,0),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNUCTR },
{ "bnuctr-", XLOCB(19,BOFM4,CBSO,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNUCTR },
{ "bnuctr+", XLOCB(19,BOFP,CBSO,528,0), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNUCTR },
{ "bnuctr+", XLOCB(19,BOFP4,CBSO,528,0), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNUCTR },
{ "bnuctrl", XLOCB(19,BOF,CBSO,528,1),  XLBOCBBB_MASK, PPCCOM,	{ CR }, PPC_INST_BNUCTRL },
{ "bnuctrl-",XLOCB(19,BOF,CBSO,528,1),  XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNUCTRL },
{ "bnuctrl-",XLOCB(19,BOFM4,CBSO,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNUCTRL },
{ "bnuctrl+",XLOCB(19,BOFP,CBSO,528,1), XLBOCBBB_MASK, NOPOWER4, { CR }, PPC_INST_BNUCTRL },
{ "bnuctrl+",XLOCB(19,BOFP4,CBSO,528,1), XLBOCBBB_MASK, POWER4, { CR }, PPC_INST_BNUCTRL },
{ "btctr",   XLO(19,BOT,528,0),  XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BTCTR },
{ "btctr-",  XLO(19,BOT,528,0),  XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BTCTR },
{ "btctr-",  XLO(19,BOTM4,528,0), XLBOBB_MASK, POWER4, { BI }, PPC_INST_BTCTR },
{ "btctr+",  XLO(19,BOTP,528,0), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BTCTR },
{ "btctr+",  XLO(19,BOTP4,528,0), XLBOBB_MASK, POWER4, { BI }, PPC_INST_BTCTR },
{ "btctrl",  XLO(19,BOT,528,1),  XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BTCTRL },
{ "btctrl-", XLO(19,BOT,528,1),  XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BTCTRL },
{ "btctrl-", XLO(19,BOTM4,528,1), XLBOBB_MASK, POWER4, { BI }, PPC_INST_BTCTRL },
{ "btctrl+", XLO(19,BOTP,528,1), XLBOBB_MASK, NOPOWER4,	{ BI }, PPC_INST_BTCTRL },
{ "btctrl+", XLO(19,BOTP4,528,1), XLBOBB_MASK, POWER4, { BI }, PPC_INST_BTCTRL },
{ "bfctr",   XLO(19,BOF,528,0),  XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BFCTR },
{ "bfctr-",  XLO(19,BOF,528,0),  XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BFCTR },
{ "bfctr-",  XLO(19,BOFM4,528,0), XLBOBB_MASK, POWER4, { BI }, PPC_INST_BFCTR },
{ "bfctr+",  XLO(19,BOFP,528,0), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BFCTR },
{ "bfctr+",  XLO(19,BOFP4,528,0), XLBOBB_MASK, POWER4, { BI }, PPC_INST_BFCTR },
{ "bfctrl",  XLO(19,BOF,528,1),  XLBOBB_MASK, PPCCOM,	{ BI }, PPC_INST_BFCTRL },
{ "bfctrl-", XLO(19,BOF,528,1),  XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BFCTRL },
{ "bfctrl-", XLO(19,BOFM4,528,1), XLBOBB_MASK, POWER4, { BI }, PPC_INST_BFCTRL },
{ "bfctrl+", XLO(19,BOFP,528,1), XLBOBB_MASK, NOPOWER4, { BI }, PPC_INST_BFCTRL },
{ "bfctrl+", XLO(19,BOFP4,528,1), XLBOBB_MASK, POWER4, { BI }, PPC_INST_BFCTRL },
{ "bcctr-",  XLYLK(19,528,0,0),  XLYBB_MASK,  PPCCOM,	{ BOE, BI }, PPC_INST_BCCTR },
{ "bcctr+",  XLYLK(19,528,1,0),  XLYBB_MASK,  PPCCOM,	{ BOE, BI }, PPC_INST_BCCTR },
{ "bcctrl-", XLYLK(19,528,0,1),  XLYBB_MASK,  PPCCOM,	{ BOE, BI }, PPC_INST_BCCTRL },
{ "bcctrl+", XLYLK(19,528,1,1),  XLYBB_MASK,  PPCCOM,	{ BOE, BI }, PPC_INST_BCCTRL },
{ "bcctr",   XLLK(19,528,0),     XLBH_MASK,   PPCCOM,	{ BO, BI, BH }, PPC_INST_BCCTR },
{ "bcctrl",  XLLK(19,528,1),     XLBH_MASK,   PPCCOM,	{ BO, BI, BH }, PPC_INST_BCCTRL },
{ "bcc",     XLLK(19,528,0),     XLBB_MASK,   PWRCOM,	{ BO, BI }, PPC_INST_BCC },
{ "bccl",    XLLK(19,528,1),     XLBB_MASK,   PWRCOM,	{ BO, BI }, PPC_INST_BCCL },
{ "bcctre",  XLLK(19,529,0),     XLBB_MASK,   BOOKE64,	{ BO, BI }, PPC_INST_BCCTRE },
{ "bcctrel", XLLK(19,529,1),     XLBB_MASK,   BOOKE64,	{ BO, BI }, PPC_INST_BCCTREL },

{ "rlwimi",  M(20,0),	M_MASK,		PPCCOM,		{ RA,RS,SH,MBE,ME }, PPC_INST_RLWIMI },
{ "rlimi",   M(20,0),	M_MASK,		PWRCOM,		{ RA,RS,SH,MBE,ME }, PPC_INST_RLIMI },

{ "rlwimi.", M(20,1),	M_MASK,		PPCCOM,		{ RA,RS,SH,MBE,ME }, PPC_INST_RLWIMI },
{ "rlimi.",  M(20,1),	M_MASK,		PWRCOM,		{ RA,RS,SH,MBE,ME }, PPC_INST_RLIMI },

{ "rotlwi",  MME(21,31,0), MMBME_MASK,	PPCCOM,		{ RA, RS, SH }, PPC_INST_ROTLWI },
{ "clrlwi",  MME(21,31,0), MSHME_MASK,	PPCCOM,		{ RA, RS, MB }, PPC_INST_CLRLWI },
{ "rlwinm",  M(21,0),	M_MASK,		PPCCOM,		{ RA,RS,SH,MBE,ME }, PPC_INST_RLWINM },
{ "rlinm",   M(21,0),	M_MASK,		PWRCOM,		{ RA,RS,SH,MBE,ME }, PPC_INST_RLINM },
{ "rotlwi.", MME(21,31,1), MMBME_MASK,	PPCCOM,		{ RA,RS,SH }, PPC_INST_ROTLWI },
{ "clrlwi.", MME(21,31,1), MSHME_MASK,	PPCCOM,		{ RA, RS, MB }, PPC_INST_CLRLWI },
{ "rlwinm.", M(21,1),	M_MASK,		PPCCOM,		{ RA,RS,SH,MBE,ME }, PPC_INST_RLWINM },
{ "rlinm.",  M(21,1),	M_MASK,		PWRCOM,		{ RA,RS,SH,MBE,ME }, PPC_INST_RLINM },

{ "rlmi",    M(22,0),	M_MASK,		M601,		{ RA,RS,RB,MBE,ME }, PPC_INST_RLMI },
{ "rlmi.",   M(22,1),	M_MASK,		M601,		{ RA,RS,RB,MBE,ME }, PPC_INST_RLMI },

{ "be",	     B(22,0,0),	B_MASK,		BOOKE64,	{ LI }, PPC_INST_BE },
{ "bel",     B(22,0,1),	B_MASK,		BOOKE64,	{ LI }, PPC_INST_BEL },
{ "bea",     B(22,1,0),	B_MASK,		BOOKE64,	{ LIA }, PPC_INST_BEA },
{ "bela",    B(22,1,1),	B_MASK,		BOOKE64,	{ LIA }, PPC_INST_BELA },

{ "rotlw",   MME(23,31,0), MMBME_MASK,	PPCCOM,		{ RA, RS, RB }, PPC_INST_ROTLW },
{ "rlwnm",   M(23,0),	M_MASK,		PPCCOM,		{ RA,RS,RB,MBE,ME }, PPC_INST_RLWNM },
{ "rlnm",    M(23,0),	M_MASK,		PWRCOM,		{ RA,RS,RB,MBE,ME }, PPC_INST_RLNM },
{ "rotlw.",  MME(23,31,1), MMBME_MASK,	PPCCOM,		{ RA, RS, RB }, PPC_INST_ROTLW },
{ "rlwnm.",  M(23,1),	M_MASK,		PPCCOM,		{ RA,RS,RB,MBE,ME }, PPC_INST_RLWNM },
{ "rlnm.",   M(23,1),	M_MASK,		PWRCOM,		{ RA,RS,RB,MBE,ME }, PPC_INST_RLNM },

{ "nop",     OP(24),	0xffffffff,	PPCCOM,		{ 0 }, PPC_INST_NOP },
{ "ori",     OP(24),	OP_MASK,	PPCCOM,		{ RA, RS, UI }, PPC_INST_ORI },
{ "oril",    OP(24),	OP_MASK,	PWRCOM,		{ RA, RS, UI }, PPC_INST_ORIL },

{ "oris",    OP(25),	OP_MASK,	PPCCOM,		{ RA, RS, UI }, PPC_INST_ORIS },
{ "oriu",    OP(25),	OP_MASK,	PWRCOM,		{ RA, RS, UI }, PPC_INST_ORIU },

{ "xori",    OP(26),	OP_MASK,	PPCCOM,		{ RA, RS, UI }, PPC_INST_XORI },
{ "xoril",   OP(26),	OP_MASK,	PWRCOM,		{ RA, RS, UI }, PPC_INST_XORIL },

{ "xoris",   OP(27),	OP_MASK,	PPCCOM,		{ RA, RS, UI }, PPC_INST_XORIS },
{ "xoriu",   OP(27),	OP_MASK,	PWRCOM,		{ RA, RS, UI }, PPC_INST_XORIU },

{ "andi.",   OP(28),	OP_MASK,	PPCCOM,		{ RA, RS, UI }, PPC_INST_ANDI },
{ "andil.",  OP(28),	OP_MASK,	PWRCOM,		{ RA, RS, UI }, PPC_INST_ANDIL },

{ "andis.",  OP(29),	OP_MASK,	PPCCOM,		{ RA, RS, UI }, PPC_INST_ANDIS },
{ "andiu.",  OP(29),	OP_MASK,	PWRCOM,		{ RA, RS, UI }, PPC_INST_ANDIU },

{ "rotldi",  MD(30,0,0), MDMB_MASK,	PPC64,		{ RA, RS, SH6 }, PPC_INST_ROTLDI },
{ "clrldi",  MD(30,0,0), MDSH_MASK,	PPC64,		{ RA, RS, MB6 }, PPC_INST_CLRLDI },
{ "rldicl",  MD(30,0,0), MD_MASK,	PPC64,		{ RA, RS, SH6, MB6 }, PPC_INST_RLDICL },
{ "rotldi.", MD(30,0,1), MDMB_MASK,	PPC64,		{ RA, RS, SH6 }, PPC_INST_ROTLDI },
{ "clrldi.", MD(30,0,1), MDSH_MASK,	PPC64,		{ RA, RS, MB6 }, PPC_INST_CLRLDI },
{ "rldicl.", MD(30,0,1), MD_MASK,	PPC64,		{ RA, RS, SH6, MB6 }, PPC_INST_RLDICL },

{ "rldicr",  MD(30,1,0), MD_MASK,	PPC64,		{ RA, RS, SH6, ME6 }, PPC_INST_RLDICR },
{ "rldicr.", MD(30,1,1), MD_MASK,	PPC64,		{ RA, RS, SH6, ME6 }, PPC_INST_RLDICR },

{ "rldic",   MD(30,2,0), MD_MASK,	PPC64,		{ RA, RS, SH6, MB6 }, PPC_INST_RLDIC },
{ "rldic.",  MD(30,2,1), MD_MASK,	PPC64,		{ RA, RS, SH6, MB6 }, PPC_INST_RLDIC },

{ "rldimi",  MD(30,3,0), MD_MASK,	PPC64,		{ RA, RS, SH6, MB6 }, PPC_INST_RLDIMI },
{ "rldimi.", MD(30,3,1), MD_MASK,	PPC64,		{ RA, RS, SH6, MB6 }, PPC_INST_RLDIMI },

{ "rotld",   MDS(30,8,0), MDSMB_MASK,	PPC64,		{ RA, RS, RB }, PPC_INST_ROTLD },
{ "rldcl",   MDS(30,8,0), MDS_MASK,	PPC64,		{ RA, RS, RB, MB6 }, PPC_INST_RLDCL },
{ "rotld.",  MDS(30,8,1), MDSMB_MASK,	PPC64,		{ RA, RS, RB }, PPC_INST_ROTLD },
{ "rldcl.",  MDS(30,8,1), MDS_MASK,	PPC64,		{ RA, RS, RB, MB6 }, PPC_INST_RLDCL },

{ "rldcr",   MDS(30,9,0), MDS_MASK,	PPC64,		{ RA, RS, RB, ME6 }, PPC_INST_RLDCR },
{ "rldcr.",  MDS(30,9,1), MDS_MASK,	PPC64,		{ RA, RS, RB, ME6 }, PPC_INST_RLDCR },

{ "cmpw",    XOPL(31,0,0), XCMPL_MASK, PPCCOM,		{ OBF, RA, RB }, PPC_INST_CMPW },
{ "cmpd",    XOPL(31,0,1), XCMPL_MASK, PPC64,		{ OBF, RA, RB }, PPC_INST_CMPD },
{ "cmp",     X(31,0),	XCMP_MASK,	PPC,		{ BF, L, RA, RB }, PPC_INST_CMP },
{ "cmp",     X(31,0),	XCMPL_MASK,	PWRCOM,		{ BF, RA, RB }, PPC_INST_CMP },

{ "twlgt",   XTO(31,4,TOLGT), XTO_MASK, PPCCOM,		{ RA, RB }, PPC_INST_TWLGT },
{ "tlgt",    XTO(31,4,TOLGT), XTO_MASK, PWRCOM,		{ RA, RB }, PPC_INST_TLGT },
{ "twllt",   XTO(31,4,TOLLT), XTO_MASK, PPCCOM,		{ RA, RB }, PPC_INST_TWLLT },
{ "tllt",    XTO(31,4,TOLLT), XTO_MASK, PWRCOM,		{ RA, RB }, PPC_INST_TLLT },
{ "tweq",    XTO(31,4,TOEQ), XTO_MASK,	PPCCOM,		{ RA, RB }, PPC_INST_TWEQ },
{ "teq",     XTO(31,4,TOEQ), XTO_MASK,	PWRCOM,		{ RA, RB }, PPC_INST_TEQ },
{ "twlge",   XTO(31,4,TOLGE), XTO_MASK, PPCCOM,		{ RA, RB }, PPC_INST_TWLGE },
{ "tlge",    XTO(31,4,TOLGE), XTO_MASK, PWRCOM,		{ RA, RB }, PPC_INST_TLGE },
{ "twlnl",   XTO(31,4,TOLNL), XTO_MASK, PPCCOM,		{ RA, RB }, PPC_INST_TWLNL },
{ "tlnl",    XTO(31,4,TOLNL), XTO_MASK, PWRCOM,		{ RA, RB }, PPC_INST_TLNL },
{ "twlle",   XTO(31,4,TOLLE), XTO_MASK, PPCCOM,		{ RA, RB }, PPC_INST_TWLLE },
{ "tlle",    XTO(31,4,TOLLE), XTO_MASK, PWRCOM,		{ RA, RB }, PPC_INST_TLLE },
{ "twlng",   XTO(31,4,TOLNG), XTO_MASK, PPCCOM,		{ RA, RB }, PPC_INST_TWLNG },
{ "tlng",    XTO(31,4,TOLNG), XTO_MASK, PWRCOM,		{ RA, RB }, PPC_INST_TLNG },
{ "twgt",    XTO(31,4,TOGT), XTO_MASK,	PPCCOM,		{ RA, RB }, PPC_INST_TWGT },
{ "tgt",     XTO(31,4,TOGT), XTO_MASK,	PWRCOM,		{ RA, RB }, PPC_INST_TGT },
{ "twge",    XTO(31,4,TOGE), XTO_MASK,	PPCCOM,		{ RA, RB }, PPC_INST_TWGE },
{ "tge",     XTO(31,4,TOGE), XTO_MASK,	PWRCOM,		{ RA, RB }, PPC_INST_TGE },
{ "twnl",    XTO(31,4,TONL), XTO_MASK,	PPCCOM,		{ RA, RB }, PPC_INST_TWNL },
{ "tnl",     XTO(31,4,TONL), XTO_MASK,	PWRCOM,		{ RA, RB }, PPC_INST_TNL },
{ "twlt",    XTO(31,4,TOLT), XTO_MASK,	PPCCOM,		{ RA, RB }, PPC_INST_TWLT },
{ "tlt",     XTO(31,4,TOLT), XTO_MASK,	PWRCOM,		{ RA, RB }, PPC_INST_TLT },
{ "twle",    XTO(31,4,TOLE), XTO_MASK,	PPCCOM,		{ RA, RB }, PPC_INST_TWLE },
{ "tle",     XTO(31,4,TOLE), XTO_MASK,	PWRCOM,		{ RA, RB }, PPC_INST_TLE },
{ "twng",    XTO(31,4,TONG), XTO_MASK,	PPCCOM,		{ RA, RB }, PPC_INST_TWNG },
{ "tng",     XTO(31,4,TONG), XTO_MASK,	PWRCOM,		{ RA, RB }, PPC_INST_TNG },
{ "twne",    XTO(31,4,TONE), XTO_MASK,	PPCCOM,		{ RA, RB }, PPC_INST_TWNE },
{ "tne",     XTO(31,4,TONE), XTO_MASK,	PWRCOM,		{ RA, RB }, PPC_INST_TNE },
{ "trap",    XTO(31,4,TOU), 0xffffffff,	PPCCOM,		{ 0 }, PPC_INST_TRAP },
{ "tw",      X(31,4),	X_MASK,		PPCCOM,		{ TO, RA, RB }, PPC_INST_TW },
{ "t",       X(31,4),	X_MASK,		PWRCOM,		{ TO, RA, RB }, PPC_INST_T },

{ "subfc",   XO(31,8,0,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_SUBFC },
{ "sf",      XO(31,8,0,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_SF },
{ "subc",    XO(31,8,0,0), XO_MASK,	PPC,		{ RT, RB, RA }, PPC_INST_SUBC },
{ "subfc.",  XO(31,8,0,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_SUBFC },
{ "sf.",     XO(31,8,0,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_SF },
{ "subc.",   XO(31,8,0,1), XO_MASK,	PPCCOM,		{ RT, RB, RA }, PPC_INST_SUBC },
{ "subfco",  XO(31,8,1,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_SUBFCO },
{ "sfo",     XO(31,8,1,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_SFO },
{ "subco",   XO(31,8,1,0), XO_MASK,	PPC,		{ RT, RB, RA }, PPC_INST_SUBCO },
{ "subfco.", XO(31,8,1,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_SUBFCO },
{ "sfo.",    XO(31,8,1,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_SFO },
{ "subco.",  XO(31,8,1,1), XO_MASK,	PPC,		{ RT, RB, RA }, PPC_INST_SUBCO },

{ "mulhdu",  XO(31,9,0,0), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_MULHDU },
{ "mulhdu.", XO(31,9,0,1), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_MULHDU },

{ "addc",    XO(31,10,0,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADDC },
{ "a",       XO(31,10,0,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_A },
{ "addc.",   XO(31,10,0,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADDC },
{ "a.",      XO(31,10,0,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_A },
{ "addco",   XO(31,10,1,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADDCO },
{ "ao",      XO(31,10,1,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_AO },
{ "addco.",  XO(31,10,1,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADDCO },
{ "ao.",     XO(31,10,1,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_AO },

{ "mulhwu",  XO(31,11,0,0), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_MULHWU },
{ "mulhwu.", XO(31,11,0,1), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_MULHWU },

{ "isellt",  X(31,15),      X_MASK,	PPCISEL,	{ RT, RA, RB }, PPC_INST_ISELLT },
{ "iselgt",  X(31,47),      X_MASK,	PPCISEL,	{ RT, RA, RB }, PPC_INST_ISELGT },
{ "iseleq",  X(31,79),      X_MASK,	PPCISEL,	{ RT, RA, RB }, PPC_INST_ISELEQ },
{ "isel",    XISEL(31,15),  XISEL_MASK,	PPCISEL,	{ RT, RA, RB, CRB }, PPC_INST_ISEL },

{ "mfocrf",  XFXM(31,19,0,1), XFXFXM_MASK, COM,		{ RT, FXM }, PPC_INST_MFOCRF },
{ "mfcr",    X(31,19),	XRARB_MASK,	NOPOWER4 | COM,	{ RT }, PPC_INST_MFCR },
{ "mfcr",    X(31,19),	XFXFXM_MASK,	POWER4,		{ RT, FXM4 }, PPC_INST_MFCR },

{ "lwarx",   X(31,20),	XEH_MASK,	PPC,		{ RT, RA0, RB, EH }, PPC_INST_LWARX },

{ "ldx",     X(31,21),	X_MASK,		PPC64,		{ RT, RA0, RB }, PPC_INST_LDX },

{ "icbt",    X(31,22),	X_MASK,		BOOKE | PPCE300,	{ CT, RA, RB }, PPC_INST_ICBT },
{ "icbt",    X(31,262),	XRT_MASK,	PPC403,		{ RA, RB }, PPC_INST_ICBT },

{ "lwzx",    X(31,23),	X_MASK,		PPCCOM,		{ RT, RA0, RB }, PPC_INST_LWZX },
{ "lx",      X(31,23),	X_MASK,		PWRCOM,		{ RT, RA, RB }, PPC_INST_LX },

{ "slw",     XRC(31,24,0), X_MASK,	PPCCOM,		{ RA, RS, RB }, PPC_INST_SLW },
{ "sl",      XRC(31,24,0), X_MASK,	PWRCOM,		{ RA, RS, RB }, PPC_INST_SL },
{ "slw.",    XRC(31,24,1), X_MASK,	PPCCOM,		{ RA, RS, RB }, PPC_INST_SLW },
{ "sl.",     XRC(31,24,1), X_MASK,	PWRCOM,		{ RA, RS, RB }, PPC_INST_SL },

{ "cntlzw",  XRC(31,26,0), XRB_MASK,	PPCCOM,		{ RA, RS }, PPC_INST_CNTLZW },
{ "cntlz",   XRC(31,26,0), XRB_MASK,	PWRCOM,		{ RA, RS }, PPC_INST_CNTLZ },
{ "cntlzw.", XRC(31,26,1), XRB_MASK,	PPCCOM,		{ RA, RS }, PPC_INST_CNTLZW },
{ "cntlz.",  XRC(31,26,1), XRB_MASK, 	PWRCOM,		{ RA, RS }, PPC_INST_CNTLZ },

{ "sld",     XRC(31,27,0), X_MASK,	PPC64,		{ RA, RS, RB }, PPC_INST_SLD },
{ "sld.",    XRC(31,27,1), X_MASK,	PPC64,		{ RA, RS, RB }, PPC_INST_SLD },

{ "and",     XRC(31,28,0), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_AND },
{ "and.",    XRC(31,28,1), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_AND },

{ "maskg",   XRC(31,29,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_MASKG },
{ "maskg.",  XRC(31,29,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_MASKG },

{ "icbte",   X(31,30),	X_MASK,		BOOKE64,	{ CT, RA, RB }, PPC_INST_ICBTE },

{ "lwzxe",   X(31,31),	X_MASK,		BOOKE64,	{ RT, RA0, RB }, PPC_INST_LWZXE },

{ "cmplw",   XOPL(31,32,0), XCMPL_MASK, PPCCOM,	{ OBF, RA, RB }, PPC_INST_CMPLW },
{ "cmpld",   XOPL(31,32,1), XCMPL_MASK, PPC64,		{ OBF, RA, RB }, PPC_INST_CMPLD },
{ "cmpl",    X(31,32),	XCMP_MASK,	 PPC,		{ BF, L, RA, RB }, PPC_INST_CMPL },
{ "cmpl",    X(31,32),	XCMPL_MASK,	 PWRCOM,	{ BF, RA, RB }, PPC_INST_CMPL },

{ "subf",    XO(31,40,0,0), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_SUBF },
{ "sub",     XO(31,40,0,0), XO_MASK,	PPC,		{ RT, RB, RA }, PPC_INST_SUB },
{ "subf.",   XO(31,40,0,1), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_SUBF },
{ "sub.",    XO(31,40,0,1), XO_MASK,	PPC,		{ RT, RB, RA }, PPC_INST_SUB },
{ "subfo",   XO(31,40,1,0), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_SUBFO },
{ "subo",    XO(31,40,1,0), XO_MASK,	PPC,		{ RT, RB, RA }, PPC_INST_SUBO },
{ "subfo.",  XO(31,40,1,1), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_SUBFO },
{ "subo.",   XO(31,40,1,1), XO_MASK,	PPC,		{ RT, RB, RA }, PPC_INST_SUBO },

{ "ldux",    X(31,53),	X_MASK,		PPC64,		{ RT, RAL, RB }, PPC_INST_LDUX },

{ "dcbst",   X(31,54),	XRT_MASK,	PPC,		{ RA, RB }, PPC_INST_DCBST },

{ "lwzux",   X(31,55),	X_MASK,		PPCCOM,		{ RT, RAL, RB }, PPC_INST_LWZUX },
{ "lux",     X(31,55),	X_MASK,		PWRCOM,		{ RT, RA, RB }, PPC_INST_LUX },

{ "dcbste",  X(31,62),	XRT_MASK,	BOOKE64,	{ RA, RB }, PPC_INST_DCBSTE },

{ "lwzuxe",  X(31,63),	X_MASK,		BOOKE64,	{ RT, RAL, RB }, PPC_INST_LWZUXE },

{ "cntlzd",  XRC(31,58,0), XRB_MASK,	PPC64,		{ RA, RS }, PPC_INST_CNTLZD },
{ "cntlzd.", XRC(31,58,1), XRB_MASK,	PPC64,		{ RA, RS }, PPC_INST_CNTLZD },

{ "andc",    XRC(31,60,0), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_ANDC },
{ "andc.",   XRC(31,60,1), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_ANDC },

{ "tdlgt",   XTO(31,68,TOLGT), XTO_MASK, PPC64,		{ RA, RB }, PPC_INST_TDLGT },
{ "tdllt",   XTO(31,68,TOLLT), XTO_MASK, PPC64,		{ RA, RB }, PPC_INST_TDLLT },
{ "tdeq",    XTO(31,68,TOEQ), XTO_MASK,  PPC64,		{ RA, RB }, PPC_INST_TDEQ },
{ "tdlge",   XTO(31,68,TOLGE), XTO_MASK, PPC64,		{ RA, RB }, PPC_INST_TDLGE },
{ "tdlnl",   XTO(31,68,TOLNL), XTO_MASK, PPC64,		{ RA, RB }, PPC_INST_TDLNL },
{ "tdlle",   XTO(31,68,TOLLE), XTO_MASK, PPC64,		{ RA, RB }, PPC_INST_TDLLE },
{ "tdlng",   XTO(31,68,TOLNG), XTO_MASK, PPC64,		{ RA, RB }, PPC_INST_TDLNG },
{ "tdgt",    XTO(31,68,TOGT), XTO_MASK,  PPC64,		{ RA, RB }, PPC_INST_TDGT },
{ "tdge",    XTO(31,68,TOGE), XTO_MASK,  PPC64,		{ RA, RB }, PPC_INST_TDGE },
{ "tdnl",    XTO(31,68,TONL), XTO_MASK,  PPC64,		{ RA, RB }, PPC_INST_TDNL },
{ "tdlt",    XTO(31,68,TOLT), XTO_MASK,  PPC64,		{ RA, RB }, PPC_INST_TDLT },
{ "tdle",    XTO(31,68,TOLE), XTO_MASK,  PPC64,		{ RA, RB }, PPC_INST_TDLE },
{ "tdng",    XTO(31,68,TONG), XTO_MASK,  PPC64,		{ RA, RB }, PPC_INST_TDNG },
{ "tdne",    XTO(31,68,TONE), XTO_MASK,  PPC64,		{ RA, RB }, PPC_INST_TDNE },
{ "td",	     X(31,68),	X_MASK,		 PPC64,		{ TO, RA, RB }, PPC_INST_TD },

{ "mulhd",   XO(31,73,0,0), XO_MASK,	 PPC64,		{ RT, RA, RB }, PPC_INST_MULHD },
{ "mulhd.",  XO(31,73,0,1), XO_MASK,	 PPC64,		{ RT, RA, RB }, PPC_INST_MULHD },

{ "mulhw",   XO(31,75,0,0), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_MULHW },
{ "mulhw.",  XO(31,75,0,1), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_MULHW },

{ "dlmzb",   XRC(31,78,0),  X_MASK,	PPC403 | PPC440,	{ RA, RS, RB }, PPC_INST_DLMZB },
{ "dlmzb.",  XRC(31,78,1),  X_MASK,	PPC403 | PPC440,	{ RA, RS, RB }, PPC_INST_DLMZB },

{ "mtsrd",   X(31,82),	XRB_MASK | (1 << 20), PPC64,	{ SR, RS }, PPC_INST_MTSRD },

{ "mfmsr",   X(31,83),	XRARB_MASK,	COM,		{ RT }, PPC_INST_MFMSR },

{ "ldarx",   X(31,84),	XEH_MASK,	PPC64,		{ RT, RA0, RB, EH }, PPC_INST_LDARX },

{ "dcbfl",   XOPL(31,86,1), XRT_MASK,	POWER5,		{ RA, RB }, PPC_INST_DCBFL },
{ "dcbf",    X(31,86),	XLRT_MASK,	PPC,		{ RA, RB, L }, PPC_INST_DCBF },

{ "lbzx",    X(31,87),	X_MASK,		COM,		{ RT, RA0, RB }, PPC_INST_LBZX },

{ "dcbfe",   X(31,94),	XRT_MASK,	BOOKE64,	{ RA, RB }, PPC_INST_DCBFE },

{ "lbzxe",   X(31,95),	X_MASK,		BOOKE64,	{ RT, RA0, RB }, PPC_INST_LBZXE },

{ "neg",     XO(31,104,0,0), XORB_MASK,	COM,		{ RT, RA }, PPC_INST_NEG },
{ "neg.",    XO(31,104,0,1), XORB_MASK,	COM,		{ RT, RA }, PPC_INST_NEG },
{ "nego",    XO(31,104,1,0), XORB_MASK,	COM,		{ RT, RA }, PPC_INST_NEGO },
{ "nego.",   XO(31,104,1,1), XORB_MASK,	COM,		{ RT, RA }, PPC_INST_NEGO },

{ "mul",     XO(31,107,0,0), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_MUL },
{ "mul.",    XO(31,107,0,1), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_MUL },
{ "mulo",    XO(31,107,1,0), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_MULO },
{ "mulo.",   XO(31,107,1,1), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_MULO },

{ "mtsrdin", X(31,114),	XRA_MASK,	PPC64,		{ RS, RB }, PPC_INST_MTSRDIN },

{ "clf",     X(31,118), XTO_MASK,	POWER,		{ RA, RB }, PPC_INST_CLF },

{ "lbzux",   X(31,119),	X_MASK,		COM,		{ RT, RAL, RB }, PPC_INST_LBZUX },

{ "popcntb", X(31,122), XRB_MASK,	POWER5,		{ RA, RS }, PPC_INST_POPCNTB },

{ "not",     XRC(31,124,0), X_MASK,	COM,		{ RA, RS, RBS }, PPC_INST_NOT },
{ "nor",     XRC(31,124,0), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_NOR },
{ "not.",    XRC(31,124,1), X_MASK,	COM,		{ RA, RS, RBS }, PPC_INST_NOT },
{ "nor.",    XRC(31,124,1), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_NOR },

{ "lwarxe",  X(31,126),	X_MASK,		BOOKE64,	{ RT, RA0, RB }, PPC_INST_LWARXE },

{ "lbzuxe",  X(31,127),	X_MASK,		BOOKE64,	{ RT, RAL, RB }, PPC_INST_LBZUXE },

{ "wrtee",   X(31,131),	XRARB_MASK,	PPC403 | BOOKE,	{ RS }, PPC_INST_WRTEE },

{ "dcbtstls",X(31,134),	X_MASK,		PPCCHLK,	{ CT, RA, RB }, PPC_INST_DCBTSTLS },

{ "subfe",   XO(31,136,0,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_SUBFE },
{ "sfe",     XO(31,136,0,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_SFE },
{ "subfe.",  XO(31,136,0,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_SUBFE },
{ "sfe.",    XO(31,136,0,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_SFE },
{ "subfeo",  XO(31,136,1,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_SUBFEO },
{ "sfeo",    XO(31,136,1,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_SFEO },
{ "subfeo.", XO(31,136,1,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_SUBFEO },
{ "sfeo.",   XO(31,136,1,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_SFEO },

{ "adde",    XO(31,138,0,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADDE },
{ "ae",      XO(31,138,0,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_AE },
{ "adde.",   XO(31,138,0,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADDE },
{ "ae.",     XO(31,138,0,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_AE },
{ "addeo",   XO(31,138,1,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADDEO },
{ "aeo",     XO(31,138,1,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_AEO },
{ "addeo.",  XO(31,138,1,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADDEO },
{ "aeo.",    XO(31,138,1,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_AEO },

{ "dcbtstlse",X(31,142),X_MASK,		PPCCHLK64,	{ CT, RA, RB }, PPC_INST_DCBTSTLSE },

{ "mtocrf",  XFXM(31,144,0,1), XFXFXM_MASK, COM,	{ FXM, RS }, PPC_INST_MTOCRF },
{ "mtcr",    XFXM(31,144,0xff,0), XRARB_MASK, COM,	{ RS }, PPC_INST_MTCR },
{ "mtcrf",   X(31,144),	XFXFXM_MASK,	COM,		{ FXM, RS }, PPC_INST_MTCRF },

{ "mtmsr",   X(31,146),	XRARB_MASK,	COM,		{ RS }, PPC_INST_MTMSR },

{ "stdx",    X(31,149), X_MASK,		PPC64,		{ RS, RA0, RB }, PPC_INST_STDX },

{ "stwcx.",  XRC(31,150,1), X_MASK,	PPC,		{ RS, RA0, RB }, PPC_INST_STWCX },

{ "stwx",    X(31,151), X_MASK,		PPCCOM,		{ RS, RA0, RB }, PPC_INST_STWX },
{ "stx",     X(31,151), X_MASK,		PWRCOM,		{ RS, RA, RB }, PPC_INST_STX },

{ "stwcxe.", XRC(31,158,1), X_MASK,	BOOKE64,	{ RS, RA0, RB }, PPC_INST_STWCXE },

{ "stwxe",   X(31,159), X_MASK,		BOOKE64,	{ RS, RA0, RB }, PPC_INST_STWXE },

{ "slq",     XRC(31,152,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SLQ },
{ "slq.",    XRC(31,152,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SLQ },

{ "sle",     XRC(31,153,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SLE },
{ "sle.",    XRC(31,153,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SLE },

{ "prtyw",   X(31,154),	XRB_MASK,	POWER6,		{ RA, RS }, PPC_INST_PRTYW },

{ "wrteei",  X(31,163),	XE_MASK,	PPC403 | BOOKE,	{ E }, PPC_INST_WRTEEI },

{ "dcbtls",  X(31,166),	X_MASK,		PPCCHLK,	{ CT, RA, RB }, PPC_INST_DCBTLS },
{ "dcbtlse", X(31,174),	X_MASK,		PPCCHLK64,	{ CT, RA, RB }, PPC_INST_DCBTLSE },

{ "mtmsrd",  X(31,178),	XRLARB_MASK,	PPC64,		{ RS, A_L }, PPC_INST_MTMSRD },

{ "stdux",   X(31,181),	X_MASK,		PPC64,		{ RS, RAS, RB }, PPC_INST_STDUX },

{ "stwux",   X(31,183),	X_MASK,		PPCCOM,		{ RS, RAS, RB }, PPC_INST_STWUX },
{ "stux",    X(31,183),	X_MASK,		PWRCOM,		{ RS, RA0, RB }, PPC_INST_STUX },

{ "sliq",    XRC(31,184,0), X_MASK,	M601,		{ RA, RS, SH }, PPC_INST_SLIQ },
{ "sliq.",   XRC(31,184,1), X_MASK,	M601,		{ RA, RS, SH }, PPC_INST_SLIQ },

{ "prtyd",   X(31,186),	XRB_MASK,	POWER6,		{ RA, RS }, PPC_INST_PRTYD },

{ "stwuxe",  X(31,191),	X_MASK,		BOOKE64,	{ RS, RAS, RB }, PPC_INST_STWUXE },

{ "subfze",  XO(31,200,0,0), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_SUBFZE },
{ "sfze",    XO(31,200,0,0), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_SFZE },
{ "subfze.", XO(31,200,0,1), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_SUBFZE },
{ "sfze.",   XO(31,200,0,1), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_SFZE },
{ "subfzeo", XO(31,200,1,0), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_SUBFZEO },
{ "sfzeo",   XO(31,200,1,0), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_SFZEO },
{ "subfzeo.",XO(31,200,1,1), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_SUBFZEO },
{ "sfzeo.",  XO(31,200,1,1), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_SFZEO },

{ "addze",   XO(31,202,0,0), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_ADDZE },
{ "aze",     XO(31,202,0,0), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_AZE },
{ "addze.",  XO(31,202,0,1), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_ADDZE },
{ "aze.",    XO(31,202,0,1), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_AZE },
{ "addzeo",  XO(31,202,1,0), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_ADDZEO },
{ "azeo",    XO(31,202,1,0), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_AZEO },
{ "addzeo.", XO(31,202,1,1), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_ADDZEO },
{ "azeo.",   XO(31,202,1,1), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_AZEO },

{ "mtsr",    X(31,210),	XRB_MASK | (1 << 20), COM32,	{ SR, RS }, PPC_INST_MTSR },

{ "stdcx.",  XRC(31,214,1), X_MASK,	PPC64,		{ RS, RA0, RB }, PPC_INST_STDCX },

{ "stbx",    X(31,215),	X_MASK,		COM,		{ RS, RA0, RB }, PPC_INST_STBX },

{ "sllq",    XRC(31,216,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SLLQ },
{ "sllq.",   XRC(31,216,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SLLQ },

{ "sleq",    XRC(31,217,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SLEQ },
{ "sleq.",   XRC(31,217,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SLEQ },

{ "stbxe",   X(31,223),	X_MASK,		BOOKE64,	{ RS, RA0, RB }, PPC_INST_STBXE },

{ "icblc",   X(31,230),	X_MASK,		PPCCHLK,	{ CT, RA, RB }, PPC_INST_ICBLC },

{ "subfme",  XO(31,232,0,0), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_SUBFME },
{ "sfme",    XO(31,232,0,0), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_SFME },
{ "subfme.", XO(31,232,0,1), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_SUBFME },
{ "sfme.",   XO(31,232,0,1), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_SFME },
{ "subfmeo", XO(31,232,1,0), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_SUBFMEO },
{ "sfmeo",   XO(31,232,1,0), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_SFMEO },
{ "subfmeo.",XO(31,232,1,1), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_SUBFMEO },
{ "sfmeo.",  XO(31,232,1,1), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_SFMEO },

{ "mulld",   XO(31,233,0,0), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_MULLD },
{ "mulld.",  XO(31,233,0,1), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_MULLD },
{ "mulldo",  XO(31,233,1,0), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_MULLDO },
{ "mulldo.", XO(31,233,1,1), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_MULLDO },

{ "addme",   XO(31,234,0,0), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_ADDME },
{ "ame",     XO(31,234,0,0), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_AME },
{ "addme.",  XO(31,234,0,1), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_ADDME },
{ "ame.",    XO(31,234,0,1), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_AME },
{ "addmeo",  XO(31,234,1,0), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_ADDMEO },
{ "ameo",    XO(31,234,1,0), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_AMEO },
{ "addmeo.", XO(31,234,1,1), XORB_MASK, PPCCOM,		{ RT, RA }, PPC_INST_ADDMEO },
{ "ameo.",   XO(31,234,1,1), XORB_MASK, PWRCOM,		{ RT, RA }, PPC_INST_AMEO },

{ "mullw",   XO(31,235,0,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_MULLW },
{ "muls",    XO(31,235,0,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_MULS },
{ "mullw.",  XO(31,235,0,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_MULLW },
{ "muls.",   XO(31,235,0,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_MULS },
{ "mullwo",  XO(31,235,1,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_MULLWO },
{ "mulso",   XO(31,235,1,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_MULSO },
{ "mullwo.", XO(31,235,1,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_MULLWO },
{ "mulso.",  XO(31,235,1,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_MULSO },

{ "icblce",  X(31,238),	X_MASK,		PPCCHLK64,	{ CT, RA, RB }, PPC_INST_ICBLCE },
{ "mtsrin",  X(31,242),	XRA_MASK,	PPC32,		{ RS, RB }, PPC_INST_MTSRIN },
{ "mtsri",   X(31,242),	XRA_MASK,	POWER32,	{ RS, RB }, PPC_INST_MTSRI },

{ "dcbtst",  X(31,246),	X_MASK,	PPC,			{ CT, RA, RB }, PPC_INST_DCBTST },

{ "stbux",   X(31,247),	X_MASK,		COM,		{ RS, RAS, RB }, PPC_INST_STBUX },

{ "slliq",   XRC(31,248,0), X_MASK,	M601,		{ RA, RS, SH }, PPC_INST_SLLIQ },
{ "slliq.",  XRC(31,248,1), X_MASK,	M601,		{ RA, RS, SH }, PPC_INST_SLLIQ },

{ "dcbtste", X(31,253),	X_MASK,		BOOKE64,	{ CT, RA, RB }, PPC_INST_DCBTSTE },

{ "stbuxe",  X(31,255),	X_MASK,		BOOKE64,	{ RS, RAS, RB }, PPC_INST_STBUXE },

{ "mfdcrx",  X(31,259),	X_MASK,		BOOKE,		{ RS, RA }, PPC_INST_MFDCRX },

{ "doz",     XO(31,264,0,0), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DOZ },
{ "doz.",    XO(31,264,0,1), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DOZ },
{ "dozo",    XO(31,264,1,0), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DOZO },
{ "dozo.",   XO(31,264,1,1), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DOZO },

{ "add",     XO(31,266,0,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADD },
{ "cax",     XO(31,266,0,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_CAX },
{ "add.",    XO(31,266,0,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADD },
{ "cax.",    XO(31,266,0,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_CAX },
{ "addo",    XO(31,266,1,0), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADDO },
{ "caxo",    XO(31,266,1,0), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_CAXO },
{ "addo.",   XO(31,266,1,1), XO_MASK,	PPCCOM,		{ RT, RA, RB }, PPC_INST_ADDO },
{ "caxo.",   XO(31,266,1,1), XO_MASK,	PWRCOM,		{ RT, RA, RB }, PPC_INST_CAXO },

{ "tlbiel",  X(31,274), XRTLRA_MASK,	POWER4,		{ RB, L }, PPC_INST_TLBIEL },

{ "mfapidi", X(31,275), X_MASK,		BOOKE,		{ RT, RA }, PPC_INST_MFAPIDI },

{ "lscbx",   XRC(31,277,0), X_MASK,	M601,		{ RT, RA, RB }, PPC_INST_LSCBX },
{ "lscbx.",  XRC(31,277,1), X_MASK,	M601,		{ RT, RA, RB }, PPC_INST_LSCBX },

{ "dcbt",    X(31,278),	X_MASK,		PPC,		{ CT, RA, RB }, PPC_INST_DCBT },

{ "lhzx",    X(31,279),	X_MASK,		COM,		{ RT, RA0, RB }, PPC_INST_LHZX },

{ "eqv",     XRC(31,284,0), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_EQV },
{ "eqv.",    XRC(31,284,1), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_EQV },

{ "dcbte",   X(31,286),	X_MASK,		BOOKE64,	{ CT, RA, RB }, PPC_INST_DCBTE },

{ "lhzxe",   X(31,287),	X_MASK,		BOOKE64,	{ RT, RA0, RB }, PPC_INST_LHZXE },

{ "tlbie",   X(31,306),	XRTLRA_MASK,	PPC,		{ RB, L }, PPC_INST_TLBIE },
{ "tlbi",    X(31,306),	XRT_MASK,	POWER,		{ RA0, RB }, PPC_INST_TLBI },

{ "eciwx",   X(31,310), X_MASK,		PPC,		{ RT, RA, RB }, PPC_INST_ECIWX },

{ "lhzux",   X(31,311),	X_MASK,		COM,		{ RT, RAL, RB }, PPC_INST_LHZUX },

{ "xor",     XRC(31,316,0), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_XOR },
{ "xor.",    XRC(31,316,1), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_XOR },

{ "lhzuxe",  X(31,319),	X_MASK,		BOOKE64,	{ RT, RAL, RB }, PPC_INST_LHZUXE },

{ "mfexisr",  XSPR(31,323,64),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFEXISR },
{ "mfexier",  XSPR(31,323,66),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFEXIER },
{ "mfbr0",    XSPR(31,323,128), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFBR0 },
{ "mfbr1",    XSPR(31,323,129), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFBR1 },
{ "mfbr2",    XSPR(31,323,130), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFBR2 },
{ "mfbr3",    XSPR(31,323,131), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFBR3 },
{ "mfbr4",    XSPR(31,323,132), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFBR4 },
{ "mfbr5",    XSPR(31,323,133), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFBR5 },
{ "mfbr6",    XSPR(31,323,134), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFBR6 },
{ "mfbr7",    XSPR(31,323,135), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFBR7 },
{ "mfbear",   XSPR(31,323,144), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFBEAR },
{ "mfbesr",   XSPR(31,323,145), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFBESR },
{ "mfiocr",   XSPR(31,323,160), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFIOCR },
{ "mfdmacr0", XSPR(31,323,192), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACR0 },
{ "mfdmact0", XSPR(31,323,193), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACT0 },
{ "mfdmada0", XSPR(31,323,194), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMADA0 },
{ "mfdmasa0", XSPR(31,323,195), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMASA0 },
{ "mfdmacc0", XSPR(31,323,196), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACC0 },
{ "mfdmacr1", XSPR(31,323,200), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACR1 },
{ "mfdmact1", XSPR(31,323,201), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACT1 },
{ "mfdmada1", XSPR(31,323,202), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMADA1 },
{ "mfdmasa1", XSPR(31,323,203), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMASA1 },
{ "mfdmacc1", XSPR(31,323,204), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACC1 },
{ "mfdmacr2", XSPR(31,323,208), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACR2 },
{ "mfdmact2", XSPR(31,323,209), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACT2 },
{ "mfdmada2", XSPR(31,323,210), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMADA2 },
{ "mfdmasa2", XSPR(31,323,211), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMASA2 },
{ "mfdmacc2", XSPR(31,323,212), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACC2 },
{ "mfdmacr3", XSPR(31,323,216), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACR3 },
{ "mfdmact3", XSPR(31,323,217), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACT3 },
{ "mfdmada3", XSPR(31,323,218), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMADA3 },
{ "mfdmasa3", XSPR(31,323,219), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMASA3 },
{ "mfdmacc3", XSPR(31,323,220), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMACC3 },
{ "mfdmasr",  XSPR(31,323,224), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDMASR },
{ "mfdcr",    X(31,323),	X_MASK,	PPC403 | BOOKE,	{ RT, SPR }, PPC_INST_MFDCR },

{ "div",     XO(31,331,0,0), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DIV },
{ "div.",    XO(31,331,0,1), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DIV },
{ "divo",    XO(31,331,1,0), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DIVO },
{ "divo.",   XO(31,331,1,1), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DIVO },

{ "mfpmr",   X(31,334),	X_MASK,		PPCPMR,		{ RT, PMR }, PPC_INST_MFPMR },

{ "mfmq",       XSPR(31,339,0),    XSPR_MASK, M601,	{ RT }, PPC_INST_MFMQ },
{ "mfxer",      XSPR(31,339,1),    XSPR_MASK, COM,	{ RT }, PPC_INST_MFXER },
{ "mfrtcu",     XSPR(31,339,4),    XSPR_MASK, COM,	{ RT }, PPC_INST_MFRTCU },
{ "mfrtcl",     XSPR(31,339,5),    XSPR_MASK, COM,	{ RT }, PPC_INST_MFRTCL },
{ "mfdec",      XSPR(31,339,6),    XSPR_MASK, MFDEC1,	{ RT }, PPC_INST_MFDEC },
{ "mfdec",      XSPR(31,339,22),   XSPR_MASK, MFDEC2,	{ RT }, PPC_INST_MFDEC },
{ "mflr",       XSPR(31,339,8),    XSPR_MASK, COM,	{ RT }, PPC_INST_MFLR },
{ "mfctr",      XSPR(31,339,9),    XSPR_MASK, COM,	{ RT }, PPC_INST_MFCTR },
{ "mftid",      XSPR(31,339,17),   XSPR_MASK, POWER,	{ RT }, PPC_INST_MFTID },
{ "mfdsisr",    XSPR(31,339,18),   XSPR_MASK, COM,	{ RT }, PPC_INST_MFDSISR },
{ "mfdar",      XSPR(31,339,19),   XSPR_MASK, COM,	{ RT }, PPC_INST_MFDAR },
{ "mfsdr0",     XSPR(31,339,24),   XSPR_MASK, POWER,	{ RT }, PPC_INST_MFSDR0 },
{ "mfsdr1",     XSPR(31,339,25),   XSPR_MASK, COM,	{ RT }, PPC_INST_MFSDR1 },
{ "mfsrr0",     XSPR(31,339,26),   XSPR_MASK, COM,	{ RT }, PPC_INST_MFSRR0 },
{ "mfsrr1",     XSPR(31,339,27),   XSPR_MASK, COM,	{ RT }, PPC_INST_MFSRR1 },
{ "mfcfar",     XSPR(31,339,28),   XSPR_MASK, POWER6,	{ RT }, PPC_INST_MFCFAR },
{ "mfpid",      XSPR(31,339,48),   XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFPID },
{ "mfpid",      XSPR(31,339,945),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFPID },
{ "mfcsrr0",    XSPR(31,339,58),   XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFCSRR0 },
{ "mfcsrr1",    XSPR(31,339,59),   XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFCSRR1 },
{ "mfdear",     XSPR(31,339,61),   XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFDEAR },
{ "mfdear",     XSPR(31,339,981),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDEAR },
{ "mfesr",      XSPR(31,339,62),   XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFESR },
{ "mfesr",      XSPR(31,339,980),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFESR },
{ "mfivpr",     XSPR(31,339,63),   XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVPR },
{ "mfcmpa",     XSPR(31,339,144),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFCMPA },
{ "mfcmpb",     XSPR(31,339,145),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFCMPB },
{ "mfcmpc",     XSPR(31,339,146),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFCMPC },
{ "mfcmpd",     XSPR(31,339,147),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFCMPD },
{ "mficr",      XSPR(31,339,148),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFICR },
{ "mfder",      XSPR(31,339,149),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFDER },
{ "mfcounta",   XSPR(31,339,150),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFCOUNTA },
{ "mfcountb",   XSPR(31,339,151),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFCOUNTB },
{ "mfcmpe",     XSPR(31,339,152),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFCMPE },
{ "mfcmpf",     XSPR(31,339,153),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFCMPF },
{ "mfcmpg",     XSPR(31,339,154),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFCMPG },
{ "mfcmph",     XSPR(31,339,155),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFCMPH },
{ "mflctrl1",   XSPR(31,339,156),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFLCTRL1 },
{ "mflctrl2",   XSPR(31,339,157),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFLCTRL2 },
{ "mfictrl",    XSPR(31,339,158),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFICTRL },
{ "mfbar",      XSPR(31,339,159),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFBAR },
{ "mfvrsave",   XSPR(31,339,256),  XSPR_MASK, PPCVEC,	{ RT }, PPC_INST_MFVRSAVE },
{ "mfusprg0",   XSPR(31,339,256),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFUSPRG0 },
{ "mftb",       X(31,371),	   X_MASK,    CLASSIC,	{ RT, TBR }, PPC_INST_MFTB },
{ "mftb",       XSPR(31,339,268),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFTB },
{ "mftbl",      XSPR(31,371,268),  XSPR_MASK, CLASSIC,	{ RT }, PPC_INST_MFTBL },
{ "mftbl",      XSPR(31,339,268),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFTBL },
{ "mftbu",      XSPR(31,371,269),  XSPR_MASK, CLASSIC,	{ RT }, PPC_INST_MFTBU },
{ "mftbu",      XSPR(31,339,269),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFTBU },
{ "mfsprg",     XSPR(31,339,256),  XSPRG_MASK, PPC,	{ RT, SPRG }, PPC_INST_MFSPRG },
{ "mfsprg0",    XSPR(31,339,272),  XSPR_MASK, PPC,	{ RT }, PPC_INST_MFSPRG0 },
{ "mfsprg1",    XSPR(31,339,273),  XSPR_MASK, PPC,	{ RT }, PPC_INST_MFSPRG1 },
{ "mfsprg2",    XSPR(31,339,274),  XSPR_MASK, PPC,	{ RT }, PPC_INST_MFSPRG2 },
{ "mfsprg3",    XSPR(31,339,275),  XSPR_MASK, PPC,	{ RT }, PPC_INST_MFSPRG3 },
{ "mfsprg4",    XSPR(31,339,260),  XSPR_MASK, PPC405 | BOOKE,	{ RT }, PPC_INST_MFSPRG4 },
{ "mfsprg5",    XSPR(31,339,261),  XSPR_MASK, PPC405 | BOOKE,	{ RT }, PPC_INST_MFSPRG5 },
{ "mfsprg6",    XSPR(31,339,262),  XSPR_MASK, PPC405 | BOOKE,	{ RT }, PPC_INST_MFSPRG6 },
{ "mfsprg7",    XSPR(31,339,263),  XSPR_MASK, PPC405 | BOOKE,	{ RT }, PPC_INST_MFSPRG7 },
{ "mfasr",      XSPR(31,339,280),  XSPR_MASK, PPC64,	{ RT }, PPC_INST_MFASR },
{ "mfear",      XSPR(31,339,282),  XSPR_MASK, PPC,	{ RT }, PPC_INST_MFEAR },
{ "mfpir",      XSPR(31,339,286),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFPIR },
{ "mfpvr",      XSPR(31,339,287),  XSPR_MASK, PPC,	{ RT }, PPC_INST_MFPVR },
{ "mfdbsr",     XSPR(31,339,304),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFDBSR },
{ "mfdbsr",     XSPR(31,339,1008), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDBSR },
{ "mfdbcr0",    XSPR(31,339,308),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFDBCR0 },
{ "mfdbcr0",    XSPR(31,339,1010), XSPR_MASK, PPC405,	{ RT }, PPC_INST_MFDBCR0 },
{ "mfdbcr1",    XSPR(31,339,309),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFDBCR1 },
{ "mfdbcr1",    XSPR(31,339,957),  XSPR_MASK, PPC405,	{ RT }, PPC_INST_MFDBCR1 },
{ "mfdbcr2",    XSPR(31,339,310),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFDBCR2 },
{ "mfiac1",     XSPR(31,339,312),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIAC1 },
{ "mfiac1",     XSPR(31,339,1012), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFIAC1 },
{ "mfiac2",     XSPR(31,339,313),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIAC2 },
{ "mfiac2",     XSPR(31,339,1013), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFIAC2 },
{ "mfiac3",     XSPR(31,339,314),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIAC3 },
{ "mfiac3",     XSPR(31,339,948),  XSPR_MASK, PPC405,	{ RT }, PPC_INST_MFIAC3 },
{ "mfiac4",     XSPR(31,339,315),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIAC4 },
{ "mfiac4",     XSPR(31,339,949),  XSPR_MASK, PPC405,	{ RT }, PPC_INST_MFIAC4 },
{ "mfdac1",     XSPR(31,339,316),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFDAC1 },
{ "mfdac1",     XSPR(31,339,1014), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDAC1 },
{ "mfdac2",     XSPR(31,339,317),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFDAC2 },
{ "mfdac2",     XSPR(31,339,1015), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDAC2 },
{ "mfdvc1",     XSPR(31,339,318),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFDVC1 },
{ "mfdvc1",     XSPR(31,339,950),  XSPR_MASK, PPC405,	{ RT }, PPC_INST_MFDVC1 },
{ "mfdvc2",     XSPR(31,339,319),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFDVC2 },
{ "mfdvc2",     XSPR(31,339,951),  XSPR_MASK, PPC405,	{ RT }, PPC_INST_MFDVC2 },
{ "mftsr",      XSPR(31,339,336),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFTSR },
{ "mftsr",      XSPR(31,339,984),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFTSR },
{ "mftcr",      XSPR(31,339,340),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFTCR },
{ "mftcr",      XSPR(31,339,986),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFTCR },
{ "mfivor0",    XSPR(31,339,400),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR0 },
{ "mfivor1",    XSPR(31,339,401),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR1 },
{ "mfivor2",    XSPR(31,339,402),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR2 },
{ "mfivor3",    XSPR(31,339,403),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR3 },
{ "mfivor4",    XSPR(31,339,404),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR4 },
{ "mfivor5",    XSPR(31,339,405),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR5 },
{ "mfivor6",    XSPR(31,339,406),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR6 },
{ "mfivor7",    XSPR(31,339,407),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR7 },
{ "mfivor8",    XSPR(31,339,408),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR8 },
{ "mfivor9",    XSPR(31,339,409),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR9 },
{ "mfivor10",   XSPR(31,339,410),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR10 },
{ "mfivor11",   XSPR(31,339,411),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR11 },
{ "mfivor12",   XSPR(31,339,412),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR12 },
{ "mfivor13",   XSPR(31,339,413),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR13 },
{ "mfivor14",   XSPR(31,339,414),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR14 },
{ "mfivor15",   XSPR(31,339,415),  XSPR_MASK, BOOKE,    { RT }, PPC_INST_MFIVOR15 },
{ "mfspefscr",  XSPR(31,339,512),  XSPR_MASK, PPCSPE,	{ RT }, PPC_INST_MFSPEFSCR },
{ "mfbbear",    XSPR(31,339,513),  XSPR_MASK, PPCBRLK,  { RT }, PPC_INST_MFBBEAR },
{ "mfbbtar",    XSPR(31,339,514),  XSPR_MASK, PPCBRLK,  { RT }, PPC_INST_MFBBTAR },
{ "mfivor32",   XSPR(31,339,528),  XSPR_MASK, PPCSPE,	{ RT }, PPC_INST_MFIVOR32 },
{ "mfivor33",   XSPR(31,339,529),  XSPR_MASK, PPCSPE,	{ RT }, PPC_INST_MFIVOR33 },
{ "mfivor34",   XSPR(31,339,530),  XSPR_MASK, PPCSPE,	{ RT }, PPC_INST_MFIVOR34 },
{ "mfivor35",   XSPR(31,339,531),  XSPR_MASK, PPCPMR,	{ RT }, PPC_INST_MFIVOR35 },
{ "mfibatu",    XSPR(31,339,528),  XSPRBAT_MASK, PPC,	{ RT, SPRBAT }, PPC_INST_MFIBATU },
{ "mfibatl",    XSPR(31,339,529),  XSPRBAT_MASK, PPC,	{ RT, SPRBAT }, PPC_INST_MFIBATL },
{ "mfdbatu",    XSPR(31,339,536),  XSPRBAT_MASK, PPC,	{ RT, SPRBAT }, PPC_INST_MFDBATU },
{ "mfdbatl",    XSPR(31,339,537),  XSPRBAT_MASK, PPC,	{ RT, SPRBAT }, PPC_INST_MFDBATL },
{ "mfic_cst",   XSPR(31,339,560),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFIC_CST },
{ "mfic_adr",   XSPR(31,339,561),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFIC_ADR },
{ "mfic_dat",   XSPR(31,339,562),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFIC_DAT },
{ "mfdc_cst",   XSPR(31,339,568),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFDC_CST },
{ "mfdc_adr",   XSPR(31,339,569),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFDC_ADR },
{ "mfmcsrr0",   XSPR(31,339,570),  XSPR_MASK, PPCRFMCI, { RT }, PPC_INST_MFMCSRR0 },
{ "mfdc_dat",   XSPR(31,339,570),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFDC_DAT },
{ "mfmcsrr1",   XSPR(31,339,571),  XSPR_MASK, PPCRFMCI, { RT }, PPC_INST_MFMCSRR1 },
{ "mfmcsr",     XSPR(31,339,572),  XSPR_MASK, PPCRFMCI, { RT }, PPC_INST_MFMCSR },
{ "mfmcar",     XSPR(31,339,573),  XSPR_MASK, PPCRFMCI, { RT }, PPC_INST_MFMCAR },
{ "mfdpdr",     XSPR(31,339,630),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFDPDR },
{ "mfdpir",     XSPR(31,339,631),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFDPIR },
{ "mfimmr",     XSPR(31,339,638),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFIMMR },
{ "mfmi_ctr",   XSPR(31,339,784),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMI_CTR },
{ "mfmi_ap",    XSPR(31,339,786),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMI_AP },
{ "mfmi_epn",   XSPR(31,339,787),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMI_EPN },
{ "mfmi_twc",   XSPR(31,339,789),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMI_TWC },
{ "mfmi_rpn",   XSPR(31,339,790),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMI_RPN },
{ "mfmd_ctr",   XSPR(31,339,792),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMD_CTR },
{ "mfm_casid",  XSPR(31,339,793),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFM_CASID },
{ "mfmd_ap",    XSPR(31,339,794),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMD_AP },
{ "mfmd_epn",   XSPR(31,339,795),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMD_EPN },
{ "mfmd_twb",   XSPR(31,339,796),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMD_TWB },
{ "mfmd_twc",   XSPR(31,339,797),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMD_TWC },
{ "mfmd_rpn",   XSPR(31,339,798),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMD_RPN },
{ "mfm_tw",     XSPR(31,339,799),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFM_TW },
{ "mfmi_dbcam", XSPR(31,339,816),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMI_DBCAM },
{ "mfmi_dbram0",XSPR(31,339,817),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMI_DBRAM0 },
{ "mfmi_dbram1",XSPR(31,339,818),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMI_DBRAM1 },
{ "mfmd_dbcam", XSPR(31,339,824),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMD_DBCAM },
{ "mfmd_dbram0",XSPR(31,339,825),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMD_DBRAM0 },
{ "mfmd_dbram1",XSPR(31,339,826),  XSPR_MASK, PPC860,	{ RT }, PPC_INST_MFMD_DBRAM1 },
{ "mfummcr0",   XSPR(31,339,936),  XSPR_MASK, PPC750,   { RT }, PPC_INST_MFUMMCR0 },
{ "mfupmc1",    XSPR(31,339,937),  XSPR_MASK, PPC750,   { RT }, PPC_INST_MFUPMC1 },
{ "mfupmc2",    XSPR(31,339,938),  XSPR_MASK, PPC750,   { RT }, PPC_INST_MFUPMC2 },
{ "mfusia",     XSPR(31,339,939),  XSPR_MASK, PPC750,   { RT }, PPC_INST_MFUSIA },
{ "mfummcr1",   XSPR(31,339,940),  XSPR_MASK, PPC750,   { RT }, PPC_INST_MFUMMCR1 },
{ "mfupmc3",    XSPR(31,339,941),  XSPR_MASK, PPC750,   { RT }, PPC_INST_MFUPMC3 },
{ "mfupmc4",    XSPR(31,339,942),  XSPR_MASK, PPC750,   { RT }, PPC_INST_MFUPMC4 },
{ "mfzpr",   	XSPR(31,339,944),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFZPR },
{ "mfccr0",  	XSPR(31,339,947),  XSPR_MASK, PPC405,	{ RT }, PPC_INST_MFCCR0 },
{ "mfmmcr0",	XSPR(31,339,952),  XSPR_MASK, PPC750,	{ RT }, PPC_INST_MFMMCR0 },
{ "mfpmc1",	XSPR(31,339,953),  XSPR_MASK, PPC750,	{ RT }, PPC_INST_MFPMC1 },
{ "mfsgr",	XSPR(31,339,953),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFSGR },
{ "mfpmc2",	XSPR(31,339,954),  XSPR_MASK, PPC750,	{ RT }, PPC_INST_MFPMC2 },
{ "mfdcwr", 	XSPR(31,339,954),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDCWR },
{ "mfsia",	XSPR(31,339,955),  XSPR_MASK, PPC750,	{ RT }, PPC_INST_MFSIA },
{ "mfsler",	XSPR(31,339,955),  XSPR_MASK, PPC405,	{ RT }, PPC_INST_MFSLER },
{ "mfmmcr1",	XSPR(31,339,956),  XSPR_MASK, PPC750,	{ RT }, PPC_INST_MFMMCR1 },
{ "mfsu0r",	XSPR(31,339,956),  XSPR_MASK, PPC405,	{ RT }, PPC_INST_MFSU0R },
{ "mfpmc3",	XSPR(31,339,957),  XSPR_MASK, PPC750,	{ RT }, PPC_INST_MFPMC3 },
{ "mfpmc4",	XSPR(31,339,958),  XSPR_MASK, PPC750,	{ RT }, PPC_INST_MFPMC4 },
{ "mficdbdr",   XSPR(31,339,979),  XSPR_MASK, PPC403,   { RT }, PPC_INST_MFICDBDR },
{ "mfevpr",     XSPR(31,339,982),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFEVPR },
{ "mfcdbcr",    XSPR(31,339,983),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFCDBCR },
{ "mfpit",      XSPR(31,339,987),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFPIT },
{ "mftbhi",     XSPR(31,339,988),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFTBHI },
{ "mftblo",     XSPR(31,339,989),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFTBLO },
{ "mfsrr2",     XSPR(31,339,990),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFSRR2 },
{ "mfsrr3",     XSPR(31,339,991),  XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFSRR3 },
{ "mfl2cr",     XSPR(31,339,1017), XSPR_MASK, PPC750,   { RT }, PPC_INST_MFL2CR },
{ "mfdccr",     XSPR(31,339,1018), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFDCCR },
{ "mficcr",     XSPR(31,339,1019), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFICCR },
{ "mfictc",     XSPR(31,339,1019), XSPR_MASK, PPC750,   { RT }, PPC_INST_MFICTC },
{ "mfpbl1",     XSPR(31,339,1020), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFPBL1 },
{ "mfthrm1",    XSPR(31,339,1020), XSPR_MASK, PPC750,   { RT }, PPC_INST_MFTHRM1 },
{ "mfpbu1",     XSPR(31,339,1021), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFPBU1 },
{ "mfthrm2",    XSPR(31,339,1021), XSPR_MASK, PPC750,   { RT }, PPC_INST_MFTHRM2 },
{ "mfpbl2",     XSPR(31,339,1022), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFPBL2 },
{ "mfthrm3",    XSPR(31,339,1022), XSPR_MASK, PPC750,   { RT }, PPC_INST_MFTHRM3 },
{ "mfpbu2",     XSPR(31,339,1023), XSPR_MASK, PPC403,	{ RT }, PPC_INST_MFPBU2 },
{ "mfspr",      X(31,339),	   X_MASK,    COM,	{ RT, SPR }, PPC_INST_MFSPR },

{ "lwax",    X(31,341),	X_MASK,		PPC64,		{ RT, RA0, RB }, PPC_INST_LWAX },

{ "dst",     XDSS(31,342,0), XDSS_MASK,	PPCVEC,		{ RA, RB, STRM }, PPC_INST_DST },
{ "dstt",    XDSS(31,342,1), XDSS_MASK,	PPCVEC,		{ RA, RB, STRM }, PPC_INST_DSTT },

{ "lhax",    X(31,343),	X_MASK,		COM,		{ RT, RA0, RB }, PPC_INST_LHAX },

{ "lhaxe",   X(31,351),	X_MASK,		BOOKE64,	{ RT, RA0, RB }, PPC_INST_LHAXE },

{ "dstst",   XDSS(31,374,0), XDSS_MASK,	PPCVEC,		{ RA, RB, STRM }, PPC_INST_DSTST },
{ "dststt",  XDSS(31,374,1), XDSS_MASK,	PPCVEC,		{ RA, RB, STRM }, PPC_INST_DSTSTT },

{ "dccci",   X(31,454),	XRT_MASK,	PPC403 | PPC440,	{ RA, RB }, PPC_INST_DCCCI },

{ "abs",     XO(31,360,0,0), XORB_MASK, M601,		{ RT, RA }, PPC_INST_ABS },
{ "abs.",    XO(31,360,0,1), XORB_MASK, M601,		{ RT, RA }, PPC_INST_ABS },
{ "abso",    XO(31,360,1,0), XORB_MASK, M601,		{ RT, RA }, PPC_INST_ABSO },
{ "abso.",   XO(31,360,1,1), XORB_MASK, M601,		{ RT, RA }, PPC_INST_ABSO },

{ "divs",    XO(31,363,0,0), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DIVS },
{ "divs.",   XO(31,363,0,1), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DIVS },
{ "divso",   XO(31,363,1,0), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DIVSO },
{ "divso.",  XO(31,363,1,1), XO_MASK,	M601,		{ RT, RA, RB }, PPC_INST_DIVSO },

{ "tlbia",   X(31,370),	0xffffffff,	PPC,		{ 0 }, PPC_INST_TLBIA },

{ "lwaux",   X(31,373),	X_MASK,		PPC64,		{ RT, RAL, RB }, PPC_INST_LWAUX },

{ "lhaux",   X(31,375),	X_MASK,		COM,		{ RT, RAL, RB }, PPC_INST_LHAUX },

{ "lhauxe",  X(31,383),	X_MASK,		BOOKE64,	{ RT, RAL, RB }, PPC_INST_LHAUXE },

{ "mtdcrx",  X(31,387),	X_MASK,		BOOKE,		{ RA, RS }, PPC_INST_MTDCRX },

{ "dcblc",   X(31,390),	X_MASK,		PPCCHLK,	{ CT, RA, RB }, PPC_INST_DCBLC },

{ "subfe64", XO(31,392,0,0), XO_MASK,	BOOKE64,	{ RT, RA, RB }, PPC_INST_SUBFE64 },
{ "subfe64o",XO(31,392,1,0), XO_MASK,	BOOKE64,	{ RT, RA, RB }, PPC_INST_SUBFE64O },

{ "adde64",  XO(31,394,0,0), XO_MASK,	BOOKE64,	{ RT, RA, RB }, PPC_INST_ADDE64 },
{ "adde64o", XO(31,394,1,0), XO_MASK,	BOOKE64,	{ RT, RA, RB }, PPC_INST_ADDE64O },

{ "dcblce",  X(31,398),	X_MASK,		PPCCHLK64,	{ CT, RA, RB }, PPC_INST_DCBLCE },

{ "slbmte",  X(31,402), XRA_MASK,	PPC64,		{ RS, RB }, PPC_INST_SLBMTE },

{ "sthx",    X(31,407),	X_MASK,		COM,		{ RS, RA0, RB }, PPC_INST_STHX },

{ "cmpb",    X(31,508),	X_MASK,		POWER6,		{ RA, RS, RB }, PPC_INST_CMPB },

{ "lfqx",    X(31,791),	X_MASK,		POWER2,		{ FRT, RA, RB }, PPC_INST_LFQX },

{ "lfdpx",   X(31,791),	X_MASK,		POWER6,		{ FRT, RA, RB }, PPC_INST_LFDPX },

{ "lfqux",   X(31,823),	X_MASK,		POWER2,		{ FRT, RA, RB }, PPC_INST_LFQUX },

{ "stfqx",   X(31,919),	X_MASK,		POWER2,		{ FRS, RA, RB }, PPC_INST_STFQX },

{ "stfdpx",  X(31,919),	X_MASK,		POWER6,		{ FRS, RA, RB }, PPC_INST_STFDPX },

{ "stfqux",  X(31,951),	X_MASK,		POWER2,		{ FRS, RA, RB }, PPC_INST_STFQUX },

{ "orc",     XRC(31,412,0), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_ORC },
{ "orc.",    XRC(31,412,1), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_ORC },

{ "sradi",   XS(31,413,0), XS_MASK,	PPC64,		{ RA, RS, SH6 }, PPC_INST_SRADI },
{ "sradi.",  XS(31,413,1), XS_MASK,	PPC64,		{ RA, RS, SH6 }, PPC_INST_SRADI },

{ "sthxe",   X(31,415),	X_MASK,		BOOKE64,	{ RS, RA0, RB }, PPC_INST_STHXE },

{ "slbie",   X(31,434),	XRTRA_MASK,	PPC64,		{ RB }, PPC_INST_SLBIE },

{ "ecowx",   X(31,438),	X_MASK,		PPC,		{ RT, RA, RB }, PPC_INST_ECOWX },

{ "sthux",   X(31,439),	X_MASK,		COM,		{ RS, RAS, RB }, PPC_INST_STHUX },

{ "sthuxe",  X(31,447),	X_MASK,		BOOKE64,	{ RS, RAS, RB }, PPC_INST_STHUXE },

{ "cctpl",   0x7c210b78,    0xffffffff,	CELL,		{ 0 }, PPC_INST_CCTPL },
{ "cctpm",   0x7c421378,    0xffffffff,	CELL,		{ 0 }, PPC_INST_CCTPM },
{ "cctph",   0x7c631b78,    0xffffffff,	CELL,		{ 0 }, PPC_INST_CCTPH },
{ "db8cyc",  0x7f9ce378,    0xffffffff,	CELL,		{ 0 }, PPC_INST_DB8CYC },
{ "db10cyc", 0x7fbdeb78,    0xffffffff,	CELL,		{ 0 }, PPC_INST_DB10CYC },
{ "db12cyc", 0x7fdef378,    0xffffffff,	CELL,		{ 0 }, PPC_INST_DB12CYC },
{ "db16cyc", 0x7ffffb78,    0xffffffff,	CELL,		{ 0 }, PPC_INST_DB16CYC },
{ "mr",	     XRC(31,444,0), X_MASK,	COM,		{ RA, RS, RBS }, PPC_INST_MR },
{ "or",      XRC(31,444,0), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_OR },
{ "mr.",     XRC(31,444,1), X_MASK,	COM,		{ RA, RS, RBS }, PPC_INST_MR },
{ "or.",     XRC(31,444,1), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_OR },

{ "mtexisr",  XSPR(31,451,64),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTEXISR },
{ "mtexier",  XSPR(31,451,66),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTEXIER },
{ "mtbr0",    XSPR(31,451,128), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTBR0 },
{ "mtbr1",    XSPR(31,451,129), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTBR1 },
{ "mtbr2",    XSPR(31,451,130), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTBR2 },
{ "mtbr3",    XSPR(31,451,131), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTBR3 },
{ "mtbr4",    XSPR(31,451,132), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTBR4 },
{ "mtbr5",    XSPR(31,451,133), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTBR5 },
{ "mtbr6",    XSPR(31,451,134), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTBR6 },
{ "mtbr7",    XSPR(31,451,135), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTBR7 },
{ "mtbear",   XSPR(31,451,144), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTBEAR },
{ "mtbesr",   XSPR(31,451,145), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTBESR },
{ "mtiocr",   XSPR(31,451,160), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTIOCR },
{ "mtdmacr0", XSPR(31,451,192), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACR0 },
{ "mtdmact0", XSPR(31,451,193), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACT0 },
{ "mtdmada0", XSPR(31,451,194), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMADA0 },
{ "mtdmasa0", XSPR(31,451,195), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMASA0 },
{ "mtdmacc0", XSPR(31,451,196), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACC0 },
{ "mtdmacr1", XSPR(31,451,200), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACR1 },
{ "mtdmact1", XSPR(31,451,201), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACT1 },
{ "mtdmada1", XSPR(31,451,202), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMADA1 },
{ "mtdmasa1", XSPR(31,451,203), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMASA1 },
{ "mtdmacc1", XSPR(31,451,204), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACC1 },
{ "mtdmacr2", XSPR(31,451,208), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACR2 },
{ "mtdmact2", XSPR(31,451,209), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACT2 },
{ "mtdmada2", XSPR(31,451,210), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMADA2 },
{ "mtdmasa2", XSPR(31,451,211), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMASA2 },
{ "mtdmacc2", XSPR(31,451,212), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACC2 },
{ "mtdmacr3", XSPR(31,451,216), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACR3 },
{ "mtdmact3", XSPR(31,451,217), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACT3 },
{ "mtdmada3", XSPR(31,451,218), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMADA3 },
{ "mtdmasa3", XSPR(31,451,219), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMASA3 },
{ "mtdmacc3", XSPR(31,451,220), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMACC3 },
{ "mtdmasr",  XSPR(31,451,224), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDMASR },
{ "mtdcr",    X(31,451),	X_MASK,	PPC403 | BOOKE,	{ SPR, RS }, PPC_INST_MTDCR },

{ "subfze64",XO(31,456,0,0), XORB_MASK, BOOKE64,	{ RT, RA }, PPC_INST_SUBFZE64 },
{ "subfze64o",XO(31,456,1,0), XORB_MASK, BOOKE64,	{ RT, RA }, PPC_INST_SUBFZE64O },

{ "divdu",   XO(31,457,0,0), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_DIVDU },
{ "divdu.",  XO(31,457,0,1), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_DIVDU },
{ "divduo",  XO(31,457,1,0), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_DIVDUO },
{ "divduo.", XO(31,457,1,1), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_DIVDUO },

{ "addze64", XO(31,458,0,0), XORB_MASK, BOOKE64,	{ RT, RA }, PPC_INST_ADDZE64 },
{ "addze64o",XO(31,458,1,0), XORB_MASK, BOOKE64,	{ RT, RA }, PPC_INST_ADDZE64O },

{ "divwu",   XO(31,459,0,0), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_DIVWU },
{ "divwu.",  XO(31,459,0,1), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_DIVWU },
{ "divwuo",  XO(31,459,1,0), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_DIVWUO },
{ "divwuo.", XO(31,459,1,1), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_DIVWUO },

{ "mtmq",      XSPR(31,467,0),    XSPR_MASK, M601,	{ RS }, PPC_INST_MTMQ },
{ "mtxer",     XSPR(31,467,1),    XSPR_MASK, COM,	{ RS }, PPC_INST_MTXER },
{ "mtlr",      XSPR(31,467,8),    XSPR_MASK, COM,	{ RS }, PPC_INST_MTLR },
{ "mtctr",     XSPR(31,467,9),    XSPR_MASK, COM,	{ RS }, PPC_INST_MTCTR },
{ "mttid",     XSPR(31,467,17),   XSPR_MASK, POWER,	{ RS }, PPC_INST_MTTID },
{ "mtdsisr",   XSPR(31,467,18),   XSPR_MASK, COM,	{ RS }, PPC_INST_MTDSISR },
{ "mtdar",     XSPR(31,467,19),   XSPR_MASK, COM,	{ RS }, PPC_INST_MTDAR },
{ "mtrtcu",    XSPR(31,467,20),   XSPR_MASK, COM,	{ RS }, PPC_INST_MTRTCU },
{ "mtrtcl",    XSPR(31,467,21),   XSPR_MASK, COM,	{ RS }, PPC_INST_MTRTCL },
{ "mtdec",     XSPR(31,467,22),   XSPR_MASK, COM,	{ RS }, PPC_INST_MTDEC },
{ "mtsdr0",    XSPR(31,467,24),   XSPR_MASK, POWER,	{ RS }, PPC_INST_MTSDR0 },
{ "mtsdr1",    XSPR(31,467,25),   XSPR_MASK, COM,	{ RS }, PPC_INST_MTSDR1 },
{ "mtsrr0",    XSPR(31,467,26),   XSPR_MASK, COM,	{ RS }, PPC_INST_MTSRR0 },
{ "mtsrr1",    XSPR(31,467,27),   XSPR_MASK, COM,	{ RS }, PPC_INST_MTSRR1 },
{ "mtcfar",    XSPR(31,467,28),   XSPR_MASK, POWER6,	{ RS }, PPC_INST_MTCFAR },
{ "mtpid",     XSPR(31,467,48),   XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTPID },
{ "mtpid",     XSPR(31,467,945),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTPID },
{ "mtdecar",   XSPR(31,467,54),   XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTDECAR },
{ "mtcsrr0",   XSPR(31,467,58),   XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTCSRR0 },
{ "mtcsrr1",   XSPR(31,467,59),   XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTCSRR1 },
{ "mtdear",    XSPR(31,467,61),   XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTDEAR },
{ "mtdear",    XSPR(31,467,981),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDEAR },
{ "mtesr",     XSPR(31,467,62),   XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTESR },
{ "mtesr",     XSPR(31,467,980),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTESR },
{ "mtivpr",    XSPR(31,467,63),   XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVPR },
{ "mtcmpa",    XSPR(31,467,144),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTCMPA },
{ "mtcmpb",    XSPR(31,467,145),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTCMPB },
{ "mtcmpc",    XSPR(31,467,146),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTCMPC },
{ "mtcmpd",    XSPR(31,467,147),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTCMPD },
{ "mticr",     XSPR(31,467,148),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTICR },
{ "mtder",     XSPR(31,467,149),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTDER },
{ "mtcounta",  XSPR(31,467,150),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTCOUNTA },
{ "mtcountb",  XSPR(31,467,151),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTCOUNTB },
{ "mtcmpe",    XSPR(31,467,152),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTCMPE },
{ "mtcmpf",    XSPR(31,467,153),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTCMPF },
{ "mtcmpg",    XSPR(31,467,154),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTCMPG },
{ "mtcmph",    XSPR(31,467,155),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTCMPH },
{ "mtlctrl1",  XSPR(31,467,156),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTLCTRL1 },
{ "mtlctrl2",  XSPR(31,467,157),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTLCTRL2 },
{ "mtictrl",   XSPR(31,467,158),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTICTRL },
{ "mtbar",     XSPR(31,467,159),  XSPR_MASK, PPC860,	{ RS }, PPC_INST_MTBAR },
{ "mtvrsave",  XSPR(31,467,256),  XSPR_MASK, PPCVEC,	{ RS }, PPC_INST_MTVRSAVE },
{ "mtusprg0",  XSPR(31,467,256),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTUSPRG0 },
{ "mtsprg",    XSPR(31,467,256),  XSPRG_MASK,PPC,	{ SPRG, RS }, PPC_INST_MTSPRG },
{ "mtsprg0",   XSPR(31,467,272),  XSPR_MASK, PPC,	{ RS }, PPC_INST_MTSPRG0 },
{ "mtsprg1",   XSPR(31,467,273),  XSPR_MASK, PPC,	{ RS }, PPC_INST_MTSPRG1 },
{ "mtsprg2",   XSPR(31,467,274),  XSPR_MASK, PPC,	{ RS }, PPC_INST_MTSPRG2 },
{ "mtsprg3",   XSPR(31,467,275),  XSPR_MASK, PPC,	{ RS }, PPC_INST_MTSPRG3 },
{ "mtsprg4",   XSPR(31,467,276),  XSPR_MASK, PPC405 | BOOKE, { RS }, PPC_INST_MTSPRG4 },
{ "mtsprg5",   XSPR(31,467,277),  XSPR_MASK, PPC405 | BOOKE, { RS }, PPC_INST_MTSPRG5 },
{ "mtsprg6",   XSPR(31,467,278),  XSPR_MASK, PPC405 | BOOKE, { RS }, PPC_INST_MTSPRG6 },
{ "mtsprg7",   XSPR(31,467,279),  XSPR_MASK, PPC405 | BOOKE, { RS }, PPC_INST_MTSPRG7 },
{ "mtasr",     XSPR(31,467,280),  XSPR_MASK, PPC64,	{ RS }, PPC_INST_MTASR },
{ "mtear",     XSPR(31,467,282),  XSPR_MASK, PPC,	{ RS }, PPC_INST_MTEAR },
{ "mttbl",     XSPR(31,467,284),  XSPR_MASK, PPC,	{ RS }, PPC_INST_MTTBL },
{ "mttbu",     XSPR(31,467,285),  XSPR_MASK, PPC,	{ RS }, PPC_INST_MTTBU },
{ "mtdbsr",    XSPR(31,467,304),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTDBSR },
{ "mtdbsr",    XSPR(31,467,1008), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDBSR },
{ "mtdbcr0",   XSPR(31,467,308),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTDBCR0 },
{ "mtdbcr0",   XSPR(31,467,1010), XSPR_MASK, PPC405,	{ RS }, PPC_INST_MTDBCR0 },
{ "mtdbcr1",   XSPR(31,467,309),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTDBCR1 },
{ "mtdbcr1",   XSPR(31,467,957),  XSPR_MASK, PPC405,	{ RS }, PPC_INST_MTDBCR1 },
{ "mtdbcr2",   XSPR(31,467,310),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTDBCR2 },
{ "mtiac1",    XSPR(31,467,312),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIAC1 },
{ "mtiac1",    XSPR(31,467,1012), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTIAC1 },
{ "mtiac2",    XSPR(31,467,313),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIAC2 },
{ "mtiac2",    XSPR(31,467,1013), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTIAC2 },
{ "mtiac3",    XSPR(31,467,314),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIAC3 },
{ "mtiac3",    XSPR(31,467,948),  XSPR_MASK, PPC405,	{ RS }, PPC_INST_MTIAC3 },
{ "mtiac4",    XSPR(31,467,315),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIAC4 },
{ "mtiac4",    XSPR(31,467,949),  XSPR_MASK, PPC405,	{ RS }, PPC_INST_MTIAC4 },
{ "mtdac1",    XSPR(31,467,316),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTDAC1 },
{ "mtdac1",    XSPR(31,467,1014), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDAC1 },
{ "mtdac2",    XSPR(31,467,317),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTDAC2 },
{ "mtdac2",    XSPR(31,467,1015), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDAC2 },
{ "mtdvc1",    XSPR(31,467,318),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTDVC1 },
{ "mtdvc1",    XSPR(31,467,950),  XSPR_MASK, PPC405,	{ RS }, PPC_INST_MTDVC1 },
{ "mtdvc2",    XSPR(31,467,319),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTDVC2 },
{ "mtdvc2",    XSPR(31,467,951),  XSPR_MASK, PPC405,	{ RS }, PPC_INST_MTDVC2 },
{ "mttsr",     XSPR(31,467,336),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTTSR },
{ "mttsr",     XSPR(31,467,984),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTTSR },
{ "mttcr",     XSPR(31,467,340),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTTCR },
{ "mttcr",     XSPR(31,467,986),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTTCR },
{ "mtivor0",   XSPR(31,467,400),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR0 },
{ "mtivor1",   XSPR(31,467,401),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR1 },
{ "mtivor2",   XSPR(31,467,402),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR2 },
{ "mtivor3",   XSPR(31,467,403),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR3 },
{ "mtivor4",   XSPR(31,467,404),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR4 },
{ "mtivor5",   XSPR(31,467,405),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR5 },
{ "mtivor6",   XSPR(31,467,406),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR6 },
{ "mtivor7",   XSPR(31,467,407),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR7 },
{ "mtivor8",   XSPR(31,467,408),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR8 },
{ "mtivor9",   XSPR(31,467,409),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR9 },
{ "mtivor10",  XSPR(31,467,410),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR10 },
{ "mtivor11",  XSPR(31,467,411),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR11 },
{ "mtivor12",  XSPR(31,467,412),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR12 },
{ "mtivor13",  XSPR(31,467,413),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR13 },
{ "mtivor14",  XSPR(31,467,414),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR14 },
{ "mtivor15",  XSPR(31,467,415),  XSPR_MASK, BOOKE,     { RS }, PPC_INST_MTIVOR15 },
{ "mtspefscr",  XSPR(31,467,512),  XSPR_MASK, PPCSPE,   { RS }, PPC_INST_MTSPEFSCR },
{ "mtbbear",   XSPR(31,467,513),  XSPR_MASK, PPCBRLK,   { RS }, PPC_INST_MTBBEAR },
{ "mtbbtar",   XSPR(31,467,514),  XSPR_MASK, PPCBRLK,  { RS }, PPC_INST_MTBBTAR },
{ "mtivor32",  XSPR(31,467,528),  XSPR_MASK, PPCSPE,	{ RS }, PPC_INST_MTIVOR32 },
{ "mtivor33",  XSPR(31,467,529),  XSPR_MASK, PPCSPE,	{ RS }, PPC_INST_MTIVOR33 },
{ "mtivor34",  XSPR(31,467,530),  XSPR_MASK, PPCSPE,	{ RS }, PPC_INST_MTIVOR34 },
{ "mtivor35",  XSPR(31,467,531),  XSPR_MASK, PPCPMR,	{ RS }, PPC_INST_MTIVOR35 },
{ "mtibatu",   XSPR(31,467,528),  XSPRBAT_MASK, PPC,	{ SPRBAT, RS }, PPC_INST_MTIBATU },
{ "mtibatl",   XSPR(31,467,529),  XSPRBAT_MASK, PPC,	{ SPRBAT, RS }, PPC_INST_MTIBATL },
{ "mtdbatu",   XSPR(31,467,536),  XSPRBAT_MASK, PPC,	{ SPRBAT, RS }, PPC_INST_MTDBATU },
{ "mtdbatl",   XSPR(31,467,537),  XSPRBAT_MASK, PPC,	{ SPRBAT, RS }, PPC_INST_MTDBATL },
{ "mtmcsrr0",  XSPR(31,467,570),  XSPR_MASK, PPCRFMCI,  { RS }, PPC_INST_MTMCSRR0 },
{ "mtmcsrr1",  XSPR(31,467,571),  XSPR_MASK, PPCRFMCI,  { RS }, PPC_INST_MTMCSRR1 },
{ "mtmcsr",    XSPR(31,467,572),  XSPR_MASK, PPCRFMCI,  { RS }, PPC_INST_MTMCSR },
{ "mtummcr0",  XSPR(31,467,936),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTUMMCR0 },
{ "mtupmc1",   XSPR(31,467,937),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTUPMC1 },
{ "mtupmc2",   XSPR(31,467,938),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTUPMC2 },
{ "mtusia",    XSPR(31,467,939),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTUSIA },
{ "mtummcr1",  XSPR(31,467,940),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTUMMCR1 },
{ "mtupmc3",   XSPR(31,467,941),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTUPMC3 },
{ "mtupmc4",   XSPR(31,467,942),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTUPMC4 },
{ "mtzpr",     XSPR(31,467,944),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTZPR },
{ "mtccr0",    XSPR(31,467,947),  XSPR_MASK, PPC405,	{ RS }, PPC_INST_MTCCR0 },
{ "mtmmcr0",   XSPR(31,467,952),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTMMCR0 },
{ "mtsgr",     XSPR(31,467,953),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTSGR },
{ "mtpmc1",    XSPR(31,467,953),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTPMC1 },
{ "mtdcwr",    XSPR(31,467,954),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDCWR },
{ "mtpmc2",    XSPR(31,467,954),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTPMC2 },
{ "mtsler",    XSPR(31,467,955),  XSPR_MASK, PPC405,	{ RS }, PPC_INST_MTSLER },
{ "mtsia",     XSPR(31,467,955),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTSIA },
{ "mtsu0r",    XSPR(31,467,956),  XSPR_MASK, PPC405,	{ RS }, PPC_INST_MTSU0R },
{ "mtmmcr1",   XSPR(31,467,956),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTMMCR1 },
{ "mtpmc3",    XSPR(31,467,957),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTPMC3 },
{ "mtpmc4",    XSPR(31,467,958),  XSPR_MASK, PPC750,    { RS }, PPC_INST_MTPMC4 },
{ "mticdbdr",  XSPR(31,467,979),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTICDBDR },
{ "mtevpr",    XSPR(31,467,982),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTEVPR },
{ "mtcdbcr",   XSPR(31,467,983),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTCDBCR },
{ "mtpit",     XSPR(31,467,987),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTPIT },
{ "mttbhi",    XSPR(31,467,988),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTTBHI },
{ "mttblo",    XSPR(31,467,989),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTTBLO },
{ "mtsrr2",    XSPR(31,467,990),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTSRR2 },
{ "mtsrr3",    XSPR(31,467,991),  XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTSRR3 },
{ "mtl2cr",    XSPR(31,467,1017), XSPR_MASK, PPC750,    { RS }, PPC_INST_MTL2CR },
{ "mtdccr",    XSPR(31,467,1018), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTDCCR },
{ "mticcr",    XSPR(31,467,1019), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTICCR },
{ "mtictc",    XSPR(31,467,1019), XSPR_MASK, PPC750,    { RS }, PPC_INST_MTICTC },
{ "mtpbl1",    XSPR(31,467,1020), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTPBL1 },
{ "mtthrm1",   XSPR(31,467,1020), XSPR_MASK, PPC750,    { RS }, PPC_INST_MTTHRM1 },
{ "mtpbu1",    XSPR(31,467,1021), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTPBU1 },
{ "mtthrm2",   XSPR(31,467,1021), XSPR_MASK, PPC750,    { RS }, PPC_INST_MTTHRM2 },
{ "mtpbl2",    XSPR(31,467,1022), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTPBL2 },
{ "mtthrm3",   XSPR(31,467,1022), XSPR_MASK, PPC750,    { RS }, PPC_INST_MTTHRM3 },
{ "mtpbu2",    XSPR(31,467,1023), XSPR_MASK, PPC403,	{ RS }, PPC_INST_MTPBU2 },
{ "mtspr",     X(31,467),	  X_MASK,    COM,	{ SPR, RS }, PPC_INST_MTSPR },

{ "dcbi",    X(31,470),	XRT_MASK,	PPC,		{ RA, RB }, PPC_INST_DCBI },

{ "nand",    XRC(31,476,0), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_NAND },
{ "nand.",   XRC(31,476,1), X_MASK,	COM,		{ RA, RS, RB }, PPC_INST_NAND },

{ "dcbie",   X(31,478),	XRT_MASK,	BOOKE64,	{ RA, RB }, PPC_INST_DCBIE },

{ "dcread",  X(31,486),	X_MASK,		PPC403 | PPC440,	{ RT, RA, RB }, PPC_INST_DCREAD },

{ "mtpmr",   X(31,462),	X_MASK,		PPCPMR,		{ PMR, RS }, PPC_INST_MTPMR },

{ "icbtls",  X(31,486),	X_MASK,		PPCCHLK,	{ CT, RA, RB }, PPC_INST_ICBTLS },

{ "nabs",    XO(31,488,0,0), XORB_MASK, M601,		{ RT, RA }, PPC_INST_NABS },
{ "subfme64",XO(31,488,0,0), XORB_MASK, BOOKE64,	{ RT, RA }, PPC_INST_SUBFME64 },
{ "nabs.",   XO(31,488,0,1), XORB_MASK, M601,		{ RT, RA }, PPC_INST_NABS },
{ "nabso",   XO(31,488,1,0), XORB_MASK, M601,		{ RT, RA }, PPC_INST_NABSO },
{ "subfme64o",XO(31,488,1,0), XORB_MASK, BOOKE64,	{ RT, RA }, PPC_INST_SUBFME64O },
{ "nabso.",  XO(31,488,1,1), XORB_MASK, M601,		{ RT, RA }, PPC_INST_NABSO },

{ "divd",    XO(31,489,0,0), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_DIVD },
{ "divd.",   XO(31,489,0,1), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_DIVD },
{ "divdo",   XO(31,489,1,0), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_DIVDO },
{ "divdo.",  XO(31,489,1,1), XO_MASK,	PPC64,		{ RT, RA, RB }, PPC_INST_DIVDO },

{ "addme64", XO(31,490,0,0), XORB_MASK, BOOKE64,	{ RT, RA }, PPC_INST_ADDME64 },
{ "addme64o",XO(31,490,1,0), XORB_MASK, BOOKE64,	{ RT, RA }, PPC_INST_ADDME64O },

{ "divw",    XO(31,491,0,0), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_DIVW },
{ "divw.",   XO(31,491,0,1), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_DIVW },
{ "divwo",   XO(31,491,1,0), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_DIVWO },
{ "divwo.",  XO(31,491,1,1), XO_MASK,	PPC,		{ RT, RA, RB }, PPC_INST_DIVWO },

{ "icbtlse", X(31,494),	X_MASK,		PPCCHLK64,	{ CT, RA, RB }, PPC_INST_ICBTLSE },

{ "slbia",   X(31,498),	0xffffffff,	PPC64,		{ 0 }, PPC_INST_SLBIA },

{ "cli",     X(31,502), XRB_MASK,	POWER,		{ RT, RA }, PPC_INST_CLI },

{ "stdcxe.", XRC(31,511,1), X_MASK,	BOOKE64,	{ RS, RA, RB }, PPC_INST_STDCXE },

{ "mcrxr",   X(31,512),	XRARB_MASK | (3 << 21), COM,	{ BF }, PPC_INST_MCRXR },

{ "bblels",  X(31,518),	X_MASK,		PPCBRLK,	{ 0 }, PPC_INST_BBLELS },
{ "mcrxr64", X(31,544),	XRARB_MASK | (3 << 21), BOOKE64,	{ BF }, PPC_INST_MCRXR64 },

{ "clcs",    X(31,531), XRB_MASK,	M601,		{ RT, RA }, PPC_INST_CLCS },

{ "ldbrx",   X(31,532),	X_MASK,		CELL,		{ RT, RA0, RB }, PPC_INST_LDBRX },

{ "lswx",    X(31,533),	X_MASK,		PPCCOM,		{ RT, RA0, RB }, PPC_INST_LSWX },
{ "lsx",     X(31,533),	X_MASK,		PWRCOM,		{ RT, RA, RB }, PPC_INST_LSX },

{ "lwbrx",   X(31,534),	X_MASK,		PPCCOM,		{ RT, RA0, RB }, PPC_INST_LWBRX },
{ "lbrx",    X(31,534),	X_MASK,		PWRCOM,		{ RT, RA, RB }, PPC_INST_LBRX },

{ "lfsx",    X(31,535),	X_MASK,		COM,		{ FRT, RA0, RB }, PPC_INST_LFSX },

{ "srw",     XRC(31,536,0), X_MASK,	PPCCOM,		{ RA, RS, RB }, PPC_INST_SRW },
{ "sr",      XRC(31,536,0), X_MASK,	PWRCOM,		{ RA, RS, RB }, PPC_INST_SR },
{ "srw.",    XRC(31,536,1), X_MASK,	PPCCOM,		{ RA, RS, RB }, PPC_INST_SRW },
{ "sr.",     XRC(31,536,1), X_MASK,	PWRCOM,		{ RA, RS, RB }, PPC_INST_SR },

{ "rrib",    XRC(31,537,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_RRIB },
{ "rrib.",   XRC(31,537,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_RRIB },

{ "srd",     XRC(31,539,0), X_MASK,	PPC64,		{ RA, RS, RB }, PPC_INST_SRD },
{ "srd.",    XRC(31,539,1), X_MASK,	PPC64,		{ RA, RS, RB }, PPC_INST_SRD },

{ "maskir",  XRC(31,541,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_MASKIR },
{ "maskir.", XRC(31,541,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_MASKIR },

{ "lwbrxe",  X(31,542),	X_MASK,		BOOKE64,	{ RT, RA0, RB }, PPC_INST_LWBRXE },

{ "lfsxe",   X(31,543),	X_MASK,		BOOKE64,	{ FRT, RA0, RB }, PPC_INST_LFSXE },

{ "bbelr",   X(31,550),	X_MASK,		PPCBRLK,	{ 0 }, PPC_INST_BBELR },

{ "tlbsync", X(31,566),	0xffffffff,	PPC,		{ 0 }, PPC_INST_TLBSYNC },

{ "lfsux",   X(31,567),	X_MASK,		COM,		{ FRT, RAS, RB }, PPC_INST_LFSUX },

{ "lfsuxe",  X(31,575),	X_MASK,		BOOKE64,	{ FRT, RAS, RB }, PPC_INST_LFSUXE },

{ "mfsr",    X(31,595),	XRB_MASK | (1 << 20), COM32,	{ RT, SR }, PPC_INST_MFSR },

{ "lswi",    X(31,597),	X_MASK,		PPCCOM,		{ RT, RA0, NB }, PPC_INST_LSWI },
{ "lsi",     X(31,597),	X_MASK,		PWRCOM,		{ RT, RA0, NB }, PPC_INST_LSI },

{ "lwsync",  XSYNC(31,598,1), 0xffffffff, PPC,		{ 0 }, PPC_INST_LWSYNC },
{ "ptesync", XSYNC(31,598,2), 0xffffffff, PPC64,	{ 0 }, PPC_INST_PTESYNC },
{ "msync",   X(31,598), 0xffffffff,	BOOKE,		{ 0 }, PPC_INST_MSYNC },
{ "sync",    X(31,598), XSYNC_MASK,	PPCCOM,		{ LS }, PPC_INST_SYNC },
{ "dcs",     X(31,598), 0xffffffff,	PWRCOM,		{ 0 }, PPC_INST_DCS },

{ "lfdx",    X(31,599), X_MASK,		COM,		{ FRT, RA0, RB }, PPC_INST_LFDX },

{ "lfdxe",   X(31,607), X_MASK,		BOOKE64,	{ FRT, RA0, RB }, PPC_INST_LFDXE },

{ "mffgpr",  XRC(31,607,0), XRA_MASK,	POWER6,		{ FRT, RB }, PPC_INST_MFFGPR },

{ "mfsri",   X(31,627), X_MASK,		PWRCOM,		{ RT, RA, RB }, PPC_INST_MFSRI },

{ "dclst",   X(31,630), XRB_MASK,	PWRCOM,		{ RS, RA }, PPC_INST_DCLST },

{ "lfdux",   X(31,631), X_MASK,		COM,		{ FRT, RAS, RB }, PPC_INST_LFDUX },

{ "lfduxe",  X(31,639), X_MASK,		BOOKE64,	{ FRT, RAS, RB }, PPC_INST_LFDUXE },

{ "mfsrin",  X(31,659), XRA_MASK,	PPC32,		{ RT, RB }, PPC_INST_MFSRIN },

{ "stdbrx",  X(31,660), X_MASK,		CELL,		{ RS, RA0, RB }, PPC_INST_STDBRX },

{ "stswx",   X(31,661), X_MASK,		PPCCOM,		{ RS, RA0, RB }, PPC_INST_STSWX },
{ "stsx",    X(31,661), X_MASK,		PWRCOM,		{ RS, RA0, RB }, PPC_INST_STSX },

{ "stwbrx",  X(31,662), X_MASK,		PPCCOM,		{ RS, RA0, RB }, PPC_INST_STWBRX },
{ "stbrx",   X(31,662), X_MASK,		PWRCOM,		{ RS, RA0, RB }, PPC_INST_STBRX },

{ "stfsx",   X(31,663), X_MASK,		COM,		{ FRS, RA0, RB }, PPC_INST_STFSX },

{ "srq",     XRC(31,664,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SRQ },
{ "srq.",    XRC(31,664,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SRQ },

{ "sre",     XRC(31,665,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SRE },
{ "sre.",    XRC(31,665,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SRE },

{ "stwbrxe", X(31,670), X_MASK,		BOOKE64,	{ RS, RA0, RB }, PPC_INST_STWBRXE },

{ "stfsxe",  X(31,671), X_MASK,		BOOKE64,	{ FRS, RA0, RB }, PPC_INST_STFSXE },

{ "stfsux",  X(31,695),	X_MASK,		COM,		{ FRS, RAS, RB }, PPC_INST_STFSUX },

{ "sriq",    XRC(31,696,0), X_MASK,	M601,		{ RA, RS, SH }, PPC_INST_SRIQ },
{ "sriq.",   XRC(31,696,1), X_MASK,	M601,		{ RA, RS, SH }, PPC_INST_SRIQ },

{ "stfsuxe", X(31,703),	X_MASK,		BOOKE64,	{ FRS, RAS, RB }, PPC_INST_STFSUXE },

{ "stswi",   X(31,725),	X_MASK,		PPCCOM,		{ RS, RA0, NB }, PPC_INST_STSWI },
{ "stsi",    X(31,725),	X_MASK,		PWRCOM,		{ RS, RA0, NB }, PPC_INST_STSI },

{ "stfdx",   X(31,727),	X_MASK,		COM,		{ FRS, RA0, RB }, PPC_INST_STFDX },

{ "srlq",    XRC(31,728,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SRLQ },
{ "srlq.",   XRC(31,728,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SRLQ },

{ "sreq",    XRC(31,729,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SREQ },
{ "sreq.",   XRC(31,729,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SREQ },

{ "stfdxe",  X(31,735),	X_MASK,		BOOKE64,	{ FRS, RA0, RB }, PPC_INST_STFDXE },

{ "mftgpr",  XRC(31,735,0), XRA_MASK,	POWER6,		{ RT, FRB }, PPC_INST_MFTGPR },

{ "dcba",    X(31,758),	XRT_MASK,	PPC405 | BOOKE,	{ RA, RB }, PPC_INST_DCBA },

{ "stfdux",  X(31,759),	X_MASK,		COM,		{ FRS, RAS, RB }, PPC_INST_STFDUX },

{ "srliq",   XRC(31,760,0), X_MASK,	M601,		{ RA, RS, SH }, PPC_INST_SRLIQ },
{ "srliq.",  XRC(31,760,1), X_MASK,	M601,		{ RA, RS, SH }, PPC_INST_SRLIQ },

{ "dcbae",   X(31,766),	XRT_MASK,	BOOKE64,	{ RA, RB }, PPC_INST_DCBAE },

{ "stfduxe", X(31,767),	X_MASK,		BOOKE64,	{ FRS, RAS, RB }, PPC_INST_STFDUXE },

{ "tlbivax", X(31,786),	XRT_MASK,	BOOKE,		{ RA, RB }, PPC_INST_TLBIVAX },
{ "tlbivaxe",X(31,787),	XRT_MASK,	BOOKE64,	{ RA, RB }, PPC_INST_TLBIVAXE },

{ "lwzcix",  X(31,789),	X_MASK,		POWER6,		{ RT, RA0, RB }, PPC_INST_LWZCIX },

{ "lhbrx",   X(31,790),	X_MASK,		COM,		{ RT, RA0, RB }, PPC_INST_LHBRX },

{ "sraw",    XRC(31,792,0), X_MASK,	PPCCOM,		{ RA, RS, RB }, PPC_INST_SRAW },
{ "sra",     XRC(31,792,0), X_MASK,	PWRCOM,		{ RA, RS, RB }, PPC_INST_SRA },
{ "sraw.",   XRC(31,792,1), X_MASK,	PPCCOM,		{ RA, RS, RB }, PPC_INST_SRAW },
{ "sra.",    XRC(31,792,1), X_MASK,	PWRCOM,		{ RA, RS, RB }, PPC_INST_SRA },

{ "srad",    XRC(31,794,0), X_MASK,	PPC64,		{ RA, RS, RB }, PPC_INST_SRAD },
{ "srad.",   XRC(31,794,1), X_MASK,	PPC64,		{ RA, RS, RB }, PPC_INST_SRAD },

{ "lhbrxe",  X(31,798),	X_MASK,		BOOKE64,	{ RT, RA0, RB }, PPC_INST_LHBRXE },

{ "ldxe",    X(31,799),	X_MASK,		BOOKE64,	{ RT, RA0, RB }, PPC_INST_LDXE },
{ "lduxe",   X(31,831),	X_MASK,		BOOKE64,	{ RT, RA0, RB }, PPC_INST_LDUXE },

{ "rac",     X(31,818),	X_MASK,		PWRCOM,		{ RT, RA, RB }, PPC_INST_RAC },

{ "lhzcix",  X(31,821),	X_MASK,		POWER6,		{ RT, RA0, RB }, PPC_INST_LHZCIX },

{ "dss",     XDSS(31,822,0), XDSS_MASK,	PPCVEC,		{ STRM }, PPC_INST_DSS },
{ "dssall",  XDSS(31,822,1), XDSS_MASK,	PPCVEC,		{ 0 }, PPC_INST_DSSALL },

{ "srawi",   XRC(31,824,0), X_MASK,	PPCCOM,		{ RA, RS, SH }, PPC_INST_SRAWI },
{ "srai",    XRC(31,824,0), X_MASK,	PWRCOM,		{ RA, RS, SH }, PPC_INST_SRAI },
{ "srawi.",  XRC(31,824,1), X_MASK,	PPCCOM,		{ RA, RS, SH }, PPC_INST_SRAWI },
{ "srai.",   XRC(31,824,1), X_MASK,	PWRCOM,		{ RA, RS, SH }, PPC_INST_SRAI },

{ "slbmfev", X(31,851), XRA_MASK,	PPC64,		{ RT, RB }, PPC_INST_SLBMFEV },

{ "lbzcix",  X(31,853),	X_MASK,		POWER6,		{ RT, RA0, RB }, PPC_INST_LBZCIX },

{ "mbar",    X(31,854),	X_MASK,		BOOKE,		{ MO }, PPC_INST_MBAR },
{ "eieio",   X(31,854),	0xffffffff,	PPC,		{ 0 }, PPC_INST_EIEIO },

{ "lfiwax",  X(31,855),	X_MASK,		POWER6,		{ FRT, RA0, RB }, PPC_INST_LFIWAX },

{ "ldcix",   X(31,885),	X_MASK,		POWER6,		{ RT, RA0, RB }, PPC_INST_LDCIX },

{ "tlbsx",   XRC(31,914,0), X_MASK, 	PPC403 | BOOKE,	{ RTO, RA, RB }, PPC_INST_TLBSX },
{ "tlbsx.",  XRC(31,914,1), X_MASK, 	PPC403 | BOOKE,	{ RTO, RA, RB }, PPC_INST_TLBSX },
{ "tlbsxe",  XRC(31,915,0), X_MASK,	BOOKE64,	{ RTO, RA, RB }, PPC_INST_TLBSXE },
{ "tlbsxe.", XRC(31,915,1), X_MASK,	BOOKE64,	{ RTO, RA, RB }, PPC_INST_TLBSXE },

{ "slbmfee", X(31,915), XRA_MASK,	PPC64,		{ RT, RB }, PPC_INST_SLBMFEE },

{ "stwcix",  X(31,917),	X_MASK,		POWER6,		{ RS, RA0, RB }, PPC_INST_STWCIX },

{ "sthbrx",  X(31,918),	X_MASK,		COM,		{ RS, RA0, RB }, PPC_INST_STHBRX },

{ "sraq",    XRC(31,920,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SRAQ },
{ "sraq.",   XRC(31,920,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SRAQ },

{ "srea",    XRC(31,921,0), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SREA },
{ "srea.",   XRC(31,921,1), X_MASK,	M601,		{ RA, RS, RB }, PPC_INST_SREA },

{ "extsh",   XRC(31,922,0), XRB_MASK,	PPCCOM,		{ RA, RS }, PPC_INST_EXTSH },
{ "exts",    XRC(31,922,0), XRB_MASK,	PWRCOM,		{ RA, RS }, PPC_INST_EXTS },
{ "extsh.",  XRC(31,922,1), XRB_MASK,	PPCCOM,		{ RA, RS }, PPC_INST_EXTSH },
{ "exts.",   XRC(31,922,1), XRB_MASK,	PWRCOM,		{ RA, RS }, PPC_INST_EXTS },

{ "sthbrxe", X(31,926),	X_MASK,		BOOKE64,	{ RS, RA0, RB }, PPC_INST_STHBRXE },

{ "stdxe",   X(31,927), X_MASK,		BOOKE64,	{ RS, RA0, RB }, PPC_INST_STDXE },

{ "tlbrehi", XTLB(31,946,0), XTLB_MASK,	PPC403,		{ RT, RA }, PPC_INST_TLBREHI },
{ "tlbrelo", XTLB(31,946,1), XTLB_MASK,	PPC403,		{ RT, RA }, PPC_INST_TLBRELO },
{ "tlbre",   X(31,946),	X_MASK,		PPC403 | BOOKE,	{ RSO, RAOPT, SHO }, PPC_INST_TLBRE },

{ "sthcix",  X(31,949),	X_MASK,		POWER6,		{ RS, RA0, RB }, PPC_INST_STHCIX },

{ "sraiq",   XRC(31,952,0), X_MASK,	M601,		{ RA, RS, SH }, PPC_INST_SRAIQ },
{ "sraiq.",  XRC(31,952,1), X_MASK,	M601,		{ RA, RS, SH }, PPC_INST_SRAIQ },

{ "extsb",   XRC(31,954,0), XRB_MASK,	PPC,		{ RA, RS}, PPC_INST_EXTSB },
{ "extsb.",  XRC(31,954,1), XRB_MASK,	PPC,		{ RA, RS}, PPC_INST_EXTSB },

{ "stduxe",  X(31,959),	X_MASK,		BOOKE64,	{ RS, RAS, RB }, PPC_INST_STDUXE },

{ "iccci",   X(31,966),	XRT_MASK,	PPC403 | PPC440,	{ RA, RB }, PPC_INST_ICCCI },

{ "tlbwehi", XTLB(31,978,0), XTLB_MASK,	PPC403,		{ RT, RA }, PPC_INST_TLBWEHI },
{ "tlbwelo", XTLB(31,978,1), XTLB_MASK,	PPC403,		{ RT, RA }, PPC_INST_TLBWELO },
{ "tlbwe",   X(31,978),	X_MASK,		PPC403 | BOOKE,	{ RSO, RAOPT, SHO }, PPC_INST_TLBWE },
{ "tlbld",   X(31,978),	XRTRA_MASK,	PPC,		{ RB }, PPC_INST_TLBLD },

{ "stbcix",  X(31,981),	X_MASK,		POWER6,		{ RS, RA0, RB }, PPC_INST_STBCIX },

{ "icbi",    X(31,982),	XRT_MASK,	PPC,		{ RA, RB }, PPC_INST_ICBI },

{ "stfiwx",  X(31,983),	X_MASK,		PPC,		{ FRS, RA0, RB }, PPC_INST_STFIWX },

{ "extsw",   XRC(31,986,0), XRB_MASK,	PPC64 | BOOKE64,{ RA, RS }, PPC_INST_EXTSW },
{ "extsw.",  XRC(31,986,1), XRB_MASK,	PPC64,		{ RA, RS }, PPC_INST_EXTSW },

{ "icread",  X(31,998),	XRT_MASK,	PPC403 | PPC440,	{ RA, RB }, PPC_INST_ICREAD },

{ "icbie",   X(31,990),	XRT_MASK,	BOOKE64,	{ RA, RB }, PPC_INST_ICBIE },
{ "stfiwxe", X(31,991),	X_MASK,		BOOKE64,	{ FRS, RA0, RB }, PPC_INST_STFIWXE },

{ "tlbli",   X(31,1010), XRTRA_MASK,	PPC,		{ RB }, PPC_INST_TLBLI },

{ "stdcix",  X(31,1013), X_MASK,	POWER6,		{ RS, RA0, RB }, PPC_INST_STDCIX },

{ "dcbzl",   XOPL(31,1014,1), XRT_MASK,POWER4,            { RA, RB }, PPC_INST_DCBZL },
{ "dcbz",    X(31,1014), XRT_MASK,	PPC,		{ RA, RB }, PPC_INST_DCBZ },
{ "dclz",    X(31,1014), XRT_MASK,	PPC,		{ RA, RB }, PPC_INST_DCLZ },

{ "dcbze",   X(31,1022), XRT_MASK,	BOOKE64,	{ RA, RB }, PPC_INST_DCBZE },

{ "lvebx",   X(31,   7), X_MASK,	PPCVEC,		{ VD, RA, RB }, PPC_INST_LVEBX },
{ "lvehx",   X(31,  39), X_MASK,	PPCVEC,		{ VD, RA, RB }, PPC_INST_LVEHX },
{ "lvewx",   X(31,  71), X_MASK,	PPCVEC,		{ VD, RA, RB }, PPC_INST_LVEWX },
{ "lvsl",    X(31,   6), X_MASK,	PPCVEC,		{ VD, RA, RB }, PPC_INST_LVSL },
{ "lvsr",    X(31,  38), X_MASK,	PPCVEC,		{ VD, RA, RB }, PPC_INST_LVSR },
{ "lvx",     X(31, 103), X_MASK,	PPCVEC,		{ VD, RA, RB }, PPC_INST_LVX },
{ "lvxl",    X(31, 359), X_MASK,	PPCVEC,		{ VD, RA, RB }, PPC_INST_LVXL },
{ "stvebx",  X(31, 135), X_MASK,	PPCVEC,		{ VS, RA, RB }, PPC_INST_STVEBX },
{ "stvehx",  X(31, 167), X_MASK,	PPCVEC,		{ VS, RA, RB }, PPC_INST_STVEHX },
{ "stvewx",  X(31, 199), X_MASK,	PPCVEC,		{ VS, RA, RB }, PPC_INST_STVEWX },
{ "stvx",    X(31, 231), X_MASK,	PPCVEC,		{ VS, RA, RB }, PPC_INST_STVX },
{ "stvxl",   X(31, 487), X_MASK,	PPCVEC,		{ VS, RA, RB }, PPC_INST_STVXL },

/* New load/store left/right index vector instructions that are in the Cell only.  */
{ "lvlx",    X(31, 519), X_MASK,	CELL | PPCVEC128,		{ VD, RA0, RB }, PPC_INST_LVLX },
{ "lvlxl",   X(31, 775), X_MASK,	CELL | PPCVEC128,		{ VD, RA0, RB }, PPC_INST_LVLXL },
{ "lvrx",    X(31, 551), X_MASK,	CELL | PPCVEC128,		{ VD, RA0, RB }, PPC_INST_LVRX },
{ "lvrxl",   X(31, 807), X_MASK,	CELL | PPCVEC128,		{ VD, RA0, RB }, PPC_INST_LVRXL },
{ "stvlx",   X(31, 647), X_MASK,	CELL | PPCVEC128,		{ VS, RA0, RB }, PPC_INST_STVLX },
{ "stvlxl",  X(31, 903), X_MASK,	CELL | PPCVEC128,		{ VS, RA0, RB }, PPC_INST_STVLXL },
{ "stvrx",   X(31, 679), X_MASK,	CELL | PPCVEC128,		{ VS, RA0, RB }, PPC_INST_STVRX },
{ "stvrxl",  X(31, 935), X_MASK,	CELL | PPCVEC128,		{ VS, RA0, RB }, PPC_INST_STVRXL },

{ "lwz",     OP(32),	OP_MASK,	PPCCOM,		{ RT, D, RA0 }, PPC_INST_LWZ },
{ "l",	     OP(32),	OP_MASK,	PWRCOM,		{ RT, D, RA0 }, PPC_INST_L },

{ "lwzu",    OP(33),	OP_MASK,	PPCCOM,		{ RT, D, RAL }, PPC_INST_LWZU },
{ "lu",      OP(33),	OP_MASK,	PWRCOM,		{ RT, D, RA0 }, PPC_INST_LU },

{ "lbz",     OP(34),	OP_MASK,	COM,		{ RT, D, RA0 }, PPC_INST_LBZ },

{ "lbzu",    OP(35),	OP_MASK,	COM,		{ RT, D, RAL }, PPC_INST_LBZU },

{ "stw",     OP(36),	OP_MASK,	PPCCOM,		{ RS, D, RA0 }, PPC_INST_STW },
{ "st",      OP(36),	OP_MASK,	PWRCOM,		{ RS, D, RA0 }, PPC_INST_ST },

{ "stwu",    OP(37),	OP_MASK,	PPCCOM,		{ RS, D, RAS }, PPC_INST_STWU },
{ "stu",     OP(37),	OP_MASK,	PWRCOM,		{ RS, D, RA0 }, PPC_INST_STU },

{ "stb",     OP(38),	OP_MASK,	COM,		{ RS, D, RA0 }, PPC_INST_STB },

{ "stbu",    OP(39),	OP_MASK,	COM,		{ RS, D, RAS }, PPC_INST_STBU },

{ "lhz",     OP(40),	OP_MASK,	COM,		{ RT, D, RA0 }, PPC_INST_LHZ },

{ "lhzu",    OP(41),	OP_MASK,	COM,		{ RT, D, RAL }, PPC_INST_LHZU },

{ "lha",     OP(42),	OP_MASK,	COM,		{ RT, D, RA0 }, PPC_INST_LHA },

{ "lhau",    OP(43),	OP_MASK,	COM,		{ RT, D, RAL }, PPC_INST_LHAU },

{ "sth",     OP(44),	OP_MASK,	COM,		{ RS, D, RA0 }, PPC_INST_STH },

{ "sthu",    OP(45),	OP_MASK,	COM,		{ RS, D, RAS }, PPC_INST_STHU },

{ "lmw",     OP(46),	OP_MASK,	PPCCOM,		{ RT, D, RAM }, PPC_INST_LMW },
{ "lm",      OP(46),	OP_MASK,	PWRCOM,		{ RT, D, RA0 }, PPC_INST_LM },

{ "stmw",    OP(47),	OP_MASK,	PPCCOM,		{ RS, D, RA0 }, PPC_INST_STMW },
{ "stm",     OP(47),	OP_MASK,	PWRCOM,		{ RS, D, RA0 }, PPC_INST_STM },

{ "lfs",     OP(48),	OP_MASK,	COM,		{ FRT, D, RA0 }, PPC_INST_LFS },

{ "lfsu",    OP(49),	OP_MASK,	COM,		{ FRT, D, RAS }, PPC_INST_LFSU },

{ "lfd",     OP(50),	OP_MASK,	COM,		{ FRT, D, RA0 }, PPC_INST_LFD },

{ "lfdu",    OP(51),	OP_MASK,	COM,		{ FRT, D, RAS }, PPC_INST_LFDU },

{ "stfs",    OP(52),	OP_MASK,	COM,		{ FRS, D, RA0 }, PPC_INST_STFS },

{ "stfsu",   OP(53),	OP_MASK,	COM,		{ FRS, D, RAS }, PPC_INST_STFSU },

{ "stfd",    OP(54),	OP_MASK,	COM,		{ FRS, D, RA0 }, PPC_INST_STFD },

{ "stfdu",   OP(55),	OP_MASK,	COM,		{ FRS, D, RAS }, PPC_INST_STFDU },

{ "lq",      OP(56),	OP_MASK,	POWER4,		{ RTQ, DQ, RAQ }, PPC_INST_LQ },

{ "lfq",     OP(56),	OP_MASK,	POWER2,		{ FRT, D, RA0 }, PPC_INST_LFQ },

{ "lfqu",    OP(57),	OP_MASK,	POWER2,		{ FRT, D, RA0 }, PPC_INST_LFQU },

{ "lfdp",    OP(57),	OP_MASK,	POWER6,		{ FRT, D, RA0 }, PPC_INST_LFDP },

{ "lbze",    DEO(58,0), DE_MASK,	BOOKE64,	{ RT, DE, RA0 }, PPC_INST_LBZE },
{ "lbzue",   DEO(58,1), DE_MASK,	BOOKE64,	{ RT, DE, RAL }, PPC_INST_LBZUE },
{ "lhze",    DEO(58,2), DE_MASK,	BOOKE64,	{ RT, DE, RA0 }, PPC_INST_LHZE },
{ "lhzue",   DEO(58,3), DE_MASK,	BOOKE64,	{ RT, DE, RAL }, PPC_INST_LHZUE },
{ "lhae",    DEO(58,4), DE_MASK,	BOOKE64,	{ RT, DE, RA0 }, PPC_INST_LHAE },
{ "lhaue",   DEO(58,5), DE_MASK,	BOOKE64,	{ RT, DE, RAL }, PPC_INST_LHAUE },
{ "lwze",    DEO(58,6), DE_MASK,	BOOKE64,	{ RT, DE, RA0 }, PPC_INST_LWZE },
{ "lwzue",   DEO(58,7), DE_MASK,	BOOKE64,	{ RT, DE, RAL }, PPC_INST_LWZUE },
{ "stbe",    DEO(58,8), DE_MASK,	BOOKE64,	{ RS, DE, RA0 }, PPC_INST_STBE },
{ "stbue",   DEO(58,9), DE_MASK,	BOOKE64,	{ RS, DE, RAS }, PPC_INST_STBUE },
{ "sthe",    DEO(58,10), DE_MASK,	BOOKE64,	{ RS, DE, RA0 }, PPC_INST_STHE },
{ "sthue",   DEO(58,11), DE_MASK,	BOOKE64,	{ RS, DE, RAS }, PPC_INST_STHUE },
{ "stwe",    DEO(58,14), DE_MASK,	BOOKE64,	{ RS, DE, RA0 }, PPC_INST_STWE },
{ "stwue",   DEO(58,15), DE_MASK,	BOOKE64,	{ RS, DE, RAS }, PPC_INST_STWUE },

{ "ld",      DSO(58,0),	DS_MASK,	PPC64,		{ RT, DS, RA0 }, PPC_INST_LD },

{ "ldu",     DSO(58,1), DS_MASK,	PPC64,		{ RT, DS, RAL }, PPC_INST_LDU },

{ "lwa",     DSO(58,2), DS_MASK,	PPC64,		{ RT, DS, RA0 }, PPC_INST_LWA },

{ "dadd",    XRC(59,2,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DADD },
{ "dadd.",   XRC(59,2,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DADD },

{ "dqua",    ZRC(59,3,0), Z2_MASK,	POWER6,		{ FRT, FRA, FRB, RMC }, PPC_INST_DQUA },
{ "dqua.",   ZRC(59,3,1), Z2_MASK,	POWER6,		{ FRT, FRA, FRB, RMC }, PPC_INST_DQUA },

{ "fdivs",   A(59,18,0), AFRC_MASK,	PPC,		{ FRT, FRA, FRB }, PPC_INST_FDIVS },
{ "fdivs.",  A(59,18,1), AFRC_MASK,	PPC,		{ FRT, FRA, FRB }, PPC_INST_FDIVS },

{ "fsubs",   A(59,20,0), AFRC_MASK,	PPC,		{ FRT, FRA, FRB }, PPC_INST_FSUBS },
{ "fsubs.",  A(59,20,1), AFRC_MASK,	PPC,		{ FRT, FRA, FRB }, PPC_INST_FSUBS },

{ "fadds",   A(59,21,0), AFRC_MASK,	PPC,		{ FRT, FRA, FRB }, PPC_INST_FADDS },
{ "fadds.",  A(59,21,1), AFRC_MASK,	PPC,		{ FRT, FRA, FRB }, PPC_INST_FADDS },

{ "fsqrts",  A(59,22,0), AFRAFRC_MASK,	PPC,		{ FRT, FRB }, PPC_INST_FSQRTS },
{ "fsqrts.", A(59,22,1), AFRAFRC_MASK,	PPC,		{ FRT, FRB }, PPC_INST_FSQRTS },

{ "fres",    A(59,24,0), AFRALFRC_MASK,	PPC,		{ FRT, FRB, A_L }, PPC_INST_FRES },
{ "fres.",   A(59,24,1), AFRALFRC_MASK,	PPC,		{ FRT, FRB, A_L }, PPC_INST_FRES },

{ "fmuls",   A(59,25,0), AFRB_MASK,	PPC,		{ FRT, FRA, FRC }, PPC_INST_FMULS },
{ "fmuls.",  A(59,25,1), AFRB_MASK,	PPC,		{ FRT, FRA, FRC }, PPC_INST_FMULS },

{ "frsqrtes", A(59,26,0), AFRALFRC_MASK,POWER5,		{ FRT, FRB, A_L }, PPC_INST_FRSQRTES },
{ "frsqrtes.",A(59,26,1), AFRALFRC_MASK,POWER5,		{ FRT, FRB, A_L }, PPC_INST_FRSQRTES },

{ "fmsubs",  A(59,28,0), A_MASK,	PPC,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMSUBS },
{ "fmsubs.", A(59,28,1), A_MASK,	PPC,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMSUBS },

{ "fmadds",  A(59,29,0), A_MASK,	PPC,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMADDS },
{ "fmadds.", A(59,29,1), A_MASK,	PPC,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMADDS },

{ "fnmsubs", A(59,30,0), A_MASK,	PPC,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMSUBS },
{ "fnmsubs.",A(59,30,1), A_MASK,	PPC,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMSUBS },

{ "fnmadds", A(59,31,0), A_MASK,	PPC,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMADDS },
{ "fnmadds.",A(59,31,1), A_MASK,	PPC,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMADDS },

{ "dmul",    XRC(59,34,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DMUL },
{ "dmul.",   XRC(59,34,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DMUL },

{ "drrnd",   ZRC(59,35,0), Z2_MASK,	POWER6,		{ FRT, FRA, FRB, RMC }, PPC_INST_DRRND },
{ "drrnd.",  ZRC(59,35,1), Z2_MASK,	POWER6,		{ FRT, FRA, FRB, RMC }, PPC_INST_DRRND },

{ "dscli",   ZRC(59,66,0), Z_MASK,	POWER6,		{ FRT, FRA, SH16 }, PPC_INST_DSCLI },
{ "dscli.",  ZRC(59,66,1), Z_MASK,	POWER6,		{ FRT, FRA, SH16 }, PPC_INST_DSCLI },

{ "dquai",   ZRC(59,67,0), Z2_MASK,	POWER6,		{ TE,  FRT, FRB, RMC }, PPC_INST_DQUAI },
{ "dquai.",  ZRC(59,67,1), Z2_MASK,	POWER6,		{ TE,  FRT, FRB, RMC }, PPC_INST_DQUAI },

{ "dscri",   ZRC(59,98,0), Z_MASK,	POWER6,		{ FRT, FRA, SH16 }, PPC_INST_DSCRI },
{ "dscri.",  ZRC(59,98,1), Z_MASK,	POWER6,		{ FRT, FRA, SH16 }, PPC_INST_DSCRI },

{ "drintx",  ZRC(59,99,0), Z2_MASK,	POWER6,		{ R, FRT, FRB, RMC }, PPC_INST_DRINTX },
{ "drintx.", ZRC(59,99,1), Z2_MASK,	POWER6,		{ R, FRT, FRB, RMC }, PPC_INST_DRINTX },

{ "dcmpo",   X(59,130),	   X_MASK,	POWER6,		{ BF,  FRA, FRB }, PPC_INST_DCMPO },

{ "dtstex",  X(59,162),	   X_MASK,	POWER6,		{ BF,  FRA, FRB }, PPC_INST_DTSTEX },
{ "dtstdc",  Z(59,194),	   Z_MASK,	POWER6,		{ BF,  FRA, DCM }, PPC_INST_DTSTDC },
{ "dtstdg",  Z(59,226),	   Z_MASK,	POWER6,		{ BF,  FRA, DGM }, PPC_INST_DTSTDG },

{ "drintn",  ZRC(59,227,0), Z2_MASK,	POWER6,		{ R, FRT, FRB, RMC }, PPC_INST_DRINTN },
{ "drintn.", ZRC(59,227,1), Z2_MASK,	POWER6,		{ R, FRT, FRB, RMC }, PPC_INST_DRINTN },

{ "dctdp",   XRC(59,258,0), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCTDP },
{ "dctdp.",  XRC(59,258,1), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCTDP },

{ "dctfix",  XRC(59,290,0), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCTFIX },
{ "dctfix.", XRC(59,290,1), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCTFIX },

{ "ddedpd",  XRC(59,322,0), X_MASK,	POWER6,		{ SP, FRT, FRB }, PPC_INST_DDEDPD },
{ "ddedpd.", XRC(59,322,1), X_MASK,	POWER6,		{ SP, FRT, FRB }, PPC_INST_DDEDPD },

{ "dxex",    XRC(59,354,0), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DXEX },
{ "dxex.",   XRC(59,354,1), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DXEX },

{ "dsub",    XRC(59,514,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DSUB },
{ "dsub.",   XRC(59,514,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DSUB },

{ "ddiv",    XRC(59,546,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DDIV },
{ "ddiv.",   XRC(59,546,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DDIV },

{ "dcmpu",   X(59,642),	    X_MASK,	POWER6,		{ BF,  FRA, FRB }, PPC_INST_DCMPU },

{ "dtstsf",  X(59,674),	   X_MASK,	POWER6,		{ BF,  FRA, FRB }, PPC_INST_DTSTSF },

{ "drsp",    XRC(59,770,0), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DRSP },
{ "drsp.",   XRC(59,770,1), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DRSP },

{ "dcffix",  XRC(59,802,0), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCFFIX },
{ "dcffix.", XRC(59,802,1), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCFFIX },

{ "denbcd",  XRC(59,834,0), X_MASK,	POWER6,		{ S, FRT, FRB }, PPC_INST_DENBCD },
{ "denbcd.", XRC(59,834,1), X_MASK,	POWER6,		{ S, FRT, FRB }, PPC_INST_DENBCD },

{ "diex",    XRC(59,866,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DIEX },
{ "diex.",   XRC(59,866,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DIEX },

{ "stfq",    OP(60),	OP_MASK,	POWER2,		{ FRS, D, RA }, PPC_INST_STFQ },

{ "stfqu",   OP(61),	OP_MASK,	POWER2,		{ FRS, D, RA }, PPC_INST_STFQU },

{ "stfdp",   OP(61),	OP_MASK,	POWER6,		{ FRT, D, RA0 }, PPC_INST_STFDP },

{ "lde",     DEO(62,0), DE_MASK,	BOOKE64,	{ RT, DES, RA0 }, PPC_INST_LDE },
{ "ldue",    DEO(62,1), DE_MASK,	BOOKE64,	{ RT, DES, RA0 }, PPC_INST_LDUE },
{ "lfse",    DEO(62,4), DE_MASK,	BOOKE64,	{ FRT, DES, RA0 }, PPC_INST_LFSE },
{ "lfsue",   DEO(62,5), DE_MASK,	BOOKE64,	{ FRT, DES, RAS }, PPC_INST_LFSUE },
{ "lfde",    DEO(62,6), DE_MASK,	BOOKE64,	{ FRT, DES, RA0 }, PPC_INST_LFDE },
{ "lfdue",   DEO(62,7), DE_MASK,	BOOKE64,	{ FRT, DES, RAS }, PPC_INST_LFDUE },
{ "stde",    DEO(62,8), DE_MASK,	BOOKE64,	{ RS, DES, RA0 }, PPC_INST_STDE },
{ "stdue",   DEO(62,9), DE_MASK,	BOOKE64,	{ RS, DES, RAS }, PPC_INST_STDUE },
{ "stfse",   DEO(62,12), DE_MASK,	BOOKE64,	{ FRS, DES, RA0 }, PPC_INST_STFSE },
{ "stfsue",  DEO(62,13), DE_MASK,	BOOKE64,	{ FRS, DES, RAS }, PPC_INST_STFSUE },
{ "stfde",   DEO(62,14), DE_MASK,	BOOKE64,	{ FRS, DES, RA0 }, PPC_INST_STFDE },
{ "stfdue",  DEO(62,15), DE_MASK,	BOOKE64,	{ FRS, DES, RAS }, PPC_INST_STFDUE },

{ "std",     DSO(62,0),	DS_MASK,	PPC64,		{ RS, DS, RA0 }, PPC_INST_STD },

{ "stdu",    DSO(62,1),	DS_MASK,	PPC64,		{ RS, DS, RAS }, PPC_INST_STDU },

{ "stq",     DSO(62,2),	DS_MASK,	POWER4,		{ RSQ, DS, RA0 }, PPC_INST_STQ },

{ "fcmpu",   X(63,0),	X_MASK | (3 << 21),	COM,		{ BF, FRA, FRB }, PPC_INST_FCMPU },

{ "daddq",   XRC(63,2,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DADDQ },
{ "daddq.",  XRC(63,2,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DADDQ },

{ "dquaq",   ZRC(63,3,0), Z2_MASK,	POWER6,		{ FRT, FRA, FRB, RMC }, PPC_INST_DQUAQ },
{ "dquaq.",  ZRC(63,3,1), Z2_MASK,	POWER6,		{ FRT, FRA, FRB, RMC }, PPC_INST_DQUAQ },

{ "fcpsgn",  XRC(63,8,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_FCPSGN },
{ "fcpsgn.", XRC(63,8,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_FCPSGN },

{ "frsp",    XRC(63,12,0), XRA_MASK,	COM,		{ FRT, FRB }, PPC_INST_FRSP },
{ "frsp.",   XRC(63,12,1), XRA_MASK,	COM,		{ FRT, FRB }, PPC_INST_FRSP },

{ "fctiw",   XRC(63,14,0), XRA_MASK,	PPCCOM,		{ FRT, FRB }, PPC_INST_FCTIW },
{ "fcir",    XRC(63,14,0), XRA_MASK,	POWER2,		{ FRT, FRB }, PPC_INST_FCIR },
{ "fctiw.",  XRC(63,14,1), XRA_MASK,	PPCCOM,		{ FRT, FRB }, PPC_INST_FCTIW },
{ "fcir.",   XRC(63,14,1), XRA_MASK,	POWER2,		{ FRT, FRB }, PPC_INST_FCIR },

{ "fctiwz",  XRC(63,15,0), XRA_MASK,	PPCCOM,		{ FRT, FRB }, PPC_INST_FCTIWZ },
{ "fcirz",   XRC(63,15,0), XRA_MASK,	POWER2,		{ FRT, FRB }, PPC_INST_FCIRZ },
{ "fctiwz.", XRC(63,15,1), XRA_MASK,	PPCCOM,		{ FRT, FRB }, PPC_INST_FCTIWZ },
{ "fcirz.",  XRC(63,15,1), XRA_MASK,	POWER2,		{ FRT, FRB }, PPC_INST_FCIRZ },

{ "fdiv",    A(63,18,0), AFRC_MASK,	PPCCOM,		{ FRT, FRA, FRB }, PPC_INST_FDIV },
{ "fd",      A(63,18,0), AFRC_MASK,	PWRCOM,		{ FRT, FRA, FRB }, PPC_INST_FD },
{ "fdiv.",   A(63,18,1), AFRC_MASK,	PPCCOM,		{ FRT, FRA, FRB }, PPC_INST_FDIV },
{ "fd.",     A(63,18,1), AFRC_MASK,	PWRCOM,		{ FRT, FRA, FRB }, PPC_INST_FD },

{ "fsub",    A(63,20,0), AFRC_MASK,	PPCCOM,		{ FRT, FRA, FRB }, PPC_INST_FSUB },
{ "fs",      A(63,20,0), AFRC_MASK,	PWRCOM,		{ FRT, FRA, FRB }, PPC_INST_FS },
{ "fsub.",   A(63,20,1), AFRC_MASK,	PPCCOM,		{ FRT, FRA, FRB }, PPC_INST_FSUB },
{ "fs.",     A(63,20,1), AFRC_MASK,	PWRCOM,		{ FRT, FRA, FRB }, PPC_INST_FS },

{ "fadd",    A(63,21,0), AFRC_MASK,	PPCCOM,		{ FRT, FRA, FRB }, PPC_INST_FADD },
{ "fa",      A(63,21,0), AFRC_MASK,	PWRCOM,		{ FRT, FRA, FRB }, PPC_INST_FA },
{ "fadd.",   A(63,21,1), AFRC_MASK,	PPCCOM,		{ FRT, FRA, FRB }, PPC_INST_FADD },
{ "fa.",     A(63,21,1), AFRC_MASK,	PWRCOM,		{ FRT, FRA, FRB }, PPC_INST_FA },

{ "fsqrt",   A(63,22,0), AFRAFRC_MASK,	PPCPWR2,	{ FRT, FRB }, PPC_INST_FSQRT },
{ "fsqrt.",  A(63,22,1), AFRAFRC_MASK,	PPCPWR2,	{ FRT, FRB }, PPC_INST_FSQRT },

{ "fsel",    A(63,23,0), A_MASK,	PPC,		{ FRT,FRA,FRC,FRB }, PPC_INST_FSEL },
{ "fsel.",   A(63,23,1), A_MASK,	PPC,		{ FRT,FRA,FRC,FRB }, PPC_INST_FSEL },

{ "fre",     A(63,24,0), AFRALFRC_MASK,	POWER5,		{ FRT, FRB, A_L }, PPC_INST_FRE },
{ "fre.",    A(63,24,1), AFRALFRC_MASK,	POWER5,		{ FRT, FRB, A_L }, PPC_INST_FRE },

{ "fmul",    A(63,25,0), AFRB_MASK,	PPCCOM,		{ FRT, FRA, FRC }, PPC_INST_FMUL },
{ "fm",      A(63,25,0), AFRB_MASK,	PWRCOM,		{ FRT, FRA, FRC }, PPC_INST_FM },
{ "fmul.",   A(63,25,1), AFRB_MASK,	PPCCOM,		{ FRT, FRA, FRC }, PPC_INST_FMUL },
{ "fm.",     A(63,25,1), AFRB_MASK,	PWRCOM,		{ FRT, FRA, FRC }, PPC_INST_FM },

{ "frsqrte", A(63,26,0), AFRALFRC_MASK,	PPC,		{ FRT, FRB, A_L }, PPC_INST_FRSQRTE },
{ "frsqrte.",A(63,26,1), AFRALFRC_MASK,	PPC,		{ FRT, FRB, A_L }, PPC_INST_FRSQRTE },

{ "fmsub",   A(63,28,0), A_MASK,	PPCCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMSUB },
{ "fms",     A(63,28,0), A_MASK,	PWRCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMS },
{ "fmsub.",  A(63,28,1), A_MASK,	PPCCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMSUB },
{ "fms.",    A(63,28,1), A_MASK,	PWRCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMS },

{ "fmadd",   A(63,29,0), A_MASK,	PPCCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMADD },
{ "fma",     A(63,29,0), A_MASK,	PWRCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMA },
{ "fmadd.",  A(63,29,1), A_MASK,	PPCCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMADD },
{ "fma.",    A(63,29,1), A_MASK,	PWRCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FMA },

{ "fnmsub",  A(63,30,0), A_MASK,	PPCCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMSUB },
{ "fnms",    A(63,30,0), A_MASK,	PWRCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMS },
{ "fnmsub.", A(63,30,1), A_MASK,	PPCCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMSUB },
{ "fnms.",   A(63,30,1), A_MASK,	PWRCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMS },

{ "fnmadd",  A(63,31,0), A_MASK,	PPCCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMADD },
{ "fnma",    A(63,31,0), A_MASK,	PWRCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMA },
{ "fnmadd.", A(63,31,1), A_MASK,	PPCCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMADD },
{ "fnma.",   A(63,31,1), A_MASK,	PWRCOM,		{ FRT,FRA,FRC,FRB }, PPC_INST_FNMA },

{ "fcmpo",   X(63,32),	X_MASK | (3 << 21),	COM,		{ BF, FRA, FRB }, PPC_INST_FCMPO },

{ "dmulq",   XRC(63,34,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DMULQ },
{ "dmulq.",  XRC(63,34,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DMULQ },

{ "drrndq",  ZRC(63,35,0), Z2_MASK,	POWER6,		{ FRT, FRA, FRB, RMC }, PPC_INST_DRRNDQ },
{ "drrndq.", ZRC(63,35,1), Z2_MASK,	POWER6,		{ FRT, FRA, FRB, RMC }, PPC_INST_DRRNDQ },

{ "mtfsb1",  XRC(63,38,0), XRARB_MASK,	COM,		{ BT }, PPC_INST_MTFSB1 },
{ "mtfsb1.", XRC(63,38,1), XRARB_MASK,	COM,		{ BT }, PPC_INST_MTFSB1 },

{ "fneg",    XRC(63,40,0), XRA_MASK,	COM,		{ FRT, FRB }, PPC_INST_FNEG },
{ "fneg.",   XRC(63,40,1), XRA_MASK,	COM,		{ FRT, FRB }, PPC_INST_FNEG },

{ "mcrfs",   X(63,64),	XRB_MASK | (3 << 21) | (3 << 16), COM,	{ BF, BFA }, PPC_INST_MCRFS },

{ "dscliq",  ZRC(63,66,0), Z_MASK,	POWER6,		{ FRT, FRA, SH16 }, PPC_INST_DSCLIQ },
{ "dscliq.", ZRC(63,66,1), Z_MASK,	POWER6,		{ FRT, FRA, SH16 }, PPC_INST_DSCLIQ },

{ "dquaiq",  ZRC(63,67,0), Z2_MASK,	POWER6,		{ TE,  FRT, FRB, RMC }, PPC_INST_DQUAIQ },
{ "dquaiq.", ZRC(63,67,1), Z2_MASK,	POWER6,		{ FRT, FRA, FRB, RMC }, PPC_INST_DQUAIQ },

{ "mtfsb0",  XRC(63,70,0), XRARB_MASK,	COM,		{ BT }, PPC_INST_MTFSB0 },
{ "mtfsb0.", XRC(63,70,1), XRARB_MASK,	COM,		{ BT }, PPC_INST_MTFSB0 },

{ "fmr",     XRC(63,72,0), XRA_MASK,	COM,		{ FRT, FRB }, PPC_INST_FMR },
{ "fmr.",    XRC(63,72,1), XRA_MASK,	COM,		{ FRT, FRB }, PPC_INST_FMR },

{ "dscriq",  ZRC(63,98,0), Z_MASK,	POWER6,		{ FRT, FRA, SH16 }, PPC_INST_DSCRIQ },
{ "dscriq.", ZRC(63,98,1), Z_MASK,	POWER6,		{ FRT, FRA, SH16 }, PPC_INST_DSCRIQ },

{ "drintxq", ZRC(63,99,0), Z2_MASK,	POWER6,		{ R, FRT, FRB, RMC }, PPC_INST_DRINTXQ },
{ "drintxq.",ZRC(63,99,1), Z2_MASK,	POWER6,		{ R, FRT, FRB, RMC }, PPC_INST_DRINTXQ },

{ "dcmpoq",  X(63,130),	   X_MASK,	POWER6,		{ BF,  FRA, FRB }, PPC_INST_DCMPOQ },

{ "mtfsfi",  XRC(63,134,0), XWRA_MASK | (3 << 21) | (1 << 11), COM, { BFF, U, W }, PPC_INST_MTFSFI },
{ "mtfsfi.", XRC(63,134,1), XWRA_MASK | (3 << 21) | (1 << 11), COM, { BFF, U, W }, PPC_INST_MTFSFI },

{ "fnabs",   XRC(63,136,0), XRA_MASK,	COM,		{ FRT, FRB }, PPC_INST_FNABS },
{ "fnabs.",  XRC(63,136,1), XRA_MASK,	COM,		{ FRT, FRB }, PPC_INST_FNABS },

{ "dtstexq", X(63,162),	    X_MASK,	POWER6,		{ BF,  FRA, FRB }, PPC_INST_DTSTEXQ },
{ "dtstdcq", Z(63,194),	    Z_MASK,	POWER6,		{ BF,  FRA, DCM }, PPC_INST_DTSTDCQ },
{ "dtstdgq", Z(63,226),	    Z_MASK,	POWER6,		{ BF,  FRA, DGM }, PPC_INST_DTSTDGQ },

{ "drintnq", ZRC(63,227,0), Z2_MASK,	POWER6,		{ R, FRT, FRB, RMC }, PPC_INST_DRINTNQ },
{ "drintnq.",ZRC(63,227,1), Z2_MASK,	POWER6,		{ R, FRT, FRB, RMC }, PPC_INST_DRINTNQ },

{ "dctqpq",  XRC(63,258,0), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCTQPQ },
{ "dctqpq.", XRC(63,258,1), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCTQPQ },

{ "fabs",    XRC(63,264,0), XRA_MASK,	COM,		{ FRT, FRB }, PPC_INST_FABS },
{ "fabs.",   XRC(63,264,1), XRA_MASK,	COM,		{ FRT, FRB }, PPC_INST_FABS },

{ "dctfixq", XRC(63,290,0), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCTFIXQ },
{ "dctfixq.",XRC(63,290,1), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCTFIXQ },

{ "ddedpdq", XRC(63,322,0), X_MASK,	POWER6,		{ SP, FRT, FRB }, PPC_INST_DDEDPDQ },
{ "ddedpdq.",XRC(63,322,1), X_MASK,	POWER6,		{ SP, FRT, FRB }, PPC_INST_DDEDPDQ },

{ "dxexq",   XRC(63,354,0), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DXEXQ },
{ "dxexq.",  XRC(63,354,1), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DXEXQ },

{ "frin",    XRC(63,392,0), XRA_MASK,	POWER5,		{ FRT, FRB }, PPC_INST_FRIN },
{ "frin.",   XRC(63,392,1), XRA_MASK,	POWER5,		{ FRT, FRB }, PPC_INST_FRIN },
{ "friz",    XRC(63,424,0), XRA_MASK,	POWER5,		{ FRT, FRB }, PPC_INST_FRIZ },
{ "friz.",   XRC(63,424,1), XRA_MASK,	POWER5,		{ FRT, FRB }, PPC_INST_FRIZ },
{ "frip",    XRC(63,456,0), XRA_MASK,	POWER5,		{ FRT, FRB }, PPC_INST_FRIP },
{ "frip.",   XRC(63,456,1), XRA_MASK,	POWER5,		{ FRT, FRB }, PPC_INST_FRIP },
{ "frim",    XRC(63,488,0), XRA_MASK,	POWER5,		{ FRT, FRB }, PPC_INST_FRIM },
{ "frim.",   XRC(63,488,1), XRA_MASK,	POWER5,		{ FRT, FRB }, PPC_INST_FRIM },

{ "dsubq",   XRC(63,514,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DSUBQ },
{ "dsubq.",  XRC(63,514,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DSUBQ },

{ "ddivq",   XRC(63,546,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DDIVQ },
{ "ddivq.",  XRC(63,546,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DDIVQ },

{ "mffs",    XRC(63,583,0), XRARB_MASK,	COM,		{ FRT }, PPC_INST_MFFS },
{ "mffs.",   XRC(63,583,1), XRARB_MASK,	COM,		{ FRT }, PPC_INST_MFFS },

{ "dcmpuq",  X(63,642),	    X_MASK,	POWER6,		{ BF,  FRA, FRB }, PPC_INST_DCMPUQ },

{ "dtstsfq", X(63,674),	    X_MASK,	POWER6,		{ BF,  FRA, FRB }, PPC_INST_DTSTSFQ },

{ "mtfsf",   XFL(63,711,0), XFL_MASK,	COM,		{ FLM, FRB, XFL_L, W }, PPC_INST_MTFSF },
{ "mtfsf.",  XFL(63,711,1), XFL_MASK,	COM,		{ FLM, FRB, XFL_L, W }, PPC_INST_MTFSF },

{ "drdpq",   XRC(63,770,0), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DRDPQ },
{ "drdpq.",  XRC(63,770,1), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DRDPQ },

{ "dcffixq", XRC(63,802,0), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCFFIXQ },
{ "dcffixq.",XRC(63,802,1), X_MASK,	POWER6,		{ FRT, FRB }, PPC_INST_DCFFIXQ },

{ "fctid",   XRC(63,814,0), XRA_MASK,	PPC64,		{ FRT, FRB }, PPC_INST_FCTID },
{ "fctid.",  XRC(63,814,1), XRA_MASK,	PPC64,		{ FRT, FRB }, PPC_INST_FCTID },

{ "fctidz",  XRC(63,815,0), XRA_MASK,	PPC64,		{ FRT, FRB }, PPC_INST_FCTIDZ },
{ "fctidz.", XRC(63,815,1), XRA_MASK,	PPC64,		{ FRT, FRB }, PPC_INST_FCTIDZ },

{ "denbcdq", XRC(63,834,0), X_MASK,	POWER6,		{ S, FRT, FRB }, PPC_INST_DENBCDQ },
{ "denbcdq.",XRC(63,834,1), X_MASK,	POWER6,		{ S, FRT, FRB }, PPC_INST_DENBCDQ },

{ "fcfid",   XRC(63,846,0), XRA_MASK,	PPC64,		{ FRT, FRB }, PPC_INST_FCFID },
{ "fcfid.",  XRC(63,846,1), XRA_MASK,	PPC64,		{ FRT, FRB }, PPC_INST_FCFID },

{ "diexq",   XRC(63,866,0), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DIEXQ },
{ "diexq.",  XRC(63,866,1), X_MASK,	POWER6,		{ FRT, FRA, FRB }, PPC_INST_DIEXQ },

};

// (.+?")(.+)?(".+?)(\},)
// $1$2$3, POWERPC_INSTRUCTION_\U$2 $4

const int powerpc_num_opcodes =
sizeof(powerpc_opcodes) / sizeof(powerpc_opcodes[0]);

/* The macro table.  This is only used by the assembler.  */

/* The expressions of the form (-x ! 31) & (x | 31) have the value 0
   when x=0; 32-x when x is between 1 and 31; are negative if x is
   negative; and are 32 or more otherwise.  This is what you want
   when, for instance, you are emulating a right shift by a
   rotate-left-and-mask, because the underlying instructions support
   shifts of size 0 but not shifts of size 32.  By comparison, when
   extracting x bits from some word you want to use just 32-x, because
   the underlying instructions don't support extracting 0 bits but do
   support extracting the whole word (32 bits in this case).  */

const struct powerpc_macro powerpc_macros[] = {
{ "extldi",  4,   PPC64,	"rldicr %0,%1,%3,(%2)-1" },
{ "extldi.", 4,   PPC64,	"rldicr. %0,%1,%3,(%2)-1" },
{ "extrdi",  4,   PPC64,	"rldicl %0,%1,(%2)+(%3),64-(%2)" },
{ "extrdi.", 4,   PPC64,	"rldicl. %0,%1,(%2)+(%3),64-(%2)" },
{ "insrdi",  4,   PPC64,	"rldimi %0,%1,64-((%2)+(%3)),%3" },
{ "insrdi.", 4,   PPC64,	"rldimi. %0,%1,64-((%2)+(%3)),%3" },
{ "rotrdi",  3,   PPC64,	"rldicl %0,%1,(-(%2)!63)&((%2)|63),0" },
{ "rotrdi.", 3,   PPC64,	"rldicl. %0,%1,(-(%2)!63)&((%2)|63),0" },
{ "sldi",    3,   PPC64,	"rldicr %0,%1,%2,63-(%2)" },
{ "sldi.",   3,   PPC64,	"rldicr. %0,%1,%2,63-(%2)" },
{ "srdi",    3,   PPC64,	"rldicl %0,%1,(-(%2)!63)&((%2)|63),%2" },
{ "srdi.",   3,   PPC64,	"rldicl. %0,%1,(-(%2)!63)&((%2)|63),%2" },
{ "clrrdi",  3,   PPC64,	"rldicr %0,%1,0,63-(%2)" },
{ "clrrdi.", 3,   PPC64,	"rldicr. %0,%1,0,63-(%2)" },
{ "clrlsldi",4,   PPC64,	"rldic %0,%1,%3,(%2)-(%3)" },
{ "clrlsldi.",4,  PPC64,	"rldic. %0,%1,%3,(%2)-(%3)" },

{ "extlwi",  4,   PPCCOM,	"rlwinm %0,%1,%3,0,(%2)-1" },
{ "extlwi.", 4,   PPCCOM,	"rlwinm. %0,%1,%3,0,(%2)-1" },
{ "extrwi",  4,   PPCCOM,	"rlwinm %0,%1,((%2)+(%3))&((%2)+(%3)<>32),32-(%2),31" },
{ "extrwi.", 4,   PPCCOM,	"rlwinm. %0,%1,((%2)+(%3))&((%2)+(%3)<>32),32-(%2),31" },
{ "inslwi",  4,   PPCCOM,	"rlwimi %0,%1,(-(%3)!31)&((%3)|31),%3,(%2)+(%3)-1" },
{ "inslwi.", 4,   PPCCOM,	"rlwimi. %0,%1,(-(%3)!31)&((%3)|31),%3,(%2)+(%3)-1"},
{ "insrwi",  4,   PPCCOM,	"rlwimi %0,%1,32-((%2)+(%3)),%3,(%2)+(%3)-1" },
{ "insrwi.", 4,   PPCCOM,	"rlwimi. %0,%1,32-((%2)+(%3)),%3,(%2)+(%3)-1"},
{ "rotrwi",  3,   PPCCOM,	"rlwinm %0,%1,(-(%2)!31)&((%2)|31),0,31" },
{ "rotrwi.", 3,   PPCCOM,	"rlwinm. %0,%1,(-(%2)!31)&((%2)|31),0,31" },
{ "slwi",    3,   PPCCOM,	"rlwinm %0,%1,%2,0,31-(%2)" },
{ "sli",     3,   PWRCOM,	"rlinm %0,%1,%2,0,31-(%2)" },
{ "slwi.",   3,   PPCCOM,	"rlwinm. %0,%1,%2,0,31-(%2)" },
{ "sli.",    3,   PWRCOM,	"rlinm. %0,%1,%2,0,31-(%2)" },
{ "srwi",    3,   PPCCOM,	"rlwinm %0,%1,(-(%2)!31)&((%2)|31),%2,31" },
{ "sri",     3,   PWRCOM,	"rlinm %0,%1,(-(%2)!31)&((%2)|31),%2,31" },
{ "srwi.",   3,   PPCCOM,	"rlwinm. %0,%1,(-(%2)!31)&((%2)|31),%2,31" },
{ "sri.",    3,   PWRCOM,	"rlinm. %0,%1,(-(%2)!31)&((%2)|31),%2,31" },
{ "clrrwi",  3,   PPCCOM,	"rlwinm %0,%1,0,0,31-(%2)" },
{ "clrrwi.", 3,   PPCCOM,	"rlwinm. %0,%1,0,0,31-(%2)" },
{ "clrlslwi",4,   PPCCOM,	"rlwinm %0,%1,%3,(%2)-(%3),31-(%3)" },
{ "clrlslwi.",4,  PPCCOM,	"rlwinm. %0,%1,%3,(%2)-(%3),31-(%3)" },
};

const int powerpc_num_macros =
sizeof(powerpc_macros) / sizeof(powerpc_macros[0]);


/* This file provides several disassembler functions, all of which use
   the disassembler interface defined in dis-asm.h.  Several functions
   are provided because this file handles disassembly for the PowerPC
   in both big and little endian mode and also for the POWER (RS/6000)
   chip.  */

static int print_insn_powerpc(bfd_vma, struct disassemble_info*, int, int);
static int decode_insn_powerpc(bfd_vma memaddr, disassemble_info* info, int bigendian, int dialect, ppc_insn* oinsn);

/* Determine which set of machines to disassemble for.  PPC403/601 or
   BookE.  For convenience, also disassemble instructions supported
   by the AltiVec vector unit.  */

static int
powerpc_dialect(struct disassemble_info* info)
{
    int dialect = PPC_OPCODE_PPC;

    if (BFD_DEFAULT_TARGET_SIZE == 64)
        dialect |= PPC_OPCODE_64;

    if (info->disassembler_options
        && strstr(info->disassembler_options, "booke") != NULL)
        dialect |= PPC_OPCODE_BOOKE | PPC_OPCODE_BOOKE64;
    else if ((info->mach == bfd_mach_ppc_e500)
        || (info->disassembler_options
            && strstr(info->disassembler_options, "e500") != NULL))
        dialect |= (PPC_OPCODE_BOOKE
            | PPC_OPCODE_SPE | PPC_OPCODE_ISEL
            | PPC_OPCODE_EFS | PPC_OPCODE_BRLOCK
            | PPC_OPCODE_PMR | PPC_OPCODE_CACHELCK
            | PPC_OPCODE_RFMCI);
    else if (info->disassembler_options
        && strstr(info->disassembler_options, "efs") != NULL)
        dialect |= PPC_OPCODE_EFS;
    else if (info->disassembler_options
        && strstr(info->disassembler_options, "e300") != NULL)
        dialect |= PPC_OPCODE_E300 | PPC_OPCODE_CLASSIC | PPC_OPCODE_COMMON;
    else if (info->disassembler_options
        && strstr(info->disassembler_options, "440") != NULL)
        dialect |= PPC_OPCODE_BOOKE | PPC_OPCODE_32
        | PPC_OPCODE_440 | PPC_OPCODE_ISEL | PPC_OPCODE_RFMCI;
    else
        dialect |= (PPC_OPCODE_403 | PPC_OPCODE_601 | PPC_OPCODE_CLASSIC
            | PPC_OPCODE_COMMON | PPC_OPCODE_ALTIVEC);

    if (info->disassembler_options
        && strstr(info->disassembler_options, "power4") != NULL)
        dialect |= PPC_OPCODE_POWER4;

    if (info->disassembler_options
        && strstr(info->disassembler_options, "power5") != NULL)
        dialect |= PPC_OPCODE_POWER4 | PPC_OPCODE_POWER5;

    if (info->disassembler_options
        && strstr(info->disassembler_options, "cell") != NULL)
        dialect |= PPC_OPCODE_POWER4 | PPC_OPCODE_CELL | PPC_OPCODE_ALTIVEC | PPC_OPCODE_VMX_128;

    if (info->disassembler_options
        && strstr(info->disassembler_options, "power6") != NULL)
        dialect |= PPC_OPCODE_POWER4 | PPC_OPCODE_POWER5 | PPC_OPCODE_POWER6 | PPC_OPCODE_ALTIVEC;

    if (info->disassembler_options
        && strstr(info->disassembler_options, "any") != NULL)
        dialect |= PPC_OPCODE_ANY;

    if (info->disassembler_options)
    {
        if (strstr(info->disassembler_options, "32") != NULL)
            dialect &= ~PPC_OPCODE_64;
        else if (strstr(info->disassembler_options, "64") != NULL)
            dialect |= PPC_OPCODE_64;
    }

    info->private_data = (char*)0 + dialect;
    return dialect;
}

int decode_insn_ppc(bfd_vma memaddr, disassemble_info* info, ppc_insn* oinsn)
{
    int dialect = (char*)info->private_data - (char*)0;
    return decode_insn_powerpc(memaddr, info, 1, dialect, oinsn);
}

/* Qemu default */
int
print_insn_ppc(bfd_vma memaddr, struct disassemble_info* info)
{
    int dialect = (char*)info->private_data - (char*)0;
    return print_insn_powerpc(memaddr, info, 1, dialect);
}

/* Print a big endian PowerPC instruction.  */

int
print_insn_big_powerpc(bfd_vma memaddr, struct disassemble_info* info)
{
    int dialect = (char*)info->private_data - (char*)0;
    return print_insn_powerpc(memaddr, info, 1, dialect);
}

/* Print a little endian PowerPC instruction.  */

int
print_insn_little_powerpc(bfd_vma memaddr, struct disassemble_info* info)
{
    int dialect = (char*)info->private_data - (char*)0;
    return print_insn_powerpc(memaddr, info, 0, dialect);
}

/* Print a POWER (RS/6000) instruction.  */

int
print_insn_rs6000(bfd_vma memaddr, struct disassemble_info* info)
{
    return print_insn_powerpc(memaddr, info, 1, PPC_OPCODE_POWER);
}

/* Extract the operand value from the PowerPC or POWER instruction.  */

static long
operand_value_powerpc(const struct powerpc_operand* operand,
    unsigned long insn, int dialect)
{
    long value;
    int invalid;
    /* Extract the value from the instruction.  */
    if (operand->extract)
        value = (*operand->extract) (insn, dialect, &invalid);
    else
    {
        value = (insn >> operand->shift) & operand->bitm;
        if ((operand->flags & PPC_OPERAND_SIGNED) != 0)
        {
            /* BITM is always some number of zeros followed by some
               number of ones, followed by some numer of zeros.  */
            unsigned long top = operand->bitm;
            /* top & -top gives the rightmost 1 bit, so this
               fills in any trailing zeros.  */
            top |= (top & -top) - 1;
            top &= ~(top >> 1);
            value = (value ^ top) - top;
        }
    }

    return value;
}

/* Determine whether the optional operand(s) should be printed.  */

static int
skip_optional_operands(const unsigned char* opindex,
    unsigned long insn, int dialect)
{
    const struct powerpc_operand* operand;

    for (; *opindex != 0; opindex++)
    {
        operand = &powerpc_operands[*opindex];
        if ((operand->flags & PPC_OPERAND_NEXT) != 0
            || ((operand->flags & PPC_OPERAND_OPTIONAL) != 0
                && operand_value_powerpc(operand, insn, dialect) != 0))
            return 0;
    }

    return 1;
}

/* Print a PowerPC or POWER instruction.  */

static int
print_insn_powerpc(bfd_vma memaddr,
    struct disassemble_info* info,
    int bigendian,
    int dialect)
{
    bfd_byte buffer[4];
    int status;
    unsigned long insn;
    const struct powerpc_opcode* opcode;
    const struct powerpc_opcode* opcode_end;
    unsigned long op;

    if (dialect == 0)
        dialect = powerpc_dialect(info);

    status = (*info->read_memory_func) (memaddr, buffer, 4, info);
    if (status != 0)
    {
        (*info->memory_error_func) (status, memaddr, info);
        return -1;
    }

    if (bigendian)
        insn = bfd_getb32(buffer);
    else
        insn = bfd_getl32(buffer);

    /* Get the major opcode of the instruction.  */
    op = PPC_OP(insn);

    /* Find the first match in the opcode table.  We could speed this up
       a bit by doing a binary search on the major opcode.  */
    opcode_end = powerpc_opcodes + powerpc_num_opcodes;
again:
    for (opcode = powerpc_opcodes; opcode < opcode_end; opcode++)
    {
        unsigned long table_op;
        const unsigned char* opindex;
        const struct powerpc_operand* operand;
        int invalid;
        int need_comma;
        int need_paren;
        int skip_optional;

        table_op = PPC_OP(opcode->opcode);
        if (op < table_op)
            break;
        if (op > table_op)
            continue;

        if ((insn & opcode->mask) != opcode->opcode
            || (opcode->flags & dialect) == 0)
            continue;

        /* Make two passes over the operands.  First see if any of them
       have extraction functions, and, if they do, make sure the
       instruction is valid.  */
        invalid = 0;
        for (opindex = opcode->operands; *opindex != 0; opindex++)
        {
            operand = powerpc_operands + *opindex;
            if (operand->extract)
                (*operand->extract) (insn, dialect, &invalid);
        }
        if (invalid)
            continue;

        /* The instruction is valid.  */
        if (opcode->operands[0] != 0)
            (*info->fprintf_func) (info->stream, "%-7s ", opcode->name);
        else
            (*info->fprintf_func) (info->stream, "%s", opcode->name);

        /* Now extract and print the operands.  */
        need_comma = 0;
        need_paren = 0;
        skip_optional = -1;
        for (opindex = opcode->operands; *opindex != 0; opindex++)
        {
            long value;

            operand = powerpc_operands + *opindex;

            /* Operands that are marked FAKE are simply ignored.  We
               already made sure that the extract function considered
               the instruction to be valid.  */
            if ((operand->flags & PPC_OPERAND_FAKE) != 0)
                continue;

            /* If all of the optional operands have the value zero,
               then don't print any of them.  */
            if ((operand->flags & PPC_OPERAND_OPTIONAL) != 0)
            {
                if (skip_optional < 0)
                    skip_optional = skip_optional_operands(opindex, insn,
                        dialect);
                if (skip_optional)
                    continue;
            }

            value = operand_value_powerpc(operand, insn, dialect);

            if (need_comma)
            {
                (*info->fprintf_func) (info->stream, ",");
                need_comma = 0;
            }

            /* Print the operand as directed by the flags.  */
            if ((operand->flags & PPC_OPERAND_GPR) != 0
                || ((operand->flags & PPC_OPERAND_GPR_0) != 0 && value != 0))
                (*info->fprintf_func) (info->stream, "r%ld", value);
            else if ((operand->flags & PPC_OPERAND_FPR) != 0)
                (*info->fprintf_func) (info->stream, "f%ld", value);
            else if ((operand->flags & PPC_OPERAND_VR) != 0)
                (*info->fprintf_func) (info->stream, "v%ld", value);
            else if ((operand->flags & PPC_OPERAND_RELATIVE) != 0)
                (*info->print_address_func) (memaddr + value, info);
            else if ((operand->flags & PPC_OPERAND_ABSOLUTE) != 0)
                (*info->print_address_func) ((bfd_vma)value & 0xffffffff, info);
            else if ((operand->flags & PPC_OPERAND_CR) == 0
                || (dialect & PPC_OPCODE_PPC) == 0)
                (*info->fprintf_func) (info->stream, "%ld", value);
            else
            {
                if (operand->bitm == 7)
                    (*info->fprintf_func) (info->stream, "cr%ld", value);
                else
                {
                    static const char* cbnames[4] = { "lt", "gt", "eq", "so" };
                    int cr;
                    int cc;

                    cr = value >> 2;
                    if (cr != 0)
                        (*info->fprintf_func) (info->stream, "4*cr%d+", cr);
                    cc = value & 3;
                    (*info->fprintf_func) (info->stream, "%s", cbnames[cc]);
                }
            }

            if (need_paren)
            {
                (*info->fprintf_func) (info->stream, ")");
                need_paren = 0;
            }

            if ((operand->flags & PPC_OPERAND_PARENS) == 0)
                need_comma = 1;
            else
            {
                (*info->fprintf_func) (info->stream, "(");
                need_paren = 1;
            }
        }

        /* We have found and printed an instruction; return.  */
        return 4;
    }

    if ((dialect & PPC_OPCODE_ANY) != 0)
    {
        dialect = ~PPC_OPCODE_ANY;
        goto again;
    }

    /* We could not find a match.  */
    (*info->fprintf_func) (info->stream, ".long 0x%lx", insn);

    return 4;
}

static int decode_insn_powerpc(bfd_vma memaddr, disassemble_info* info, int bigendian, int dialect, ppc_insn* oinsn)
{
    bfd_byte buffer[4];
    int status;
    unsigned long insn;
    const struct powerpc_opcode* opcode;
    const struct powerpc_opcode* opcode_end;
    unsigned long op;
    char* stream = oinsn->op_str;

    if (dialect == 0)
        dialect = powerpc_dialect(info);

    oinsn->op_str[0] = 0;
    status = (*info->read_memory_func) (memaddr, buffer, 4, info);
    if (status != 0)
    {
        (*info->memory_error_func) (status, memaddr, info);
        return -1;
    }

    if (bigendian)
        insn = bfd_getb32(buffer);
    else
        insn = bfd_getl32(buffer);

    oinsn->instruction = insn;
    memset(oinsn->operands, 0, sizeof(oinsn->operands));

    /* Get the major opcode of the instruction.  */
    op = PPC_OP(insn);

    /* Find the first match in the opcode table.  We could speed this up
       a bit by doing a binary search on the major opcode.  */
    opcode_end = powerpc_opcodes + powerpc_num_opcodes;
again:
    for (opcode = powerpc_opcodes; opcode < opcode_end; opcode++)
    {
        unsigned long table_op;
        unsigned long i_op;
        const unsigned char* opindex;
        const struct powerpc_operand* operand;
        int invalid;
        int need_comma;
        int need_paren;
        int skip_optional;

        table_op = PPC_OP(opcode->opcode);
        if (op < table_op)
            break;
        if (op > table_op)
            continue;

        if ((insn & opcode->mask) != opcode->opcode
            || (opcode->flags & dialect) == 0)
            continue;

        /* Make two passes over the operands.  First see if any of them
       have extraction functions, and, if they do, make sure the
       instruction is valid.  */
        invalid = 0;
        for (opindex = opcode->operands; *opindex != 0; opindex++)
        {
            operand = powerpc_operands + *opindex;
            if (operand->extract)
                (*operand->extract) (insn, dialect, &invalid);
        }
        if (invalid)
            continue;

        /* The instruction is valid.  */
        oinsn->opcode = opcode;

        /* Now extract and print the operands.  */
        need_comma = 0;
        need_paren = 0;
        skip_optional = -1;
        i_op = 0;
        for (opindex = opcode->operands; *opindex != 0; opindex++, i_op++)
        {
            long value;

            operand = powerpc_operands + *opindex;

            /* Operands that are marked FAKE are simply ignored.  We
               already made sure that the extract function considered
               the instruction to be valid.  */
            if ((operand->flags & PPC_OPERAND_FAKE) != 0)
                continue;

            /* If all of the optional operands have the value zero,
               then don't print any of them.  */
            if ((operand->flags & PPC_OPERAND_OPTIONAL) != 0)
            {
                if (skip_optional < 0)
                    skip_optional = skip_optional_operands(opindex, insn,
                        dialect);
                if (skip_optional)
                    continue;
            }

            value = operand_value_powerpc(operand, insn, dialect);
            oinsn->operands[i_op] = value;

            if (operand->flags & PPC_OPERAND_RELATIVE)
            {
                oinsn->operands[i_op] += memaddr;
            }
            else if (operand->flags & PPC_OPERAND_ABSOLUTE)
            {
                oinsn->operands[i_op] &= 0xffffffff;
            }

            if (need_comma)
            {
                stream = stream + sprintf(stream, ",");
                need_comma = 0;
            }

            /* Print the operand as directed by the flags.  */
            if ((operand->flags & PPC_OPERAND_GPR) != 0
                || ((operand->flags & PPC_OPERAND_GPR_0) != 0 && value != 0))
                stream = stream + sprintf(stream, "r%ld", value);
            else if ((operand->flags & PPC_OPERAND_FPR) != 0)
                stream = stream + sprintf(stream, "f%ld", value);
            else if ((operand->flags & PPC_OPERAND_VR) != 0)
                stream = stream + sprintf(stream, "v%ld", value);
            else if ((operand->flags & PPC_OPERAND_RELATIVE) != 0)
                stream = stream + sprintf(stream, "0x%llx", memaddr + value);
            else if ((operand->flags & PPC_OPERAND_ABSOLUTE) != 0)
                stream = stream + sprintf(stream, "0x%llx", (bfd_vma)value & 0xffffffff);
            else if ((operand->flags & PPC_OPERAND_CR) == 0
                || (dialect & PPC_OPCODE_PPC) == 0)
                stream = stream + sprintf(stream, "%ld", value);
            else
            {
                if (operand->bitm == 7)
                    stream = stream + sprintf(stream, "cr%ld", value);
                else
                {
                    static const char* cbnames[4] = { "lt", "gt", "eq", "so" };
                    int cr;
                    int cc;

                    cr = value >> 2;
                    if (cr != 0)
                        stream = stream + sprintf(stream, "4*cr%d+", cr);
                    cc = value & 3;
                    stream = stream + sprintf(stream, "%s", cbnames[cc]);
                }
            }

            if (need_paren)
            {
                stream = stream + sprintf(stream, ")");
                need_paren = 0;
            }

            if ((operand->flags & PPC_OPERAND_PARENS) == 0)
                need_comma = 1;
            else
            {
                stream = stream + sprintf(stream, "(");
                need_paren = 1;
            }
        }

        /* We have found and printed an instruction; return.  */
        return 4;
    }

    if ((dialect & PPC_OPCODE_ANY) != 0)
    {
        dialect = ~PPC_OPCODE_ANY;
        goto again;
    }

    /* We could not find a match.  */
    stream = stream + sprintf(stream, ".long 0x%lx", insn);
    oinsn->opcode = 0;

    return 4;
}
