/*
insts.h

diStorm3 - Powerful disassembler for X86/AMD64
http://ragestorm.net/distorm/
distorm at gmail dot com
Copyright (C) 2003-2016 Gil Dabah
This library is licensed under the BSD license. See the file COPYING.
*/


#ifndef INSTS_H
#define INSTS_H

#include "instructions.h"


/* Flags Table */
extern __constant const _iflags FlagsTable[];

/* Root Trie DB */
extern __constant const _InstSharedInfo InstSharedInfoTable[];
extern __constant const _InstInfo InstInfos[];
extern __constant const _InstInfoEx InstInfosEx[];
extern __constant const _InstNode InstructionsTree[];

/* 3DNow! Trie DB */
extern __constant const _InstNode Table_0F_0F;
/* AVX related: */
extern __constant const _InstNode Table_0F, Table_0F_38, Table_0F_3A;

/*
 * The inst_lookup will return on of these two instructions according to the specified decoding mode.
 * ARPL or MOVSXD on 64 bits is one byte instruction at index 0x63.
 */
extern __constant const _InstInfo II_MOVSXD;

/*
 * The NOP instruction can be prefixed by REX in 64bits, therefore we have to decide in runtime whether it's an XCHG or NOP instruction.
 * If 0x90 is prefixed by a usable REX it will become XCHG, otherwise it will become a NOP.
 * Also note that if it's prefixed by 0xf3, it becomes a Pause.
 */
extern __constant const _InstInfo II_NOP;
extern __constant const _InstInfo II_PAUSE;

/*
 * RDRAND and VMPTRLD share same 2.3 bytes opcode, and then alternates on the MOD bits,
 * RDRAND is OT_FULL_REG while VMPTRLD is OT_MEM, and there's no such mixed type.
 * So a hack into the inst_lookup was added for this decision, the DB isn't flexible enough. :(
 */
extern __constant const _InstInfo II_RDRAND;

/*
 * Used for letting the extract operand know the type of operands without knowing the
 * instruction itself yet, because of the way those instructions work.
 * See function instructions.c!inst_lookup_3dnow.
 */
extern __constant const _InstInfo II_3DNOW;

/* Helper tables for pseudo compare mnemonics. */
extern __constant const uint16_t CmpMnemonicOffsets[8]; /* SSE */
extern __constant const uint16_t VCmpMnemonicOffsets[32]; /* AVX */

#endif /* INSTS_H */
