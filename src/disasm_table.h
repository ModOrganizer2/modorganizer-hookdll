/*
Mod Organizer API hooking

Copyright (C) 2012 Sebastian Herbord. All rights reserved.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

// Operand types
#define OPT_NOOPT			0	// no operand
#define OPT_ADDR			1	// absolute address
#define OPT_RM_OPERAND		2	// r/m picks operand
#define OPT_RM_GPREG		3	// r/m picks general purpous register
#define OPT_RM_CONTROLREG	4	// r/m picks control register
#define OPT_RM_DEBUGREG		5	// r/m picks debug register
#define OPT_RM_MEMORY		6	// r/m picks memory address
#define OPT_RM_REG			7	// r/m picks register ???
#define OPT_RM_SEGREG		8	// r/m picks segment register
#define OPT_RM_TESTREG		9	// r/m picks test register
#define OPT_FLAGS			10	// operates on flags
#define OPT_IMMEDIATE		11	// immediate data
#define OPT_RELOFFSET		12	// relative offset
#define OPT_DS_ESI			13	// operates on DS:ESI
#define OPT_ES_EDI			14	// operates on ES_EDI
#define OPT_FIXEDREG		15	// operates on a fixed register
#define OPT_OFFSETONLY		16	// only offset ???
#define OPT_CGROUP			17	// operand type is decided by group

// Operand sizes
#define OPS_NULL				0	// no operand
#define OPS_BOUND				1	// special case bound: double word or quad word
#define OPS_BYTE				2	// one byte
#define OPS_WORD				3	// one word (= 2 byte)
#define OPS_BYTEORWORD			4	// one byte or one word depending on mode
#define OPS_DWORD				5	// one double word
#define OPS_WORDORDWORD			6	// one word or one double word
#define OPS_WORD_WORDORDWORD	7	// one word AND either a word or a dword
									//(reg16:16 or reg16:32, ptr16:16 or ptr16:32, m16:16 or m16:32)
#define OPS_WORD_DWORD			8	// one word and a dword
#define OPS_CGROUP				9	// operand size is decided by group

// flags
#define HASRM		1	// command contains R/M
#define PREFIX		2	// this is a prefix
#define ILLEGAL		4
#define _GRP		8	// a group of commands. which one to actually use is decided by the 3-bit r/m opcode-extension
#define CGROUP		_GRP | HASRM	// a group automatically has a Mod R/M field

#define DEFAULT_COPY	0	// No special copy function neccessary

struct TableEntry;
typedef void *(*COPYFUNC)(void *tgt, void *src, const TableEntry *tableEntry);

struct TableEntry {
	const char		*name;
	int				op1type;
	int				op1size;
	int				op2type;
	int				op2size;
	int				op3type;
	int				op3size;
	char			flags;
	COPYFUNC		copyFunc;			// function to properly copy the cmd
};

extern const TableEntry table1[];
extern const TableEntry table2[];
extern const int optogroup[17][2];
extern const TableEntry groups[8][8];
