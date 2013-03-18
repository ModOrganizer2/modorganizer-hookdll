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

#include "stdafx.h"
#include <vector>
#include <stdexcept>
#include "disasm.h"
#include "disasm_table.h"
#include "logger.h"


Disasm::Disasm() throw()
  : _cmd_info(), _start(NULL), _cur(NULL), _64bit(false)
{
}


Disasm::Disasm(PBYTE code, bool e64bit)
  : _cmd_info(), _start(NULL), _cur(NULL)
{
	Init(code, e64bit);
}


Disasm::~Disasm() throw()
{
}


void Disasm::Init(PBYTE code, bool e64bit)
{
	_start = code;
	_cur = code;
	_64bit = e64bit;
	if (_64bit) {
		throw std::runtime_error("64 bit executables currently not supported by disassembler");
	}
	ReadCommand(code);
}


void Disasm::Reset() throw()
{
	_cur = _start;
	ReadCommand(_cur);
}


/// Returns a pointer to the next command
PBYTE Disasm::GetNextCommand() throw()
{
	_cur = _cur + _cmd_info.numBytes;
	ReadCommand(_cur);
	return _cur;
}


BOOL Disasm::IsGroup(short group, short groupMember) const throw()
{
	return _cmd_info.isGroup && (_cmd_info.group == group) &&
		(_cmd_info.groupMember == groupMember);
}


int Disasm::GetOpType1() throw()
{
	const TableEntry *table = _cmd_info.twoByteOpcode ? table2 : table1;
	if ((_cmd_info.isGroup) &&
		(groups[_cmd_info.group][_cmd_info.groupMember].op1type != OPT_CGROUP)) {
			return groups[_cmd_info.group][_cmd_info.groupMember].op1type;
	} else {
		return table[_cmd_info.opcode].op1type;
	}
}


int Disasm::GetOpType2() throw()
{
	const TableEntry *table = _cmd_info.twoByteOpcode ? table2 : table1;
	if ((_cmd_info.isGroup) &&
		(groups[_cmd_info.group][_cmd_info.groupMember].op2type != OPT_CGROUP)) {
			return groups[_cmd_info.group][_cmd_info.groupMember].op2type;
	} else {
		return table[_cmd_info.opcode].op2type;
	}

}

int Disasm::GetOpType3() throw()
{
	const TableEntry *table = _cmd_info.twoByteOpcode ? table2 : table1;
	if ((_cmd_info.isGroup) &&
		(groups[_cmd_info.group][_cmd_info.groupMember].op3type != OPT_CGROUP)) {
			return groups[_cmd_info.group][_cmd_info.groupMember].op3type;
	} else {
		return table[_cmd_info.opcode].op3type;
	}

}

int Disasm::GetOpSize1() throw()
{
	const TableEntry *table = _cmd_info.twoByteOpcode ? table2 : table1;
	if ((_cmd_info.isGroup) &&
		(groups[_cmd_info.group][_cmd_info.groupMember].op1size != OPS_CGROUP)) {
			return groups[_cmd_info.group][_cmd_info.groupMember].op1size;
	} else {
		return table[_cmd_info.opcode].op1size;
	}
}

int Disasm::GetOpSize2() throw()
{
	const TableEntry *table = _cmd_info.twoByteOpcode ? table2 : table1;
	if ((_cmd_info.isGroup) &&
		(groups[_cmd_info.group][_cmd_info.groupMember].op2size != OPS_CGROUP)) {
			return groups[_cmd_info.group][_cmd_info.groupMember].op2size;
	} else {
		return table[_cmd_info.opcode].op2size;
	}

}

int Disasm::GetOpSize3() throw()
{
	const TableEntry *table = _cmd_info.twoByteOpcode ? table2 : table1;
	if ((_cmd_info.isGroup) &&
		(groups[_cmd_info.group][_cmd_info.groupMember].op3size != OPS_CGROUP)) {
			return groups[_cmd_info.group][_cmd_info.groupMember].op3size;
	} else {
		return table[_cmd_info.opcode].op3size;
	}
}

PBYTE Disasm::GetAbsoluteDestination()
{
	if (IsGroup(4, 4) ||			// near absolute indirect
			IsGroup(4, 5)) {
		return 0;
	}

	PBYTE destination = _cur + _cmd_info.numBytes;

  // this is broken! size for "byteorword" and "wordordword" depend on protected vs. real-mode, 32bit vs. 64bit and segment information. argh!
	switch(GetOpSize1()) {
		case OPS_BYTE: {
			destination += *reinterpret_cast<signed char*>(_cmd_info.param1);
		} break;
		case OPS_WORD: {
			destination += *reinterpret_cast<signed short*>(_cmd_info.param1);
		} break;
		case OPS_BYTEORWORD: {
			if (_cmd_info.oso) {
				destination += *reinterpret_cast<signed char*>(_cmd_info.param1);
			} else {
				destination += *reinterpret_cast<signed short*>(_cmd_info.param1);
			}
		} break;
		case OPS_DWORD: {
			destination += *reinterpret_cast<signed long*>(_cmd_info.param1);
		} break;
		case OPS_WORDORDWORD: {
			if (_cmd_info.oso) {
				destination += *reinterpret_cast<signed short*>(_cmd_info.param1);
			} else {
				destination += *reinterpret_cast<signed long*>(_cmd_info.param1);
			}
		} break;
		default: {
		} break;
	}
	return destination;
}

BOOL Disasm::JumpTargets(PBYTE begin, PBYTE end)
{

	if (!IsJump()) {
		return FALSE;
	}

	PBYTE target = GetAbsoluteDestination();
	return (target > begin) && (target < end);
}


BOOL Disasm::IsJump() throw()
{
	return ((_cmd_info.relative) ||			 // should catch all relative jumps
					IsGroup(4, 4) ||						 // near absolute indirect
					IsGroup(4, 5) ||						 // far absolute indirect
					(_cmd_info.opcode == 0xEA)); // far absolute direct
}


BOOL Disasm::IsShortConditionalJump() throw()
{
	if (!_cmd_info.twoByteOpcode &&
      (((_cmd_info.opcode >= 0x70) && (_cmd_info.opcode <= 0x7F)) ||	// short conditional jumps
       ((_cmd_info.opcode >= 0xE0) && (_cmd_info.opcode <= 0xE3)))) {	// more short conditional jumps
		return TRUE;
	} else {
		return FALSE;
	}
}


PBYTE Disasm::CopyE0123(PBYTE ptr) throw()
{
	// In case of JCXZ, LOOP, LOOPE,... we have to do bit of a hack, because there is no near jump available
	// The target then contains the following sequence:
	//			<original opcode> 02
	//			JMP				  02
	//			JMP				  <original target>
	*ptr = _cmd_info.opcode;
	ptr++;
	*ptr = 0x02;
	ptr++;
	*ptr = 0xEB;
	ptr++;
	*ptr = 0x02;
  ptr++;
	*ptr = 0xE9;
	ptr++;

	return ptr;
}

PBYTE Disasm::CopyShortConditional(PBYTE target)
{
	PBYTE ptr = target;
	if ((_cmd_info.opcode >= 0xE0) && (_cmd_info.opcode <= 0xE3)) {
		ptr = CopyE0123(ptr);
	} else {
		*ptr = 0x0F;
		ptr++;
		*ptr = _cmd_info.opcode + 0x10;
		ptr++;
	}

	PBYTE endptr = ptr + sizeof(unsigned long);
	*reinterpret_cast<ULONG_PTR*>(ptr) = GetAbsoluteDestination() - endptr;
	return endptr;
}


PBYTE Disasm::CopyShortJump(PBYTE target)
{
	PBYTE ptr = target;
	*ptr = 0xE9;
	ptr++;

	PBYTE endptr = ptr + sizeof(unsigned long);
	*reinterpret_cast<ULONG*>(ptr) = GetAbsoluteDestination() - endptr;

	return endptr;
}


PBYTE Disasm::CopyRelative(PBYTE target, PBYTE pos1, size_t size)
{
	// If the jump-target is within the copied function, don't change anything
	PBYTE absoluteDestination = GetAbsoluteDestination();
	if ((absoluteDestination >= pos1) &&
		(absoluteDestination < pos1 + size)) {
			return CopyDirect(target);
	}

	if (IsShortConditionalJump()) {
		return CopyShortConditional(target);
	}

	if (_cmd_info.opcode == 0xEB) {
		return CopyShortJump(target);
	}

	// In the remaining cases, we assume the command can be kept unchanged, only the
	// destination needs to be adjusted
	PBYTE endptr = CopyDirect(target);
	PBYTE tparam1 = target + (_cmd_info.param1 - _cur);
	*reinterpret_cast<ULONG*>(tparam1) = absoluteDestination - endptr;

	return endptr;
}


PBYTE Disasm::CopyDirect(PBYTE target) throw()
{
	memmove(target, _cur, _cmd_info.numBytes);
	return target + _cmd_info.numBytes;
}


PBYTE Disasm::CopyTo(PBYTE target, PBYTE pos1, size_t size)
{
	if (_cmd_info.relative) {
		return CopyRelative(target, pos1, size);
	} else {
		// TODO: Adjust absolute jumps!
		return CopyDirect(target);
	}
}


const char *Disasm::GetName() const throw()
{
	return _cmd_info.name;
}


BYTE Disasm::GetOpcode() const throw()
{
	return _cmd_info.opcode;
}


BOOL Disasm::TwoByteOp() const throw()
{
  return _cmd_info.twoByteOpcode;
}

BYTE Disasm::GetReg1() const
{
  return _cmd_info.modrm & 0x07;
}

BYTE Disasm::GetReg2() const
{
  return (_cmd_info.modrm & 0x38) >> 3;
}

size_t Disasm::GetSize() const throw()
{
	return _cmd_info.numBytes;
}


BOOL Disasm::IsRelative() const throw()
{
	return _cmd_info.relative;
}


void Disasm::ResetCmdInfo() throw()
{
	memset(&_cmd_info, 0, sizeof(_cmd_info));
}


BOOL Disasm::HasSIB(BYTE modrm) throw()
{
	if (((modrm & 0xC0) != 0xC0) && ((modrm & 0x07) == 0x04)) {
		return TRUE;
	} else {
		return FALSE;
	}
}


size_t Disasm::GetImmediateBytes(int optype, int opsize, bool oso) throw()
{
	if ((optype == OPT_IMMEDIATE) ||
	    (optype == OPT_ADDR) ||
	    (optype == OPT_RELOFFSET) ||
		(optype == OPT_OFFSETONLY)) {
		switch (opsize) {
			case OPS_BYTE: {
				return 1;
			} break;
			case OPS_WORD: {
				return 2;
			} break;
			case OPS_DWORD: {
				return 4;
			} break;
			case OPS_WORD_DWORD: {
				return 6;
			} break;
			case OPS_BYTEORWORD: {
				return oso ? 1 : 2;
			} break;
			case OPS_WORDORDWORD: {
				return oso ? 2 : 4;
			} break;
			case OPS_WORD_WORDORDWORD: {
				return oso ? 4 : 6;
			} break;
			default: {
				return 0;
			} break;
		}
	} else {
		return 0;
	}
}


void Disasm::ReadCommand(BYTE *pos)
{
	bool oso = false;
	bool aso = false;
	bool op64 = false;
//	bool simd = false;
	bool mandatory = false;
	PBYTE curByte = pos;
	ResetCmdInfo();
	{	// read prefix bytes
		int numPrefixes = 0;
		while (	(table1[*curByte].flags & PREFIX) ||
						(_64bit && ((*curByte >= 0x40) && (*curByte <= 0x4F)))) {
			_cmd_info.prefix[numPrefixes]= *curByte;
			switch (*curByte) {
				case 0x66: { // Operand-size override
					mandatory = true;
					oso = true;
				} break;
				case 0x67: { // Address-size override
					aso = true;
				} break;
				case 0x48: { // REX.W
					op64 = true;
				} break;
				//case 0x66:  // In combination with a 0x0F escape opcode, these are mandatory prefixes
				case 0xF2:	  // for simd instructions.
				case 0xF3: {  // otherwise, the mandatory flag will be ignored.
					mandatory = true;
				} break;
			}
			numPrefixes++;
			curByte++;
		}
	}

	const TableEntry *table = 0;

	{ // read opcode
		if (*curByte == 0x0F) {
			_cmd_info.twoByteOpcode = true;
/*			mandatory prefix + 0x0F isn't always a simd instruction
			if (mandatory) {
				simd = true;
				throw extended_exception("simd instructions currently not supported. "
							"Please contact the author", __FILE__, __LINE__);
			}*/
			curByte++;
		}
		if (((*curByte == 0x38) || (*curByte == 0x3A)) &&
			(_cmd_info.twoByteOpcode)) {
				// TODO: fix this!
        return;
		}
		table = _cmd_info.twoByteOpcode ? table2 : table1;

		_cmd_info.opcode = *curByte;
		if (table[_cmd_info.opcode].flags & _GRP) {
			_cmd_info.isGroup = true;
			_cmd_info.group = 42;
			for (int i = 0; i < 17 && _cmd_info.group == 42; i++) {
				if (optogroup[i][0] == _cmd_info.opcode) {
          _cmd_info.group = static_cast<short>(optogroup[i][1]);
				}
			}
		}
		curByte++;
	}

	int displacement = 0;
	if (table[_cmd_info.opcode].flags & HASRM) { // read Mod R/M
		_cmd_info.hasModRM = true;
		_cmd_info.modrm = *curByte;
		if (_cmd_info.isGroup) {
			_cmd_info.groupMember = (_cmd_info.modrm & 0x38) >> 3;
		}
		if (((_cmd_info.modrm & 0xC0) == 0x80) ||
			(((_cmd_info.modrm & 0xC0) == 0x00) && ((_cmd_info.modrm & 0x07) == 0x05))) {
				displacement = 4;	// dword displacement
		} else if ((_cmd_info.modrm & 0xC0) == 0x40) {
			displacement = 1;		// byte displacement
		}
		curByte++;
	}
	_cmd_info.displ = curByte;

	if (HasSIB(_cmd_info.modrm)) {
		_cmd_info.sib = *curByte;
		if ((_cmd_info.sib & 0x07) == 0x05) {
			// sib specifies
			if (((_cmd_info.modrm & 0xC0) == 0x00) ||
				((_cmd_info.modrm & 0xC0) == 0x80)) {
					displacement = 4;
			} else if ((_cmd_info.modrm & 0xC0) == 0x40) {
				displacement = 1;
			}
			_cmd_info.displ = curByte + 1;
		}
		curByte++;
	}

	curByte += displacement; // skip displacement calculated before


	if (table[_cmd_info.opcode].op1type == OPT_RELOFFSET) {
			 _cmd_info.relative = true;
	}

	_cmd_info.numBytes = curByte - pos;


	{ // Parameter 1
		if (GetImmediateBytes(GetOpType1(), GetOpSize1(), oso) != 0) {
			_cmd_info.param1 = _cur + _cmd_info.numBytes;
		} else {
			// TODO: Is this correct?
			_cmd_info.param1 = (displacement > 0) ? _cmd_info.displ : 0;
		}
		_cmd_info.numBytes += GetImmediateBytes(GetOpType1(), GetOpSize1(), oso);
	}

	{ // Parameter 2
		if (GetImmediateBytes(GetOpType2(), GetOpSize2(), oso) != 0) {
			_cmd_info.param2 = _cur + _cmd_info.numBytes;
		} else {
			_cmd_info.param2 = 0;
		}
		_cmd_info.numBytes += GetImmediateBytes(GetOpType2(), GetOpSize2(), oso);
	}

	{ // Parameter 3
		if (GetImmediateBytes(GetOpType3(), GetOpSize3(), oso) != 0) {
			_cmd_info.param3 = _cur + _cmd_info.numBytes;
		} else {
			_cmd_info.param3 = 0;
		}
		_cmd_info.numBytes += GetImmediateBytes(GetOpType3(), GetOpSize3(), oso);
	}

	if (!_cmd_info.isGroup) {
		_cmd_info.name = table[_cmd_info.opcode].name;
	} else {
		_cmd_info.name = groups[_cmd_info.group][_cmd_info.groupMember].name;
	}
}

const PBYTE Disasm::GetDispl() throw()
{
	return _cmd_info.displ;
}

const PBYTE Disasm::GetParam1() throw()
{
	return _cmd_info.param1;
}

FuncDisasm::FuncDisasm() throw()
  : _start(NULL), _end(NULL)
{
}

FuncDisasm::FuncDisasm(PBYTE code, bool e64bit)
{
	Init(code, e64bit);
}

FuncDisasm::~FuncDisasm() throw()
{
}

void FuncDisasm::Init(PBYTE code, bool e64bit)
{
	_disasm.Init(code, e64bit);
	_start = code;
	bool done = false;
	std::vector<PBYTE> short_jumps;
  PBYTE curPos = 0;
	PBYTE potEnd = 0;
	do {
		BYTE opcode = _disasm.GetOpcode();
		if (	(!_disasm.TwoByteOp() && (
					(opcode == 0xC3) ||							// RET
					(opcode == 0xCB) ||							// RET
					(opcode == 0xC2) ||							// RET
					(opcode == 0xCA) ||							// RET
					(opcode == 0xE9) ||							// JMP near relative
					(opcode == 0xEA) ||							// JMP far absolute
					((opcode == 0xCD) &&
					 (*_disasm.GetParam1() == 0x2E)))) ||		// INT 2E
				(_disasm.IsGroup(4, 4)) ||						// JMP near absolute indirect
				(_disasm.IsGroup(4, 5)) ||						// JMP far absolute indirect
				(_disasm.TwoByteOp() && (opcode == 0x34)) ||	// SYSENTER (INTEL)
				(_disasm.TwoByteOp() && (opcode == 0x34))) {	// SYSCALL (AMD)
			// this might be the end of the function
			std::vector<PBYTE>::iterator iter;
			bool jumpleft = false;
			for (iter = short_jumps.begin(); iter != short_jumps.end(); ++iter) {
				if (*iter > curPos) {
					jumpleft = true;
				}
			}
			if (!jumpleft) {
				done = true;
			} else {
				// this might still be the end of this function, if all code after
				// this eventually jumps back to a position before curPos
				potEnd = curPos;
			}
		} else if ( (opcode == 0xEB) ||							// JMP short
					((opcode >= 0x70) && (opcode <= 0x7F)) ||	// Jcc short
					(opcode == 0xE3)) {							// JECXZ short
			PBYTE tgt = _disasm.GetAbsoluteDestination();
			if (tgt > curPos) {
				short_jumps.push_back(tgt);
			} else if (tgt < potEnd) {
				std::vector<PBYTE>::iterator iter;
				bool jumpleft = false;
				for (iter = short_jumps.begin(); iter != short_jumps.end(); ++iter) {
					if (*iter > curPos) {
						jumpleft = true;
					}
				}
				if (!jumpleft) {
					done = true;
				}
			}
		}
		curPos = _disasm.GetNextCommand();
	} while(!done);
	_end = curPos - 1;
}
