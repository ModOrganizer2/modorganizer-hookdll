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

#ifndef DISASM_H
#define DISASM_H


#define WIN32_LEAN_AND_MEAN
#include <windows.h>


class Disasm {

public:

	Disasm() throw();

	/// Initialize a disassembler on the given code position
	/// \param	code	code position to start disassembling
	/// \param	e64bit	target is a 64bit executable (currently not supported!)
  Disasm(PBYTE code, bool e64bit = false);

	~Disasm() throw();

	/// Initialize a disassembler on the given code position
	/// \param	code	code position to start disassembling
	/// \param	e64bit	target is a 64bit executable (currently not supported!)
  void Init(PBYTE code, bool e64bit = false);

	/// Returns a pointer to the next command
	PBYTE GetNextCommand() throw();

	/// Jump back to the first instruction
	void Reset() throw();

	/// Copy current command to target address
	/// \param	target	the target address to copy to
	/// \param	pos1		beginning of the whole copy operation (including previous and future CopyTos)
	///									This (and the next parameter) is important to decide whether a relative jump
	///									has to be adjusted
	/// \param	size		number of bytes that are being copied
	/// \return					the first byte after the copied instruction
  PBYTE CopyTo(PBYTE target, PBYTE pos1, size_t size);

	const char *GetName() const throw();

	BYTE GetOpcode() const throw();

	BOOL TwoByteOp() const throw();

  BYTE GetReg1() const;
  BYTE GetReg2() const;

	size_t GetSize() const throw();

	BOOL IsRelative() const throw();

	BOOL IsGroup(short group, short groupMember) const throw();

  BOOL JumpTargets(PBYTE begin, PBYTE end);

  const PBYTE GetDispl() throw();

  const PBYTE GetParam1() throw();

  PBYTE GetAbsoluteDestination();

private:

	struct {
		const char *name;
		BYTE prefix[5];			// including REX, every command can have 5 prefixes
		BYTE opcode;
		BYTE modrm;
		BYTE sib;
		bool twoByteOpcode, hasModRM, isGroup;
		bool oso, aso;
		short group, groupMember;
		bool relative;
		PBYTE param1;
		PBYTE param2;
		PBYTE param3;
		PBYTE displ;
		size_t numBytes;
	} _cmd_info;

private:

	size_t GetImmediateBytes(int optype, int opsize, bool oso) throw();

	void ResetCmdInfo() throw();

  void ReadCommand(BYTE *pos);

	BOOL HasSIB(BYTE modrm) throw();

	int GetOpType1() throw();

	int GetOpType2() throw();

	int GetOpType3() throw();

	int GetOpSize1() throw();

	int GetOpSize2() throw();

	int GetOpSize3() throw();

	PBYTE CopyE0123(PBYTE ptr) throw();

  PBYTE CopyShortConditional(PBYTE target);

  PBYTE CopyShortJump(PBYTE target);

  PBYTE CopyRelative(PBYTE target, PBYTE pos1, size_t size);

	PBYTE CopyDirect(PBYTE target) throw();

	BOOL IsShortConditionalJump() throw();

	BOOL IsJump() throw();

private:

	BYTE *_start, *_cur;
	BOOL _64bit;
};

// Acquires info on the function that startes at the specific function
class FuncDisasm {

public:

	FuncDisasm() throw();

	/// Initialize a function disassembler on the given code position
	/// \param	code	code position to start disassembling
	/// \param	e64bit	target is a 64bit executable (currently not supported!)
  FuncDisasm(PBYTE code, bool e64bit = false);

	~FuncDisasm() throw();

	/// Initialize a function disassembler on the given code position
	/// \param	code		code position to start disassembling
	/// \param	e64bit	target is a 64bit executable (currently not supported!)
  void Init(PBYTE code, bool e64bit = false);

	// return the internal binary disassembler, positioned at the start of the function
	Disasm &GetDisasm() throw() { _disasm.Reset(); return _disasm; }

	// return the size of the disassembled function
	size_t GetSize() throw() { return _end - _start + 1; }

	// return the last byte of the function
	PBYTE GetEnd() throw() { return _end; }

private:

	Disasm _disasm;
	PBYTE _start, _end;

};


#endif // DISASM_H
