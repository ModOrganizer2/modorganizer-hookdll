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

#ifndef APIHOOK_H
#define APIHOOK_H


#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "disasm.h"


class ApiHook
{

public:

	ApiHook(LPCTSTR moduleName, LPCSTR functionName, LPVOID replacement);
	~ApiHook();

	LPVOID GetReroute();

private:

	static const BYTE jump[];
	static const BYTE prefix[];

private:

	/// replace all occurences of pattern in the memory area start to (start + size) with
	///	"addr". If relative_adjust is true, the addr actually written is a relative address
	///	based on the absolute address "addr" and the location of the pattern */
	void AddrReplace(LPBYTE start, ULONG pattern, LPVOID addr, size_t size, BOOL relative_adjust);

  /// Create the reroute function
  /// \param hookInsertionAddress (in&out) address we intend to insert our hook. On call this should
  ///        contain the function address, on return it may be adjusted to a better place where we
  ///        the jump can be inserted
  /// \return	number of bytes actually moved from original
  ///					original + return-value therefore returns the address of
  ///					the first instruction that has not been moved */
  size_t CreateReroute(LPBYTE &hookInsertionAddress);

	BOOL Hook(LPVOID original, LPVOID replacement);

  void RemoveHook();

	BOOL InsertHook(LPVOID original, LPVOID replacement);

	BOOL IsFunctionEnd(const Disasm &dis);

private:

  bool _installed;
  LPBYTE _reroute;
	const TCHAR *_moduleName;
	const char *_functionName;
	FuncDisasm _fdisasm;
  LPVOID _origPos;
  int _bytesMoved;

};

#endif // APIHOOK_H
