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
#include "apihook.h"
#include <cassert>
#include <exception>
#include <stdexcept>
#include "logger.h"


const BYTE ApiHook::jump[] = {
	0xE9, 0xBB, 0xBB, 0xBB, 0xBB				// JMP 0xBBBBBBBB (addr. of reroute function (relative))
};


LPVOID MyGetProcAddress(HMODULE module, LPCSTR functionName)
{
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    return NULL;
  }

  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(((LPBYTE)dosHeader) + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
    return NULL;
  }

  PIMAGE_OPTIONAL_HEADER optionalHeader = &ntHeaders->OptionalHeader;
  PIMAGE_DATA_DIRECTORY dataDirectory = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)dosHeader + dataDirectory->VirtualAddress);

  ULONG *addressOfNames = (ULONG*)((BYTE*) module + exportDirectory->AddressOfNames);
  ULONG *funcAddr = (ULONG*)((BYTE*) module + exportDirectory->AddressOfFunctions);

  for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
    char *curFunctionName = (char*)((BYTE*) module + addressOfNames[i]);
    USHORT *nameOrdinals = (USHORT*)((BYTE*) module + exportDirectory->AddressOfNameOrdinals);
    if (strcmp(functionName, curFunctionName) == 0) {
      if (funcAddr[nameOrdinals[i]] >= dataDirectory->VirtualAddress &&
          funcAddr[nameOrdinals[i]] < dataDirectory->VirtualAddress + dataDirectory->Size) {
        char *forwardLibName  = _strdup((LPSTR)module + funcAddr[nameOrdinals[i]]);
        char *forwardFunctionName = strchr(forwardLibName, '.');
        *forwardFunctionName = 0;
        ++forwardFunctionName;

        HMODULE forwardLib = ::LoadLibraryA(forwardLibName);
        LPVOID forward = NULL;
        if (forwardLib) {
          forward = MyGetProcAddress(forwardLib, forwardFunctionName);
        }
        ::FreeLibrary(forwardLib);
        return forward;
      }
      return (void*)((BYTE*)module + funcAddr[nameOrdinals[i]]);
    }
  }
  return NULL;
}



ApiHook::ApiHook(LPCTSTR moduleName,
								 LPCSTR functionName,
								 LPVOID replacement)
  :	_reroute(0), _moduleName(moduleName), _functionName(functionName), _bytesMoved(0), _installed(false)
{
	HMODULE mh = ::GetModuleHandle(moduleName);
	if (mh != NULL) {
    // using custom getprocaddress to avoid tools that hook getprocaddress (like AcLayer)
    _origPos = (LPVOID)(MyGetProcAddress(mh, functionName));
  } else {
    Logger::Instance().error("%s is not a valid module name", moduleName);
    throw std::runtime_error("hook failed");
  }
  if (_origPos == NULL) {
    Logger::Instance().error("%s is not a function in %ls", functionName, moduleName);
    throw std::runtime_error("hook failed");
	}
  _fdisasm.Init(reinterpret_cast<LPBYTE>(_origPos));
  if (!Hook(_origPos, replacement)) {
    Logger::Instance().error("%s in %s can not be hooked", functionName, moduleName);
    throw std::runtime_error("hook failed");
	}
  _installed = true;
  LOGDEBUG("hook for %s installed at %p", functionName, _origPos);
}

ApiHook::~ApiHook()
{
  RemoveHook();
}


LPVOID ApiHook::GetReroute()
{
	return reinterpret_cast<LPVOID>(_reroute);
}


BOOL ApiHook::Hook(LPVOID original, LPVOID replacement)
{
	size_t size = _fdisasm.GetSize();

	if (size < sizeof(jump)) {
    Logger::Instance().error("function at %p is too small to be hooked", original);
		return FALSE;
	}

  return InsertHook(original, replacement);
}

void ApiHook::AddrReplace(LPBYTE start,
													ULONG pattern,
													LPVOID addr,
													size_t size,
													BOOL relative_adjust)
{
  if (start == NULL) throw std::runtime_error("NULL-Pointer as start-address");
	if (start == NULL) throw std::runtime_error("NULL-Pointer as replacement-address");

	BOOL found = FALSE;

  LPBYTE ptr = start;
	while (ptr <= start + size - sizeof(ULONG))
	{
		ULONG* ulptr = reinterpret_cast<ULONG*>(ptr);
		if (*ulptr == pattern) {
			if (relative_adjust) {
        ULONG relPtr = reinterpret_cast<ULONG>(addr) - ((ULONG)ulptr + sizeof(ULONG));
				*ulptr = relPtr;
			} else {
				*ulptr = reinterpret_cast<ULONG>(addr);
			}
			found = TRUE;
			ptr += sizeof(ULONG);
		} else {
			ptr++;
		}
	}

	if (!found) {
		throw std::runtime_error("pattern not found");
	}
}


size_t ApiHook::CreateReroute(LPBYTE original)
{
  size_t size = 0;
  size_t relativeAdd = 0;
  int num = 0;
  PBYTE curPos = _fdisasm.GetEnd();
	Disasm disasm = _fdisasm.GetDisasm();
	// Calculate how many instructions need to be moved
	while (size < sizeof(jump)) {
		size += disasm.GetSize();
		if (disasm.IsRelative()) {
			relativeAdd += 3 + sizeof(void*);	// if the jump is relative or near, it will have to
																				// be adjusted, possible increasing the size of the command
		}
		num++;
		curPos = disasm.GetNextCommand();
	}
	int tmpnum = num;
	size_t tmpsize = size;
	// Continue copying operations if a jump follows that targets the already to-be-copied area
	while (curPos < _fdisasm.GetEnd()) {
		tmpnum++;
		tmpsize += disasm.GetSize();
		if (disasm.JumpTargets(original, original + size)) {
			num = tmpnum;
			size = tmpsize;
		}
		curPos = disasm.GetNextCommand();
	}

	size_t jlen = sizeof(void*) + 1;					// size of a jump: 1 byte opcode + size of an address

	// allocate memory for the reroute that is executable
  _reroute = reinterpret_cast<LPBYTE>(::VirtualAlloc(NULL,
																			size + jlen + sizeof(char*) + relativeAdd,
																			MEM_COMMIT | MEM_RESERVE,
																			PAGE_EXECUTE_READWRITE));

	LPBYTE rerouteEnd = _reroute;
	disasm.Reset();

  // Copy instructions and adjust relative jumps if neccessary
	for (int i = 0; i < num; i++) {
		rerouteEnd = disasm.CopyTo(rerouteEnd, original, size);
		disasm.GetNextCommand();
	}

	// Add jump back to original function
	*rerouteEnd = 0xE9;					// JMP
	++rerouteEnd;
	*(reinterpret_cast<ULONG*>(rerouteEnd)) =
					reinterpret_cast<ULONG>(original) + size -
					(reinterpret_cast<ULONG>(rerouteEnd) + sizeof(ULONG));	 // Distance to original function
//  LOGDEBUG("jump from %p to %p, relative: %p", reinterpret_cast<ULONG>(rerouteEnd) + sizeof(ULONG),
//    reinterpret_cast<ULONG>(original) + size, *(reinterpret_cast<ULONG*>(rerouteEnd)));

	return size;
}

BOOL ApiHook::InsertHook(LPVOID original, LPVOID replacement)
{
  _bytesMoved = CreateReroute(reinterpret_cast<LPBYTE>(original));

	DWORD oldprotect, ignore;
	// Set the target function to copy on write, so we don't modify code for other processes
	if (!::VirtualProtect(original,
												sizeof(jump),
												PAGE_EXECUTE_WRITECOPY,
												&oldprotect)) {
    throw std::runtime_error("failed to change virtual protection");
	}

  // Copy the jump instruction to the target address and insert the reroute addresses
	memmove(original, &jump, sizeof(jump));
	AddrReplace(reinterpret_cast<LPBYTE>(original), 0xBBBBBBBB, replacement, sizeof(jump), TRUE);

	// restore old memory protection
	if (!::VirtualProtect(original, sizeof(jump), oldprotect, &ignore)) {
    throw std::runtime_error("failed to change virtual protection");
	}

	return TRUE;
}


void ApiHook::RemoveHook()
{
  if (_installed) {
    DWORD oldprotect, ignore;
    // Set the target function to copy on write, so we don't modify code for other processes
    if (!::VirtualProtect(_origPos,
                          sizeof(jump),
                          PAGE_EXECUTE_WRITECOPY,
                          &oldprotect)) {
      throw std::runtime_error("failed to change virtual protection");
    }

    // Copy the jump instruction to the target address and insert the reroute addresses
    memmove(_origPos, &jump, sizeof(jump));
    AddrReplace(reinterpret_cast<LPBYTE>(_origPos), 0xBBBBBBBB, _reroute, sizeof(jump), TRUE);

    // restore old memory protection
    if (!::VirtualProtect(_origPos, sizeof(jump), oldprotect, &ignore)) {
      throw std::runtime_error("failed to change virtual protection");
    }
  }
}
