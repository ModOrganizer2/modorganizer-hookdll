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
#include <windows_error.h>
#include "logger.h"


const BYTE ApiHook::jump[] = {
  0xE9, 0xBB, 0xBB, 0xBB, 0xBB        // JMP 0xBBBBBBBB (addr. of reroute function (relative))
};


LPVOID MyGetProcAddress(HMODULE module, LPCSTR functionName)
{
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    return nullptr;
  }

  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(((LPBYTE)dosHeader) + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
    return nullptr;
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
        LPVOID forward = nullptr;
        if (forwardLib != nullptr) {
          forward = MyGetProcAddress(forwardLib, forwardFunctionName);
          ::FreeLibrary(forwardLib);
        }
        return forward;
      }
      return (void*)((BYTE*)module + funcAddr[nameOrdinals[i]]);
    }
  }
  return nullptr;
}



ApiHook::ApiHook(LPCTSTR moduleName,
                 LPCSTR functionName,
                 LPVOID replacement)
  : _reroute(0), _moduleName(moduleName), _functionName(functionName), _bytesMoved(0), _installed(false)
{
  HMODULE mh = ::GetModuleHandle(moduleName);
  if (mh != nullptr) {
    // using custom getprocaddress to avoid tools that hook getprocaddress (like AcLayer)
    _origPos = (LPVOID)(MyGetProcAddress(mh, functionName));
  } else {
    Logger::Instance().error("%s is not a valid module name", moduleName);
    throw std::runtime_error("hook failed");
  }
  if (_origPos == nullptr) {
    Logger::Instance().error("%s is not a function in %ls", functionName, moduleName);
    throw std::runtime_error("hook failed");
  }
  _fdisasm.Init(reinterpret_cast<LPBYTE>(_origPos));
  if (!Hook(_origPos, replacement)) {
    Logger::Instance().error("%s in %s can not be hooked", functionName, moduleName);
    throw std::runtime_error("hook failed");
  }
  _installed = true;
  LOGDEBUG("hook for %s installed at %p (trampoline at %p)", functionName, _origPos, _reroute);
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
  if (start == nullptr) throw std::runtime_error("nullptr-Pointer as start-address");
  if (start == nullptr) throw std::runtime_error("nullptr-Pointer as replacement-address");

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



#include <Psapi.h>
#include <algorithm>
static void GetSectionRange(DWORD *start, DWORD *end, HANDLE moduleHandle)
{
  BYTE *exeModule = reinterpret_cast<BYTE*>(moduleHandle);
  if (exeModule == nullptr) {
    Logger::Instance().error("failed to determine address range of executable: %lu", ::GetLastError());
    *start = *end = 0UL;
    return;
  }

  PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(exeModule);
  PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(exeModule + dosHeader->e_lfanew);
  PIMAGE_SECTION_HEADER sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(ntHeader + 1);

  for (int i = 0 ; i < ntHeader->FileHeader.NumberOfSections ; ++i) {
    if (memcmp(sectionHeader->Name, ".text", 5) == 0) {
      *start = reinterpret_cast<DWORD>(exeModule) + sectionHeader->VirtualAddress;
      *end = *start + sectionHeader->Misc.VirtualSize;
//      break;
    }
    ++sectionHeader;
  }
}
static std::wstring GetSectionName(PVOID address)
{
  HANDLE process = ::GetCurrentProcess();
  HMODULE modules[1024];
  DWORD required;
  if (::EnumProcessModules(process, modules, sizeof(modules), &required)) {
    for (DWORD i = 0; i < (std::min<DWORD>(1024UL, required) / sizeof(HMODULE)); ++i) {
      DWORD start, end;
      GetSectionRange(&start, &end, modules[i]);
      if (((DWORD)address > start) && ((DWORD)address < end)) {
        wchar_t modName[MAX_PATH];

        if (::GetModuleFileNameExW(GetCurrentProcess(), modules[i], modName, MAX_PATH)) {
          return std::wstring(modName);
        } else {
          return std::wstring(L"unknown");
        }
      }
    }
  }
  return std::wstring(L"unknown");
}



size_t ApiHook::CreateReroute(LPBYTE &hookInsertionAddress)
{
  size_t size = 0;
  size_t relativeAdd = 0;
  int num = 0;
  PBYTE curPos = _fdisasm.GetEnd();
  Disasm disasm = _fdisasm.GetDisasm();
  // Calculate how many instructions need to be moved

  PBYTE preHookJumpTarget = NULL;

  while (size < sizeof(jump)) {
    if ((size == 0) && (disasm.GetOpcode() == 0xE9)) {
      LOGDEBUG("%s seems to be hooked already: %ls",
               _functionName, ::GetSectionName(disasm.GetAbsoluteDestination()).c_str());
      preHookJumpTarget = disasm.GetAbsoluteDestination();
    } else if ((size == 0) && (disasm.GetOpcode() == 0xEB)) {
      // short jump, may be a hot-patch
      PBYTE pos = disasm.GetAbsoluteDestination();
      Disasm refDisasm(pos);
      if (refDisasm.GetOpcode() == 0xE9) {
        // aha, it IS a hot patch
        LOGDEBUG("%s seems to be hooked already (hot-patch): %ls",
                 _functionName, ::GetSectionName(refDisasm.GetAbsoluteDestination()).c_str());
        hookInsertionAddress = pos;
        preHookJumpTarget = refDisasm.GetAbsoluteDestination();
      }
    }
    if (disasm.IsRelative()) {
      relativeAdd += 3 + sizeof(void*);  // if the jump is relative or near, it will have to
                                        // be adjusted, possible increasing the size of the command
    }
    size += disasm.GetSize();
    num++;
    curPos = disasm.GetNextCommand();
  }

  if (preHookJumpTarget == NULL) {
    int tmpnum = num;
    size_t tmpsize = size;
    // Continue copying operations if a jump follows that targets the already to-be-copied area
    while (curPos < _fdisasm.GetEnd()) {
      tmpnum++;
      tmpsize += disasm.GetSize();
      if (disasm.JumpTargets(hookInsertionAddress, hookInsertionAddress + size)) {
        num = tmpnum;
        size = tmpsize;
      }
      curPos = disasm.GetNextCommand();
    }
  } // no need to fix jumps

  size_t jlen = sizeof(void*) + 1;          // size of a jump: 1 byte opcode + size of an address

  // allocate memory for the reroute that is executable
  _reroute = reinterpret_cast<LPBYTE>(::VirtualAlloc(nullptr,
                                      size + jlen + sizeof(char*) + relativeAdd,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE));

  LPBYTE rerouteEnd = _reroute;

  if (preHookJumpTarget == NULL) {
    disasm.Reset();
    // Copy instructions and adjust relative jumps if neccessary
    for (int i = 0; i < num; i++) {
      rerouteEnd = disasm.CopyTo(rerouteEnd, hookInsertionAddress, size);
      disasm.GetNextCommand();
    }
  } // no need to copy instructions

  // Add jump back to original function or the next hook in the chain
  *rerouteEnd = 0xE9;          // JMP
  ++rerouteEnd;
  if (preHookJumpTarget == NULL) {
    *(reinterpret_cast<ULONG*>(rerouteEnd)) =
            reinterpret_cast<ULONG>(hookInsertionAddress) + size -
            (reinterpret_cast<ULONG>(rerouteEnd) + sizeof(ULONG));   // Distance to original function
  } else {
    *(reinterpret_cast<ULONG*>(rerouteEnd)) =
            reinterpret_cast<ULONG>(preHookJumpTarget) -
            (reinterpret_cast<ULONG>(rerouteEnd) + sizeof(ULONG));   // Distance to original function
  }

  return size;
}

BOOL ApiHook::InsertHook(LPVOID original, LPVOID replacement)
{
  LPBYTE hookInsertionAddress = reinterpret_cast<LPBYTE>(original);
  _bytesMoved = CreateReroute(hookInsertionAddress);

  DWORD oldprotect, ignore;
  // Set the target function to copy on write, so we don't modify code for other processes
  if (!::VirtualProtect(hookInsertionAddress,
                        sizeof(jump),
                        PAGE_EXECUTE_WRITECOPY,
                        &oldprotect)) {
    throw MOShared::windows_error("failed to change virtual protection");
  }

  // Copy the jump instruction to the target address and insert the reroute addresses
  memmove(hookInsertionAddress, &jump, sizeof(jump));
  AddrReplace(hookInsertionAddress, 0xBBBBBBBB, replacement, sizeof(jump), TRUE);

  // update "origpos" to point to the place where we actually inserted the jump so it can be removed
  // correctly
  _origPos = hookInsertionAddress;

  // restore old memory protection
  if (!::VirtualProtect(hookInsertionAddress, sizeof(jump), oldprotect, &ignore)) {
    throw MOShared::windows_error("failed to restore virtual protection");
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
      throw MOShared::windows_error("failed to change virtual protection");
    }

    // Copy the jump instruction to the target address and insert the reroute addresses
    memmove(_origPos, &jump, sizeof(jump));
    AddrReplace(reinterpret_cast<LPBYTE>(_origPos), 0xBBBBBBBB, _reroute, sizeof(jump), TRUE);

    // restore old memory protection
    if (!::VirtualProtect(_origPos, sizeof(jump), oldprotect, &ignore)) {
      throw MOShared::windows_error("failed to restore virtual protection");
    }
  }
}
