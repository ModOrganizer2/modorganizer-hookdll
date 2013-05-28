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

// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "dllmain.h"
#include <stdio.h>
#include <tchar.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <sstream>
#include <fstream>
#include <regex>
#include <algorithm>
#include <Shlwapi.h>
#include <DbgHelp.h>
#include "apihook.h"
#include "logger.h"
#include "utility.h"
#include "modinfo.h"
#include "reroutes.h"
#include "inject.h"
#include "profile.h"
#include "hooklock.h"
#include <gameinfo.h>
#include <util.h>
#include <appconfig.h>
#include "obse.h"
#include <boost/scoped_array.hpp>
#include <boost/preprocessor.hpp>
#include <Shellapi.h>


using namespace MOShared;


// hook declarations
CreateProcessA_type CreateProcessA_reroute = CreateProcessA;
CreateProcessW_type CreateProcessW_reroute = CreateProcessW;
LoadLibraryExW_type LoadLibraryExW_reroute = LoadLibraryExW;
LoadLibraryW_type LoadLibraryW_reroute = LoadLibraryW;
LoadLibraryExA_type LoadLibraryExA_reroute = LoadLibraryExA;
LoadLibraryA_type LoadLibraryA_reroute = LoadLibraryA;
CreateFileW_type CreateFileW_reroute = CreateFileW;
CreateFileA_type CreateFileA_reroute = CreateFileA;
CloseHandle_type CloseHandle_reroute = CloseHandle;
FindFirstFileA_type FindFirstFileA_reroute = FindFirstFileA;
FindFirstFileW_type FindFirstFileW_reroute = FindFirstFileW;
FindFirstFileExW_type FindFirstFileExW_reroute = FindFirstFileExW;
FindNextFileA_type FindNextFileA_reroute = FindNextFileA;
FindNextFileW_type FindNextFileW_reroute = FindNextFileW;
FindClose_type FindClose_reroute = FindClose;
GetFileAttributesW_type GetFileAttributesW_reroute = GetFileAttributesW;
GetFileAttributesExW_type GetFileAttributesExW_reroute = GetFileAttributesExW;
SetFileAttributesW_type SetFileAttributesW_reroute = SetFileAttributesW;
CreateDirectoryW_type CreateDirectoryW_reroute = CreateDirectoryW;
MoveFileA_type MoveFileA_reroute = MoveFileA;
MoveFileExA_type MoveFileExA_reroute = MoveFileExA;
MoveFileW_type MoveFileW_reroute = MoveFileW;
MoveFileExW_type MoveFileExW_reroute = MoveFileExW;
DeleteFileW_type DeleteFileW_reroute = DeleteFileW;
DeleteFileA_type DeleteFileA_reroute = DeleteFileA;
GetPrivateProfileStringA_type GetPrivateProfileStringA_reroute = GetPrivateProfileStringA;
GetPrivateProfileStringW_type GetPrivateProfileStringW_reroute = GetPrivateProfileStringW;
GetPrivateProfileStructA_type GetPrivateProfileStructA_reroute = GetPrivateProfileStructA;
GetPrivateProfileStructW_type GetPrivateProfileStructW_reroute = GetPrivateProfileStructW;
GetPrivateProfileIntA_type GetPrivateProfileIntA_reroute = GetPrivateProfileIntA;
GetPrivateProfileIntW_type GetPrivateProfileIntW_reroute = GetPrivateProfileIntW;
GetPrivateProfileSectionNamesA_type GetPrivateProfileSectionNamesA_reroute = GetPrivateProfileSectionNamesA;
GetPrivateProfileSectionNamesW_type GetPrivateProfileSectionNamesW_reroute = GetPrivateProfileSectionNamesW;
GetPrivateProfileSectionA_type GetPrivateProfileSectionA_reroute = GetPrivateProfileSectionA;
GetPrivateProfileSectionW_type GetPrivateProfileSectionW_reroute = GetPrivateProfileSectionW;
WritePrivateProfileSectionA_type WritePrivateProfileSectionA_reroute = WritePrivateProfileSectionA;
WritePrivateProfileSectionW_type WritePrivateProfileSectionW_reroute = WritePrivateProfileSectionW;
WritePrivateProfileStringA_type WritePrivateProfileStringA_reroute = WritePrivateProfileStringA;
WritePrivateProfileStringW_type WritePrivateProfileStringW_reroute = WritePrivateProfileStringW;
WritePrivateProfileStructA_type WritePrivateProfileStructA_reroute = WritePrivateProfileStructA;
WritePrivateProfileStructW_type WritePrivateProfileStructW_reroute = WritePrivateProfileStructW;
OpenFile_type OpenFile_reroute = OpenFile;
GetCurrentDirectoryW_type GetCurrentDirectoryW_reroute = GetCurrentDirectoryW;
SetCurrentDirectoryW_type SetCurrentDirectoryW_reroute = SetCurrentDirectoryW;
CopyFileA_type CopyFileA_reroute = CopyFileA;
CopyFileW_type CopyFileW_reroute = CopyFileW;
CreateHardLinkW_type CreateHardLinkW_reroute = CreateHardLinkW;
CreateHardLinkA_type CreateHardLinkA_reroute = CreateHardLinkA;
GetFullPathNameW_type GetFullPathNameW_reroute = GetFullPathNameW;
SHFileOperationW_type SHFileOperationW_reroute = SHFileOperationW;
GetFileVersionInfoExW_type GetFileVersionInfoExW_reroute = GetFileVersionInfoExW;
GetFileVersionInfoSizeW_type GetFileVersionInfoSizeW_reroute = GetFileVersionInfoSizeW;
GetModuleFileNameW_type GetModuleFileNameW_reroute = GetModuleFileNameW;


ModInfo *modInfo = NULL;

std::map<std::pair<int, DWORD>, bool> skipMap;

std::string bsaResourceList;
std::map<std::string, std::string> bsaMap;
//std::set<std::string> bsaList;
//std::set<std::string> usedBSAList;

std::set<std::string> iniFilesA;

//static const int MAX_PATH_UNICODE = 32768;
static const int MAX_PATH_UNICODE = 256;

HANDLE instanceMutex = INVALID_HANDLE_VALUE;
HMODULE dllModule = NULL;
PVOID exceptionHandler = NULL;

int sLogLevel = 0;


#pragma message("the privatestring-hook is not functional with a debug build. should fix that")
#ifdef DEBUG
enum {
  HOOK_NOTYET,
  HOOK_FAILED,
  HOOK_SUCCESS
} archiveListHookState = HOOK_FAILED;
#else // DEBUG
enum {
  HOOK_NOTYET,
  HOOK_FAILED,
  HOOK_SUCCESS
} archiveListHookState = HOOK_NOTYET;
#endif // DEBUG

char modName[MAX_PATH];


BOOL CreateDirectoryRecursive(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
  WCHAR buffer[MAX_PATH + 1];
  memset(buffer, 0, sizeof(WCHAR) * (MAX_PATH + 1));
  size_t totalLen = wcslen(lpPathName);
  size_t currentLen = 0;

  while (currentLen < totalLen) {
    currentLen += wcscspn(lpPathName + currentLen, L"\\/");
    wcsncpy(buffer, lpPathName, currentLen);
    if (CreateDirectoryW_reroute(buffer, lpSecurityAttributes)) {
      if (::GetLastError() != ERROR_ALREADY_EXISTS) {
        Logger::Instance().error("failed to create intermediate directory %ls: %lu", buffer, ::GetLastError());
        return false;
      }
    }
    ++currentLen; // skip the (back-)slash
  }
  return true;
}


BOOL WINAPI CreateProcessA_rep(LPCSTR lpApplicationName,
                 LPSTR lpCommandLine,
                 LPSECURITY_ATTRIBUTES lpProcessAttributes,
                 LPSECURITY_ATTRIBUTES lpThreadAttributes,
                 BOOL bInheritHandles,
                 DWORD dwCreationFlags,
                 LPVOID lpEnvironment,
                 LPCSTR lpCurrentDirectory,
                 LPSTARTUPINFOA lpStartupInfo,
                 LPPROCESS_INFORMATION lpProcessInformation)
{
  PROFILE();
  BOOL susp = dwCreationFlags & CREATE_SUSPENDED;
  DWORD flags = dwCreationFlags | CREATE_SUSPENDED;
  LOGDEBUG("create process (a) %s - %s (in %s)",
           lpApplicationName != NULL ? lpApplicationName : "null",
           lpCommandLine != NULL ? lpCommandLine : "null",
           lpCurrentDirectory != NULL ? lpCurrentDirectory : "null");
  bool compiler = false;

  if ((lpApplicationName == NULL) && (lpCommandLine != NULL)) {
    std::tr1::cmatch match;
    try {
      std::tr1::regex exp("\"Papyrus Compiler\\\\PapyrusCompiler.exe\" ([^ ]*) -f=\"([^\"]*)\" -i=\"([^\"]*)\" -o=\"(Data/Scripts/)\"");
      if (std::tr1::regex_search(lpCommandLine, match, exp)) {
        std::string fullInput = match[3];
        fullInput.append(match[1]);
        std::string reroutedInput = modInfo->getRerouteOpenExisting(fullInput.c_str());
        size_t sPos = reroutedInput.find_last_of("\\/");
        char tempBuffer[1024];
        _snprintf(tempBuffer, 1024, "\"Papyrus Compiler\\PapyrusCompiler.exe\" %s -f=\"%s\" -i=\"%s\" -o=\"%s\"",
                  match.str(1).c_str(), match.str(2).c_str(), reroutedInput.substr(0, sPos).c_str(), match.str(4).c_str());
        LOGDEBUG("run papyrus: %s", tempBuffer);
        if (!::CreateProcessA_reroute(lpApplicationName, tempBuffer, lpProcessAttributes,
              lpThreadAttributes, bInheritHandles, flags, lpEnvironment,
              lpCurrentDirectory, lpStartupInfo, lpProcessInformation)) {
          return FALSE;
        }
        compiler = true;
      }
    } catch (const std::exception &e) {
      Logger::Instance().error("failed to parse compiler command line: %s", e.what());
      return FALSE;
    }
  }

  if (!compiler) {
    std::string reroutedCwd;
    if (lpCurrentDirectory != NULL) {
      reroutedCwd = modInfo->getRerouteOpenExisting(lpCurrentDirectory);
    }

    if (!::CreateProcessA_reroute(lpApplicationName, lpCommandLine, lpProcessAttributes,
          lpThreadAttributes, bInheritHandles, flags, lpEnvironment,
          lpCurrentDirectory != NULL ? reroutedCwd.c_str() : NULL,
          lpStartupInfo, lpProcessInformation)) {
      LOGDEBUG("process failed to start (%lu)", ::GetLastError());
      return FALSE;
    }
  }

  try {
    if (!compiler) {
      char hookPath[MAX_PATH];
      ::GetModuleFileNameA(dllModule, hookPath, MAX_PATH);
      injectDLL(lpProcessInformation->hProcess, lpProcessInformation->hThread,
                hookPath, modInfo->getProfileName(), sLogLevel);
    }
  } catch (const std::exception &e) {
    Logger::Instance().error("failed to inject into %s: %s", lpApplicationName, e.what());
  }

  if (  (!susp) && (::ResumeThread(lpProcessInformation->hThread) == (DWORD)-1)) {
    Logger::Instance().error("failed to inject into spawned process");
    return FALSE;
  }
  return TRUE;
}


BOOL WINAPI CreateProcessW_rep(LPCWSTR lpApplicationName,
                 LPWSTR lpCommandLine,
                 LPSECURITY_ATTRIBUTES lpProcessAttributes,
                 LPSECURITY_ATTRIBUTES lpThreadAttributes,
                 BOOL bInheritHandles,
                 DWORD dwCreationFlags,
                 LPVOID lpEnvironment,
                 LPCWSTR lpCurrentDirectory,
                 LPSTARTUPINFOW lpStartupInfo,
                 LPPROCESS_INFORMATION lpProcessInformation)
{
  PROFILE();

  LOGDEBUG("create process (w) %ls - %ls (in %ls)",
           lpApplicationName != NULL ? lpApplicationName : L"null",
           lpCommandLine != NULL ? lpCommandLine : L"null",
           lpCurrentDirectory != NULL ? lpCurrentDirectory : L"null");

  BOOL susp = dwCreationFlags & CREATE_SUSPENDED;
  DWORD flags = dwCreationFlags | CREATE_SUSPENDED;

  std::wstring reroutedApplicationName;
  if (lpApplicationName != NULL) {
    reroutedApplicationName = modInfo->getRerouteOpenExisting(lpApplicationName);
    lpApplicationName = reroutedApplicationName.c_str();
  }

  std::wstring reroutedCwd;
  if (lpCurrentDirectory != NULL) {
    reroutedCwd = modInfo->getRerouteOpenExisting(lpCurrentDirectory);
  }

  if (!::CreateProcessW_reroute(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, flags, lpEnvironment,
        lpCurrentDirectory != NULL ? reroutedCwd.c_str() : NULL,
        lpStartupInfo, lpProcessInformation)) {
    LOGDEBUG("process failed to start (%lu)", ::GetLastError());
    return FALSE;
  }

  try {
    char hookPath[MAX_PATH];
    ::GetModuleFileNameA(dllModule, hookPath, MAX_PATH);
    injectDLL(lpProcessInformation->hProcess, lpProcessInformation->hThread,
              hookPath, modInfo->getProfileName(), sLogLevel);
  } catch (const std::exception &e) {
    Logger::Instance().error("failed to inject into %ls: %s", lpApplicationName, e.what());
  }

  if (  (!susp) && (::ResumeThread(lpProcessInformation->hThread) == (DWORD)-1)) {
    Logger::Instance().error("failed to inject into spawned process");
    return FALSE;
  }
  return TRUE;
}


HMODULE WINAPI LoadLibraryExW_rep(LPCWSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
  PROFILE();
  std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
  return LoadLibraryExW_reroute(rerouteFilename.c_str(), hFile, dwFlags);
}


HMODULE WINAPI LoadLibraryW_rep(LPCWSTR lpFileName)
{
  PROFILE();
  std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
  return LoadLibraryW_reroute(rerouteFilename.c_str());
}


HMODULE WINAPI LoadLibraryExA_rep(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
  PROFILE();
  std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
  return LoadLibraryExA_reroute(rerouteFilename.c_str(), hFile, dwFlags);
}


HMODULE WINAPI LoadLibraryA_rep(LPCSTR lpFileName)
{
  PROFILE();
  std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
  return LoadLibraryA_reroute(rerouteFilename.c_str());
}


HANDLE WINAPI CreateFileW_rep(LPCWSTR lpFileName,
                              DWORD dwDesiredAccess,
                              DWORD dwShareMode,
                              LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                              DWORD dwCreationDisposition,
                              DWORD dwFlagsAndAttributes,
                              HANDLE hTemplateFile)
{
  PROFILE();
  std::wstring rerouteFilename;

  WCHAR fullFileName[MAX_PATH];
  memset(fullFileName, '\0', MAX_PATH * sizeof(WCHAR));
  modInfo->getFullPathName(lpFileName, fullFileName, MAX_PATH);

  modInfo->checkPathAlternative(fullFileName);

  // newly created files in the data directory go to the overwrites directory
  if (((dwCreationDisposition == CREATE_ALWAYS) || (dwCreationDisposition == CREATE_NEW)) &&
      (StartsWith(fullFileName, modInfo->getDataPathW().c_str()))) {
    std::wostringstream temp;
    temp << GameInfo::instance().getOverwriteDir() << "\\" << (fullFileName + modInfo->getDataPathW().length());
    rerouteFilename = temp.str();

    std::wstring targetDirectory = rerouteFilename.substr(0, rerouteFilename.find_last_of(L"\\/"));
    CreateDirectoryRecursive(targetDirectory.c_str(), NULL);
    modInfo->addOverwriteFile(rerouteFilename);
  }

  bool rerouted = false;

  if (rerouteFilename.length() == 0) {
    LPCWSTR baseName = GetBaseName(lpFileName);
    size_t pathLen = baseName - lpFileName;

    std::map<std::string, std::string>::iterator bsaName = bsaMap.find(ToString(baseName, true));
    if (bsaName != bsaMap.end()) {
      std::wstring bsaPath = std::wstring(lpFileName).substr(0, pathLen).append(ToWString(bsaName->second, true));
      rerouteFilename = modInfo->getRerouteOpenExisting(bsaPath.c_str(), false, &rerouted);
      if (!rerouted) {
        LOGDEBUG("createfile bsa not rerouted: %ls -> %ls -> %ls", lpFileName, bsaPath.c_str(), rerouteFilename.c_str());
      }
    } else {
      rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName, false, &rerouted);
    }
  }

  HANDLE result = CreateFileW_reroute(rerouteFilename.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

  if (rerouted) {
    LOGDEBUG("createfile: %ls -> %ls (%x - %x) = %p (%d)", lpFileName, rerouteFilename.c_str(), dwDesiredAccess, dwCreationDisposition, result, ::GetLastError());
  }

  return result;
}


HANDLE WINAPI CreateFileA_rep(LPCSTR lpFileName,
                              DWORD dwDesiredAccess,
                              DWORD dwShareMode,
                              LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                              DWORD dwCreationDisposition,
                              DWORD dwFlagsAndAttributes,
                              HANDLE hTemplateFile)
{
  PROFILE();

  wchar_t temp[MAX_PATH];
  int converted = ::MultiByteToWideChar(GetACP(), 0, lpFileName, -1, temp, MAX_PATH);
  if (converted >= MAX_PATH) temp[MAX_PATH - 1] = L'\0';
  return CreateFileW_rep(temp, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                     dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


BOOL WINAPI CloseHandle_rep(HANDLE hObject)
{
  return CloseHandle_reroute(hObject);
}


DWORD WINAPI GetFileAttributesW_rep(LPCWSTR lpFileName)
{
  PROFILE();

  if ((lpFileName == NULL) || (lpFileName[0] == L'\0')) {
    return GetFileAttributesW_reroute(lpFileName);
  }
  LPCWSTR baseName = GetBaseName(lpFileName);

  int pathLen = baseName - lpFileName;

  bool rerouted = false;

  std::wstring rerouteFilename;
  std::map<std::string, std::string>::iterator bsaName = bsaMap.find(ToString(baseName, true));
  if (bsaName != bsaMap.end()) {
    rerouteFilename = modInfo->getRerouteOpenExisting(std::wstring(lpFileName).substr(0, pathLen).append(ToWString(bsaName->second, true)).c_str(),
                                                      false, &rerouted);
  } else {
    rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName, false, &rerouted);
  }

  DWORD result = GetFileAttributesW_reroute(rerouteFilename.c_str());
  if (rerouted) {
    LOGDEBUG("get file attributes: %ls -> %ls: %x", lpFileName, rerouteFilename.c_str(), result);
  }
  return result;
}

BOOL WINAPI GetFileAttributesExW_rep(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
{
  PROFILE();
  LPCWSTR baseName = GetBaseName(lpFileName);
  int pathLen = baseName - lpFileName;

/*  if (usedBSAList.find(ToLower(ToString(baseName, true))) != usedBSAList.end()) {
    // hide bsa files loaded already through the resource archive list
    LOGDEBUG("%ls hidden from the game", lpFileName);
    return FALSE;
  }*/

  bool rerouted = false;

  std::wstring rerouteFilename;
  std::map<std::string, std::string>::iterator bsaName = bsaMap.find(ToString(baseName, true));
  if (bsaName != bsaMap.end()) {
    rerouteFilename = modInfo->getRerouteOpenExisting(std::wstring(lpFileName).substr(0, pathLen).append(ToWString(bsaName->second, true)).c_str(),
                                                      false, &rerouted);
//    usedBSAList.insert(ToLower(bsaName->second));
  } else {
    rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName, false, &rerouted);
  }

  BOOL result = GetFileAttributesExW_reroute(rerouteFilename.c_str(), fInfoLevelId, lpFileInformation);
  if (rerouted) {
    if (result && (fInfoLevelId == GetFileExInfoStandard)) {
      LPWIN32_FIND_DATAW fileData = (LPWIN32_FIND_DATAW)lpFileInformation;
      LOGDEBUG("get file attributesex: %ls -> %ls: %d (%d)", lpFileName, rerouteFilename.c_str(), result, fileData->dwFileAttributes);
    } else {
      LOGDEBUG("get file attributesex: %ls -> %ls: %d", lpFileName, rerouteFilename.c_str(), result);
    }
  }
  return result;
}


BOOL WINAPI SetFileAttributesW_rep(LPCWSTR lpFileName, DWORD dwFileAttributes)
{
  PROFILE();
  std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
  LOGDEBUG("set file attributes: %ls -> %ls", lpFileName, rerouteFilename.c_str());
  BOOL result = SetFileAttributesW_reroute(rerouteFilename.c_str(), dwFileAttributes);
  return result;
}


HANDLE WINAPI FindFirstFileExW_rep(LPCWSTR lpFileName,
                                   FINDEX_INFO_LEVELS fInfoLevelId,
                                   LPVOID lpFindFileData,
                                   FINDEX_SEARCH_OPS fSearchOp,
                                   LPVOID lpSearchFilter,
                                   DWORD dwAdditionalFlags)
{
  PROFILE();

  if (HookLock::isLocked() || (lpFileName == NULL)) return FindFirstFileExW_reroute(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
  LPCWSTR baseName = GetBaseName(lpFileName);

  size_t pathLen = baseName - lpFileName;

  std::wstring rerouteFilename = lpFileName;

  std::map<std::string, std::string>::iterator bsaName = bsaMap.find(ToString(baseName, true));
  LPCWSTR sPos = NULL;
  if (bsaName != bsaMap.end()) {
    rerouteFilename = std::wstring(lpFileName).substr(0, pathLen).append(ToWString(bsaName->second, true));
  } else if ((sPos = wcswcs(lpFileName, AppConfig::localSavePlaceholder())) != NULL) {
    rerouteFilename = modInfo->getProfilePath().append(L"\\saves\\").append(sPos + wcslen(AppConfig::localSavePlaceholder()));
  }
  HANDLE result = modInfo->findStart(rerouteFilename.c_str(), fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);

  if (result != INVALID_HANDLE_VALUE) {
    LOGDEBUG("findfirstfileex %ls: %ls (%x)", rerouteFilename.c_str(),
             ((LPWIN32_FIND_DATAW)lpFindFileData)->cFileName,
             ((LPWIN32_FIND_DATAW)lpFindFileData)->dwFileAttributes);
  } else {
    LOGDEBUG("findfirstfileex %ls: nothing found (%d)", rerouteFilename.c_str(), ::GetLastError());
  }

  return result;
}


BOOL GetNext(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
  if (modInfo->searchExists(hFindFile)) {
    return modInfo->findNext(hFindFile, lpFindFileData);
  } else {
    return FindNextFileW_reroute(hFindFile, lpFindFileData);
  }
}

BOOL WINAPI FindNextFileW_rep(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
  PROFILE();

  BOOL result = GetNext(hFindFile, lpFindFileData);
  while (result && (wcscmp(lpFindFileData->cFileName, L"profiles") == 0)) {
    LOGDEBUG("hiding %ls from target process", lpFindFileData->cFileName);
    result = GetNext(hFindFile, lpFindFileData);
  }

  if (result) {
    ::SetLastError(ERROR_SUCCESS);
  }
  return result;
}

BOOL WINAPI FindClose_rep(HANDLE hFindFile)
{
  PROFILE();
  BOOL result = false;
  if (modInfo->searchExists(hFindFile)) {
    result = modInfo->findClose(hFindFile);
  } else {
    result = FindClose_reroute(hFindFile);
  }
  return result;
}



BOOL WINAPI CreateDirectoryW_rep(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
  PROFILE();
  std::wstring reroutePath = modInfo->getRerouteOpenExisting(lpPathName);
  LOGDEBUG("create directory %ls -> %ls", lpPathName, reroutePath.c_str());
  if (StartsWith(lpPathName, modInfo->getDataPathW().c_str())) {
    // the intermediate directories may exist in the original directory but not in the rerouted location
    // so do a recursive create
    return CreateDirectoryRecursive(reroutePath.c_str(), lpSecurityAttributes);
  } else {
    return CreateDirectoryW_reroute(reroutePath.c_str(), lpSecurityAttributes);
  }
}


BOOL WINAPI DeleteFileW_rep(LPCWSTR lpFileName)
{
  PROFILE();
  WCHAR buffer[MAX_PATH];
  modInfo->getFullPathName(lpFileName, buffer, MAX_PATH);
  LPCWSTR sPos = NULL;

  if (StartsWith(buffer, modInfo->getDataPathW().c_str())) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    modInfo->removeModFile(lpFileName);
    Logger::Instance().info("deleting %ls -> %ls", lpFileName, rerouteFilename.c_str());
    return DeleteFileW_reroute(rerouteFilename.c_str());
  } else if ((sPos = wcswcs(buffer, AppConfig::localSavePlaceholder())) != NULL) {
    std::wstring rerouteFilename = modInfo->getProfilePath().append(L"\\saves\\").append(sPos + wcslen(AppConfig::localSavePlaceholder()));
    modInfo->removeModFile(lpFileName);
    Logger::Instance().info("deleting %ls -> %ls", lpFileName, rerouteFilename.c_str());
    return DeleteFileW_reroute(rerouteFilename.c_str());
  } else {
    return DeleteFileW_reroute(lpFileName);
  }
}


BOOL WINAPI DeleteFileA_rep(LPCSTR lpFileName)
{
  PROFILE();
  wchar_t fileName[MAX_PATH];
  int converted = ::MultiByteToWideChar(GetACP(), 0, lpFileName, -1, fileName, MAX_PATH);
  if (converted >= MAX_PATH) fileName[MAX_PATH - 1] = L'\0';

  return DeleteFileW_rep(fileName);
}


BOOL WINAPI MoveFileExW_rep(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags)
{
  PROFILE();
  WCHAR fullSourceName[MAX_PATH];
  modInfo->getFullPathName(lpExistingFileName, fullSourceName, MAX_PATH);
  WCHAR fullDestinationName[MAX_PATH];
  modInfo->getFullPathName(lpNewFileName, fullDestinationName, MAX_PATH);

  // source file definitively needs to be rerouted if it originates from the fake directory
  std::wstring sourceReroute = modInfo->getRerouteOpenExisting(fullSourceName);
  std::wstring destinationReroute = fullDestinationName;

  if (StartsWith(fullDestinationName, modInfo->getDataPathW().c_str())) {
    std::wostringstream temp;
    temp << GameInfo::instance().getOverwriteDir() << "\\" << (fullDestinationName + modInfo->getDataPathW().length() + 1);
    destinationReroute = temp.str();
  }

  { // create intermediate directories
    std::wstring targetDirectory = destinationReroute.substr(0, destinationReroute.find_last_of(L"\\/"));
    CreateDirectoryRecursive(targetDirectory.c_str(), NULL);
  }

  BOOL res = MoveFileExW_reroute(sourceReroute.c_str(), destinationReroute.c_str(), dwFlags);

  LOGDEBUG("move (ex) %ls to %ls - %d (%lu)", lpExistingFileName, lpNewFileName, res, ::GetLastError());

  return res;
}


BOOL WINAPI MoveFileW_rep(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)
{
  PROFILE();
  WCHAR fullSourceName[MAX_PATH];
  modInfo->getFullPathName(lpExistingFileName, fullSourceName, MAX_PATH);
  WCHAR fullDestinationName[MAX_PATH];
  modInfo->getFullPathName(lpNewFileName, fullDestinationName, MAX_PATH);

  // source file definitively needs to be rerouted if it originates from the fake directory
  std::wstring sourceReroute = modInfo->getRerouteOpenExisting(fullSourceName);
  std::wstring destinationReroute = fullDestinationName;
  LPCWSTR sPos = NULL;
  if (StartsWith(fullDestinationName, modInfo->getDataPathW().c_str())) {
    // usually, always move to the overwrite directory. However, in the "create tmp, remove original, move tmp to original"-sequence
    // we'd rather have the modified file in the original location
    destinationReroute = modInfo->getRemovedLocation(fullDestinationName);
    if (destinationReroute.empty()) {
      std::wostringstream temp;
      temp << GameInfo::instance().getOverwriteDir() << "\\" << (fullDestinationName + modInfo->getDataPathW().length() + 1);
      destinationReroute = temp.str();
    }
  } else if ((sPos = wcswcs(fullDestinationName, AppConfig::localSavePlaceholder())) != NULL) {
    destinationReroute = modInfo->getProfilePath().append(L"\\saves\\").append(sPos + wcslen(AppConfig::localSavePlaceholder()));
  }

  { // create intermediate directories
    std::wstring targetDirectory = destinationReroute.substr(0, destinationReroute.find_last_of(L"\\/"));
    CreateDirectoryRecursive(targetDirectory.c_str(), NULL);
  }

  BOOL res = MoveFileW_reroute(sourceReroute.c_str(), destinationReroute.c_str());
  LOGDEBUG("move %ls to %ls: %d (%d)", sourceReroute.c_str(), destinationReroute.c_str(), res, ::GetLastError());
  return res;
}

BOOL WINAPI MoveFileA_rep(LPCSTR lpExistingFileName, LPCSTR lpNewFileName)
{
  PROFILE();
  wchar_t source[MAX_PATH];
  int converted = ::MultiByteToWideChar(GetACP(), 0, lpExistingFileName, -1, source, MAX_PATH);
  if (converted >= MAX_PATH) source[MAX_PATH - 1] = L'\0';
  wchar_t destination[MAX_PATH];
  converted = ::MultiByteToWideChar(GetACP(), 0, lpNewFileName, -1, destination, MAX_PATH);
  if (converted >= MAX_PATH) destination[MAX_PATH - 1] = L'\0';

  return MoveFileW_rep(source, destination);
}


BOOL WINAPI MoveFileExA_rep(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags)
{
  PROFILE();
  wchar_t source[MAX_PATH];
  int converted = ::MultiByteToWideChar(GetACP(), 0, lpExistingFileName, -1, source, MAX_PATH);
  if (converted >= MAX_PATH) source[MAX_PATH - 1] = L'\0';

  wchar_t destination[MAX_PATH];
  converted = ::MultiByteToWideChar(GetACP(), 0, lpNewFileName, -1, destination, MAX_PATH);
  if (converted >= MAX_PATH) destination[MAX_PATH - 1] = L'\0';

  return MoveFileExW_rep(source, destination, dwFlags);
}

static bool firstRun = true;

static void GetSectionRange(DWORD *start, DWORD *end)
{
  BYTE *exeModule = reinterpret_cast<BYTE*>(::GetModuleHandle(NULL));
  if (exeModule == NULL) {
    Logger::Instance().error("failed to determine address range of executable: %lu", ::GetLastError());
    *start = *end = NULL;
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

#pragma optimize( "", off )

static const int s_BufferSize = 0x8000;
static char s_Buffer[s_BufferSize];
static PBYTE s_ReturnAddress = NULL;

// this includes a bit of wiggle room, for skyrim we need 42 bytes
#define FUNCTION_BUFFER_SIZE 64

#define BOOST_PP_LOCAL_LIMITS (0, FUNCTION_BUFFER_SIZE)

#define NOPEMIT(n) \
   __asm _emit 0x90

#define BOOST_PP_LOCAL_MACRO NOPEMIT

__declspec(naked) void replacementFunction()
{
  __asm {
#include BOOST_PP_LOCAL_ITERATE()
  };
}

//static char s_FunctionBuffer[FUNCTION_BUFFER_SIZE] = { 0 };
static char *s_FunctionBuffer = (char*)replacementFunction;

__declspec(naked) void pushModEAX()
{
  __asm {
    push s_BufferSize
    lea  eax, s_Buffer
    push eax
    ret
  };
}

__declspec(naked) void pushModEBX()
{
  __asm {
    push s_BufferSize
    lea  ebx, s_Buffer
    push ebx
    ret
  };
}

__declspec(naked) void pushModECX()
{
  __asm {
    push s_BufferSize
    lea  ecx, s_Buffer
    push ecx
    ret
  };
}

__declspec(naked) void pushModEDX()
{
  __asm {
    push s_BufferSize
    lea  edx, s_Buffer
    push edx
    ret
  };
}

__declspec(naked) void callInstrMod()
{
  __asm {
    call    dword ptr[GetPrivateProfileStringA]
    ret
  };
}

__declspec(naked) void returnInstrEAX()
{
  __asm {
    lea		eax, s_Buffer
    jmp		[s_ReturnAddress]
  };
}
__declspec(naked) void returnInstrEBX()
{
  __asm {
    lea		ebx, s_Buffer
    jmp		[s_ReturnAddress]
  };
}
__declspec(naked) void returnInstrECX()
{
  __asm {
    lea		ecx, s_Buffer
    jmp		[s_ReturnAddress]
  };
}
__declspec(naked) void returnInstrEDX()
{
  __asm {
    lea		edx, s_Buffer
    jmp		[s_ReturnAddress]
  };
}

#pragma optimize( "", on )

size_t getSnippetSize(void *function)
{
  // the function snippets all end in a "ret" we don't want to copy
  FuncDisasm temp(reinterpret_cast<PBYTE>(function));
  return temp.GetSize() - 1;
}


static bool identifyAndManipulate(DWORD *pos, DWORD size)
{
//  memset(s_FunctionBuffer, 0x90, FUNCTION_BUFFER_SIZE);
  DWORD ignore;
  ::VirtualProtect(s_FunctionBuffer, 256, PAGE_EXECUTE_READWRITE, &ignore);
  unsigned char *funcPtr = reinterpret_cast<unsigned char*>(*pos);

  enum Registers {
    REG_EAX,
    REG_EBX,
    REG_ECX,
    REG_EDX
  } resultRegister = REG_ECX;

  { // determine the register the result is expected in
    s_ReturnAddress = funcPtr;
    Disasm temp(s_ReturnAddress);
    bool found = false;
    for (int i = 0; i < 3; ++i) { // don't go further than 3 instructions
      if ((temp.GetOpcode() >= 0x50) && (temp.GetOpcode() <= 0x53)) {
        // a push
        switch (temp.GetOpcode()) {
          case 0x50: resultRegister = REG_EAX; break;
          case 0x51: resultRegister = REG_ECX; break;
          case 0x52: resultRegister = REG_EDX; break;
          case 0x53: resultRegister = REG_EBX; break;
        }
        found = true;
        break;
      }
      s_ReturnAddress = temp.GetNextCommand();
    }
    if (!found) {
      return false;
    }
  }

  // the replace should start at the push that put nSize on the stack, so construct the assembler instruction
  // that would do that and search backward for it
  unsigned char pushInst[] = { 0x68, 0xBA, 0xAD, 0xF0, 0x0D }; // push
  *reinterpret_cast<DWORD*>(pushInst + 1) = size;

  bool found = false;

  // if we don't find it for 75 bytes, we're definitively wrong!
  for (int i = 0; i < 75; ++i) {
    if (memcmp(pushInst, funcPtr, 5) == 0) {
      found = true;
      break;
    }

    --funcPtr;
  }

  if (!found) {
    return false;
  }
  char *tPtr = s_FunctionBuffer;
  char *functionEnd = s_FunctionBuffer + FUNCTION_BUFFER_SIZE;

  Disasm disasm(funcPtr);
  PBYTE sPtr = disasm.GetNextCommand();
  if (disasm.GetOpcode() != 0x8D) {
    return false;
  }

  //
  // if we got here we seem to be right
  //

  void *function = NULL;
  switch (disasm.GetReg2()) {
    case 0: function = pushModEAX; break;
    case 1: function = pushModECX; break;
    case 2: function = pushModEDX; break;
    case 3: function = pushModEBX; break;
  }

  size_t funcSize = getSnippetSize(function);
  memcpy(tPtr, function, funcSize);
  tPtr += funcSize;

  disasm.GetNextCommand();
  sPtr = disasm.GetNextCommand();

  while ((disasm.GetOpcode() != 0xFF) && (sPtr < s_ReturnAddress)) {
    size_t opSize = disasm.GetSize();
    if (tPtr + opSize >= functionEnd) {
      // can't be right
      return false;
    }
    memcpy(tPtr, sPtr, opSize);
    tPtr += opSize;

    sPtr = disasm.GetNextCommand();
  }

  if (sPtr >= s_ReturnAddress) {
    // call not found
    return false;
  }

  { // copy call instruction to target function
    size_t funcSize = getSnippetSize(callInstrMod);
    if (tPtr + funcSize >= functionEnd) {
      return false;
    }
    memcpy(tPtr, callInstrMod, funcSize);
    tPtr += funcSize;
    sPtr = disasm.GetNextCommand();
  }

  // slightly hacky: copy the rest up to return adress or the lea
  while ((sPtr < s_ReturnAddress) && (disasm.GetOpcode() != 0x8D)) {
    size_t opSize = disasm.GetSize();
    if (tPtr + opSize >= functionEnd) {
      // can't be right
      return false;
    }
    memcpy(tPtr, sPtr, opSize);
    tPtr += opSize;
    sPtr = disasm.GetNextCommand();
  }

  switch (resultRegister) {
    case REG_EAX: function = returnInstrEAX; break;
    case REG_EBX: function = returnInstrEBX; break;
    case REG_ECX: function = returnInstrECX; break;
    case REG_EDX: function = returnInstrEDX; break;
  }

  size_t functionSize = FuncDisasm(reinterpret_cast<PBYTE>(function)).GetSize();

  if (tPtr + functionSize >= functionEnd) {
    // can't be right
    return false;
  }

  memcpy(tPtr, function, functionSize);

  // allow write access to the memory page of the function we want to change
  DWORD oldProtection;
  if (!::VirtualProtect(funcPtr, 256, PAGE_EXECUTE_READWRITE, &oldProtection)) {
    Logger::Instance().error("failed to change protection");
    return true;
  }

  // calculate distance between the code we want to circumvent and the replacement code...
  ULONG distance = reinterpret_cast<ULONG>(s_FunctionBuffer) - 1 -
                    (reinterpret_cast<ULONG>(funcPtr) + sizeof(ULONG));
  // ... so we can do a relative jump there
  *funcPtr = 0xE9;
  *(reinterpret_cast<ULONG*>(funcPtr + 1)) = distance;
  archiveListHookState = HOOK_SUCCESS;

  // restore old page access rights
  ::VirtualProtect(funcPtr, 256, oldProtection, &oldProtection);

  Logger::Instance().info("archive list limit removed at %p", funcPtr);
  return true;
}


DWORD WINAPI GetPrivateProfileStringA_rep(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpDefault,
                                          LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
  int localDummy = 42;
  PROFILE();
  if (HookLock::isLocked() || (lpFileName == NULL)) {
    return GetPrivateProfileStringA_reroute(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);
  }

  LPCSTR lastSlash = strrchr(lpFileName, '\\');
  if (lastSlash == NULL) {
    lastSlash = strrchr(lpFileName, '/');
  }
  if (lastSlash == NULL) {
    lastSlash = lpFileName;
  } else {
    ++lastSlash;
  }

  { // mod-inis are used directly
    std::string fileName(lastSlash);
    ToLower(fileName);

    if (iniFilesA.find(fileName) == iniFilesA.end()) {
      std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
      return GetPrivateProfileStringA_reroute(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, rerouteFilename.c_str());
    }
  }

  if ((archiveListHookState == HOOK_NOTYET) && (lpKeyName[0] ==  's') && (_stricmp(lpAppName, "Archive") == 0)) {
    // if we don't reach the success-case, we can safely assume it failed
    archiveListHookState = HOOK_FAILED;
    DWORD start, end;
    GetSectionRange(&start, &end);
    // search up through the stack to find the first address that belongs to the code-segment of the game-binary.
    // that is the return address to the function that called GetPrivateProfileString
    DWORD *pos = reinterpret_cast<DWORD*>(&localDummy);
    // if this takes more than 100 steps, this was probably not called by the game binary at all
    DWORD *lastPos = pos + 100;
    for (; pos < lastPos; ++pos) {
      if ((*pos > start) && (*pos < end)) {
        if (identifyAndManipulate(pos, nSize)) {
          break;
        }
      }
    }
    if (archiveListHookState == HOOK_FAILED) {
      Logger::Instance().error("failed to remove limit on archive list!");
    }
  }

  if ((_stricmp(lpKeyName, "sResourceArchiveList") == 0) || (_stricmp(lpKeyName, "sArchiveList") == 0)) {
    size_t length = std::min<DWORD>(bsaResourceList.size(), nSize - 1);
    if ((length > 255) && (lpReturnedString != s_Buffer)) {
      LOGDEBUG("safety check: length exceeds regular size but wrong buffer (%p vs. %p)?", lpReturnedString, s_Buffer);
      length = 255;
    }
    strncpy(lpReturnedString, bsaResourceList.c_str(), length);
    lpReturnedString[length] = '\0';
    return static_cast<DWORD>(length);
  } else if (_stricmp(lpKeyName, "sResourceArchiveList2") == 0) {
    // don't use second resource list at all
    lpReturnedString[0] = '\0';
    return 0;
  } else {
    boost::scoped_array<char> temp(new char[static_cast<size_t>(nSize)]);

    DWORD res = GetPrivateProfileStringA_reroute(lpAppName, lpKeyName, "DUMMY_VALUE",
                                                 temp.get(), nSize, modInfo->getTweakedIniA().c_str());

    if (strcmp(temp.get(), "DUMMY_VALUE") == 0) {
      std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);

      res = GetPrivateProfileStringA_reroute(lpAppName, lpKeyName, lpDefault,
                                             temp.get(), nSize, rerouteFilename.c_str());
    }

    strncpy(lpReturnedString, temp.get(), static_cast<size_t>(res + 1));

    return res;
  }
}


DWORD WINAPI GetPrivateProfileStringW_rep(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpDefault,
                                          LPWSTR lpReturnedString, DWORD nSize, LPCWSTR lpFileName)
{
  PROFILE();

  if (HookLock::isLocked()) return GetPrivateProfileStringW_reroute(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);

  if (lpFileName != NULL) {
    DWORD res = GetPrivateProfileStringW_reroute(lpAppName, lpKeyName, L"DUMMY_VALUE", lpReturnedString, nSize, modInfo->getTweakedIniW().c_str());
    if (wcscmp(lpReturnedString, L"DUMMY_VALUE") == 0) {
      std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
      res = GetPrivateProfileStringW_reroute(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, rerouteFilename.c_str());
    }
    return res;
  } else {
    return GetPrivateProfileStringW_reroute(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);
  }
}


BOOL WINAPI GetPrivateProfileStructA_rep(LPCSTR lpszSection, LPCSTR lpszKey, LPVOID lpStruct, UINT uSizeStruct, LPCSTR szFile)
{
  PROFILE();

  if (szFile != NULL) {
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(szFile);
    return GetPrivateProfileStructA_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileStructA_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, szFile);
  }
}


BOOL WINAPI GetPrivateProfileStructW_rep(LPCWSTR lpszSection, LPCWSTR lpszKey, LPVOID lpStruct, UINT uSizeStruct, LPCWSTR szFile)
{
  PROFILE();

  if (szFile != NULL) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(szFile);
    return GetPrivateProfileStructW_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileStructW_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, szFile);
  }
}


DWORD WINAPI GetPrivateProfileSectionNamesA_rep(LPSTR lpszReturnBuffer, DWORD nSize, LPCSTR lpFileName)
{
  PROFILE();

  if (lpFileName != NULL) {
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return GetPrivateProfileSectionNamesA_reroute(lpszReturnBuffer, nSize, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileSectionNamesA_reroute(lpszReturnBuffer, nSize, lpFileName);
  }
}


DWORD WINAPI GetPrivateProfileSectionNamesW_rep(LPWSTR lpszReturnBuffer, DWORD nSize, LPCWSTR lpFileName)
{
  PROFILE();
  if (lpFileName != NULL) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return GetPrivateProfileSectionNamesW_reroute(lpszReturnBuffer, nSize, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileSectionNamesW_reroute(lpszReturnBuffer, nSize, lpFileName);
  }
}


DWORD WINAPI GetPrivateProfileSectionA_rep(LPCSTR lpAppName, LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
  PROFILE();

  if (lpFileName != NULL) {
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return GetPrivateProfileSectionA_reroute(lpAppName, lpReturnedString, nSize, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileSectionA_reroute(lpAppName, lpReturnedString, nSize, lpFileName);
  }
}


DWORD WINAPI GetPrivateProfileSectionW_rep(LPCWSTR lpAppName, LPWSTR lpReturnedString, DWORD nSize, LPCWSTR lpFileName)
{
  PROFILE();

  if (lpFileName != NULL) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return GetPrivateProfileSectionW_reroute(lpAppName, lpReturnedString, nSize, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileSectionW_reroute(lpAppName, lpReturnedString, nSize, lpFileName);
  }
}


UINT WINAPI GetPrivateProfileIntA_rep(LPCSTR lpAppName, LPCSTR lpKeyName, INT nDefault, LPCSTR lpFileName)
{
  PROFILE();
  HookLock lock;

  if (lpFileName != NULL) {
    UINT res = GetPrivateProfileIntA_reroute(lpAppName, lpKeyName, INT_MAX, modInfo->getTweakedIniA().c_str());
    if (res == INT_MAX) {
      std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
      return GetPrivateProfileIntA_reroute(lpAppName, lpKeyName, nDefault, rerouteFilename.c_str());
    } else {
      return res;
    }
  } else {
    return GetPrivateProfileIntA_reroute(lpAppName, lpKeyName, nDefault, lpFileName);
  }
}


UINT WINAPI GetPrivateProfileIntW_rep(LPCWSTR lpAppName, LPCWSTR lpKeyName, INT nDefault, LPCWSTR lpFileName)
{
  PROFILE();

  HookLock lock; // on some (all?) systems, getprivateprofileint calls getprivateprofilestring

  if (lpFileName != NULL) {
    UINT res = GetPrivateProfileIntW_reroute(lpAppName, lpKeyName, INT_MAX, modInfo->getTweakedIniW().c_str());
    if (res == INT_MAX) {
      std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
      return GetPrivateProfileIntW_reroute(lpAppName, lpKeyName, nDefault, rerouteFilename.c_str());
    } else {
      return res;
    }
  } else {
    return GetPrivateProfileIntW_reroute(lpAppName, lpKeyName, nDefault, lpFileName);
  }
}


BOOL WINAPI WritePrivateProfileSectionA_rep(LPCSTR lpAppName, LPCSTR lpString, LPCSTR lpFileName)
{
  PROFILE();

  if (lpFileName != NULL) {
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return WritePrivateProfileSectionA_reroute(lpAppName, lpString, rerouteFilename.c_str());
  } else {
    return WritePrivateProfileSectionA_reroute(lpAppName, lpString, lpFileName);
  }
}


BOOL WINAPI WritePrivateProfileSectionW_rep(LPCWSTR lpAppName, LPCWSTR lpString, LPCWSTR lpFileName)
{
  PROFILE();

  if (lpFileName != NULL) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return WritePrivateProfileSectionW_reroute(lpAppName, lpString, rerouteFilename.c_str());
  } else {
    return WritePrivateProfileSectionW_reroute(lpAppName, lpString, lpFileName);
  }
}


BOOL WINAPI WritePrivateProfileStringA_rep(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString, LPCSTR lpFileName)
{
  PROFILE();

  if (lpFileName != NULL) {
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return WritePrivateProfileStringA_reroute(lpAppName, lpKeyName, lpString, rerouteFilename.c_str());
  } else {
    return WritePrivateProfileStringA_reroute(lpAppName, lpKeyName, lpString, lpFileName);
  }
}


BOOL WINAPI WritePrivateProfileStringW_rep(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpString, LPCWSTR lpFileName)
{
  PROFILE();

  if (lpFileName != NULL) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return WritePrivateProfileStringW_reroute(lpAppName, lpKeyName, lpString, rerouteFilename.c_str());
  } else {
    return WritePrivateProfileStringW_reroute(lpAppName, lpKeyName, lpString, lpFileName);
  }
}


BOOL WINAPI WritePrivateProfileStructA_rep(LPCSTR lpszSection, LPCSTR lpszKey, LPVOID lpStruct,
                                           UINT uSizeStruct, LPCSTR szFile)
{
  PROFILE();

  if (szFile != NULL) {
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(szFile);
    return WritePrivateProfileStructA_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, rerouteFilename.c_str());
  } else {
    return WritePrivateProfileStructA_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, szFile);
  }
}


BOOL WINAPI WritePrivateProfileStructW_rep(LPCWSTR lpszSection, LPCWSTR lpszKey, LPVOID lpStruct,
                                           UINT uSizeStruct, LPCWSTR szFile)
{
  PROFILE();

  if (szFile != NULL) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(szFile);
    return WritePrivateProfileStructW_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, rerouteFilename.c_str());
  } else {
    return WritePrivateProfileStructW_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, szFile);
  }
}


HFILE WINAPI OpenFile_rep(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle)
{
  PROFILE();

  std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
  LOGDEBUG("openfile called: %s -> %s", lpFileName, rerouteFilename.c_str());
  return OpenFile_reroute(rerouteFilename.c_str(), lpReOpenBuff, uStyle);
}

DWORD WINAPI GetCurrentDirectoryW_rep(DWORD nBufferLength, LPWSTR lpBuffer)
{
  PROFILE();

  std::wstring FakeCurrentDirectory = modInfo->getCurrentDirectory();
  if (FakeCurrentDirectory.length() != 0) {
    size_t len = std::min<size_t>(FakeCurrentDirectory.length(), nBufferLength - 1);
    wcsncpy(lpBuffer, FakeCurrentDirectory.c_str(), len);
    lpBuffer[len] = L'\0';
    return static_cast<DWORD>(FakeCurrentDirectory.length() + 1);
  } else {
    return ::GetCurrentDirectoryW_reroute(nBufferLength, lpBuffer);
  }
}

BOOL WINAPI SetCurrentDirectoryW_rep(LPCWSTR lpPathName)
{
  PROFILE();

  std::wstring reroutedPath = modInfo->getRerouteOpenExisting(lpPathName, true);
  if (modInfo->setCwd(lpPathName)) {
    std::wstring cwdRerouted;
    if (modInfo->getCurrentDirectory().empty()) {
      cwdRerouted = modInfo->getDataPathW();
    } else {
      cwdRerouted = modInfo->getRerouteOpenExisting(L".");
    }
    LOGDEBUG("set current directory a: %ls -> %ls", lpPathName, cwdRerouted.c_str());
    BOOL res = ::SetCurrentDirectoryW_reroute(cwdRerouted.c_str());

    return res;
  } else {
    LOGDEBUG("set current directory b: %ls -> %ls", lpPathName, reroutedPath.c_str());
    BOOL res = ::SetCurrentDirectoryW_reroute(reroutedPath.c_str());

    return res;
  }
}


BOOL WINAPI CopyFileW_rep(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists)
{
  PROFILE();

  WCHAR fullNewFileName[MAX_PATH];
  modInfo->getFullPathName(lpNewFileName, fullNewFileName, MAX_PATH);

  std::wstring rerouteNewFileName = fullNewFileName;

  bool reroutedToOverwrite = false;
  if (StartsWith(fullNewFileName, modInfo->getDataPathW().c_str())) {
    std::wostringstream temp;
    temp << GameInfo::instance().getOverwriteDir() << "\\" << (fullNewFileName + modInfo->getDataPathW().length());
    rerouteNewFileName = temp.str();

    std::wstring targetDirectory = rerouteNewFileName.substr(0, rerouteNewFileName.find_last_of(L"\\/"));
    CreateDirectoryRecursive(targetDirectory.c_str(), NULL);
    reroutedToOverwrite = true;
  }

  std::wstring rerouteExistingFileName =  modInfo->getRerouteOpenExisting(lpExistingFileName);
  LOGDEBUG("copy file: %ls -> %ls", rerouteExistingFileName.c_str(), rerouteNewFileName.c_str());

  BOOL result = ::CopyFileW_reroute(rerouteExistingFileName.c_str(), rerouteNewFileName.c_str(), bFailIfExists);
  if (reroutedToOverwrite) {
    modInfo->addOverwriteFile(rerouteNewFileName);
  }
  return result;
}


BOOL WINAPI CopyFileA_rep(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists)
{
  PROFILE();

  LOGDEBUG("copy file (a): %s -> %s", lpExistingFileName, lpNewFileName);

  return CopyFileW_rep(ToWString(lpExistingFileName, false).c_str(), ToWString(lpNewFileName, false).c_str(), bFailIfExists);
}


BOOL WINAPI CreateHardLinkW_rep(LPCWSTR lpFileName, LPCWSTR lpExistingFileName,
                                LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
  PROFILE();

  WCHAR fullNewFileName[MAX_PATH];
  modInfo->getFullPathName(lpFileName, fullNewFileName, MAX_PATH);

  std::wstring rerouteNewFileName = fullNewFileName;

  bool reroutedToOverwrite = false;
  if (StartsWith(fullNewFileName, modInfo->getDataPathW().c_str())) {
    std::wostringstream temp;
    temp << GameInfo::instance().getOverwriteDir() << "\\" << (fullNewFileName + modInfo->getDataPathW().length());
    rerouteNewFileName = temp.str();

    std::wstring targetDirectory = rerouteNewFileName.substr(0, rerouteNewFileName.find_last_of(L"\\/"));
    CreateDirectoryRecursive(targetDirectory.c_str(), NULL);
    reroutedToOverwrite = true;
  }

  std::wstring rerouteExistingFileName =  modInfo->getRerouteOpenExisting(lpExistingFileName);

  BOOL result = false;

  int sourceID = ::PathGetDriveNumberW(rerouteExistingFileName.c_str());
  int destID = ::PathGetDriveNumberW(rerouteNewFileName.c_str());

  wchar_t fsName[10];
  memset(fsName, '\0', 10 * sizeof(wchar_t));
  if (destID != -1) {
    wchar_t driveRoot[4];
    _snwprintf(driveRoot, 4, L"%c:\\", 'A' + destID);
    ::GetVolumeInformationW(driveRoot, NULL, 0, NULL, NULL, NULL, fsName, 10);
  }

  if ((sourceID == destID) && (sourceID != -1) && (wcsncmp(fsName, L"NTFS", 10) == 0)) {
    LOGDEBUG("link file: %ls -> %ls", rerouteExistingFileName.c_str(), rerouteNewFileName.c_str());
    ::CreateHardLinkW_reroute(rerouteNewFileName.c_str(), rerouteExistingFileName.c_str(), lpSecurityAttributes);
  } else {
    LOGDEBUG("copy file (link impossible): %ls -> %ls", rerouteExistingFileName.c_str(), rerouteNewFileName.c_str());
    ::CopyFileW_reroute(rerouteExistingFileName.c_str(), rerouteNewFileName.c_str(), false);
  }

  if (reroutedToOverwrite) {
    modInfo->addOverwriteFile(rerouteNewFileName);
  }
  return result;
}


BOOL WINAPI CreateHardLinkA_rep(LPCSTR lpFileName, LPCSTR lpExistingFileName,
                                LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
  PROFILE();

  LOGDEBUG("link file (a): %s -> %s", lpExistingFileName, lpFileName);

  return CreateHardLinkW_rep(ToWString(lpFileName, false).c_str(), ToWString(lpExistingFileName, false).c_str(), lpSecurityAttributes);
}


DWORD WINAPI GetFullPathNameW_rep(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart)
{
  PROFILE();
  if (modInfo->getCurrentDirectory().length() != 0) {
    WCHAR cwd[MAX_PATH];
    DWORD cwdLength = ::GetCurrentDirectoryW_reroute(MAX_PATH, cwd);
    if (StartsWith(lpFileName, cwd)) {
      WCHAR temp[MAX_PATH];
      ::PathCombineW(temp, modInfo->getCurrentDirectory().c_str(), lpFileName + static_cast<size_t>(cwdLength) + 1);
      size_t count = std::min<size_t>(nBufferLength - 1, wcslen(temp));
      wcsncpy(lpBuffer, temp, count);
      lpBuffer[count] = L'\0';
      if (lpFilePart != NULL) {
        *lpFilePart = GetBaseName(lpBuffer);
        if (**lpFilePart == L'\0') {
          // lpBuffer is a directory
          *lpFilePart = NULL;
        }
      }
      return count;
    } else if (::PathIsRelativeW(lpFileName)) {
      WCHAR temp[MAX_PATH];

      ::PathCombineW(temp, modInfo->getCurrentDirectory().c_str(), lpFileName);
      WCHAR temp2[MAX_PATH];
      size_t count = 0UL;
      if (::PathCanonicalizeW(temp2, temp)) {
        count = std::min<size_t>(nBufferLength - 1, wcslen(temp2));
        wcsncpy(lpBuffer, temp2, count);
      } else {
        Logger::Instance().error("failed to canonicalize path %ls", temp);
        count = std::min<size_t>(nBufferLength - 1, wcslen(temp));
        wcsncpy(lpBuffer, temp, count);
      }
      if (lpFilePart != NULL) {
        *lpFilePart = GetBaseName(lpBuffer);
        if (**lpFilePart == L'\0') {
          // lpBuffer is a directory
          *lpFilePart = NULL;
        }
      }
      return count;
    } else {
      return ::GetFullPathNameW_reroute(lpFileName, nBufferLength, lpBuffer, lpFilePart);
    }
  } else {
    return ::GetFullPathNameW_reroute(lpFileName, nBufferLength, lpBuffer, lpFilePart);
  }
}


int STDAPICALLTYPE SHFileOperationW_rep(LPSHFILEOPSTRUCTW lpFileOp)
{
  PROFILE();

  SHFILEOPSTRUCTW newOp;
  newOp.hwnd = lpFileOp->hwnd;
  newOp.wFunc = lpFileOp->wFunc;
  newOp.fFlags = lpFileOp->fFlags;
  newOp.fAnyOperationsAborted = lpFileOp->fAnyOperationsAborted;
  newOp.hNameMappings = lpFileOp->hNameMappings;
  newOp.lpszProgressTitle = lpFileOp->lpszProgressTitle;
  std::vector<wchar_t> newFrom;
  LPCWSTR pos = lpFileOp->pFrom;
  for (;;) {
    if (*pos == L'\0') break;

    std::wstring rerouted = modInfo->getRerouteOpenExisting(pos);
    newFrom.insert(newFrom.end(), rerouted.begin(), rerouted.end());
    newFrom.push_back(L'\0');
    pos += wcslen(pos) + 1;
  }
  newFrom.push_back(L'\0');

  newOp.pFrom = &newFrom[0];

  std::vector<wchar_t> newTo;
  if (lpFileOp->pTo != NULL) {
    pos = lpFileOp->pTo;
    for (;;) {
      if (*pos == L'\0') break;

      std::wstring rerouteFilename;
      if ((wcslen(pos) == modInfo->getDataPathW().length()) &&
          (wcscmp(pos, modInfo->getDataPathW().c_str()) == 0)) {
        rerouteFilename = GameInfo::instance().getOverwriteDir();
      } else if (StartsWith(pos, modInfo->getDataPathW().c_str()) && !::FileExists(pos)) {
        std::wostringstream temp;
        temp << GameInfo::instance().getOverwriteDir() << "\\" << (pos + modInfo->getDataPathW().length());
        rerouteFilename = temp.str();

        std::wstring targetDirectory = rerouteFilename.substr(0, rerouteFilename.find_last_of(L"\\/"));
        CreateDirectoryRecursive(targetDirectory.c_str(), NULL);
        modInfo->addOverwriteFile(rerouteFilename);
      } else {
        rerouteFilename = modInfo->getRerouteOpenExisting(pos);
      }
      newTo.insert(newTo.end(), rerouteFilename.begin(), rerouteFilename.end());
      newTo.push_back(L'\0');
      pos += wcslen(pos) + 1;
    }
    newTo.push_back(L'\0');

    newOp.pTo = &newTo[0];
  } else {
    newOp.pTo = NULL;
  }

  LOGDEBUG("sh file operation %d: %ls - %ls", newOp.wFunc, newOp.pFrom,
           newOp.pTo != NULL ? newOp.pTo : L"NULL");
  return SHFileOperationW_reroute(&newOp);
}

BOOL WINAPI GetFileVersionInfoExW_rep(DWORD dwFlags, LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
  PROFILE();

  WCHAR temp[MAX_PATH];
  modInfo->getFullPathName(lptstrFilename, temp, MAX_PATH);

  std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(temp, false, NULL);

  LOGDEBUG("get file version ex w %ls -> %ls", lptstrFilename, rerouteFilename.c_str());

  return GetFileVersionInfoExW_reroute(dwFlags, rerouteFilename.c_str(), dwHandle, dwLen, lpData);
}

DWORD WINAPI GetFileVersionInfoSizeW_rep(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
  PROFILE();

  WCHAR temp[MAX_PATH];
  modInfo->getFullPathName(lptstrFilename, temp, MAX_PATH);

  std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(temp, false, NULL);

  LOGDEBUG("get file version size %ls -> %ls", lptstrFilename, rerouteFilename.c_str());

  return GetFileVersionInfoSizeW_reroute(rerouteFilename.c_str(), lpdwHandle);
}


DWORD WINAPI GetModuleFileNameW_rep(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
  PROFILE();

  DWORD res = GetModuleFileNameW_reroute(hModule, lpFilename, nSize);
  if (res != 0) {
    bool isRerouted = false;
    std::wstring rerouted = modInfo->reverseReroute(lpFilename, &isRerouted);
    if (isRerouted) {
      LOGDEBUG("get module file name %ls -> %ls", lpFilename, rerouted.c_str());
      DWORD len = (std::min<DWORD>)(rerouted.size(), nSize - 1);
      _wcsnset(lpFilename, L'\0', len + 1);
      wcsncpy(lpFilename, rerouted.c_str(), len);
      res = len;
      if (rerouted.size() > nSize) {
        ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
      }
    }
  }
  return res;
}



std::vector<ApiHook*> hooks;


#define INITHOOK(module, functionname) { ApiHook* temp = new ApiHook(module, #functionname, (void*)&functionname ## _rep); \
  functionname ## _reroute = reinterpret_cast<functionname ## _type>(temp->GetReroute()); \
  hooks.push_back(temp); }


void InitPaths()
{
}


BOOL InitHooks()
{
  LPCTSTR module = ::GetModuleHandle(TEXT("kernelbase.dll")) != NULL ? TEXT("kernelbase.dll") : TEXT("kernel32");
  try {
    INITHOOK(TEXT("kernel32.dll"), CreateProcessA);
    INITHOOK(TEXT("kernel32.dll"), CreateProcessW);
    INITHOOK(TEXT("kernel32.dll"), LoadLibraryExW);
    INITHOOK(TEXT("kernel32.dll"), LoadLibraryW);
    INITHOOK(TEXT("kernel32.dll"), LoadLibraryExA);
    INITHOOK(TEXT("kernel32.dll"), LoadLibraryA);
    INITHOOK(module, FindFirstFileExW);
    INITHOOK(module, FindNextFileW);
    INITHOOK(module, FindClose);
    INITHOOK(module, GetFileAttributesW);
    INITHOOK(module, GetFileAttributesExW);
    INITHOOK(module, SetFileAttributesW);
    INITHOOK(module, CreateFileW);
    INITHOOK(module, CreateFileA);
    INITHOOK(module, CreateDirectoryW);
    INITHOOK(module, DeleteFileW);
    INITHOOK(module, DeleteFileA);
    INITHOOK(module, CloseHandle);
    INITHOOK(module, GetCurrentDirectoryW);
    INITHOOK(module, SetCurrentDirectoryW);
    INITHOOK(TEXT("kernel32.dll"), MoveFileA);
    INITHOOK(TEXT("kernel32.dll"), MoveFileExA);
    INITHOOK(TEXT("kernel32.dll"), MoveFileW);
    INITHOOK(TEXT("kernel32.dll"), MoveFileExW);
    INITHOOK(TEXT("kernel32.dll"), GetPrivateProfileStringA);
    INITHOOK(TEXT("kernel32.dll"), GetPrivateProfileStringW);
    INITHOOK(TEXT("kernel32.dll"), GetPrivateProfileStructA);
    INITHOOK(TEXT("kernel32.dll"), GetPrivateProfileStructW);
    INITHOOK(TEXT("kernel32.dll"), GetPrivateProfileSectionNamesA);
    INITHOOK(TEXT("kernel32.dll"), GetPrivateProfileSectionNamesW);
    INITHOOK(TEXT("kernel32.dll"), GetPrivateProfileSectionA);
    INITHOOK(TEXT("kernel32.dll"), GetPrivateProfileSectionW);
    INITHOOK(TEXT("kernel32.dll"), GetPrivateProfileIntA);
    INITHOOK(TEXT("kernel32.dll"), GetPrivateProfileIntW);
    INITHOOK(TEXT("kernel32.dll"), WritePrivateProfileSectionA);
    INITHOOK(TEXT("kernel32.dll"), WritePrivateProfileSectionW);
    INITHOOK(TEXT("kernel32.dll"), WritePrivateProfileStringA);
    INITHOOK(TEXT("kernel32.dll"), WritePrivateProfileStringW);
    INITHOOK(TEXT("kernel32.dll"), WritePrivateProfileStructA);
    INITHOOK(TEXT("kernel32.dll"), WritePrivateProfileStructW);
    INITHOOK(TEXT("kernel32.dll"), OpenFile);
    INITHOOK(TEXT("kernel32.dll"), CopyFileA);
    INITHOOK(TEXT("kernel32.dll"), CopyFileW);
    INITHOOK(TEXT("kernel32.dll"), CreateHardLinkA);
    INITHOOK(TEXT("kernel32.dll"), CreateHardLinkW);
    INITHOOK(TEXT("kernel32.dll"), GetFullPathNameW);
    INITHOOK(TEXT("kernel32.dll"), GetModuleFileNameW);
    INITHOOK(TEXT("Shell32.dll"), SHFileOperationW);
    INITHOOK(TEXT("version.dll"), GetFileVersionInfoExW);
    INITHOOK(TEXT("version.dll"), GetFileVersionInfoSizeW);

    LOGDEBUG("all hooks installed");

  } catch (const std::exception& E) {
    Logger::Instance().error("Exception: %s", E.what());
    return FALSE;
  }

  return TRUE;
}


std::string FromHex(const char *string)
{
  std::string result;
  size_t length = strlen(string);
  if (length % 2 != 0) {
    Logger::Instance().error("invald length in hex string: %s", string);
    return result;
  }
  for (size_t i = 0; i < length; i += 2) {
    char temp[3];
    strncpy(temp, string + i, 2);
    temp[2] = '\0';
    char res = (char)strtol(temp, NULL, 16);
    result += res;
  }
  return result;
}


std::wstring iniDecode(const char *stringEncoded)
{
  std::string resultUTF8;
  int tPos = 0;
  for (const char *pntPtr = stringEncoded; *pntPtr != '\0'; ++pntPtr) {
    if (strncmp(pntPtr, "\\x", 2) == 0) {
      pntPtr += 2;
      int numeric = strtol(pntPtr, NULL, 16);
      resultUTF8.push_back(static_cast<char>(numeric));
      ++tPos;
      ++pntPtr;
    } else {
      resultUTF8.push_back(*pntPtr);
      ++tPos;
    }
  }
  return ToWString(resultUTF8, true);
}


BOOL SetUp(const std::wstring &iniName, const wchar_t *profileNameIn)
{
  std::wstring profileName;
  if (profileNameIn[0] == '\0') {
    // we need to figure out the correct profile from the ini file
    // for some reason, neither the A nor the W function decodes non-ascii symbols
    wchar_t profileNameW[256];
    ::GetPrivateProfileStringW(L"General", L"selected_profile", L"", profileNameW, 256, iniName.c_str());
    // profilenamew is assumed to be ascii-only
    profileName = iniDecode(ToString(profileNameW, true).c_str());
  } else {
    profileName = profileNameIn;
  }

  wchar_t modDirectory[MAX_PATH];
  {
    wchar_t temp[MAX_PATH];
    ::GetPrivateProfileStringW(L"Settings", L"mod_directory", GameInfo::instance().getModsDir().c_str(), temp, MAX_PATH, iniName.c_str());
    std::wostringstream profileDir;
    profileDir << GameInfo::instance().getProfilesDir() << "\\" << profileName;
    if (!FileExists(profileDir.str())) {
      Logger::Instance().error("profile not found at %ls", profileDir.str().c_str());
      return FALSE;
    }

    Canonicalize(modDirectory, temp);

    if (!FileExists(modDirectory)) {
      Logger::Instance().error("mod directory not found at %ls", temp);
      return FALSE;
    }
  }

  std::vector<std::wstring> iniFiles = GameInfo::instance().getIniFileNames();
  for (auto iter = iniFiles.begin(); iter != iniFiles.end(); ++iter) {
    iniFilesA.insert(ToString(ToLower(*iter), false));
  }

  Logger::Instance().info("using profile %ls", profileName.c_str());

  modInfo = new ModInfo(profileName, modDirectory, true);

  LOGDEBUG("data path: %ls", modInfo->getDataPathW().c_str());

  return TRUE;
}


void nextShortName(char *nameBuffer)
{
  ++nameBuffer[2];
  if (nameBuffer[2] > 'z') {
    ++nameBuffer[1];
    nameBuffer[2] = 'a';
  }
  if (nameBuffer[1] > 'z') {
    ++nameBuffer[0];
    nameBuffer[1] = 'a';
  }
}


BOOL SetUpBSAMap()
{
  std::wostringstream archiveFileName;
  archiveFileName << GameInfo::instance().getProfilesDir() << L"\\" << modInfo->getProfileName() << L"\\archives.txt";

  std::fstream file(archiveFileName.str().c_str());
  if (!file.is_open()) {
    Logger::Instance().error("archive \"%ls\" not found!", archiveFileName.str().c_str());
    return FALSE;
  }

  char shortName[4];
  memset(shortName, 'a', 3);
  shortName[3] = '\0';

  char buffer[1024];

  bool first = true;

  while (!file.eof()) {
    file.getline(buffer, 1024);
    if (buffer[0] == '\0') {
      continue;
    }
//    bsaList.insert(ToLower(std::string(buffer)));

    Logger::Instance().info("\"%s\" maps to \"%s\"", shortName, buffer);
    bsaMap[shortName] = buffer;
    if (!first) {
      bsaResourceList.append(",");
    } else {
      first = false;
    }
    bsaResourceList.append(shortName);
    nextShortName(shortName);
  }
  file.close();
  Logger::Instance().info("resource list: %s", bsaResourceList.c_str());

  return TRUE;
}


void RemoveHooks()
{
  for (std::vector<ApiHook*>::iterator iter = hooks.begin(); iter != hooks.end(); ++iter) {
    delete *iter;
  }
  hooks.clear();
  LOGDEBUG("hooks removed");
}


LONG WINAPI VEHandler(PEXCEPTION_POINTERS exceptionPtrs)
{
/*  if ((exceptionPtrs->ExceptionRecord->ExceptionFlags != EXCEPTION_NONCONTINUABLE) ||
      (exceptionPtrs->ExceptionRecord->ExceptionCode == 0xe06d7363)) {
    // don't want to break on non-critical exceptions. 0xe06d7363 indicates a C++ exception. why are those marked non-continuable?
    return EXCEPTION_CONTINUE_SEARCH;
  }*/

  if (exceptionPtrs->ExceptionRecord->ExceptionCode != 0xC0000005) {
    // don't want to break on non-critical errors. The above block didn't work well, crashes
    // happened for exceptions that wouldn't have been a problem
    return EXCEPTION_CONTINUE_SEARCH;
  }

  Logger::Instance().error("Windows Exception (%x). Last hooked call: %s", exceptionPtrs->ExceptionRecord->ExceptionCode, s_LastFunction);
  RemoveHooks();

  typedef BOOL (WINAPI *FuncMiniDumpWriteDump)(HANDLE process, DWORD pid, HANDLE file, MINIDUMP_TYPE dumpType,
                                               const PMINIDUMP_EXCEPTION_INFORMATION exceptionParam,
                                               const PMINIDUMP_USER_STREAM_INFORMATION userStreamParam,
                                               const PMINIDUMP_CALLBACK_INFORMATION callbackParam);
  HMODULE dbgDLL = ::LoadLibraryW_reroute(L"dbghelp.dll");

  static const int errorLen = 200;
  char errorBuffer[errorLen + 1];
  memset(errorBuffer, '\0', errorLen + 1);

  if (dbgDLL) {
    FuncMiniDumpWriteDump funcDump = (FuncMiniDumpWriteDump)::GetProcAddress(dbgDLL, "MiniDumpWriteDump");
    if (funcDump) {
      wchar_t dmpPath[MAX_PATH_UNICODE];
      ::GetModuleFileNameW(dllModule, dmpPath, MAX_PATH_UNICODE);
      wcscat(dmpPath, L".dmp");

      HANDLE dumpFile = ::CreateFileW_reroute(dmpPath,
                                     GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
      if (dumpFile != INVALID_HANDLE_VALUE) {
        _MINIDUMP_EXCEPTION_INFORMATION exceptionInfo;
        exceptionInfo.ThreadId = ::GetCurrentThreadId();
        exceptionInfo.ExceptionPointers = exceptionPtrs;
        exceptionInfo.ClientPointers = NULL;

        BOOL success = funcDump(::GetCurrentProcess(), ::GetCurrentProcessId(), dumpFile, MiniDumpNormal, &exceptionInfo, NULL, NULL);

        ::CloseHandle(dumpFile);
        if (success) {
          Logger::Instance().error("Crash dump created as %ls. Please send this file to the developer of MO", dmpPath);
        } else {
          Logger::Instance().error("No crash dump created, errorcode: %lu", ::GetLastError());
        }
      } else {
        Logger::Instance().error("No crash dump created, failed to open %ls for writing", dmpPath);
      }
    } else {
      Logger::Instance().error("No crash dump created, dbghelp.dll invalid");
    }
  } else {
    Logger::Instance().error("No crash dump created, dbghelp.dll not found");
  }

  ::RemoveVectoredExceptionHandler(exceptionHandler);

  return EXCEPTION_CONTINUE_SEARCH;
}


BOOL Init(int logLevel, const wchar_t *profileName)
{
  if (modInfo != NULL) {
    // already initialised
    return TRUE;
  }

  sLogLevel = logLevel;

  wchar_t mutexName[100];
  _snwprintf(mutexName, 100, L"mo_dll_%d", ::GetCurrentProcessId());
  instanceMutex = ::CreateMutexW(NULL, FALSE, mutexName);
  if ((instanceMutex == NULL) || (::GetLastError() == ERROR_ALREADY_EXISTS)) {
    return TRUE;
  }

  wchar_t moPath[MAX_PATH_UNICODE];
  ::GetModuleFileNameW(dllModule, moPath, MAX_PATH_UNICODE);
  wchar_t *temp = wcsrchr(moPath, L'\\');
  if (temp != NULL) {
    *temp = L'\0';
  } else {
    MessageBox(NULL, TEXT("failed to determine mo path"), TEXT("initialisation failed"), MB_OK);
    return TRUE;
  }

  // initialised once we know where mo is installed
  std::wostringstream iniName;
  try {
    {
      // if a file called mo_path exists in the same directory as the dll, it overrides the
      // path to the mod organizer
      std::string hintFileName = ToString(moPath, false);
      hintFileName.append("\\mo_path.txt");
      std::wifstream hintFile(hintFileName.c_str(), std::ifstream::in);
      if (hintFile.is_open()) {
        hintFile.getline(moPath, MAX_PATH_UNICODE);
        hintFile.close();
      }
    }

    iniName << moPath << "\\modorganizer.ini";

    wchar_t pathTemp[MAX_PATH];
    wchar_t gamePath[MAX_PATH];
    ::GetPrivateProfileStringW(L"General", L"gamePath", L"", pathTemp, MAX_PATH, iniName.str().c_str());
    Canonicalize(gamePath, iniDecode(ToString(pathTemp, false).c_str()).c_str());

    if (!GameInfo::init(moPath, gamePath)) {
      throw std::runtime_error("game not found");
    }
  } catch (const std::exception &e) {
    MessageBoxA(NULL, e.what(), "initialisation failed", MB_OK);
    return TRUE;
  }

  InitPaths();

  std::wstring logFile = GameInfo::instance().getLogDir().append(L"\\").append(AppConfig::logFile());
#ifdef UNICODE
  Logger::Init(logFile.c_str(), logLevel);
#else
  Logger::Init(ToString(logFile, false).c_str(), logLevel);
#endif

  exceptionHandler = ::AddVectoredExceptionHandler(0, VEHandler);

  OSVERSIONINFOEX versionInfo;
  ZeroMemory(&versionInfo, sizeof(OSVERSIONINFOEX));
  versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
  ::GetVersionEx((OSVERSIONINFO*)&versionInfo);
  Logger::Instance().info("Windows %d.%d (%s)", versionInfo.dwMajorVersion, versionInfo.dwMinorVersion, versionInfo.wProductType == VER_NT_WORKSTATION ? "workstation" : "server");
  ::GetModuleFileNameW(dllModule, moPath, MAX_PATH_UNICODE);
  VS_FIXEDFILEINFO version = GetFileVersion(moPath);
  Logger::Instance().info("hook.dll v%d.%d.%d",
                          version.dwFileVersionMS >> 16,
                          version.dwFileVersionMS & 0xFFFF,
                          version.dwFileVersionLS >> 16);

  Logger::Instance().info("Code page: %ld", GetACP());

  wchar_t filename[MAX_PATH];
  ::GetModuleFileNameW(NULL, filename, MAX_PATH);
  Logger::Instance().info("injecting to %ls", filename);

  if (!SetUp(iniName.str(), profileName)) {
    Logger::Instance().error("failed to set up");
    return FALSE;
  }

  {
    std::wstring filenameTemp(filename);
    size_t pos = filenameTemp.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
      modInfo->addAlternativePath(filenameTemp.substr(0, pos));
    }
  }
  if (!SetUpBSAMap()) {
    Logger::Instance().error("failed to set up list of bsas");
    return FALSE;
  }

  {
    wchar_t cwd[MAX_PATH];
    ::GetCurrentDirectoryW(MAX_PATH, cwd);
    Logger::Instance().info("working directory: %ls", cwd);
    modInfo->setCwd(cwd);
  }

  if (!InitHooks()) {
    Logger::Instance().info("failed to install hooks");
    return FALSE;
  }

  Logger::Instance().info("injection done");
  return TRUE;
}


BOOL APIENTRY DllMain(HMODULE module,
                      DWORD  reasonForCall,
                      LPVOID)
{
  switch (reasonForCall) {
    case DLL_PROCESS_ATTACH: {
      dllModule = module;
    } break;
    case DLL_PROCESS_DETACH: {
      RemoveHooks();
      //TProfile::displayProfile();

//      delete modInfo;
    } break;
	  case DLL_THREAD_ATTACH: {
    } break;
	  case DLL_THREAD_DETACH: {
    } break;
	}
	return TRUE;
}


extern "C" {

__declspec(dllexport) bool OBSEPlugin_Load(const OBSEInterface*)
{
  if (Logger::IsInitialised()) {
    Logger::Instance().info("loaded by obse");
  }

  return Init(Logger::LEVEL_INFO, L"") == TRUE;
}

__declspec(dllexport) bool OBSEPlugin_Query(const OBSEInterface*, PluginInfo* info)
{
  info->infoVersion = 1;
  info->name = "ModOrganizer";
  info->version = 1;
  return true;
}


__declspec(dllexport) bool FOSEPlugin_Load(const OBSEInterface*)
{
  if (Logger::IsInitialised()) {
    Logger::Instance().info("loaded by fose");
  }

  return Init(Logger::LEVEL_INFO, L"") == TRUE;
}

__declspec(dllexport) bool FOSEPlugin_Query(const OBSEInterface*, PluginInfo* info)
{
  info->infoVersion = 1;
  info->name = "ModOrganizer";
  info->version = 1;
  return true;
}

__declspec(dllexport) bool NVSEPlugin_Load(const OBSEInterface*)
{
  if (Logger::IsInitialised()) {
    Logger::Instance().info("loaded by nvse");
  }

  return Init(Logger::LEVEL_INFO, L"") == TRUE;
}

__declspec(dllexport) bool NVSEPlugin_Query(const OBSEInterface*, PluginInfo* info)
{
  info->infoVersion = 1;
  info->name = "ModOrganizer";
  info->version = 1;
  return true;
}

__declspec(dllexport) bool SKSEPlugin_Load(const OBSEInterface*)
{
  if (Logger::IsInitialised()) {
    Logger::Instance().info("loaded by skse");
  }

  return Init(Logger::LEVEL_INFO, L"") == TRUE;
}

__declspec(dllexport) bool SKSEPlugin_Query(const OBSEInterface*, PluginInfo* info)
{
  info->infoVersion = 1;
  info->name = "ModOrganizer";
  info->version = 1;
  return true;
}

};
