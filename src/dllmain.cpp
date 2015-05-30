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
#include <boost/assign.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/thread/mutex.hpp>
#include <Shellapi.h>
#include <Psapi.h>
#include <tuple>
#ifdef LEAK_CHECK_WITH_VLD
#include <vld.h>
#endif // LEAK_CHECK_WITH_VLD



#include <Windows.h>
#include <Shlwapi.h>
#include <ShlObj.h>

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
SHFileOperationA_type SHFileOperationA_reroute = SHFileOperationA;
SHFileOperationW_type SHFileOperationW_reroute = SHFileOperationW;
GetFileVersionInfoW_type GetFileVersionInfoW_reroute = GetFileVersionInfoW;
GetFileVersionInfoExW_type GetFileVersionInfoExW_reroute = nullptr; // not available on windows xp
GetFileVersionInfoSizeW_type GetFileVersionInfoSizeW_reroute = GetFileVersionInfoSizeW;
GetModuleFileNameA_type GetModuleFileNameA_reroute = GetModuleFileNameA;
GetModuleFileNameW_type GetModuleFileNameW_reroute = GetModuleFileNameW;

NtQueryDirectoryFile_type NtQueryDirectoryFile_reroute;


ModInfo *modInfo = nullptr;

std::map<std::pair<int, DWORD>, bool> skipMap;

std::string bsaResourceList;
std::map<std::string, std::string> bsaMap;
std::set<std::string> usedBSAList;

std::set<std::string> iniFilesA;

// processes we never want to hook
std::set<std::string> processBlacklist;

static const int MAX_PATH_UNICODE = 256;

HANDLE instanceMutex = INVALID_HANDLE_VALUE;
HMODULE dllModule = nullptr;
PVOID exceptionHandler = nullptr;

boost::mutex queryMutex;
std::map<HANDLE, std::wstring> directoryCFHandles;
std::map<HANDLE, std::deque<std::vector<uint8_t>>> qdfData;

std::map<std::wstring, std::wstring> tweakedIniValues;

int sLogLevel = 0;
bool winXP = false;


#pragma message("the privatestring-hook is not functional with a debug build. should fix that")
#if defined(DEBUG) || !defined(_MSC_VER)
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
  bool blacklisted = false;

  if (lpApplicationName != nullptr) {
    char buffer[MAX_PATH];
    LPSTR filePart = nullptr;
    if ((::GetFullPathNameA(lpApplicationName, MAX_PATH, buffer, &filePart) != 0) && (filePart != nullptr)) {
      for (char *pos = filePart; *pos != '\0'; ++pos) {
        *pos = tolower(*pos);
      }
      if (processBlacklist.find(filePart) != processBlacklist.end()) {
        blacklisted = true;
      }
    }
  }

  LOGDEBUG("create process (a) %s - %s (in %s) - %s",
           lpApplicationName != nullptr ? lpApplicationName : "null",
           lpCommandLine != nullptr ? lpCommandLine : "null",
           lpCurrentDirectory != nullptr ? lpCurrentDirectory : "null",
           blacklisted ? "NOT hooking" : "hooking");

  std::string reroutedCwd;
  if (lpCurrentDirectory != nullptr) {
    reroutedCwd = modInfo->getRerouteOpenExisting(lpCurrentDirectory);
  }

  if (!::CreateProcessA_reroute(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, flags, lpEnvironment,
        lpCurrentDirectory != nullptr ? reroutedCwd.c_str() : nullptr,
        lpStartupInfo, lpProcessInformation)) {
    LOGDEBUG("process failed to start (%lu)", ::GetLastError());
    return FALSE;
  }

  try {
    if (!blacklisted) {
      char hookPath[MAX_PATH];
      ::GetModuleFileNameA(dllModule, hookPath, MAX_PATH);
      injectDLL(lpProcessInformation->hProcess, lpProcessInformation->hThread,
                hookPath, modInfo->getProfileName(), sLogLevel);
    }
  } catch (const std::exception &e) {
    Logger::Instance().error("failed to inject into %s: %s", lpApplicationName, e.what());
  }

  if (!susp && (::ResumeThread(lpProcessInformation->hThread) == (DWORD)-1)) {
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

  BOOL susp = dwCreationFlags & CREATE_SUSPENDED;
  DWORD flags = dwCreationFlags | CREATE_SUSPENDED;
  bool blacklisted = false;

  if (lpApplicationName != nullptr) {
    wchar_t buffer[MAX_PATH];
    LPWSTR filePart = nullptr;
    if ((::GetFullPathNameW(lpApplicationName, MAX_PATH, buffer, &filePart) != 0) && (filePart != nullptr)) {
      for (wchar_t *pos = filePart; *pos != L'\0'; ++pos) {
        *pos = tolower(*pos);
      }
      if (processBlacklist.find(ToString(filePart, true)) != processBlacklist.end()) {
        blacklisted = true;
      }
    }
  }

  LOGDEBUG("create process (w) %ls - %ls (in %ls) - %s",
           lpApplicationName != nullptr ? lpApplicationName : L"null",
           lpCommandLine != nullptr ? lpCommandLine : L"null",
           lpCurrentDirectory != nullptr ? lpCurrentDirectory : L"null",
           blacklisted ? "NOT hooking" : "hooking");

  std::wstring reroutedApplicationName;
  if (lpApplicationName != nullptr) {
    reroutedApplicationName = modInfo->getRerouteOpenExisting(lpApplicationName);
    lpApplicationName = reroutedApplicationName.c_str();
  }

  std::wstring reroutedCwd;
  if (lpCurrentDirectory != nullptr) {
    reroutedCwd = modInfo->getRerouteOpenExisting(lpCurrentDirectory);
  }

  if (!::CreateProcessW_reroute(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, flags, lpEnvironment,
        lpCurrentDirectory != nullptr ? reroutedCwd.c_str() : nullptr,
        lpStartupInfo, lpProcessInformation)) {
    LOGDEBUG("process failed to start (%lu)", ::GetLastError());
    return FALSE;
  }

  try {
    if (!blacklisted) {
      char hookPath[MAX_PATH];
      ::GetModuleFileNameA(dllModule, hookPath, MAX_PATH);
      injectDLL(lpProcessInformation->hProcess, lpProcessInformation->hThread,
                hookPath, modInfo->getProfileName(), sLogLevel);
    }
  } catch (const std::exception &e) {
    Logger::Instance().error("failed to inject into %ls: %s", lpApplicationName, e.what());
  }

  if (!susp && (::ResumeThread(lpProcessInformation->hThread) == (DWORD)-1)) {
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
  return LoadLibraryExW_rep(ToWString(lpFileName, false).c_str(), hFile, dwFlags);
}


HMODULE WINAPI LoadLibraryA_rep(LPCSTR lpFileName)
{
  PROFILE();
  return LoadLibraryW_rep(ToWString(lpFileName, false).c_str());
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

  WCHAR fullFileNameBuf[MAX_PATH];
  LPWSTR fullFileName = fullFileNameBuf;
  memset(fullFileName, '\0', MAX_PATH * sizeof(WCHAR));
  modInfo->getFullPathName(lpFileName, fullFileName, MAX_PATH);
  modInfo->checkPathAlternative(fullFileName);

  if (StartsWith(fullFileName, L"\\\\?\\")) {
    fullFileName = fullFileName + 4;
  }

  bool rerouted = false;
  // newly created files in the data directory go to overwrite
  if (((dwCreationDisposition == CREATE_ALWAYS)
       || (dwCreationDisposition == CREATE_NEW)
       || (dwCreationDisposition == OPEN_ALWAYS)
       )
      && (PathStartsWith(fullFileName, modInfo->getDataPathW().c_str()))) {
    // need to check if the file exists. If it does, act on the existing file, otherwise the behaviour is not transparent
    // if the regular call causes an error message and rerouted to overwrite
    rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName, false, &rerouted);
    if (!rerouted && !FileExists_reroute(lpFileName)) {
      rerouteFilename = modInfo->getOverwritePath() + L"\\" + (fullFileName + modInfo->getDataPathW().length());

      std::wstring targetDirectory = rerouteFilename.substr(0, rerouteFilename.find_last_of(L"\\/"));
      CreateDirectoryRecursive(targetDirectory.c_str(), nullptr);
      modInfo->addOverwriteFile(rerouteFilename);
    }
  }

  if (rerouteFilename.length() == 0) {
    LPCWSTR baseName = GetBaseName(lpFileName);

    if (usedBSAList.find(ToLower(ToString(baseName, true))) != usedBSAList.end()) {
      // hide bsa files loaded already through the resource archive list
      LOGDEBUG("%ls hidden from the game", lpFileName);
      ::SetLastError(ERROR_FILE_NOT_FOUND);
      return INVALID_HANDLE_VALUE;
    }

    size_t pathLen = baseName - lpFileName;

    std::map<std::string, std::string>::iterator bsaName = bsaMap.find(ToString(baseName, true));
    if (bsaName != bsaMap.end()) {
      std::wstring bsaPath = std::wstring(lpFileName).substr(0, pathLen) + ToWString(bsaName->second, true);
      rerouteFilename = modInfo->getRerouteOpenExisting(bsaPath.c_str(), false, &rerouted);
      if (!rerouted) {
        LOGDEBUG("createfile bsa not rerouted: %ls -> %ls -> %ls", lpFileName, bsaPath.c_str(), rerouteFilename.c_str());
      }
      // bsa found under its obfuscated name, don't let the game find it under its original name any more, otherwise that
      // would overwrite the load order again
      usedBSAList.insert(ToLower(bsaName->second));
    } else {
      rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName, false, &rerouted);
    }
  }

  HANDLE result = CreateFileW_reroute(rerouteFilename.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

  if (PathStartsWith(fullFileName, modInfo->getDataPathW().c_str())
      && (result != INVALID_HANDLE_VALUE)
      && (dwFlagsAndAttributes == FILE_FLAG_BACKUP_SEMANTICS)) {
    LOGDEBUG("handle opened with backup semantics: %ls", lpFileName);
    directoryCFHandles[result] = std::wstring(fullFileName);
  }

  if (rerouted) {
    LOGDEBUG("createfile w: %ls -> %ls (%x - %x) = %p (%d)", lpFileName, rerouteFilename.c_str(), dwDesiredAccess, dwCreationDisposition, result, ::GetLastError());
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

  return CreateFileW_rep(ToWString(lpFileName, false).c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                     dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


BOOL WINAPI CloseHandle_rep(HANDLE hObject)
{
  {
    auto iter = directoryCFHandles.find(hObject);
    if (iter != directoryCFHandles.end()) {
      directoryCFHandles.erase(iter);
    }
  }
  {
    auto iter = qdfData.find(hObject);
    if (iter != qdfData.end()) {
      qdfData.erase(iter);
    }
  }
  return CloseHandle_reroute(hObject);
}


DWORD WINAPI GetFileAttributesW_rep(LPCWSTR lpFileName)
{
  PROFILE();

  if ((lpFileName == nullptr) || (lpFileName[0] == L'\0')) {
    return GetFileAttributesW_reroute(lpFileName);
  }

  HookLock lock(HookLock::GET_ATTRIBUTES_GROUP);
  UNREFERENCED_PARAMETER(lock);

  LPCWSTR baseName = GetBaseName(lpFileName);
  int pathLen = baseName - lpFileName;

  if (usedBSAList.find(ToLower(ToString(baseName, true))) != usedBSAList.end()) {
    // hide bsa files loaded already through the resource archive list
    LOGDEBUG("%ls hidden from the game", lpFileName);
    ::SetLastError(ERROR_FILE_NOT_FOUND);
    return INVALID_FILE_ATTRIBUTES;
  }

  bool rerouted = false;

  std::wstring rerouteFilename;
  std::map<std::string, std::string>::iterator bsaName = bsaMap.find(ToString(baseName, true));
  if (bsaName != bsaMap.end()) {
    rerouteFilename = modInfo->getRerouteOpenExisting((std::wstring(lpFileName).substr(0, pathLen) + ToWString(bsaName->second, true)).c_str(),
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

  if (HookLock::isLocked(HookLock::GET_ATTRIBUTES_GROUP)) {
    return GetFileAttributesExW_reroute(lpFileName, fInfoLevelId, lpFileInformation);
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

  BOOL result = GetFileAttributesExW_reroute(rerouteFilename.c_str(), fInfoLevelId, lpFileInformation);
//  logging here is just tooo noisy
/*  if (rerouted) {
    if (result && (fInfoLevelId == GetFileExInfoStandard)) {
      LPWIN32_FIND_DATAW fileData = (LPWIN32_FIND_DATAW)lpFileInformation;
      LOGDEBUG("get file attributesex: %ls -> %ls: %d (%d)", lpFileName, rerouteFilename.c_str(), result, fileData->dwFileAttributes);
    } else {
      LOGDEBUG("get file attributesex: %ls -> %ls: %d", lpFileName, rerouteFilename.c_str(), result);
    }
  }*/
  return result;
}


BOOL WINAPI SetFileAttributesW_rep(LPCWSTR lpFileName, DWORD dwFileAttributes)
{
  PROFILE();
  bool rerouted = false;
  std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName, false, &rerouted);
  if (rerouted) {
    LOGDEBUG("set file attributes: %ls -> %ls", lpFileName, rerouteFilename.c_str());
  }
  return SetFileAttributesW_reroute(rerouteFilename.c_str(), dwFileAttributes);
}


HANDLE WINAPI FindFirstFileExW_rep(LPCWSTR lpFileName,
                                   FINDEX_INFO_LEVELS fInfoLevelId,
                                   LPVOID lpFindFileData,
                                   FINDEX_SEARCH_OPS fSearchOp,
                                   LPVOID lpSearchFilter,
                                   DWORD dwAdditionalFlags)
{
  PROFILE();

  if (HookLock::isLocked(HookLock::FIND_FILE_GROUP) || (lpFileName == nullptr)) {
    return FindFirstFileExW_reroute(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
  }

  LPCWSTR baseName = GetBaseName(lpFileName);

  size_t pathLen = baseName - lpFileName;

  std::wstring rerouteFilename = lpFileName;
  std::map<std::string, std::string>::iterator bsaName = bsaMap.find(ToString(baseName, true));
  LPCWSTR sPos = nullptr;
  if (bsaName != bsaMap.end()) {
    rerouteFilename = std::wstring(lpFileName).substr(0, pathLen) + ToWString(bsaName->second, true);
  } else if ((sPos = wcswcs(lpFileName, AppConfig::localSavePlaceholder())) != nullptr) {
    rerouteFilename = modInfo->getProfilePath() + L"\\saves\\" + (sPos + wcslen(AppConfig::localSavePlaceholder()));
  }
  bool rerouted = false;
  HANDLE result = modInfo->findStart(rerouteFilename.c_str(), fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags, &rerouted);

  if ((result != INVALID_HANDLE_VALUE) && rerouted) {
    LOGDEBUG("findfirstfileex %ls: %ls (%x)", rerouteFilename.c_str(),
             ((LPWIN32_FIND_DATAW)lpFindFileData)->cFileName,
             ((LPWIN32_FIND_DATAW)lpFindFileData)->dwFileAttributes);
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
  WCHAR fullPathNameBuf[MAX_PATH];
  LPWSTR fullPathName = fullPathNameBuf;
  memset(fullPathName, '\0', MAX_PATH * sizeof(WCHAR));
  modInfo->getFullPathName(lpPathName, fullPathName, MAX_PATH);

  bool rerouted = false;
  std::wstring reroutePath = modInfo->getRerouteOpenExisting(fullPathName, false, &rerouted);
  if (PathStartsWith(fullPathName, modInfo->getDataPathW().c_str())) {
    if (!rerouted) {
      // redirect directory creation to overwrite
      std::wostringstream temp;
      temp << modInfo->getOverwritePath() << "\\" << (fullPathName + modInfo->getDataPathW().length());
      reroutePath = temp.str();
    }
    LOGDEBUG("create directory: %ls -> %ls", lpPathName, reroutePath.c_str());

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
  LPCWSTR sPos = nullptr;

  if (PathStartsWith(buffer, modInfo->getDataPathW().c_str())) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    modInfo->removeModFile(lpFileName);
    Logger::Instance().info("deleting %ls -> %ls", lpFileName, rerouteFilename.c_str());
    return DeleteFileW_reroute(rerouteFilename.c_str());
  } else if ((sPos = wcswcs(buffer, AppConfig::localSavePlaceholder())) != nullptr) {
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
  bool sourceRerouted = false;
  bool destinationRerouted = false;
  int originID = -1;
  std::wstring sourceReroute = modInfo->getRerouteOpenExisting(fullSourceName, false, &sourceRerouted, &originID);
  std::wstring destinationReroute = fullDestinationName;

  if (PathStartsWith(fullDestinationName, modInfo->getDataPathW().c_str())) {
    destinationReroute = modInfo->getRemovedLocation(fullDestinationName);

    // usually, always move to the overwrite directory. However, in the "create tmp, remove original, move tmp to original"-sequence
    // we'd rather have the modified file in the original location. If the source file was part of a mod we leave the file in that
    // mod
    std::wostringstream temp;
    if (!destinationReroute.empty()) {
      // In the "create tmp, remove original, move tmp to original"-sequence we'd rather have the modified file in the original location.
    } else if (sourceRerouted && (originID != -1)) {
      // source file is rerouted, destination file would be in data. use the same directory instead
      FilesOrigin origin = modInfo->getFilesOrigin(originID);
      temp << origin.getPath() << "\\" << (fullDestinationName + modInfo->getDataPathW().length() + 1);
      destinationReroute = temp.str();
    } else {
      // default case - reroute to overwrite
      temp << modInfo->getOverwritePath() << "\\" << (fullDestinationName + modInfo->getDataPathW().length() + 1);
      destinationReroute = temp.str();
    }
    destinationRerouted = true;
  } else if (LPCWSTR sPos = wcswcs(fullDestinationName, AppConfig::localSavePlaceholder())) {
    destinationReroute = modInfo->getProfilePath() + L"\\saves\\" + (sPos + wcslen(AppConfig::localSavePlaceholder()));
    // destinationRerouted is not set here because then we would try to add the mod file to the
    // directory structure which doesn't make sense for saves
  }

  { // create intermediate directories
    std::wstring targetDirectory = destinationReroute.substr(0, destinationReroute.find_last_of(L"\\/"));
    CreateDirectoryRecursive(targetDirectory.c_str(), nullptr);
  }

  BOOL res = MoveFileExW_reroute(sourceReroute.c_str(), destinationReroute.c_str(), dwFlags);
  if (res) {
    if (sourceRerouted) {
      modInfo->removeModFile(fullSourceName);
    }
    if (destinationRerouted) {
      modInfo->addModFile(destinationReroute.c_str());
    }
  }

  if (sourceRerouted) {
    LOGDEBUG("move (ex) %ls to %ls - %d (%lu)", lpExistingFileName, lpNewFileName, res, ::GetLastError());
  }

  return res;
}


BOOL WINAPI MoveFileW_rep(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)
{
  PROFILE();
  return MoveFileExW_rep(lpExistingFileName, lpNewFileName, MOVEFILE_COPY_ALLOWED);
}

BOOL WINAPI MoveFileA_rep(LPCSTR lpExistingFileName, LPCSTR lpNewFileName)
{
  PROFILE();

  return MoveFileW_rep(ToWString(lpExistingFileName, false).c_str()
                       , ToWString(lpNewFileName, false).c_str());
}


BOOL WINAPI MoveFileExA_rep(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags)
{
  PROFILE();

  return MoveFileExW_rep(ToWString(lpExistingFileName, false).c_str()
                         , ToWString(lpNewFileName, false).c_str()
                         , dwFlags);
}

static bool firstRun = true;

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


static const int s_BufferSize = 0x8000;
static char s_Buffer[s_BufferSize];
static PBYTE s_ReturnAddress = nullptr;

// this includes a bit of wiggle room, for skyrim we need 42 bytes
#define FUNCTION_BUFFER_SIZE 64

#ifdef _MSC_VER
#pragma optimize( "", off )

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

#else
void replacementFunction() {}
static char *s_FunctionBuffer = (char*)replacementFunction;

void pushModEAX() {}
void pushModEBX() {}
void pushModECX() {}
void pushModEDX() {}
void returnInstrEAX() {}
void returnInstrEBX() {}
void returnInstrECX() {}
void returnInstrEDX() {}
void callInstrMod() {}


#endif


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

  void *function = nullptr;
  switch (disasm.GetReg2()) {
    case 0: function = reinterpret_cast<void*>(pushModEAX); break;
    case 1: function = reinterpret_cast<void*>(pushModECX); break;
    case 2: function = reinterpret_cast<void*>(pushModEDX); break;
    case 3: function = reinterpret_cast<void*>(pushModEBX); break;
    default: return false;
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
    size_t funcSize = getSnippetSize(reinterpret_cast<void*>(callInstrMod));
    if (tPtr + funcSize >= functionEnd) {
      return false;
    }
    memcpy(tPtr, reinterpret_cast<void*>(callInstrMod), funcSize);
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
    case REG_EAX: function = reinterpret_cast<void*>(returnInstrEAX); break;
    case REG_EBX: function = reinterpret_cast<void*>(returnInstrEBX); break;
    case REG_ECX: function = reinterpret_cast<void*>(returnInstrECX); break;
    case REG_EDX: function = reinterpret_cast<void*>(returnInstrEDX); break;
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


static std::set<std::string> missingIniA;
static std::set<std::string> existingIniA;


DWORD WINAPI GetPrivateProfileStringA_rep(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpDefault,
                                          LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
  int localDummy = 42;  // this is a marker for the beginning of this function
  PROFILE();

  if ((lpFileName != nullptr) && (missingIniA.find(lpFileName) != missingIniA.end())) {
    errno = 0x02;
    ::SetLastError(ERROR_FILE_NOT_FOUND);
    int defLength = lpDefault != nullptr ? strlen(lpDefault) : 0;
    int res = (std::min<int>)(nSize - 1, defLength);
    if (res > 0) {
      strncpy(lpReturnedString, lpDefault, res);
      lpReturnedString[res] = '\0';
      return res;
    } else {
      lpReturnedString[0] = '\0';
      return 0;
    }
  }

  if (HookLock::isLocked(HookLock::GET_PROFILESTRING_GROUP) || (lpFileName == nullptr)) {
    return GetPrivateProfileStringA_reroute(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);
  }

  LPCSTR lastSlash = strrchr(lpFileName, '\\');
  if (lastSlash == nullptr) {
    lastSlash = strrchr(lpFileName, '/');
  }
  if (lastSlash == nullptr) {
    lastSlash = lpFileName;
  } else {
    ++lastSlash;
  }

  { // mod-inis are used directly
    std::string fileName(lastSlash);
    fileName = ToLower(fileName);

    if (iniFilesA.find(fileName) == iniFilesA.end()) {
      std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
      errno = 0;
      ::SetLastError(NOERROR);
      DWORD res = GetPrivateProfileStringA_reroute(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, rerouteFilename.c_str());
      // lpFileName can't be nullptr here because there is a test earlier in the function
      if ((::GetLastError() == ERROR_FILE_NOT_FOUND) && (lpFileName != nullptr) &&
          !(existingIniA.find(lpFileName) != existingIniA.end()) && !FileExists(lpFileName)) {
        LOGDEBUG("%s doesn't exist, no further queries", lpFileName);
        missingIniA.insert(lpFileName);
      } else {
        existingIniA.insert(lpFileName);
      }
      return res;
    }
  }

  if ((archiveListHookState == HOOK_NOTYET)
      && (lpKeyName != nullptr) && (lpKeyName[0] == 's')
      && (_stricmp(lpAppName, "Archive") == 0)) {
    // if we don't reach the success-case, we can safely assume it failed
    archiveListHookState = HOOK_FAILED;
    DWORD start, end;
    GetSectionRange(&start, &end, ::GetModuleHandle(nullptr));
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

  if ((lpKeyName != nullptr)
      && ((_stricmp(lpKeyName, "sResourceArchiveList") == 0) || (_stricmp(lpKeyName, "sArchiveList") == 0))) {
    size_t length = std::min<DWORD>(bsaResourceList.size(), nSize - 1);
    if ((length > 255) && (lpReturnedString != s_Buffer)) {
      LOGDEBUG("safety check: length exceeds regular size but wrong buffer (%p vs. %p)?", lpReturnedString, s_Buffer);
      length = 255;
    }
    strncpy(lpReturnedString, bsaResourceList.c_str(), length);
    lpReturnedString[length] = '\0';
    return static_cast<DWORD>(length);
  } else if ((lpKeyName != nullptr) && (_stricmp(lpKeyName, "sResourceArchiveList2") == 0)) {
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
    } else if (lpKeyName != nullptr) {
      tweakedIniValues[ToWString(lpKeyName, false)] = ToWString(temp.get(), false);
    }

    strncpy(lpReturnedString, temp.get(), static_cast<size_t>(res + 1));

    return res;
  }
}


DWORD WINAPI GetPrivateProfileStringW_rep(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpDefault,
                                          LPWSTR lpReturnedString, DWORD nSize, LPCWSTR lpFileName)
{
  PROFILE();
  if (HookLock::isLocked(HookLock::GET_PROFILESTRING_GROUP))
    return GetPrivateProfileStringW_reroute(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);

  if (lpFileName != nullptr) {
    DWORD res = GetPrivateProfileStringW_reroute(lpAppName, lpKeyName, L"DUMMY_VALUE", lpReturnedString, nSize, modInfo->getTweakedIniW().c_str());
    if (wcscmp(lpReturnedString, L"DUMMY_VALUE") == 0) {
      std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
      res = GetPrivateProfileStringW_reroute(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, rerouteFilename.c_str());
    } else if (lpKeyName != nullptr) {
      tweakedIniValues[lpKeyName] = lpReturnedString;
    }
    return res;
  } else {
    return GetPrivateProfileStringW_reroute(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);
  }
}


BOOL WINAPI GetPrivateProfileStructA_rep(LPCSTR lpszSection, LPCSTR lpszKey, LPVOID lpStruct, UINT uSizeStruct, LPCSTR szFile)
{
  PROFILE();

  if (szFile != nullptr) {
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(szFile);
    return GetPrivateProfileStructA_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileStructA_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, szFile);
  }
}


BOOL WINAPI GetPrivateProfileStructW_rep(LPCWSTR lpszSection, LPCWSTR lpszKey, LPVOID lpStruct, UINT uSizeStruct, LPCWSTR szFile)
{
  PROFILE();

  if (szFile != nullptr) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(szFile);
    return GetPrivateProfileStructW_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileStructW_reroute(lpszSection, lpszKey, lpStruct, uSizeStruct, szFile);
  }
}


DWORD WINAPI GetPrivateProfileSectionNamesA_rep(LPSTR lpszReturnBuffer, DWORD nSize, LPCSTR lpFileName)
{
  PROFILE();

  if (lpFileName != nullptr) {
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return GetPrivateProfileSectionNamesA_reroute(lpszReturnBuffer, nSize, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileSectionNamesA_reroute(lpszReturnBuffer, nSize, lpFileName);
  }
}


DWORD WINAPI GetPrivateProfileSectionNamesW_rep(LPWSTR lpszReturnBuffer, DWORD nSize, LPCWSTR lpFileName)
{
  PROFILE();

  if (lpFileName != nullptr) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return GetPrivateProfileSectionNamesW_reroute(lpszReturnBuffer, nSize, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileSectionNamesW_reroute(lpszReturnBuffer, nSize, lpFileName);
  }
}


DWORD WINAPI GetPrivateProfileSectionA_rep(LPCSTR lpAppName, LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
  PROFILE();

  if (lpFileName != nullptr) {
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return GetPrivateProfileSectionA_reroute(lpAppName, lpReturnedString, nSize, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileSectionA_reroute(lpAppName, lpReturnedString, nSize, lpFileName);
  }
}


DWORD WINAPI GetPrivateProfileSectionW_rep(LPCWSTR lpAppName, LPWSTR lpReturnedString, DWORD nSize, LPCWSTR lpFileName)
{
  PROFILE();

  if (lpFileName != nullptr) {
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return GetPrivateProfileSectionW_reroute(lpAppName, lpReturnedString, nSize, rerouteFilename.c_str());
  } else {
    return GetPrivateProfileSectionW_reroute(lpAppName, lpReturnedString, nSize, lpFileName);
  }
}


UINT WINAPI GetPrivateProfileIntA_rep(LPCSTR lpAppName, LPCSTR lpKeyName, INT nDefault, LPCSTR lpFileName)
{
  PROFILE();

  if ((lpFileName != nullptr) && (missingIniA.find(lpFileName) != missingIniA.end())) {
    ::SetLastError(ERROR_FILE_NOT_FOUND);
    return nDefault;
  }
  HookLock lock(HookLock::GET_PROFILESTRING_GROUP);
  UNREFERENCED_PARAMETER(lock);

  if (lpFileName != nullptr) {
    UINT res = GetPrivateProfileIntA_reroute(lpAppName, lpKeyName, INT_MAX, modInfo->getTweakedIniA().c_str());
    if (res == INT_MAX) {
      std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
      res = GetPrivateProfileIntA_reroute(lpAppName, lpKeyName, nDefault, rerouteFilename.c_str());
    } else if (lpKeyName != nullptr) {
      tweakedIniValues[ToWString(lpKeyName, false)] = std::to_wstring(static_cast<unsigned long long>(res));
    }
    return res;
  } else {
    return GetPrivateProfileIntA_reroute(lpAppName, lpKeyName, nDefault, lpFileName);
  }
}


UINT WINAPI GetPrivateProfileIntW_rep(LPCWSTR lpAppName, LPCWSTR lpKeyName, INT nDefault, LPCWSTR lpFileName)
{
  PROFILE();

  HookLock lock(HookLock::GET_PROFILESTRING_GROUP); // on some (all?) systems, getprivateprofileint calls getprivateprofilestring

  if (lpFileName != nullptr) {
    UINT res = GetPrivateProfileIntW_reroute(lpAppName, lpKeyName, INT_MAX, modInfo->getTweakedIniW().c_str());
    if (res == INT_MAX) {
      std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
      res = GetPrivateProfileIntW_reroute(lpAppName, lpKeyName, nDefault, rerouteFilename.c_str());
    } else if (lpKeyName != nullptr) {
      tweakedIniValues[lpKeyName] = std::to_wstring(static_cast<unsigned long long>(res));
    }
    return res;
  } else {
    return GetPrivateProfileIntW_reroute(lpAppName, lpKeyName, nDefault, lpFileName);
  }
}



// ensures that the specified file exists (virtually) IF it is inside the data directory
void MakeFileExist(LPCWSTR fileName)
{
  WCHAR fullFileNameBuf[MAX_PATH];
  LPWSTR fullFileName = fullFileNameBuf;
  memset(fullFileName, '\0', MAX_PATH * sizeof(WCHAR));
  modInfo->getFullPathName(fileName, fullFileName, MAX_PATH);
  modInfo->checkPathAlternative(fullFileName);

  if (StartsWith(fullFileName, L"\\\\?\\")) {
    fullFileName = fullFileName + 4;
  }

  bool rerouted = false;

  if (PathStartsWith(fullFileName, modInfo->getDataPathW().c_str())) {
    // need to check if the file exists. If it does, act on the existing file, otherwise the behaviour is not transparent
    // if the regular call causes an error message and rerouted to overwrite
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(fileName, false, &rerouted);
    if (!rerouted && !FileExists_reroute(fileName)) {
      std::wostringstream temp;
      temp << modInfo->getOverwritePath() << "\\" << (fullFileName + modInfo->getDataPathW().length());
      rerouteFilename = temp.str();

      std::wstring targetDirectory = rerouteFilename.substr(0, rerouteFilename.find_last_of(L"\\/"));
      CreateDirectoryRecursive(targetDirectory.c_str(), nullptr);
      modInfo->addOverwriteFile(rerouteFilename);
    }
  }
}


// ensures that the specified file exists (virtually) IF it is inside the data directory
void MakeFileExist(LPCSTR fileName)
{
  MakeFileExist(ToWString(fileName, false).c_str());
}

BOOL WINAPI WritePrivateProfileSectionA_rep(LPCSTR lpAppName, LPCSTR lpString, LPCSTR lpFileName)
{
  PROFILE();

  if (lpFileName != nullptr) {
    MakeFileExist(lpFileName);
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return WritePrivateProfileSectionA_reroute(lpAppName, lpString, rerouteFilename.c_str());
  } else {
    return WritePrivateProfileSectionA_reroute(lpAppName, lpString, lpFileName);
  }
}


BOOL WINAPI WritePrivateProfileSectionW_rep(LPCWSTR lpAppName, LPCWSTR lpString, LPCWSTR lpFileName)
{
  PROFILE();

  if (lpFileName != nullptr) {
    MakeFileExist(lpFileName);
    std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return WritePrivateProfileSectionW_reroute(lpAppName, lpString, rerouteFilename.c_str());
  } else {
    return WritePrivateProfileSectionW_reroute(lpAppName, lpString, lpFileName);
  }
}


BOOL WINAPI WritePrivateProfileStringA_rep(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString, LPCSTR lpFileName)
{
  PROFILE();
  // lpKeyName is in fact allowed to be null, in which case this function has entirely different semantics
  if (lpKeyName != nullptr) {
    std::wstring keyW = ToWString(lpKeyName, false);
    if (tweakedIniValues.find(keyW) != tweakedIniValues.end()) {
      if (ToWString(lpString, false) != tweakedIniValues[keyW]) {
        // store in current tweaked file so the setting is used in this session
        BOOL res = WritePrivateProfileStringA_reroute(lpAppName, lpKeyName, lpString, modInfo->getTweakedIniA().c_str());
        // also store in "profile_tweaks.ini" for this profile so the settings can be applied in the future
        WritePrivateProfileStringA_reroute(lpAppName, lpKeyName, lpString,
                                           ToString(modInfo->getProfilePath() + L"\\" + AppConfig::profileTweakIni().c_str(), false).c_str());
        return res;
      } else {
        return true;
      }
    }
  }

  if (lpFileName != nullptr) {
    MakeFileExist(lpFileName);
    std::string rerouteFilename = modInfo->getRerouteOpenExisting(lpFileName);
    return WritePrivateProfileStringA_reroute(lpAppName, lpKeyName, lpString, rerouteFilename.c_str());
  } else {
    return WritePrivateProfileStringA_reroute(lpAppName, lpKeyName, lpString, lpFileName);
  }
}


BOOL WINAPI WritePrivateProfileStringW_rep(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpString, LPCWSTR lpFileName)
{
  PROFILE();

  if (lpFileName != nullptr) {
    MakeFileExist(lpFileName);
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

  if (szFile != nullptr) {
    MakeFileExist(szFile);
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

  if (szFile != nullptr) {
    MakeFileExist(szFile);
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
  std::wstring fakeCurrentDirectory = modInfo->getCurrentDirectory();
  if (fakeCurrentDirectory.length() != 0) {
    if (nBufferLength > 0) {
      size_t len = std::min<size_t>(fakeCurrentDirectory.length(), nBufferLength - 1);
      wcsncpy(lpBuffer, fakeCurrentDirectory.c_str(), len);
      lpBuffer[len] = L'\0';
    }
    return static_cast<DWORD>(fakeCurrentDirectory.length());
  } else {
    return ::GetCurrentDirectoryW_reroute(nBufferLength, lpBuffer);
  }
}


BOOL WINAPI SetCurrentDirectoryW_rep(LPCWSTR lpPathName)
{
  PROFILE();

  missingIniA.clear();
  existingIniA.clear();

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
    std::wstring reroutedPath = modInfo->getRerouteOpenExisting(lpPathName, true);

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
  if (PathStartsWith(fullNewFileName, modInfo->getDataPathW().c_str())) {
    std::wostringstream temp;
    temp << modInfo->getOverwritePath() << "\\" << (fullNewFileName + modInfo->getDataPathW().length());
    rerouteNewFileName = temp.str();

    std::wstring targetDirectory = rerouteNewFileName.substr(0, rerouteNewFileName.find_last_of(L"\\/"));
    CreateDirectoryRecursive(targetDirectory.c_str(), nullptr);
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
  if (PathStartsWith(fullNewFileName, modInfo->getDataPathW().c_str())) {
    std::wostringstream temp;
    temp << modInfo->getOverwritePath() << "\\" << (fullNewFileName + modInfo->getDataPathW().length());
    rerouteNewFileName = temp.str();

    std::wstring targetDirectory = rerouteNewFileName.substr(0, rerouteNewFileName.find_last_of(L"\\/"));
    CreateDirectoryRecursive(targetDirectory.c_str(), nullptr);
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
    driveRoot[3] = L'\0';
    ::GetVolumeInformationW(driveRoot, nullptr, 0, nullptr, nullptr, nullptr, fsName, 10);
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

  LPCWSTR searchPath = lpFileName;
  if ((wcslen(searchPath) > 2)
      && (searchPath[1] == L':')
      && (searchPath[2] == L'.')) {
    searchPath += 2;
  }

  if (modInfo->getCurrentDirectory().length() != 0) {
    WCHAR cwd[MAX_PATH];
    DWORD cwdLength = ::GetCurrentDirectoryW_reroute(MAX_PATH, cwd);
    if (StartsWith(lpFileName, cwd)) {
      WCHAR temp[MAX_PATH];
      ::PathCombineW(temp, modInfo->getCurrentDirectory().c_str(), lpFileName + static_cast<size_t>(cwdLength) + 1);
      size_t length = wcslen(temp);
      if ((lpBuffer != nullptr) && (nBufferLength > 0)) {
        size_t count = std::min<size_t>(nBufferLength - 1, length);
        wcsncpy(lpBuffer, temp, count);
        lpBuffer[count] = L'\0';
        if (lpFilePart != nullptr) {
          *lpFilePart = GetBaseName(lpBuffer);
          if (**lpFilePart == L'\0') {
            // lpBuffer is a directory
            *lpFilePart = nullptr;
          }
        }
        return count;
      } else {
        return length + 1;
      }
    } else if (::PathIsRelativeW(searchPath)) {
      WCHAR temp[MAX_PATH];

      ::PathCombineW(temp, modInfo->getCurrentDirectory().c_str(), searchPath);

      WCHAR temp2[MAX_PATH];
      size_t count = 0UL;
      if (::PathCanonicalizeW(temp2, temp)) {
        size_t length = wcslen(temp2);
        if ((lpBuffer != nullptr) && (nBufferLength > 0)) {
          count = std::min<size_t>(nBufferLength - 1, length);
          wcsncpy(lpBuffer, temp2, count);
        } else {
          count = length + 1;
        }
      } else {
        Logger::Instance().error("failed to canonicalize path %ls", temp);
        size_t length = wcslen(temp);
        if (nBufferLength > 0) {
          count = std::min<size_t>(nBufferLength - 1, length);
          wcsncpy(lpBuffer, temp, count);
        } else {
          count = length + 1;
        }
      }
      if (count < nBufferLength) {
        lpBuffer[count] = L'\0';
        if (lpFilePart != nullptr) {
          *lpFilePart = GetBaseName(lpBuffer);
          if (**lpFilePart == L'\0') {
            // lpBuffer is a directory
            *lpFilePart = nullptr;
          }
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


int STDAPICALLTYPE SHFileOperationA_rep(LPSHFILEOPSTRUCTA lpFileOp)
{
  PROFILE();
  HookLock lock(HookLock::SH_FILEOPERATION_GROUP);

  SHFILEOPSTRUCTA newOp;
  newOp.hwnd = lpFileOp->hwnd;
  newOp.wFunc = lpFileOp->wFunc;
  newOp.fFlags = lpFileOp->fFlags;
  newOp.fAnyOperationsAborted = lpFileOp->fAnyOperationsAborted;
  newOp.hNameMappings = lpFileOp->hNameMappings;
  newOp.lpszProgressTitle = lpFileOp->lpszProgressTitle;
  std::vector<char> newFrom;
  LPCSTR pos = lpFileOp->pFrom;
  for (;;) {
    if (*pos == '\0') break;

    std::string rerouted = modInfo->getRerouteOpenExisting(pos);
    newFrom.insert(newFrom.end(), rerouted.begin(), rerouted.end());
    newFrom.push_back('\0');
    pos += strlen(pos) + 1;
  }
  newFrom.push_back('\0');

  newOp.pFrom = &newFrom[0];

  std::vector<char> newTo;
  if (lpFileOp->pTo != nullptr) {
    pos = lpFileOp->pTo;
    for (;;) {
      if (*pos == L'\0') break;

      bool rerouted = false;
      std::string rerouteFilename = modInfo->getRerouteOpenExisting(pos, false, &rerouted);
      if (!rerouted && PathStartsWith(pos, modInfo->getDataPathA().c_str())) {
        // TODO need to addOverwriteFile in both cases and if the destination is a directory we need to
        // extract the file name
        if (strlen(pos) == modInfo->getDataPathA().length()) {
          rerouteFilename = ToString(modInfo->getOverwritePath(), false);
        } else {
          std::ostringstream temp;
          temp << ToString(modInfo->getOverwritePath(), false) << "\\" << (pos + modInfo->getDataPathA().length());
          rerouteFilename = temp.str();

          std::string targetDirectory = rerouteFilename.substr(0, rerouteFilename.find_last_of("\\/"));
          CreateDirectoryRecursive(ToWString(targetDirectory, false).c_str(), nullptr);
          modInfo->addOverwriteFile(ToWString(rerouteFilename, false));
        }
      }

      newTo.insert(newTo.end(), rerouteFilename.begin(), rerouteFilename.end());
      newTo.push_back('\0');
      pos += strlen(pos) + 1;
    }
    newTo.push_back('\0');

    newOp.pTo = &newTo[0];
  } else {
    newOp.pTo = nullptr;
  }

  LOGDEBUG("sh file operation a %d: %s - %s", newOp.wFunc, newOp.pFrom,
           newOp.pTo != nullptr ? newOp.pTo : "nullptr");
  return SHFileOperationA_reroute(&newOp);
}

int STDAPICALLTYPE SHFileOperationW_rep(LPSHFILEOPSTRUCTW lpFileOp)
{
  PROFILE();

  // avoid recursive call from SHFileOperationA
  if (HookLock::isLocked(HookLock::SH_FILEOPERATION_GROUP))
    return SHFileOperationW_reroute(lpFileOp);

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
  if (lpFileOp->pTo != nullptr) {
    pos = lpFileOp->pTo;
    for (;;) {
      if (*pos == L'\0') break;

      bool rerouted = false;
      std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(pos, false, &rerouted);
      if (!rerouted && PathStartsWith(pos, modInfo->getDataPathW().c_str())) {
        // TODO need to addOverwriteFile in both cases and if the destination is a directory we need to
        // extract the file name
        if (wcslen(pos) == modInfo->getDataPathW().length()) {
          rerouteFilename = modInfo->getOverwritePath();
        } else {
          std::wostringstream temp;
          temp << modInfo->getOverwritePath() << "\\" << (pos + modInfo->getDataPathW().length());
          rerouteFilename = temp.str();

          std::wstring targetDirectory = rerouteFilename.substr(0, rerouteFilename.find_last_of(L"\\/"));
          CreateDirectoryRecursive(targetDirectory.c_str(), nullptr);
          modInfo->addOverwriteFile(rerouteFilename);
        }
      }
      newTo.insert(newTo.end(), rerouteFilename.begin(), rerouteFilename.end());
      newTo.push_back(L'\0');
      pos += wcslen(pos) + 1;
    }
    newTo.push_back(L'\0');

    newOp.pTo = &newTo[0];
  } else {
    newOp.pTo = nullptr;
  }

  LOGDEBUG("sh file operation w %d: %ls - %ls", newOp.wFunc, newOp.pFrom,
           newOp.pTo != nullptr ? newOp.pTo : L"nullptr");
  return SHFileOperationW_reroute(&newOp);
}

BOOL WINAPI GetFileVersionInfoW_rep(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
  PROFILE();

  HookLock lock(HookLock::GET_FILEVERSION_GROUP); // GetFileVersionInfoW calls the ex variant on some but not all windows variants

  WCHAR temp[MAX_PATH];
  modInfo->getFullPathName(lptstrFilename, temp, MAX_PATH);

  bool rerouted = false;
  std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(temp, false, &rerouted);

  BOOL res = GetFileVersionInfoW_reroute(rerouteFilename.c_str(), dwHandle, dwLen, lpData);

  if (rerouted) {
    LOGDEBUG("get file version w %ls -> %ls: %d", lptstrFilename, rerouteFilename.c_str(), res);
  }

  return res;
}


BOOL WINAPI GetFileVersionInfoExW_rep(DWORD dwFlags, LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
  PROFILE();

  if (HookLock::isLocked(HookLock::GET_FILEVERSION_GROUP)) {
    return GetFileVersionInfoExW_reroute(dwFlags, lptstrFilename, dwHandle, dwLen, lpData);;
  }

  WCHAR temp[MAX_PATH];
  modInfo->getFullPathName(lptstrFilename, temp, MAX_PATH);

  bool rerouted = false;
  std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(temp, false, &rerouted);

  if (rerouted) {
    LOGDEBUG("get file version ex w %ls -> %ls", lptstrFilename, rerouteFilename.c_str());
  }

  return GetFileVersionInfoExW_reroute(dwFlags, rerouteFilename.c_str(), dwHandle, dwLen, lpData);
}

DWORD WINAPI GetFileVersionInfoSizeW_rep(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
  PROFILE();

  WCHAR temp[MAX_PATH];
  modInfo->getFullPathName(lptstrFilename, temp, MAX_PATH);

  bool rerouted = false;
  std::wstring rerouteFilename = modInfo->getRerouteOpenExisting(temp, false, &rerouted);

  DWORD res = GetFileVersionInfoSizeW_reroute(rerouteFilename.c_str(), lpdwHandle);

  if (rerouted) {
    LOGDEBUG("get file version size %ls -> %ls -> %lu (%x)", lptstrFilename, rerouteFilename.c_str(), res, ::GetLastError());
  }

  return res;
}


DWORD WINAPI GetModuleFileNameW_rep(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
  PROFILE();

  DWORD oldSize = GetModuleFileNameW_reroute(hModule, lpFilename, nSize);
  if (HookLock::isLocked(HookLock::GET_MODULENAME_GROUP)) {
    return oldSize;
  }

  if (oldSize != 0) {
    // found name
    bool isRerouted = false;
    std::wstring rerouted = modInfo->reverseReroute(lpFilename, &isRerouted);
    if (isRerouted) {
      DWORD reroutedSize = rerouted.size();
      if (reroutedSize >= nSize) {
        if (!winXP) {
          ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        reroutedSize = nSize - 1;
      }
      // res can't be bigger than nSize-1 at this point
      if (reroutedSize > 0) {
        if (reroutedSize < oldSize) {
          // zero out the string windows has previously written to
          memset(lpFilename, '\0', std::min(oldSize, nSize) * sizeof(wchar_t));
        }
        // this truncates the string if the buffer is too small
        wcsncpy(lpFilename, rerouted.c_str(), reroutedSize + 1);
      }
      return reroutedSize;
    }
  }
  return oldSize;
}


DWORD WINAPI GetModuleFileNameA_rep(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
  PROFILE();

  HookLock lock(HookLock::GET_MODULENAME_GROUP);

  DWORD origSize = GetModuleFileNameA_reroute(hModule, lpFilename, nSize);

  if (origSize != 0) {
    // found name
    bool isRerouted = false;
    std::wstring oldName = ToWString(lpFilename, false);
    std::wstring reroutedW = modInfo->reverseReroute(oldName, &isRerouted);
    if (isRerouted) {
      std::string rerouted = ToString(reroutedW, false);
      DWORD reroutedSize = rerouted.size();
      if (reroutedSize >= nSize) {
        if (!winXP) {
          ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        reroutedSize = nSize - 1;
      }
      // res can't be bigger than nSize-1 at this point
      if (reroutedSize > 0) {
        if (reroutedSize < origSize) {
          // zero out the string windows has previously written to
          memset(lpFilename, '\0', std::min(origSize, nSize) * sizeof(char));
        }
        // this truncates the string if the buffer is too small
        strncpy(lpFilename, rerouted.c_str(), reroutedSize + 1);
      }
      return reroutedSize;
    }
  }
  return origSize;
}

#ifdef _MSC_VER
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;
#endif


typedef struct _FILE_OBJECTID_INFORMATION {
  LONGLONG FileReference;
  UCHAR    ObjectId[16];
  union {
    struct {
      UCHAR BirthVolumeId[16];
      UCHAR BirthObjectId[16];
      UCHAR DomainId[16];
    };
    UCHAR  ExtendedInfo[48];
  };
} FILE_OBJECTID_INFORMATION, *PFILE_OBJECTID_INFORMATION;

typedef struct _FILE_REPARSE_POINT_INFORMATION {
  LONGLONG FileReference;
  ULONG    Tag;
} FILE_REPARSE_POINT_INFORMATION, *PFILE_REPARSE_POINT_INFORMATION;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#define STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006L)
#define STATUS_NO_SUCH_FILE ((NTSTATUS)0xC000000FL)

#ifdef _MSC_VER
enum _MY_FILE_INFORMATION_CLASS {
    FileDirectoryInformation        = 1,
    FileFullDirectoryInformation    = 2,
    FileBothDirectoryInformation    = 3,
    FileNamesInformation            = 12,
    FileObjectIdInformation         = 29,
    FileReparsePointInformation     = 33,
    FileIdBothDirectoryInformation  = 37,
    FileIdFullDirectoryInformation  = 38
};
#endif

ULONG StructMinSize(FILE_INFORMATION_CLASS infoClass)
{
  switch (infoClass) {
    case FileBothDirectoryInformation: return sizeof(FILE_BOTH_DIR_INFORMATION);
    case FileDirectoryInformation: return sizeof(FILE_DIRECTORY_INFORMATION);
    case FileFullDirectoryInformation: return sizeof(FILE_FULL_DIR_INFORMATION);
    case FileIdBothDirectoryInformation: return sizeof(FILE_ID_BOTH_DIR_INFORMATION);
    case FileIdFullDirectoryInformation: return sizeof(FILE_ID_FULL_DIR_INFORMATION);
    case FileNamesInformation: return sizeof(FILE_NAMES_INFORMATION);
    case FileObjectIdInformation: return sizeof(FILE_OBJECTID_INFORMATION);
    case FileReparsePointInformation: return sizeof(FILE_REPARSE_POINT_INFORMATION);
    default: return 0;
  }
}

void GetInfoData(LPVOID address, FILE_INFORMATION_CLASS infoClass, ULONG &offset, std::wstring &fileName)
{
  switch (infoClass) {
    case FileBothDirectoryInformation: {
      FILE_BOTH_DIR_INFORMATION *info = reinterpret_cast<FILE_BOTH_DIR_INFORMATION*>(address);
      offset = info->NextEntryOffset;
      fileName.assign(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileDirectoryInformation: {
      FILE_DIRECTORY_INFORMATION *info = reinterpret_cast<FILE_DIRECTORY_INFORMATION*>(address);
      offset = info->NextEntryOffset;
      fileName.assign(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileNamesInformation: {
      FILE_NAMES_INFORMATION *info = reinterpret_cast<FILE_NAMES_INFORMATION*>(address);
      offset = info->NextEntryOffset;
      fileName.assign(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileIdFullDirectoryInformation: {
      FILE_ID_FULL_DIR_INFORMATION *info = reinterpret_cast<FILE_ID_FULL_DIR_INFORMATION*>(address);
      offset = info->NextEntryOffset;
      fileName.assign(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileFullDirectoryInformation: {
      FILE_FULL_DIR_INFORMATION *info = reinterpret_cast<FILE_FULL_DIR_INFORMATION*>(address);
      offset = info->NextEntryOffset;
      fileName.assign(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileIdBothDirectoryInformation: {
      FILE_ID_BOTH_DIR_INFORMATION *info = reinterpret_cast<FILE_ID_BOTH_DIR_INFORMATION*>(address);
      offset = info->NextEntryOffset;
      fileName.assign(info->FileName, info->FileNameLength / sizeof(WCHAR));
    } break;
    case FileObjectIdInformation: {
      offset = sizeof(FILE_OBJECTID_INFORMATION);
    } break;
    case FileReparsePointInformation: {
      offset = sizeof(FILE_REPARSE_POINT_INFORMATION);
    } break;
    default: {
      offset = ULONG_MAX;
    } break;
  }
}


int NextDividableBy(int number, int divider)
{
  return static_cast<int>(ceilf(static_cast<float>(number) / static_cast<float>(divider)) * divider);
}



NTSTATUS addNtSearchData(const std::wstring &localPath,
                     PUNICODE_STRING FileName, FILE_INFORMATION_CLASS FileInformationClass,
                     boost::scoped_array<uint8_t> &buffer, ULONG bufferSize,
                     std::pair<HANDLE, std::deque<std::vector<uint8_t>>> &result, std::set<std::wstring> &foundFiles)
{
  NTSTATUS res = STATUS_NO_SUCH_FILE;
  // try to open the directory handle. If this doesn't work, the mod contains no such directory
  HANDLE hdl = ::CreateFileW_reroute(localPath.c_str(),
                                     GENERIC_READ,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     nullptr,
                                     OPEN_EXISTING,
                                     FILE_FLAG_BACKUP_SEMANTICS,
                                     nullptr);
  if (hdl != INVALID_HANDLE_VALUE) {
    IO_STATUS_BLOCK status;
    res = NtQueryDirectoryFile_reroute(hdl, nullptr, nullptr, nullptr, &status, buffer.get(),
                                       bufferSize, FileInformationClass, FALSE, FileName, FALSE);
    while ((res == STATUS_SUCCESS) && (status.Information > 0)) {
      uint8_t *pos = buffer.get();
      ULONG totalOffset = 0;
      while (totalOffset < status.Information) {
        ULONG offset;
        std::wstring fileName;
        GetInfoData(pos, FileInformationClass, offset, fileName);

        bool add = !modInfo->isFileHidden(fileName);
        if (fileName.length() > 0) {
          auto res = foundFiles.insert(ToLower(fileName));
          add = res.second;
        }
        ULONG size = offset != 0 ? offset : (status.Information - totalOffset);
        if (add) {
          result.second.push_back(std::vector<uint8_t>(pos, pos + size));
        }

        pos += size;
        totalOffset += size;
      }

      res = NtQueryDirectoryFile_reroute(hdl, nullptr, nullptr, nullptr, &status, buffer.get(),
                                         bufferSize, FileInformationClass, FALSE, FileName, FALSE);
    }
  }
  return res;
}


// TODO: This doesn't report errors in the hooked path. It doesn't handle the Apc routine. It doesn't handle the corner
// case where, on first call, the buffer is allowed to be smaller than the data element as long as it's long enough to receive the
// fixed block size. It doesn't signal IO Completion objects. It ... augh fuck this function is complicated...
NTSTATUS WINAPI NtQueryDirectoryFile_rep(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                 PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                 ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                 PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
  if (   (directoryCFHandles.find(FileHandle) != directoryCFHandles.end())
      && (ApcRoutine == nullptr)) {   // this hook doesn't support asynchronous operation
    LOGDEBUG("ntquerydirectoryfile called with a rerouted handle from CreateFile (%d) (%d) (%.*ls)",
        ReturnSingleEntry, FileInformationClass, FileName != nullptr ? FileName->Length : 4, FileName != nullptr ? FileName->Buffer : L"null");
    if (RestartScan) {
      // drop our own cache data on rescan
      queryMutex.lock();
      auto iter = qdfData.find(FileHandle);
      if (iter != qdfData.end()) {
        qdfData.erase(iter);
      }
      queryMutex.unlock();
    }

    bool noSuchFile = true;

    if (qdfData.find(FileHandle) == qdfData.end()) {
      // no data yet, query it
      std::set<std::wstring> foundFiles;

      std::pair<HANDLE, std::deque<std::vector<uint8_t>>> result(FileHandle, std::deque<std::vector<uint8_t>>());

      std::wstring relativePath = directoryCFHandles[FileHandle].size() > modInfo->getDataPathW().size()
                                      ? directoryCFHandles[FileHandle].substr(modInfo->getDataPathW().length() + 1)
                                      : std::wstring();


      // we use one large buffer and copy the required section to newly allocated parts.
      ULONG bufferSize = (std::max<ULONG>(64 * 1024, Length)); // should usually be sufficiently oversized
      boost::scoped_array<uint8_t> buffer(new uint8_t[bufferSize]);

      if (addNtSearchData(directoryCFHandles[FileHandle], FileName, FileInformationClass, buffer, bufferSize, result, foundFiles) != STATUS_NO_SUCH_FILE) {
        noSuchFile = false;
      }

      // for each overlay directory, repeat this search
      std::vector<std::wstring> modNames = modInfo->modNames();
      for (auto iter = modNames.begin(); iter != modNames.end(); ++iter) {
        std::wstring localPath = modInfo->getModPathW() + L"\\" + *iter + L"\\" + relativePath;
        if (addNtSearchData(localPath, FileName, FileInformationClass, buffer, bufferSize, result, foundFiles) != STATUS_NO_SUCH_FILE) {
          noSuchFile = false;
        }
      }
      queryMutex.lock();
      qdfData.insert(result);
      queryMutex.unlock();
    }

    ULONG offset = 0;

    boost::mutex::scoped_lock l(queryMutex);
    uint8_t *destination = nullptr;
    // ok, data available, return it
    while (qdfData[FileHandle].size() > 0) {
      const std::vector<uint8_t> &data = qdfData[FileHandle].front();
      if (data.size() < (Length - offset)) {
        ULONG size = data.size();
        destination = reinterpret_cast<uint8_t*>(FileInformation) + offset;
        memcpy(destination, &data[0], size);

        size = NextDividableBy(size, 8);
        memcpy(destination, &size, sizeof(ULONG));

        offset += (std::max<int>)(size, data.size()); // size is >= data.size except for the last element, so that after this loop offset contains the total data copied
        qdfData[FileHandle].pop_front();
        if (ReturnSingleEntry) {
          break;
        }
      } else {
        if (offset == 0) {
          // we didn't have space for a single entry
          return STATUS_BUFFER_OVERFLOW;
        }
        break;
      }
    }

    if (destination != nullptr) {
      ULONG zero = 0UL;
      memcpy(destination, &zero, sizeof(ULONG));
    }
    NTSTATUS res;

    if (noSuchFile) {
      res = STATUS_NO_SUCH_FILE;
    } else if ((qdfData[FileHandle].size() > 0) || (offset > 0)) {
      res = STATUS_SUCCESS;
    } else {
      res = STATUS_NO_MORE_FILES;
    }
    IoStatusBlock->Status = res;
    IoStatusBlock->Information = offset;
    return res;
  } else {
    return NtQueryDirectoryFile_reroute(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
                                        Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
  }
}


std::vector<ApiHook*> hooks;


#define INITHOOK(module, functionname) { ApiHook* temp = new ApiHook(module, #functionname, (void*)&functionname ## _rep); \
  functionname ## _reroute = reinterpret_cast<functionname ## _type>(temp->GetReroute()); \
  hooks.push_back(temp); }


BOOL InitHooks()
{
  LPCTSTR module = ::GetModuleHandle(TEXT("kernelbase.dll")) != nullptr ? TEXT("kernelbase.dll") : TEXT("kernel32");

  /*
  OSVERSIONINFO versionInfo;
  versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
  GetVersionEx(&versionInfo);
  */

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
    INITHOOK(TEXT("kernel32.dll"), GetModuleFileNameA);
    INITHOOK(TEXT("kernel32.dll"), GetModuleFileNameW);
    INITHOOK(TEXT("Shell32.dll"), SHFileOperationA);
    INITHOOK(TEXT("Shell32.dll"), SHFileOperationW);
    INITHOOK(TEXT("version.dll"), GetFileVersionInfoW);
    INITHOOK(TEXT("version.dll"), GetFileVersionInfoSizeW);

    INITHOOK(TEXT("ntdll.dll"), NtQueryDirectoryFile);

    OSVERSIONINFOEX versionInfo;
    versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    versionInfo.dwMajorVersion = 6;
    ULONGLONG mask = ::VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL);

    if (::VerifyVersionInfo(&versionInfo, VER_MAJORVERSION, mask)) {
    //if (versionInfo.dwMajorVersion >= 6) { // vista and up
      INITHOOK(TEXT("version.dll"), GetFileVersionInfoExW);
    }

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
    char res = (char)strtol(temp, nullptr, 16);
    result += res;
  }
  return result;
}


std::wstring iniDecode(const char *stringEncoded)
{
  std::string resultUTF8;
  bool escaped = false;
  for (const char *pntPtr = stringEncoded; *pntPtr != '\0'; ++pntPtr) {
    if (!escaped && (strncmp(pntPtr, "\\x", 2) == 0)) {
      pntPtr += 2;
      int numeric = strtol(pntPtr, nullptr, 16);
      resultUTF8.push_back(static_cast<char>(numeric));
      ++pntPtr;
    } else {
      resultUTF8.push_back(*pntPtr);
      if (escaped) {
        escaped = false;
      } else if (*pntPtr == '\\') {
        escaped = true;
      }
    }
  }
  return ToWString(resultUTF8, true);
}


BOOL SetUp(const std::wstring &iniName, const wchar_t *profileNameIn, const std::wstring &moPath, const std::wstring &moDataPath)
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

  std::vector<std::wstring> iniFiles = GameInfo::instance().getIniFileNames();
  for (auto iter = iniFiles.begin(); iter != iniFiles.end(); ++iter) {
    iniFilesA.insert(ToString(ToLower(*iter), false));
  }

  Logger::Instance().info("using profile %ls", profileName.c_str());

  try {
    modInfo = new ModInfo(profileName, true, moPath, moDataPath);
  } catch (const std::exception &e) {
    Logger::Instance().error("failed to initialize vfs: %s", e.what());
    return FALSE;
  }

  if (!FileExists(modInfo->getProfilePath().c_str())) {
    Logger::Instance().error("profile not found at %ls", modInfo->getProfilePath().c_str());
    return FALSE;
  }

  if (!FileExists(modInfo->getModPathW().c_str())) {
    Logger::Instance().error("mod directory not found at %ls", modInfo->getModPathW().c_str());
    return FALSE;
  }

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


BOOL SetUpBSAMap(bool fallout)
{
  if (fallout) {
    LOGDEBUG("will apply fallout specific workaround");
  }

  std::wostringstream archiveFileName;
  archiveFileName << modInfo->getProfilePath() << L"\\archives.txt";

  std::fstream file(ToString(archiveFileName.str(), false).c_str());
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

    Logger::Instance().info("\"%s\" maps to \"%s\"", shortName, buffer);
    bsaMap[shortName] = buffer;
    if (fallout) {
      usedBSAList.insert(ToLower(buffer));
    }
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


void SetUpBlacklist()
{
  std::ifstream blacklistFile(ToString(modInfo->getMOPath(), false) + "\\process_blacklist.txt", std::ifstream::in);
  if (blacklistFile.is_open()) {
    char buffer[MAX_PATH];
    while (blacklistFile.getline(buffer, MAX_PATH)) {
      processBlacklist.insert(ToLower(buffer));
    }

    blacklistFile.close();
  } else {
    std::list<std::string> temp = { "steam.exe", "steamerrorreporter.exe", "chrome.exe", "firefox.exe", "opera.exe" };
    processBlacklist = std::set<std::string>(temp.begin(), temp.end());
  }
}


void RemoveHooks()
{
  if (hooks.size() > 0) {
    for (std::vector<ApiHook*>::iterator iter = hooks.begin(); iter != hooks.end(); ++iter) {
      delete *iter;
    }
    hooks.clear();
    LOGDEBUG("hooks removed");
  }
}


void writeMiniDump(PEXCEPTION_POINTERS exceptionPtrs)
{
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
      if (::GetModuleFileNameW(dllModule, dmpPath, MAX_PATH_UNICODE) == 0) {
        Logger::Instance().error("No crash dump created, failed to determine destination directory. errorcode: %lu", ::GetLastError());
        return;
      }
      wcscat(dmpPath, L".dmp");

      HANDLE dumpFile = ::CreateFileW_reroute(dmpPath,
                                     GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (dumpFile != INVALID_HANDLE_VALUE) {
        _MINIDUMP_EXCEPTION_INFORMATION exceptionInfo;
        exceptionInfo.ThreadId = ::GetCurrentThreadId();
        exceptionInfo.ExceptionPointers = exceptionPtrs;
        exceptionInfo.ClientPointers = false;

        BOOL success = funcDump(::GetCurrentProcess(), ::GetCurrentProcessId(), dumpFile, MiniDumpNormal, &exceptionInfo, nullptr, nullptr);

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
}


std::set<HANDLE> previousHits;

LONG WINAPI VEHandler(PEXCEPTION_POINTERS exceptionPtrs)
{
  DWORD start, end;
  GetSectionRange(&start, &end, dllModule);

  if (((DWORD)exceptionPtrs->ExceptionRecord->ExceptionAddress < start) ||
      ((DWORD)exceptionPtrs->ExceptionRecord->ExceptionAddress > end)) {
    // origin isn't the hook-dll
    if (
        (exceptionPtrs->ExceptionRecord->ExceptionCode >= 0x80000000)     // only "warnings"
        && (exceptionPtrs->ExceptionRecord->ExceptionCode != 0xe06d7363)  // C++ exception, may be handled in code
        && (previousHits.find(exceptionPtrs->ExceptionRecord->ExceptionAddress) == previousHits.end())
        ) {
      std::wstring modName = GetSectionName(exceptionPtrs->ExceptionRecord->ExceptionAddress);
      Logger::Instance().info("Windows Exception (%x). Origin: \"%ls\" (%x). Last hooked call: %s",
                              exceptionPtrs->ExceptionRecord->ExceptionCode,
                              modName.c_str(),
                              exceptionPtrs->ExceptionRecord->ExceptionAddress,
                              s_LastFunction);
      previousHits.insert(exceptionPtrs->ExceptionRecord->ExceptionAddress);
    }
    return EXCEPTION_CONTINUE_SEARCH;
  } else {
    if ((exceptionPtrs->ExceptionRecord->ExceptionFlags != EXCEPTION_NONCONTINUABLE) ||
        (exceptionPtrs->ExceptionRecord->ExceptionCode == 0xe06d7363)) {
      // don't want to break on non-critical exceptions. 0xe06d7363 indicates a C++ exception. why are those marked non-continuable?
      Logger::Instance().info("Windows Exception (%x). Last hooked call: %s",
                              exceptionPtrs->ExceptionRecord->ExceptionCode, s_LastFunction);
    }

    if (exceptionPtrs->ExceptionRecord->ExceptionCode == 0xC0000005) {
      Logger::Instance().error("This is a critical error, the application will probably crash now.");
      RemoveHooks();

      writeMiniDump(exceptionPtrs);

      if (exceptionHandler != nullptr) {
        ::RemoveVectoredExceptionHandler(exceptionHandler);
      }
    }

    return EXCEPTION_CONTINUE_SEARCH;
  }
}

std::wstring getMODataPath(const std::wstring &moPath)
{
  std::wifstream instanceFile(ToString(moPath, false) + "\\INSTANCE");
  std::wstring instancePath;
  if (instanceFile.is_open()) {
    wchar_t buffer[MAX_PATH];
    instanceFile.getline(buffer, MAX_PATH);
    instanceFile.close();
    instancePath = buffer;
  }

  if (instancePath.length() != 0) {
    wchar_t appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, appDataPath))) {
      return std::wstring(appDataPath) + L"\\ModOrganizer\\" + instancePath;
    }
  }
  return moPath;
}


BOOL Init(int logLevel, const wchar_t *profileName)
{
  if (modInfo != nullptr) {
    // already initialised
    return TRUE;
  }

  sLogLevel = logLevel;

  wchar_t mutexName[101];
  _snwprintf(mutexName, 100, L"mo_dll_%d", ::GetCurrentProcessId());
  mutexName[100] = '\0';
  instanceMutex = ::CreateMutexW(nullptr, FALSE, mutexName);
  if ((instanceMutex == nullptr) || (::GetLastError() == ERROR_ALREADY_EXISTS)) {
    return TRUE;
  }

  wchar_t pathBuffer[MAX_PATH_UNICODE];
  {
    if (::GetModuleFileNameW(dllModule, pathBuffer, MAX_PATH_UNICODE) == 0) {
      MessageBox(nullptr, TEXT("failed to determine mo path"), TEXT("initialisation failed"), MB_OK);
      return TRUE;
    }

    wchar_t *temp = wcsrchr(pathBuffer, L'\\');
    if (temp != nullptr) {
      *temp = L'\0';
    } else {
      MessageBox(nullptr, TEXT("failed to determine mo path"), TEXT("initialisation failed"), MB_OK);
      return TRUE;
    }

    // initialised once we know where mo is installed
    {
      // if a file called mo_path exists in the same directory as the dll, it overrides the
      // path to the mod organizer
      std::string hintFileName = ToString(pathBuffer, false);
      hintFileName.append("\\mo_path.txt");
      std::wifstream hintFile(hintFileName.c_str(), std::ifstream::in);
      if (hintFile.is_open()) {
        hintFile.getline(pathBuffer, MAX_PATH_UNICODE);
        hintFile.close();
      }
    }
  }
  std::wstring moPath(pathBuffer);
  std::wstring moDataPath = getMODataPath(moPath);

  std::wstring logFile = moDataPath + L"\\" + AppConfig::logPath() + L"\\" + AppConfig::logFileName();
#ifdef UNICODE
  Logger::Init(logFile.c_str(), logLevel);
#else
  Logger::Init(ToString(logFile, false).c_str(), logLevel);
#endif

  // initialised once we know where mo is installed
  std::wostringstream iniName;
  try {
    iniName << moDataPath << "\\" << AppConfig::iniFileName();

    wchar_t pathTemp[MAX_PATH];
    wchar_t gamePath[MAX_PATH];
    ::GetPrivateProfileStringW(L"General", L"gamePath", L"", pathTemp, MAX_PATH, iniName.str().c_str());
    Canonicalize(gamePath, iniDecode(ToString(pathTemp, false).c_str()).c_str());

    if (!GameInfo::init(moPath, moDataPath, gamePath)) {
      throw std::runtime_error("game not found");
    }
  } catch (const std::exception &e) {
    ::MessageBoxA(nullptr, e.what(), "initialisation failed", MB_OK);
    return TRUE;
  }
  exceptionHandler = ::AddVectoredExceptionHandler(0, VEHandler);

  OSVERSIONINFOEX versionInfo;
  ZeroMemory(&versionInfo, sizeof(OSVERSIONINFOEX));
  versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
  ::GetVersionEx((OSVERSIONINFO*)&versionInfo);
  winXP = (versionInfo.dwMajorVersion == 5) && (versionInfo.dwMinorVersion == 1);
  Logger::Instance().info("Windows %d.%d (%s)",
                          versionInfo.dwMajorVersion,
                          versionInfo.dwMinorVersion,
                          versionInfo.wProductType == VER_NT_WORKSTATION ? "workstation"
                                                                         : "server");
  ::GetModuleFileNameW(dllModule, pathBuffer, MAX_PATH_UNICODE);
  VS_FIXEDFILEINFO version = GetFileVersion(pathBuffer);
  Logger::Instance().info("hook.dll v%d.%d.%d",
                          version.dwFileVersionMS >> 16,
                          version.dwFileVersionMS & 0xFFFF,
                          version.dwFileVersionLS >> 16);

  Logger::Instance().info("Code page: %ld", GetACP());

  wchar_t filename[MAX_PATH];
  ::GetModuleFileNameW(nullptr, filename, MAX_PATH);
  Logger::Instance().info("injecting to %ls", filename);

  LPCWSTR baseName = ::GetBaseName(filename);

  bool fallout = StartsWith(baseName, L"fallout");

  if (!SetUp(iniName.str(), profileName, moPath, moDataPath)) {
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

  if (!SetUpBSAMap(fallout)) {
    Logger::Instance().error("failed to set up list of bsas");
    return FALSE;
  }
  SetUpBlacklist();

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
  LPVOID tlsData;
  switch (reasonForCall) {
    case DLL_PROCESS_ATTACH: {
      dllModule = module;
    } break;
    case DLL_PROCESS_DETACH: {
      RemoveHooks();
      //TProfile::displayProfile();

      delete modInfo;
      modInfo = nullptr;
    } break;
    case DLL_THREAD_ATTACH: {
      tlsData = ::InitTLS();
    } break;
    case DLL_THREAD_DETACH: {
      tlsData = ::TlsGetValue(tlsIndex);
      if (tlsData != nullptr) {
        ::LocalFree((HLOCAL)tlsData);
      }
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
