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


#include "StdAfx.h"
#include "modinfo.h"
#include "logger.h"
#include "reroutes.h"
#include "utility.h"
#include "profile.h"
#include "hooklock.h"
#include <gameinfo.h>
#include <appconfig.h>
#ifdef __GNUC__
#include <cstdlib>
#endif
#include <ctime>
#include <util.h>
#include <iterator>
#include <Shlwapi.h>
#include <fstream>
#include <sstream>
#include <algorithm>


using namespace MOShared;


extern WCHAR dataPathAbsoluteW[MAX_PATH];
extern char dataPathAbsoluteA[MAX_PATH];


/*bool FileExists(std::wstring filename)
{
  WIN32_FIND_DATAW findData;
  ZeroMemory(&findData, sizeof(WIN32_FIND_DATAW));

  HANDLE search = FindFirstFileExW(filename.c_str(), FindExInfoStandard, &findData, FindExSearchNameMatch, NULL, 0);
  if (search == INVALID_HANDLE_VALUE) {
    return false;
  } else {
    FindClose(search);
    return true;
  }
}*/


bool FileExists_reroute(std::wstring filename)
{
  WIN32_FIND_DATAW findData;
  ZeroMemory(&findData, sizeof(WIN32_FIND_DATAW));

  HANDLE search = INVALID_HANDLE_VALUE;
  if (FindFirstFileExW_reroute != NULL) {
    search = FindFirstFileExW_reroute(filename.c_str(), FindExInfoStandard, &findData, FindExSearchNameMatch, NULL, 0);
  } else {
    search = FindFirstFileExW(filename.c_str(), FindExInfoStandard, &findData, FindExSearchNameMatch, NULL, 0);
  }
  if (search == INVALID_HANDLE_VALUE) {
    return false;
  } else {
    FindClose(search);
    return true;
  }
}


typedef DWORD (WINAPI *GetFinalPathNameByHandleW_type)(HANDLE, LPCWSTR, DWORD, DWORD);


ModInfo::ModInfo(const std::wstring &profileName, const std::wstring &modDirectory, bool enableHiding)
  : m_ProfileName(profileName), m_ModsPath(modDirectory), m_CurrentDirectory(), m_DirectoryStructure(L"data", NULL, 0), m_ModCount(0),
    m_SavesReroute(false)

{
  // modlist
  std::wostringstream temp;
  temp << GameInfo::instance().getProfilesDir() << "\\" << profileName;
  m_ProfilePath = temp.str();

  m_TweakedIniPathW = m_ProfilePath + L"\\initweaks.ini";
  m_TweakedIniPathA = ToString(m_TweakedIniPathW, false);

  if (!::FileExists_reroute(m_TweakedIniPathW)) {
    Logger::Instance().info("no ini tweaks file");
  }

  m_ModListPath = m_ProfilePath.substr().append(L"\\modlist.txt");

  {
    wchar_t buffer[MAX_PATH];
    Canonicalize(buffer, (GameInfo::instance().getGameDirectory() + L"\\data").c_str());
    m_DataPathAbsoluteW = buffer;
  }

  m_DataPathAbsoluteA = ToString(m_DataPathAbsoluteW, false);

  HANDLE dataDir = ::CreateFileW(m_DataPathAbsoluteW.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (dataDir == INVALID_HANDLE_VALUE) {
    LOGDEBUG("invalid handle: %d - %ls", ::GetLastError(), m_DataPathAbsoluteW.c_str());
  }

  { // see if there is a potential alternative game path
    WCHAR buffer[MAX_PATH];
    WCHAR *finalPath = buffer;

    HMODULE kernel32Handle = ::GetModuleHandle(TEXT("kernel32.dll"));
    GetFinalPathNameByHandleW_type getFinalPathNameByHandleW = (GetFinalPathNameByHandleW_type)::GetProcAddress(kernel32Handle, "GetFinalPathNameByHandleW");
    if (getFinalPathNameByHandleW != NULL) {
      // vista and up, handle junction points
      DWORD res = getFinalPathNameByHandleW(dataDir, buffer, MAX_PATH, VOLUME_NAME_DOS);
      if (res != 0) {
        if (StartsWith(buffer, L"\\\\?\\")) {
          finalPath += 4;
        }
        if (_wcsicmp(finalPath, m_DataPathAbsoluteW.c_str()) != 0) {
          Logger::Instance().info("data path may be a junction to %ls", finalPath);
          m_DataPathAbsoluteAlternativeW = finalPath;

        }
      } else {
        Logger::Instance().error("failed to determine final path: %lu", ::GetLastError());
      }
    }

    if (m_DataPathAbsoluteAlternativeW.length() == 0) {
      std::wstring regPath = GameInfo::instance().getRegPath();
      if (!StartsWith(m_DataPathAbsoluteW.c_str(), regPath.c_str())) {
        regPath.append(L"\\data");
        wchar_t temp[MAX_PATH];
        Canonicalize(temp, regPath.c_str());
        m_DataPathAbsoluteAlternativeW = temp;
        Logger::Instance().info("data path from registry differs from configured game path: %ls", temp);
      }
    }
  }

  ::CloseHandle(dataDir);

  std::fstream file(m_ModListPath.c_str());
  if (!file.is_open()) {
    Logger::Instance().error("mod list \"%ls\" not found!", m_ModListPath.c_str());
    return;
  }

  LOGDEBUG("mods are in \"%ls\"", m_ModsPath.c_str());

  char buffer[1024];

  while (!file.eof()) {
    file.getline(buffer, 1024);
    if (buffer[0] == '\0') {
      continue;
    }
    if ((buffer[0] != '#') && (buffer[0] != '-')) {
      char *bufferPtr = buffer;
      if (*bufferPtr == '+') {
        ++bufferPtr;
      }
      temp.str(L""); temp.clear();
      temp << m_ModsPath << L"\\" << ToWString(bufferPtr, true);
      if (!FileExists(temp.str())) {
        Logger::Instance().error("mod \"%ls\" doesn't exist, maybe there is a typo?", temp.str().c_str());
      } else {
        Logger::Instance().info("using mod \"%s\"", bufferPtr);
        m_ModList.push_back(ToWString(bufferPtr, true));
      }
    }
  }
  file.close();
  int index = 1;

  // mod list is sorted by priority descending, hence the reverse iterator
  for (std::vector<std::wstring>::reverse_iterator modIter = m_ModList.rbegin(); modIter != m_ModList.rend(); ++modIter, ++index) {
    temp.str(L""); temp.clear();
    temp << m_ModsPath << "\\" << *modIter;
    m_DirectoryStructure.addFromOrigin(*modIter, temp.str(), index);

    WIN32_FIND_DATAW findData;
    std::wstring bsaSearch = temp.str().append(L"\\*.bsa");
    HANDLE search = ::FindFirstFileW(bsaSearch.c_str(), &findData);
    BOOL success = search != INVALID_HANDLE_VALUE;
    while (success) {
      std::wstring tempStr = temp.str();
      m_DirectoryStructure.addFromBSA(*modIter,
                                      tempStr,
                                      tempStr.append(L"\\").append(findData.cFileName),
                                      index);
      success = ::FindNextFileW(search, &findData);
    }
  }

  m_DirectoryStructure.addFromOrigin(L"overwrite", GameInfo::instance().getOverwriteDir(), index);

  temp.str(L""); temp.clear();
  temp << GameInfo::instance().getGameDirectory() << "\\data";
  m_DirectoryStructure.addFromOrigin(L"data", temp.str(), 0);

  m_DataOrigin = m_DirectoryStructure.getOriginByName(L"data").getID();

  if (enableHiding) {
    std::wstring hidePattern = m_ProfilePath.substr().append(L"\\hide_*.txt");
    WIN32_FIND_DATAW findData;
    HANDLE search = ::FindFirstFileW(hidePattern.c_str(), &findData);
    BOOL success = search != INVALID_HANDLE_VALUE;
    while (success) {
      loadDeleters(ToString(m_ProfilePath.substr().append(L"\\").append(findData.cFileName), false));
      success = ::FindNextFileW(search, &findData);
    }
    ::FindClose(search);
  }

  m_UpdateNotification = ::FindFirstChangeNotificationW(GameInfo::instance().getOverwriteDir().c_str(), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME);

  // dumpDirectoryStructure(&m_DirectoryStructure, 0);
}


ModInfo::~ModInfo()
{
  ::FindCloseChangeNotification(m_UpdateNotification);
}


bool ModInfo::detectOverwriteChange()
{
  if (::WaitForSingleObject(m_UpdateNotification, 0) == WAIT_OBJECT_0) {
    if (::FindNextChangeNotification(m_UpdateNotification)) {
      try {
        FilesOrigin &origin = m_DirectoryStructure.getOriginByName(L"overwrite");
        origin.enable(false);
        HookLock lock; // addFromOrigin uses FindFirstFileEx, rerouting that could be disastrous
        m_DirectoryStructure.addFromOrigin(L"overwrite", GameInfo::instance().getOverwriteDir(), origin.getPriority());
        return true;
      } catch (const std::exception &e) {
        Logger::Instance().error("failed to update overwrite directory: %s", e.what());
      }
    }
  }
  return false;
}


std::wstring ModInfo::reverseReroute(const std::wstring &path, bool *rerouted)
{
  std::wstring result;
  wchar_t temp[MAX_PATH];
  Canonicalize(temp, path.c_str());
  std::wstring overwriteDir = GameInfo::instance().getOverwriteDir();
  if (StartsWith(temp, m_ModsPath.c_str())) {
    wchar_t *relPath = temp + m_ModsPath.length();
    if (*relPath != L'\0') relPath += 1;
    // skip the mod name
    relPath = wcschr(relPath, L'\\');

    if (relPath != NULL) {
      Canonicalize(temp, (m_DataPathAbsoluteW + relPath).c_str());
      result.assign(temp);
    } else {
      result = m_DataPathAbsoluteW;
    }

    if (rerouted != NULL) *rerouted = true;
  } else if (StartsWith(temp, overwriteDir.c_str())) {
    wchar_t *relPath = temp + overwriteDir.length();
    if (*relPath != L'\0') relPath += 1;
    Canonicalize(temp, (m_DataPathAbsoluteW + relPath).c_str());
    result.assign(temp);

    if (rerouted != NULL) *rerouted = true;
  } else {
    result.assign(temp);
    if (rerouted != NULL) *rerouted = false;
  }
  return result;
}


bool ModInfo::setCwd(const std::wstring &currentDirectory)
{
  bool rerouted = false;
  m_CurrentDirectory = reverseReroute(currentDirectory, &rerouted);
  if (!rerouted && FileExists_reroute(m_CurrentDirectory.c_str())) {
    // regular un-rerouted setcwd
    m_CurrentDirectory.clear();
  }
  return !m_CurrentDirectory.empty();
}


void ModInfo::checkPathAlternative(LPCWSTR path)
{
  if (m_DataPathAbsoluteAlternativeW.length() != 0) {
    if (StartsWith(path, m_DataPathAbsoluteAlternativeW.c_str())) {
      m_DataPathAbsoluteW = m_DataPathAbsoluteAlternativeW;
      m_DataPathAbsoluteA = ToString(m_DataPathAbsoluteW, false);
      m_DataPathAbsoluteAlternativeW.clear();
      Logger::Instance().info("using alternative data path");
    } else if (StartsWith(path, m_DataPathAbsoluteW.c_str())) {
      m_DataPathAbsoluteAlternativeW.clear();
    }
  }
}


void ModInfo::addAlternativePath(const std::wstring &path)
{
  if ((m_DataPathAbsoluteAlternativeW.length() == 0) &&
      (!StartsWith(m_DataPathAbsoluteW.c_str(), path.c_str()))) {
    wchar_t temp[MAX_PATH];
    Canonicalize(temp, path.substr().append(L"\\data").c_str());
    if (FileExists(std::wstring(temp) + L"\\" + GameInfo::instance().getReferenceDataFile())) {
      m_DataPathAbsoluteAlternativeW = temp;
      Logger::Instance().info("executable path differs from data path: %ls", temp);
    }
  }
}


void ModInfo::dumpDirectoryStructure(const DirectoryEntry *directory, int indent)
{
  Logger::Instance().info("%*c[%ls]", indent, ' ', directory->getName().c_str());
  { // print files
    std::vector<FileEntry::Ptr> files = directory->getFiles();
    for (auto iter = files.begin(); iter != files.end(); ++iter) {
      bool ignore;
      Logger::Instance().info("%*c%ls - %ls", indent + 2, ' ', (*iter)->getName().c_str(),
                              m_DirectoryStructure.getOriginByID((*iter)->getOrigin(ignore)).getName().c_str());
    }
  }

  { // recurse into subdirectories
    std::vector<DirectoryEntry*>::const_iterator iter, end;
    directory->getSubDirectories(iter, end);
    for (; iter != end; ++iter) {
      dumpDirectoryStructure(*iter, indent + 2);
    }
  }
}


void ModInfo::loadDeleters(const std::string &listFileName)
{
  std::fstream file(listFileName.c_str());
  if (!file.is_open()) {
    Logger::Instance().error("blacklist \"%s\" not found!", listFileName.c_str());
    return;
  }
  char buffer[1024];
  wchar_t fileName[MAX_PATH];
#ifndef __GNUC__
  size_t Converted;
#endif

  while (!file.eof()) {
    file.getline(buffer, 1024);
    if ((buffer[0] == '\0') ||
        (buffer[0] == '#')) {
      continue;
    }
#ifdef __GNUC__
    mbstowcs(fileName, buffer, MAX_PATH);
#else
    mbstowcs_s(&Converted, fileName, MAX_PATH, buffer, _TRUNCATE);
#endif
    m_HiddenFiles.insert(fileName);

    m_DirectoryStructure.removeFile(fileName, NULL);
  }
}


void ModInfo::addModDirectory(const std::wstring& modPath)
{
  std::wstring name;
  size_t namePos = modPath.find_last_of(L"/\\");
  // TODO this fails if modPath ends with a backslash. How does the offset in find_last_of work?
  if (namePos != std::string::npos) {
    name = modPath.substr(namePos + 1);
  }
  m_DirectoryStructure.addFromOrigin(name, modPath, static_cast<int>(m_ModList.size()));
}


void ModInfo::addModFile(const std::wstring &fileName)
{
#ifdef DEBUG_LOG
  size_t offset = m_ModsPath.length() + m_ModList.rbegin()->length() + 2; // 2 (back-)slashes
  LOGDEBUG("add mod file %ls (%ls)", fileName.c_str(), fileName.substr(offset).c_str());
#endif // DEBUG_LOG
  FILETIME time;
  SYSTEMTIME now;
  GetSystemTime(&now);
  SystemTimeToFileTime(&now, &time);

  FilesOrigin& origin = m_DirectoryStructure.getOriginByName(fileName);
  m_DirectoryStructure.insertFile(fileName, origin, time);
}


void ModInfo::addOverwriteFile(const std::wstring &fileName)
{
  size_t offset = GameInfo::instance().getOverwriteDir().length() + 1;
  while ((fileName[offset] == '\\') || (fileName[offset] == '/')) {
    ++offset;
  }
#ifdef DEBUG_LOG
  LOGDEBUG("add overwrite file %ls (%ls)", fileName.c_str(), fileName.substr(offset).c_str());
#endif // DEBUG_LOG
  SYSTEMTIME now;
  GetSystemTime(&now);
  FILETIME time;
  SystemTimeToFileTime(&now, &time);
  FilesOrigin &origin = m_DirectoryStructure.getOriginByName(L"overwrite");
  m_DirectoryStructure.insertFile(fileName.substr(offset), origin, time);
}


void ModInfo::addRemoval(const std::wstring &fileName, int origin)
{
  time_t now = time(NULL);
  // first, remove outdated entries
  for (std::list<RemovalInfo>::const_iterator iter = m_RemovalInfo.begin(); iter != m_RemovalInfo.end();) {
    if (iter->time + 5 < now) {
      iter = m_RemovalInfo.erase(iter);
    } else {
      ++iter;
    }
  }

  WCHAR temp[MAX_PATH];
  getFullPathName(fileName.c_str(), temp, MAX_PATH);

  RemovalInfo newInfo;
  newInfo.origin = origin;
  newInfo.fileName.assign(temp);
  newInfo.time = now;
  m_RemovalInfo.push_back(newInfo);
}

std::wstring ModInfo::getRemovedLocation(const std::wstring &fileName)
{
  time_t now = time(NULL);
  for (std::list<RemovalInfo>::const_iterator iter = m_RemovalInfo.begin(); iter != m_RemovalInfo.end();) {
    if (iter->time + 5 < now) {
      iter = m_RemovalInfo.erase(iter);
    } else if (_wcsicmp(iter->fileName.c_str(), fileName.c_str()) == 0) {
      // got a hit!
      std::wostringstream fullPath;
      fullPath <<  m_DirectoryStructure.getOriginByID(iter->origin).getPath() << (fileName.c_str() + m_DataPathAbsoluteW.length());
      LOGDEBUG("using path from previous deletion: %ls", fullPath.str().c_str());
      return fullPath.str();
    } else {
      ++iter;
    }
  }
  return std::wstring();
}


void ModInfo::removeModFile(const std::wstring &fileName)
{
  WCHAR temp[MAX_PATH];
  getFullPathName(fileName.c_str(), temp, MAX_PATH);

  if ((StartsWith(temp, m_DataPathAbsoluteW.c_str())) &&
      (wcslen(temp) != m_DataPathAbsoluteW.length())) {
    int origin = -1;
    m_DirectoryStructure.removeFile(temp + m_DataPathAbsoluteW.length() + 1, &origin);
    addRemoval(fileName, origin);
    LOGDEBUG("remove mod file %ls", fileName.c_str());
  }

}


bool ModInfo::modExists(const std::wstring &modName)
{
  for (std::vector<std::wstring>::iterator iter = m_ModList.begin(); iter != m_ModList.end(); ++iter) {
    if (*iter == modName) {
      return true;
    }
  }
  return false;
}

void ModInfo::rewriteModList()
{
#ifndef __GNUC__
  size_t Converted;
#endif
  char modPath[MAX_PATH];
  std::ofstream file(m_ModListPath.c_str(), std::ios::trunc);
  for (std::vector<std::wstring>::iterator iter = m_ModList.begin(); iter != m_ModList.end(); ++iter) {
#ifdef __GNUC__
    wcstombs(modPath, iter->c_str(), MAX_PATH);
#else
    wcstombs_s(&Converted, modPath, MAX_PATH, iter->c_str(), _TRUNCATE);
#endif
    file << modPath << std::endl;
  }
}


void ModInfo::appendMod(LPCWSTR modName)
{
  m_ModList.push_back(modName);
  rewriteModList();
}


std::wstring ModInfo::getCurrentDirectory()
{
  return m_CurrentDirectory;
}


void ModInfo::addSearchResult(SearchBuffer& searchBuffer, LPCWSTR directory, WIN32_FIND_DATAW& searchData)
{
  WCHAR buffer[MAX_PATH];
  if (directory[0] != L'\0') {
    _snwprintf(buffer, MAX_PATH, L"%ls\\%ls", directory, searchData.cFileName);
    if (m_HiddenFiles.find(buffer) == m_HiddenFiles.end()) {
      searchBuffer.insert(searchData);
    }
  } else {
    if (m_HiddenFiles.find(searchData.cFileName) == m_HiddenFiles.end()) {
      searchBuffer.insert(searchData);
    }
  }
}


void ModInfo::addSearchResults(SearchBuffer& searchBuffer, HANDLE& primaryHandle, HANDLE searchHandle, LPCWSTR directory, WIN32_FIND_DATAW& searchData)
{
  if (primaryHandle == INVALID_HANDLE_VALUE) {
    primaryHandle = searchHandle;
  }

  addSearchResult(searchBuffer, directory, searchData);

  ::ZeroMemory(&searchData, sizeof(WIN32_FIND_DATAW));
  while (FindNextFileW_reroute(searchHandle, &searchData)) {
    addSearchResult(searchBuffer, directory, searchData);
  }
}

bool LessThanDate(const WIN32_FIND_DATAW& lhs, const WIN32_FIND_DATAW& rhs) {
  return ::CompareFileTime(&lhs.ftCreationTime, &rhs.ftCreationTime) < 0;
}


bool LessThanName(const WIN32_FIND_DATAW& lhs, const WIN32_FIND_DATAW& rhs) {
  return wcscmp(lhs.cFileName, rhs.cFileName) < 0;
}


HANDLE ModInfo::dataSearch(LPCWSTR absoluteFileName,
                           size_t filenameOffset,
                           HANDLE dataHandle,
                           WIN32_FIND_DATAW &searchData,
                           FINDEX_INFO_LEVELS fInfoLevelId,
                           FINDEX_SEARCH_OPS fSearchOp,
                           LPVOID lpSearchFilter,
                           DWORD dwAdditionalFlags)
{
  // path component relative to the data directory
  const wchar_t* slashPos = wcsrchr(absoluteFileName, L'\\');
  if (slashPos == NULL) {
    slashPos = wcsrchr(absoluteFileName, L'/');
  }
  WCHAR relativePath[MAX_PATH];

  if (slashPos != NULL) {
    size_t length = std::min<size_t>(static_cast<size_t>(slashPos - absoluteFileName - filenameOffset), MAX_PATH);
    if (length > 0) {
      wcsncpy(relativePath, absoluteFileName + filenameOffset, length);
      relativePath[length] = L'\0';
    } else {
      relativePath[0] = L'\0';
    }
  } else {
    relativePath[0] = L'\0';
  }

  HANDLE primaryHandle = INVALID_HANDLE_VALUE;

  SearchBuffer searchBuffer;
  // add all elements of the vanilla data-directory
  if (dataHandle != INVALID_HANDLE_VALUE) {
    addSearchResults(searchBuffer, primaryHandle, dataHandle, relativePath, searchData);
  }

  // add elements from the mod directories
  for (std::vector<std::wstring>::iterator iter = m_ModList.begin(); iter != m_ModList.end(); ++iter) {
    std::wostringstream fullPath;
    fullPath << m_ModsPath << "\\" << *iter << (absoluteFileName + filenameOffset);
    ::ZeroMemory(&searchData, sizeof(WIN32_FIND_DATAW));
    dataHandle = FindFirstFileExW_reroute(fullPath.str().c_str(), fInfoLevelId, &searchData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    if (dataHandle != INVALID_HANDLE_VALUE) {
      addSearchResults(searchBuffer, primaryHandle, dataHandle, relativePath, searchData);
      if (primaryHandle != dataHandle) {
        // close the search handle unless it's the primary handle
        FindClose_reroute(dataHandle);
      }
    }
  }

  // and the overwrite folder too
  {
    std::wostringstream fullPath;
    fullPath << GameInfo::instance().getOverwriteDir() << "\\" << (absoluteFileName + filenameOffset);
    ::ZeroMemory(&searchData, sizeof(WIN32_FIND_DATAW));
    dataHandle = FindFirstFileExW_reroute(fullPath.str().c_str(), fInfoLevelId, &searchData, fSearchOp, lpSearchFilter, dwAdditionalFlags);

    if (dataHandle != INVALID_HANDLE_VALUE) {
      addSearchResults(searchBuffer, primaryHandle, dataHandle, relativePath, searchData);
    }
  }

  // if no search result, close the primary handle too
  if ((primaryHandle == INVALID_HANDLE_VALUE) &&
      (searchBuffer.empty())) {
    // all search results filtered
    FindClose_reroute(primaryHandle);
    primaryHandle = INVALID_HANDLE_VALUE;
  }

  if (primaryHandle != INVALID_HANDLE_VALUE) {
    // copy search results to buffer
    m_Searches[primaryHandle].first = SearchResult();
    std::copy(searchBuffer.begin(), searchBuffer.end(), std::back_inserter(m_Searches[primaryHandle].first));
    std::sort(m_Searches[primaryHandle].first.begin(), m_Searches[primaryHandle].first.end(), LessThanName);
    m_Searches[primaryHandle].second = m_Searches[primaryHandle].first.begin();
  }

  return primaryHandle;
}


HANDLE ModInfo::findStart(LPCWSTR lpFileName,
                          FINDEX_INFO_LEVELS fInfoLevelId,
                          LPVOID lpFindFileData,
                          FINDEX_SEARCH_OPS fSearchOp,
                          LPVOID lpSearchFilter,
                          DWORD dwAdditionalFlags)
{
  WCHAR temp[MAX_PATH];
  getFullPathName(lpFileName, temp, MAX_PATH);
  FileEntry::Ptr file;
  if (StartsWith(temp, m_DataPathAbsoluteW.c_str())) {
    file = m_DirectoryStructure.searchFile(temp + m_DataPathAbsoluteW.length() + 1, NULL);
  }
  if (file.get() != NULL) {
    // early out if the pattern is a single file because we can find it in-memory
    return FindFirstFileExW_reroute(file->getFullPath().c_str(), fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
  } else {
    WIN32_FIND_DATAW tempData;
    ::ZeroMemory(&tempData, sizeof(WIN32_FIND_DATAW));
    HANDLE searchHandle = FindFirstFileExW_reroute(lpFileName, fInfoLevelId, &tempData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    // search pattern with full absolute path
    WCHAR absoluteFileName[MAX_PATH];
    getFullPathName(lpFileName, absoluteFileName, MAX_PATH);

    size_t filenameOffset = 0;
    if ((StartsWith(absoluteFileName, m_DataPathAbsoluteW.c_str())) &&
        ((absoluteFileName[m_DataPathAbsoluteW.length()] == '\\') ||
         (absoluteFileName[m_DataPathAbsoluteW.length()] == '/'))) {
      filenameOffset = m_DataPathAbsoluteW.length();
    } else {
      *reinterpret_cast<LPWIN32_FIND_DATAW>(lpFindFileData) = tempData;
      return searchHandle;
    }

    HANDLE handle = dataSearch(absoluteFileName, filenameOffset, searchHandle,
                      tempData, fInfoLevelId, fSearchOp,
                      lpSearchFilter, dwAdditionalFlags);

    if (handle != INVALID_HANDLE_VALUE) {
      // if there were results, add them to our buffer
      findNext(handle, (LPWIN32_FIND_DATAW)lpFindFileData);
      ::SetLastError(ERROR_SUCCESS);
    } else {
      ::SetLastError(ERROR_FILE_NOT_FOUND);
    }
    return handle;
  }
}


BOOL ModInfo::findNext(HANDLE handle, LPWIN32_FIND_DATAW findFileData)
{
  SearchesMap::iterator Iter = m_Searches.find(handle);
  if (Iter != m_Searches.end()) {
    std::pair<SearchResult, SearchResult::iterator> &search = Iter->second;
    if (search.second != search.first.end()) {
      *findFileData = *(search.second);
      ++search.second;
      return true;
    } else {
      ::SetLastError(ERROR_NO_MORE_FILES);
      return false;
    }
  } else {
    ::SetLastError(ERROR_NO_MORE_FILES);
    return false;
  }
}


BOOL ModInfo::findClose(HANDLE handle)
{
  SearchesMap::iterator Iter = m_Searches.find(handle);
  if (Iter != m_Searches.end()) {
    m_Searches.erase(Iter);
  }

  return FindClose_reroute(handle);
}


BOOL ModInfo::searchExists(HANDLE handle)
{
  return m_Searches.find(handle) != m_Searches.end();
}


const std::string &ModInfo::getTweakedIniA() const
{
  return m_TweakedIniPathA;
}


const std::wstring &ModInfo::getTweakedIniW() const
{
  return m_TweakedIniPathW;
}


std::string ModInfo::getRerouteOpenExisting(LPCSTR originalName)
{
  std::wstring temp = getRerouteOpenExisting(ToWString(originalName, false).c_str());
  return ToString(getRerouteOpenExisting(temp.c_str()), false);
}


void ModInfo::getFullPathName(LPCWSTR originalName, LPWSTR targetBuffer, size_t bufferLength)
{
  WCHAR temp[MAX_PATH];
  if (m_CurrentDirectory.length() != 0) {
    WCHAR cwd[MAX_PATH];
    DWORD length = ::GetCurrentDirectoryW_reroute(MAX_PATH, cwd);
    if (StartsWith(originalName, cwd)) {
      _snwprintf(temp, bufferLength, L"%ls\\%ls", m_CurrentDirectory.c_str(), originalName + static_cast<size_t>(length));
    } else {
      ::PathCombineW(temp, m_CurrentDirectory.c_str(), originalName);
    }
  } else {
    ::GetFullPathNameW_reroute(originalName, static_cast<DWORD>(bufferLength), temp, NULL);
  }
  checkPathAlternative(temp);
  ::Canonicalize(targetBuffer, temp);
}


std::wstring ModInfo::getRerouteOpenExisting(LPCWSTR originalName, bool preferOriginal, bool *rerouted)
{
  PROFILE_S();

  if (rerouted != NULL) {
    *rerouted = false;
  }

  WCHAR temp[MAX_PATH];
  getFullPathName(originalName, temp, MAX_PATH);
  std::wstring result;
  LPCWSTR baseName = GetBaseName(temp);
  LPCWSTR sPos = NULL;
  if (GameInfo::instance().rerouteToProfile(baseName, originalName)) {
    result = m_ProfilePath.substr().append(L"\\").append(baseName);
    if (rerouted != NULL) {
      *rerouted = true;
    }
  } else if ((sPos = wcswcs(temp, AppConfig::localSavePlaceholder())) != NULL) {
    m_SavesReroute = true;
    result = m_ProfilePath.substr().append(L"\\saves\\").append(sPos + wcslen(AppConfig::localSavePlaceholder()));
    if (rerouted != NULL) {
      *rerouted = true;
    }
  } else if (m_SavesReroute && EndsWith(temp, L".skse") && ((sPos = wcswcs(temp, L"\\My Games\\Skyrim\\Saves\\")) != NULL)) {
    // !workaround! skse saving to hard-coded path
    result = m_ProfilePath.substr().append(L"\\saves\\").append(sPos + 23);
    if (rerouted != NULL) {
      *rerouted = true;
    }
  } else if ((StartsWith(temp, m_DataPathAbsoluteW.c_str())) &&
             (wcslen(temp) != m_DataPathAbsoluteW.length())) {
    if (!preferOriginal || !FileExists_reroute(temp)) {
      int origin = 0;
      result = getPath(temp, m_DataPathAbsoluteW.length(), origin);
      if (result.size() == 0) {
        result = originalName;
      } else {
        // it's not rerouted if the file comes from data directory
        if ((rerouted != NULL) && (origin != m_DataOrigin)) {
          *rerouted = true;
        }
      }
    } else {
      result = originalName;
    }
  } else {
    result = originalName;
  }
  return result;
}


std::wstring ModInfo::getPath(LPCWSTR originalName, size_t offset, int &origin)
{
  detectOverwriteChange();
  bool archive = false;
  origin = m_DirectoryStructure.getOrigin(originalName + offset + 1, archive);
  if (archive) {
    LOGDEBUG("using %ls from archive", originalName);
    return std::wstring();
  } else if (origin == -1) {
    return std::wstring();
  } else {
    std::wostringstream fullPath;
    fullPath <<  m_DirectoryStructure.getOriginByID(origin).getPath() << (originalName + offset);
    if (m_ModAccess.find(origin) == m_ModAccess.end()) {
      Logger::Instance().debug("first access to %s", ToString( m_DirectoryStructure.getOriginByID(origin).getName(), true).c_str());
      m_ModAccess.insert(origin);
    }
    return fullPath.str();
  }
}

/* BROKEN AND OBSOLETE
std::wstring ModInfo::getValidPath(LPCWSTR path, size_t offset)
{
  WCHAR buffer[MAX_PATH + 1];
  memset(buffer, 0, sizeof(WCHAR) * (MAX_PATH + 1));

  LPCWSTR endPtr = path + wcslen(path);

  std::wostringstream result;
  offset += wcsspn(path + offset, L"\\/");
  wcsncpy(buffer, path, offset);
  result << buffer;
  path += offset;

  DirectoryEntry *dirEntry = &m_DirectoryStructure;
  bool first = true;

  while ((dirEntry != NULL) && (path < endPtr)) {
    size_t len = wcscspn(path, L"\\/");
    memset(buffer, 0, sizeof(WCHAR) + (MAX_PATH + 1));
    wcsncpy(buffer, path, len);
    dirEntry = dirEntry->findSubDirectory(buffer);
    if (dirEntry != NULL) {
      if (!first) {
        result << "\\";
      } else {
        first = false;
      }
      result << buffer;
    }
    path += len + 1;
  }
  return result.str();
}*/
