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
#include <Shlobj.h>
#include <Shlwapi.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <boost/scoped_array.hpp>


using namespace MOShared;


extern WCHAR dataPathAbsoluteW[MAX_PATH];
extern char dataPathAbsoluteA[MAX_PATH];


bool FileExists_reroute(const std::wstring &filename)
{
  WIN32_FIND_DATAW findData;
  ZeroMemory(&findData, sizeof(WIN32_FIND_DATAW));

  HANDLE search = INVALID_HANDLE_VALUE;
  search = FindFirstFileExW_reroute(filename.c_str(), FindExInfoStandard, &findData, FindExSearchNameMatch, nullptr, 0);

  if (search == INVALID_HANDLE_VALUE) {
    return false;
  } else {
    FindClose(search);
    return true;
  }
}


typedef DWORD (WINAPI *GetFinalPathNameByHandleW_type)(HANDLE, LPCWSTR, DWORD, DWORD);


ModInfo::ModInfo(const std::wstring &profileName, bool enableHiding, const std::wstring &moPath, const std::wstring &moDataPath)
  : m_ProfileName(profileName)
  , m_CurrentDirectory()
  , m_MOPathW(moPath)
  , m_MODataPathW(moDataPath)
  , m_DirectoryStructure(L"data", nullptr, 0)
  , m_ModCount(0)
  , m_SavesReroute(false)
{
  m_ProfilePath = m_MODataPathW + L"\\" + AppConfig::profilesPath() + L"\\" + profileName;
  m_OverwritePathW = m_MODataPathW + L"\\" + AppConfig::overwritePath();

  {
    wchar_t temp[MAX_PATH];

    ::GetPrivateProfileStringW(L"Settings", L"mod_directory",
                               (m_MODataPathW + L"\\" + AppConfig::modsPath()).c_str(),
                               temp, MAX_PATH, (m_MODataPathW + L"\\" + AppConfig::iniFileName()).c_str());

    wchar_t modDirectory[MAX_PATH];
    Canonicalize(modDirectory, temp);

    m_ModsPath = modDirectory;
  }

  m_TweakedIniPathW = m_ProfilePath + L"\\initweaks.ini";
  m_TweakedIniPathA = ToString(m_TweakedIniPathW, false);

  if (!::FileExists_reroute(m_TweakedIniPathW)) {
    Logger::Instance().info("no ini tweaks file");
  }

  m_ModListPath = m_ProfilePath + L"\\modlist.txt";

  {
    wchar_t buffer[MAX_PATH];
    Canonicalize(buffer, (GameInfo::instance().getGameDirectory() + L"\\data").c_str());
    m_DataPathAbsoluteW = buffer;
  }

  m_DataPathAbsoluteA = ToString(m_DataPathAbsoluteW, false);
  Logger::Instance().info("data path is %ls", m_DataPathAbsoluteW.c_str());
  HANDLE dataDir = ::CreateFileW(m_DataPathAbsoluteW.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (dataDir == INVALID_HANDLE_VALUE) {
    LOGDEBUG("invalid handle: %d - %ls", ::GetLastError(), m_DataPathAbsoluteW.c_str());
  }

  { // see if there is a potential alternative game path
    WCHAR buffer[MAX_PATH];
    WCHAR *finalPath = buffer;

    HMODULE kernel32Handle = ::GetModuleHandle(TEXT("kernel32.dll"));
    GetFinalPathNameByHandleW_type getFinalPathNameByHandleW = (GetFinalPathNameByHandleW_type)::GetProcAddress(kernel32Handle, "GetFinalPathNameByHandleW");
    if (getFinalPathNameByHandleW != nullptr) {
      // vista and up, handle junction points
      DWORD res = getFinalPathNameByHandleW(dataDir, buffer, MAX_PATH, VOLUME_NAME_DOS);
      if (res != 0) {
        if (StartsWith(buffer, L"\\\\?\\")) {
          finalPath += 4;
        }
        if (_wcsicmp(finalPath, m_DataPathAbsoluteW.c_str()) != 0) {
          Logger::Instance().info("data path may also be a junction to %ls", finalPath);
          m_DataPathAbsoluteAlternativeW = finalPath;

        }
      } else {
        Logger::Instance().error("failed to determine final path: %lu", ::GetLastError());
      }
    }

    if (m_DataPathAbsoluteAlternativeW.length() == 0) {
      std::wstring regPath = GameInfo::instance().getRegPath();
      if (!regPath.empty()) {
        if (*regPath.rbegin() == '\\') {
          regPath.resize(regPath.size() - 1);
        }
        if (!PathStartsWith(m_DataPathAbsoluteW.c_str(), regPath.c_str())) {
          regPath.append(L"\\data");
          wchar_t temp[MAX_PATH];
          Canonicalize(temp, regPath.c_str());
          m_DataPathAbsoluteAlternativeW = temp;
          Logger::Instance().info("data path from registry differs from configured game path: %ls", regPath.c_str());
        }
      }
    }
  }

  ::CloseHandle(dataDir);

  std::fstream file(ToString(m_ModListPath, false).c_str());
  if (!file.is_open()) {
    Logger::Instance().error("failed to read \"%ls\": %s", m_ModListPath.c_str(), strerror(errno));
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
      } // leave * for now to identify foreign mods, it can't be part of a valid file name anyway
      std::wostringstream temp;
      temp << m_ModsPath << L"\\" << ToWString(bufferPtr, true);
      if ((buffer[0] != '*') && !FileExists(temp.str())) {
        Logger::Instance().error("mod \"%ls\" doesn't exist, maybe there is a typo?", temp.str().c_str());
      } else {
        Logger::Instance().info("using mod \"%s\"", bufferPtr);
        m_ModList.push_back(ToWString(bufferPtr, true));
      }
    }
  }
  file.close();
  int index = 1;

  time_t start = time(nullptr);

  m_DirectoryStructure.addFromOrigin(L"data", GameInfo::instance().getGameDirectory() + L"\\data", 0);

  // mod list is sorted by priority descending, hence the reverse iterator
  for (std::vector<std::wstring>::reverse_iterator modIter = m_ModList.rbegin(); modIter != m_ModList.rend(); ++modIter, ++index) {
    std::wstring modName = *modIter;
    std::wstring modPath;
    WIN32_FIND_DATAW findData;
    HANDLE bsaSearch = INVALID_HANDLE_VALUE;
    if (modIter->at(0) == L'*') {
      size_t offset = modName.find_first_of(L':');
      if (offset == std::string::npos) {
        offset = 1;
      } else {
        offset += 2;
      }
      modName = modName.substr(offset);
      modPath = GameInfo::instance().getGameDirectory() + L"\\data";
      m_DirectoryStructure.createOrigin(modName, modPath, index);
      bsaSearch = ::FindFirstFileW((modPath + L"\\" + modName + L"*.bsa").c_str(), &findData);
    } else {
      LOGDEBUG("indexing %ls", modName.c_str());
      modPath = m_ModsPath + L"\\" + modName;
      m_DirectoryStructure.addFromOrigin(modName, modPath, index);
      m_UpdateHandles.push_back(::FindFirstChangeNotificationW(modPath.c_str(), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME));
      m_UpdateOriginIDs.push_back(m_DirectoryStructure.getOriginByName(modName).getID());

      bsaSearch = ::FindFirstFileW((modPath + L"\\*.bsa").c_str(), &findData);
    }
    BOOL success = bsaSearch != INVALID_HANDLE_VALUE;
    while (success) {
      LOGDEBUG("reading BSA %ls", findData.cFileName);
      m_DirectoryStructure.addFromBSA(modName,
                                      modPath,
                                      modPath + L"\\" + findData.cFileName,
                                      index);
      success = ::FindNextFileW(bsaSearch, &findData);
    }
  }

  LOGDEBUG("indexing overwrite");
  m_DirectoryStructure.addFromOrigin(L"overwrite", m_OverwritePathW, index);

  LOGDEBUG("update vfs took %ld seconds", time(nullptr) - start);

  m_DataOrigin = m_DirectoryStructure.getOriginByName(L"data").getID();

  if (enableHiding) {
    std::wstring hidePattern = m_ProfilePath + L"\\hide_*.txt";
    WIN32_FIND_DATAW findData;
    HANDLE search = ::FindFirstFileW(hidePattern.c_str(), &findData);
    BOOL success = search != INVALID_HANDLE_VALUE;
    while (success) {
      loadDeleters(ToString(m_ProfilePath + L"\\" + findData.cFileName, false));
      success = ::FindNextFileW(search, &findData);
    }
    ::FindClose(search);
  }

  m_UpdateOriginIDs.push_back(m_DirectoryStructure.getOriginByName(L"overwrite").getID());
  m_UpdateHandles.push_back(::FindFirstChangeNotificationW(m_OverwritePathW.c_str(), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME));
  // dumpDirectoryStructure(&m_DirectoryStructure, 0);
}


ModInfo::~ModInfo()
{
  for (auto iter = m_UpdateHandles.begin(); iter != m_UpdateHandles.end(); ++iter) {
    ::FindCloseChangeNotification(*iter);
  }
}


bool ModInfo::detectOverwriteChange()
{
  std::set<int> modifiedOrigins;

  HANDLE *handles = m_UpdateHandles.data();

  // do a non-waiting WaitForMultipleObjects for all the update handles. Since there is an upper
  // limit on how many handles can be waited for at once we do this in batches
  for (size_t offset = 0; offset < m_UpdateHandles.size(); ) {
    int handleCount = std::min<int>(MAXIMUM_WAIT_OBJECTS, m_UpdateHandles.size() - offset);
    DWORD res = ::WaitForMultipleObjects(handleCount, handles + offset, FALSE, 0);
    if ((res == WAIT_TIMEOUT) || (res == WAIT_FAILED)) {
      // none of the handles signaled so continue with the next block
      offset += MAXIMUM_WAIT_OBJECTS;
    } else {
      // WFMO only returns one signaled handle so repeat with the same block
      // note: I understand the documentation such that only the event that triggered the return
      // was reset so other signaled handlers should remain signaled
      size_t handleIdx = (res - WAIT_OBJECT_0) + offset;
      if (::FindNextChangeNotification(m_UpdateHandles[handleIdx])) {
        if (handleIdx < m_UpdateOriginIDs.size()) {
          modifiedOrigins.insert(handleIdx);
        }
      }
    }
  }

  for (int idx : modifiedOrigins) {
    int originId = m_UpdateOriginIDs[idx];
    try {
      FilesOrigin &origin = m_DirectoryStructure.getOriginByID(originId);
      time_t before = time(nullptr);
      {
        // addFromOrigin uses FindFirstFileEx, rerouting that could be disastrous
        HookLock lock(0xFFFFFFFF);
        m_DirectoryStructure.addFromOrigin(origin.getName(),
                                           origin.getPath(),
                                           origin.getPriority());
      }
      origin.enable(false, before);
    } catch (const std::exception &e) {
      Logger::Instance().error("failed to update mod directory: %s", e.what());
    }
  }

  return !modifiedOrigins.empty();
}


std::wstring ModInfo::reverseReroute(const std::wstring &path, bool *rerouted)
{
  std::wstring result;
  size_t length = path.length() * 2;
  boost::scoped_array<wchar_t> temp(new wchar_t[length]);
  Canonicalize(temp.get(), path.c_str(), length);
  if (PathStartsWith(temp.get(), m_ModsPath.c_str())) {
    // path points to a mod
    wchar_t *relPath = temp.get() + m_ModsPath.length();
    if (*relPath != L'\0') {
      relPath += 1;
    }
    // skip the mod name
    relPath = wcschr(relPath, L'\\');

    if (relPath != nullptr) {
      std::wstring combined = m_DataPathAbsoluteW + L"\\" + relPath;
      boost::scoped_array<wchar_t> reroutedPath(new wchar_t[combined.length() * 2]);
      Canonicalize(reroutedPath.get(), combined.c_str());
      result.assign(reroutedPath.get());
    } else {
      result = m_DataPathAbsoluteW;
    }

    if (rerouted != nullptr) {
      *rerouted = true;
    }
  } else if (PathStartsWith(temp.get(), m_OverwritePathW.c_str())) {
    // path points to reroute directory
    wchar_t *relPath = temp.get() + m_OverwritePathW.length();
    if (*relPath != L'\0') relPath += 1;

    std::wstring combined = m_DataPathAbsoluteW + L"\\" + relPath;
    boost::scoped_array<wchar_t> reroutedPath(new wchar_t[combined.length() * 2]);
    Canonicalize(reroutedPath.get(), combined.c_str());
    result.assign(reroutedPath.get());

    if (rerouted != nullptr) {
      *rerouted = true;
    }
  } else {
    // not rerouted, returns the unmodified path
    result.assign(path);
    if (rerouted != nullptr) {
      *rerouted = false;
    }
  }
  return result;
}

const FilesOrigin &ModInfo::getFilesOrigin(int originID) const
{
  return m_DirectoryStructure.getOriginByID(originID);
}

bool DirectoryExists(const std::wstring &directory)
{
  DWORD attributes = GetFileAttributesW(directory.c_str());
  if (attributes != INVALID_FILE_ATTRIBUTES) {
    return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0UL;
  } else {
    // this could also be the case if the directory exists but we can't read it. tough luck
    return false;
  }
}

bool ModInfo::setCwd(const std::wstring &currentDirectory)
{
  bool rerouted = false;
  m_CurrentDirectory = reverseReroute(currentDirectory, &rerouted);
  if (!rerouted && DirectoryExists(m_CurrentDirectory)) {
    // regular un-rerouted setcwd
    m_CurrentDirectory.clear();
  }
  return !m_CurrentDirectory.empty();
}

void ModInfo::setMOPath(const std::wstring &moPath)
{
  m_MOPathW = moPath;

}


void ModInfo::checkPathAlternative(LPCWSTR path)
{
  if (m_DataPathAbsoluteAlternativeW.length() != 0) {
    if (PathStartsWith(path, m_DataPathAbsoluteAlternativeW.c_str())) {
      m_DataPathAbsoluteW = m_DataPathAbsoluteAlternativeW;
      m_DataPathAbsoluteA = ToString(m_DataPathAbsoluteW, false);
      m_DataPathAbsoluteAlternativeW.clear();
      Logger::Instance().info("using alternative data path");
    } else if (PathStartsWith(path, m_DataPathAbsoluteW.c_str())) {
      m_DataPathAbsoluteAlternativeW.clear();
    }
  }
}


void ModInfo::addAlternativePath(const std::wstring &path)
{
  if ((m_DataPathAbsoluteAlternativeW.length() == 0) &&
      (!PathStartsWith(m_DataPathAbsoluteW.c_str(), path.c_str()))) {
    wchar_t temp[MAX_PATH];
    Canonicalize(temp, (path + L"\\data").c_str());
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

    m_DirectoryStructure.removeFile(fileName, nullptr);
  }
}


void ModInfo::addModFile(const std::wstring &fileName)
{
  if (PathStartsWith(fileName.c_str(), m_ModsPath.c_str())) {
    wchar_t buffer[MAX_PATH];
    LPCWSTR modName = fileName.c_str() + m_ModsPath.length() + 1;
    size_t len = wcscspn(modName, L"\\/");
    wcsncpy(buffer, modName, len);
    buffer[len] = L'\0';
    addModFile(buffer, fileName);
  } else if (PathStartsWith(fileName.c_str(), m_OverwritePathW.c_str())) {
    addOverwriteFile(fileName);
  } else {
    Logger::Instance().error("not a mod directory: %ls", fileName.c_str());
  }
}


void ModInfo::addOverwriteFile(const std::wstring &fileName)
{
  addModFile(L"overwrite", fileName);
}


void ModInfo::addModFile(LPCWSTR originName, const std::wstring &fileName)
{
  FilesOrigin &origin = m_DirectoryStructure.getOriginByName(originName);
  size_t offset = origin.getPath().length() + 1;
  while ((fileName[offset] == '\\') || (fileName[offset] == '/')) {
    ++offset;
  }
  LOGDEBUG("add mod file %ls (%ls)", fileName.c_str(), fileName.substr(offset).c_str());
  SYSTEMTIME now;
  GetSystemTime(&now);
  FILETIME time;
  if (SystemTimeToFileTime(&now, &time)) {
    m_DirectoryStructure.insertFile(fileName.substr(offset), origin, time);
  }
  else {
    Logger::Instance().error("failed to determine file time for %ls", fileName.c_str());
  }
}


void ModInfo::addRemoval(const std::wstring &fileName, int origin)
{
  time_t now = time(nullptr);
  // first, remove outdated entries
  for (std::list<RemovalInfo>::const_iterator iter = m_RemovalInfo.begin(); iter != m_RemovalInfo.end();) {
    if (iter->time + 5 < now) {
      iter = m_RemovalInfo.erase(iter);
    } else {
      ++iter;
    }
  }

  RemovalInfo newInfo;
  newInfo.origin = origin;
  newInfo.fileName.assign(fileName);
  newInfo.time = now;
  m_RemovalInfo.push_back(newInfo);
}

std::wstring ModInfo::getRemovedLocation(const std::wstring &fileName)
{
  time_t now = time(nullptr);
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
  WCHAR fullPath[MAX_PATH];
  getFullPathName(fileName.c_str(), fullPath, MAX_PATH);

  if (PathStartsWith(fullPath, m_DataPathAbsoluteW.c_str()) &&
      (wcslen(fullPath) != m_DataPathAbsoluteW.length())) {
    int origin = -1;
    if (!m_DirectoryStructure.removeFile(fullPath + m_DataPathAbsoluteW.length() + 1, &origin)) {
      Logger::Instance().error("failed to remove virtual file %ls", fullPath + m_DataPathAbsoluteW.length() + 1);
    }
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


std::wstring ModInfo::getCurrentDirectory()
{
  return m_CurrentDirectory;
}


void ModInfo::addSearchResult(SearchBuffer &searchBuffer, LPCWSTR directory, WIN32_FIND_DATAW &searchData)
{
  WCHAR buffer[MAX_PATH];
  if (directory[0] != L'\0') {
    _snwprintf_s(buffer, _TRUNCATE, L"%ls\\%ls", directory, searchData.cFileName);
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
  if (slashPos == nullptr) {
    slashPos = wcsrchr(absoluteFileName, L'/');
  }
  WCHAR relativePath[MAX_PATH];

  if (slashPos != nullptr) {
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
    if (dataHandle != primaryHandle) {
      FindClose_reroute(dataHandle);
    }
  }

  const DirectoryEntry *searchDirectory = nullptr;
  if (relativePath[0] != '\0') {
    // micro-optimization: don't search if the parent directory doesn't even exist in the mod
    std::wstring parentDir(relativePath + 1);
    parentDir.append(L"\\");
    m_DirectoryStructure.searchFile(parentDir, &searchDirectory);
  }

  // add elements from the mod directories
  for (const std::wstring &name : m_ModList) {
    if (name.at(0) == L'*') {
      continue;
    }
    std::wostringstream fullPath;
    fullPath << m_ModsPath << "\\" << name << (absoluteFileName + filenameOffset);
    try {
      FilesOrigin &origin = m_DirectoryStructure.getOriginByName(name);
      if ((relativePath[0] != '\0') &&
          ((searchDirectory == nullptr) ||
           !searchDirectory->hasContentsFromOrigin(origin.getID()))) {
        continue;
      }
    } catch (const std::out_of_range &e) {
      Logger::Instance().error("invalid mod name %ls: %s", name.c_str(), e.what());
      continue;
    }

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
    std::wstring fullPath = m_OverwritePathW + L"\\" + (absoluteFileName + filenameOffset);
    ::ZeroMemory(&searchData, sizeof(WIN32_FIND_DATAW));
    dataHandle = FindFirstFileExW_reroute(fullPath.c_str(), fInfoLevelId, &searchData, fSearchOp, lpSearchFilter, dwAdditionalFlags);

    if (dataHandle != INVALID_HANDLE_VALUE) {
      addSearchResults(searchBuffer, primaryHandle, dataHandle, relativePath, searchData);
      if (primaryHandle != dataHandle) {
        // close the search handle unless it's the primary handle
        FindClose_reroute(dataHandle);
      }
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
                          DWORD dwAdditionalFlags,
                          bool *rerouted)
{
  WCHAR temp[MAX_PATH];
  getFullPathName(lpFileName, temp, MAX_PATH);
  FileEntry::Ptr file;
  if (PathStartsWith(temp, m_DataPathAbsoluteW.c_str())) {
    file = m_DirectoryStructure.searchFile(temp + m_DataPathAbsoluteW.length() + 1, nullptr);
  }
  if (rerouted != nullptr) *rerouted = false;
  if (file.get() != nullptr) {
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
    if (PathStartsWith(absoluteFileName, m_DataPathAbsoluteW.c_str())
        && (absoluteFileName[m_DataPathAbsoluteW.length()] != L'\0')) {
      if (rerouted != nullptr) *rerouted = true;
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
  SearchesMap::iterator iter = m_Searches.find(handle);
  if (iter != m_Searches.end()) {
    m_Searches.erase(iter);
  }

  return FindClose_reroute(handle);
}


BOOL ModInfo::searchExists(HANDLE handle)
{
  return m_Searches.find(handle) != m_Searches.end();
}

bool ModInfo::isFileHidden(const std::wstring &fileName) const
{
  return m_HiddenFiles.find(fileName) != m_HiddenFiles.end();
}


const std::string &ModInfo::getTweakedIniA() const
{
  return m_TweakedIniPathA;
}


const std::wstring &ModInfo::getTweakedIniW() const
{
  return m_TweakedIniPathW;
}


std::string ModInfo::getRerouteOpenExisting(LPCSTR originalName, bool preferOriginal, bool *rerouted, int *originID)
{
  return ToString(getRerouteOpenExisting(ToWString(originalName, false).c_str(), preferOriginal, rerouted, originID), false);
}


void ModInfo::getFullPathName(LPCWSTR originalName, LPWSTR targetBuffer, size_t bufferLength)
{
  WCHAR temp[MAX_PATH];
  if (m_CurrentDirectory.length() != 0) {
    WCHAR cwd[MAX_PATH];
    DWORD length = ::GetCurrentDirectoryW_reroute(MAX_PATH, cwd);
    if (StartsWith(originalName, cwd)) {
      _snwprintf_s(temp, _TRUNCATE, L"%ls\\%ls", m_CurrentDirectory.c_str(), originalName + static_cast<size_t>(length));
    } else {
      ::PathCombineW(temp, m_CurrentDirectory.c_str(), originalName);
    }
  } else {
    ::GetFullPathNameW_reroute(originalName, static_cast<DWORD>(bufferLength), temp, nullptr);
  }
  checkPathAlternative(temp);
  Canonicalize(targetBuffer, temp, bufferLength);
}


std::wstring ModInfo::getRerouteOpenExisting(LPCWSTR originalName, bool preferOriginal, bool *rerouted, int *originID)
{
  PROFILE_S();

  if (rerouted != nullptr) {
    *rerouted = false;
  }

  WCHAR tempBuf[MAX_PATH];
  getFullPathName(originalName, tempBuf, MAX_PATH);
  LPCWSTR temp = tempBuf;
  if (StartsWith(temp, L"\\\\?\\")) {
    temp += 4;
  }

  std::wstring result;
  LPCWSTR baseName = GetBaseName(temp);
  LPCWSTR sPos = nullptr;
  if (GameInfo::instance().rerouteToProfile(baseName, originalName)) {
    result = m_ProfilePath + L"\\" + baseName;
    if (rerouted != nullptr) {
      *rerouted = true;
    }
  } else if ((sPos = wcswcs(temp, AppConfig::localSavePlaceholder())) != nullptr) {
    m_SavesReroute = true;
    result = m_ProfilePath + L"\\saves\\" + (sPos + wcslen(AppConfig::localSavePlaceholder()));
    if (rerouted != nullptr) {
      *rerouted = true;
    }
  } else if (m_SavesReroute
             && (EndsWith(temp, L".skse")
                 || EndsWith(temp, L".obse"))
             && ((sPos = wcswcs(temp, L"\\My Games\\Skyrim\\Saves\\")) != nullptr)) {
    // !workaround! skse saving to hard-coded path
    result = m_ProfilePath + L"\\saves\\" + (sPos + 23);
    if (rerouted != nullptr) {
      *rerouted = true;
    }
  } else if (PathStartsWith(temp, m_DataPathAbsoluteW.c_str())
             && (wcslen(temp) != m_DataPathAbsoluteW.length())) {
    if (!preferOriginal || !FileExists_reroute(temp)) {
      int origin = 0;
      result = getPath(temp, m_DataPathAbsoluteW.length(), origin);
      if (result.size() == 0) {
        result = originalName;
      } else {
        // it's not rerouted if the file comes from data directory
        if ((rerouted != nullptr) && (origin != m_DataOrigin)) {
          *rerouted = true;
          if (originID != nullptr) {
            *originID = origin;
          }
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


std::wstring ModInfo::getPath(LPCWSTR originalName, size_t offset, int &originId)
{
  detectOverwriteChange();
  bool archive = false;
  if (wcslen(originalName) < offset) {
    Logger::Instance().error("invalid offset %d to %ls", offset, originalName);
    return std::wstring();
  }
  originId = m_DirectoryStructure.getOrigin(originalName + offset + 1, archive);
  if (archive) {
    return std::wstring();
  } else if (originId == -1) {
    return std::wstring();
  } else {
    FilesOrigin &origin = m_DirectoryStructure.getOriginByID(originId);
    std::wstring fullPath = origin.getPath() + (originalName + offset);
    if (m_ModAccess.insert(originId).second) {
      Logger::Instance().debug("first access to %ls", origin.getName().c_str());
    }
    return fullPath;
  }
}
