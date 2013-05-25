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

#pragma once

#include <vector>
#include <map>
#include <string>
#include <set>
#include <list>
#include "logger.h"
#include <directoryentry.h>


class ModInfo {

public:

  ModInfo(const std::wstring &profileName, const std::wstring &modDirectory, bool enableHiding);
  ~ModInfo();

  /**
   * overwrite the real current working directory with one that is allowed to be virtual. Supported
   * functions will then treat all relative paths as relative to this directory
   * @param currentDirectory the new "fake" current directory
   **/
  bool setCwd(const std::wstring &currentDirectory);

  inline void checkPathAlternative(LPCWSTR path);
  void addAlternativePath(const std::wstring &path);

  void addModDirectory(const std::wstring &modPath);
  void addModFile(const std::wstring &fileName);
  void addOverwriteFile(const std::wstring &fileName);

  /**
   * removes the specified file from the directory structure
   * @param fileName full path to the file (at its actual physical location)
   **/
  void removeModFile(const std::wstring &fileName);

  bool modExists(const std::wstring& modName);

  void rewriteModList();
  void appendMod(LPCWSTR modName);

  HANDLE findStart(LPCWSTR lpFileName,
                   FINDEX_INFO_LEVELS fInfoLevelId,
                   LPVOID lpFindFileData,
                   FINDEX_SEARCH_OPS fSearchOp,
                   LPVOID lpSearchFilter,
                   DWORD dwAdditionalFlags);
  BOOL findNext(HANDLE handle, LPWIN32_FIND_DATAW findFileData);
  BOOL findClose(HANDLE handle);

  BOOL searchExists(HANDLE handle);

  std::wstring getProfileName() const { return m_ProfileName; }
  std::wstring getProfilePath() const { return m_ProfilePath; }

  const std::string &getTweakedIniA() const;
  const std::wstring &getTweakedIniW() const;

  std::string getRerouteOpenExisting(LPCSTR originalName);
  std::wstring getRerouteOpenExisting(LPCWSTR originalName, bool preferOriginal = false, bool *rerouted = NULL);
  std::wstring getPath(LPCWSTR originalName, size_t offset, int &origin);

  const std::string &getDataPathA() const { return m_DataPathAbsoluteA; }
  const std::wstring &getDataPathW() const { return m_DataPathAbsoluteW; }

  const std::wstring &getModPathW() const { return m_ModsPath; }

  // get the part of path that is valid within any of the mod directories
//  std::wstring getValidPath(LPCWSTR path, size_t offset);

  void dumpDirectoryStructure(const MOShared::DirectoryEntry *directory, int indent);

  std::wstring getCurrentDirectory();

  // drop-in replacement for the GetFullPathNameW function, taking into account
  // the fake cwd
  void getFullPathName(LPCWSTR originalName, LPWSTR targetBuffer, size_t bufferLength);

  std::wstring getRemovedLocation(const std::wstring &fileName);

private:

  struct _LessThanName {
    bool operator()(const WIN32_FIND_DATAW& lhs, const WIN32_FIND_DATAW& rhs) const {
      return _wcsicmp(lhs.cFileName, rhs.cFileName) < 0;
    }
  };

  typedef std::set<WIN32_FIND_DATAW, _LessThanName> SearchBuffer;
  typedef std::vector<WIN32_FIND_DATAW> SearchResult;
  typedef std::map<HANDLE, std::pair<SearchResult, SearchResult::iterator> > SearchesMap;

  void addSearchResult(SearchBuffer& searchBuffer, LPCWSTR directory, WIN32_FIND_DATAW& searchData);

  void addSearchResults(SearchBuffer& searchBuffer, HANDLE& primaryHandle, HANDLE searchHandle, LPCWSTR directory, WIN32_FIND_DATAW &searchData);

  HANDLE dataSearch(LPCWSTR absoluteFileName, size_t filenameOffset, HANDLE dataHandle, WIN32_FIND_DATAW &tempData,
                    FINDEX_INFO_LEVELS fInfoLevelId, FINDEX_SEARCH_OPS fSearchOp,
                    LPVOID lpSearchFilter, DWORD dwAdditionalFlags);

  void loadDeleters(const std::string &fileName);

  void createDirectoryStructure(MOShared::DirectoryEntry &directoryEntry, const std::wstring &basePath, const std::wstring &dirName, int index);

  bool detectOverwriteChange();

  void addRemoval(const std::wstring &fileName, int origin);

private:

  struct RemovalInfo {
    RemovalInfo() : fileName(), origin(-1), time(0) {}
    RemovalInfo(const RemovalInfo &reference) : fileName(reference.fileName), origin(reference.origin), time(reference.time) { LOGDEBUG("copy: %ls", fileName.c_str()); }
    std::wstring fileName;
    int origin;
    time_t time;
  };

private:
  std::wstring m_ProfileName;
  std::wstring m_ProfilePath;
  std::wstring m_ModListPath;
  std::wstring m_ModsPath;

  std::string m_TweakedIniPathA;
  std::wstring m_TweakedIniPathW;

  std::wstring m_CurrentDirectory;

  std::string m_DataPathAbsoluteA;
  std::wstring m_DataPathAbsoluteW;

  std::wstring m_DataPathAbsoluteAlternativeW;

  std::vector<std::wstring> m_ModList;
  std::set<int> m_ModAccess;
  std::set<std::wstring> m_HiddenFiles;
  MOShared::DirectoryEntry m_DirectoryStructure;
  int m_ModCount;

  std::list<RemovalInfo> m_RemovalInfo;

  SearchesMap m_Searches;

  HANDLE m_UpdateNotification;

  int m_DataOrigin;


  bool m_SavesReroute; // workaround skse

};

