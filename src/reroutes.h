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

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>


typedef BOOL (WINAPI *CreateProcessA_type)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                           LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
extern CreateProcessA_type CreateProcessA_reroute;

typedef BOOL (WINAPI *CreateProcessW_type)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                           LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
extern CreateProcessW_type CreateProcessW_reroute;

typedef HMODULE (WINAPI *LoadLibraryExW_type)(LPCWSTR, HANDLE, DWORD);
extern LoadLibraryExW_type LoadLibraryExW_reroute;

typedef HMODULE (WINAPI *LoadLibraryW_type)(LPCWSTR);
extern LoadLibraryW_type LoadLibraryW_reroute;

typedef HMODULE (WINAPI *LoadLibraryExA_type)(LPCSTR, HANDLE, DWORD);
extern LoadLibraryExA_type LoadLibraryExA_reroute;

typedef HMODULE (WINAPI *LoadLibraryA_type)(LPCSTR);
extern LoadLibraryA_type LoadLibraryA_reroute;

typedef HANDLE (WINAPI *CreateFileW_type)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
extern CreateFileW_type CreateFileW_reroute;

typedef HANDLE (WINAPI *CreateFileA_type)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
extern CreateFileA_type CreateFileA_reroute;

typedef BOOL (WINAPI *CloseHandle_type)(HANDLE);
extern CloseHandle_type CloseHandle_reroute;

typedef HANDLE (WINAPI *FindFirstFileA_type)(LPCSTR, LPWIN32_FIND_DATAA);
extern FindFirstFileA_type FindFirstFileA_reroute;

typedef HANDLE (WINAPI *FindFirstFileW_type)(LPCWSTR, LPWIN32_FIND_DATAW);
extern FindFirstFileW_type FindFirstFileW_reroute;

typedef HANDLE (WINAPI *FindFirstFileExW_type)(LPCWSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
extern FindFirstFileExW_type FindFirstFileExW_reroute;

typedef BOOL (WINAPI *FindNextFileA_type)(HANDLE, LPWIN32_FIND_DATAA);
extern FindNextFileA_type FindNextFileA_reroute;

typedef BOOL (WINAPI *FindNextFileW_type)(HANDLE, LPWIN32_FIND_DATAW);
extern FindNextFileW_type FindNextFileW_reroute;

typedef BOOL (WINAPI *FindClose_type)(HANDLE);
extern FindClose_type FindClose_reroute;

typedef DWORD (WINAPI *GetFileAttributesW_type)(LPCWSTR);
extern GetFileAttributesW_type GetFileAttributesW_reroute;

typedef BOOL (WINAPI *GetFileAttributesExW_type)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
extern GetFileAttributesExW_type GetFileAttributesExW_reroute;

typedef BOOL (WINAPI *SetFileAttributesW_type)(LPCWSTR, DWORD);
extern SetFileAttributesW_type SetFileAttributesW_reroute;

typedef BOOL (WINAPI *CreateDirectoryW_type)(LPCWSTR, LPSECURITY_ATTRIBUTES);
extern CreateDirectoryW_type CreateDirectoryW_reroute;

typedef BOOL (WINAPI *MoveFileA_type)(LPCSTR,LPCSTR);
extern MoveFileA_type MoveFileA_reroute;

typedef BOOL (WINAPI *MoveFileExA_type)(LPCSTR, LPCSTR, DWORD);
extern MoveFileExA_type MoveFileExA_reroute;

typedef BOOL (WINAPI *MoveFileW_type)(LPCWSTR,LPCWSTR);
extern MoveFileW_type MoveFileW_reroute;

typedef BOOL (WINAPI *MoveFileExW_type)(LPCWSTR, LPCWSTR, DWORD);
extern MoveFileExW_type MoveFileExW_reroute;

typedef BOOL (WINAPI *DeleteFileA_type)(LPCSTR);
extern DeleteFileA_type DeleteFileA_reroute;

typedef BOOL (WINAPI *DeleteFileW_type)(LPCWSTR);
extern DeleteFileW_type DeleteFileW_reroute;

typedef BOOL (WINAPI *SetCurrentDirectoryA_type)(LPCSTR);
extern SetCurrentDirectoryA_type SetCurrentDirectoryA_reroute;

typedef BOOL (WINAPI *SetCurrentDirectoryW_type)(LPCWSTR);
extern SetCurrentDirectoryW_type SetCurrentDirectoryW_reroute;

typedef DWORD (WINAPI *GetPrivateProfileStringA_type)(LPCSTR, LPCSTR, LPCSTR, LPSTR, DWORD, LPCSTR);
extern GetPrivateProfileStringA_type GetPrivateProfileStringA_reroute;

typedef DWORD (WINAPI *GetPrivateProfileStringW_type)(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, DWORD, LPCWSTR);
extern GetPrivateProfileStringW_type GetPrivateProfileStringW_reroute;

typedef BOOL (WINAPI *GetPrivateProfileStructA_type)(LPCSTR, LPCSTR, LPVOID, UINT, LPCSTR);
extern GetPrivateProfileStructA_type GetPrivateProfileStructA_reroute;

typedef BOOL (WINAPI *GetPrivateProfileStructW_type)(LPCWSTR, LPCWSTR, LPVOID, UINT, LPCWSTR);
extern GetPrivateProfileStructW_type GetPrivateProfileStructW_reroute;

typedef DWORD (WINAPI *GetPrivateProfileSectionNamesA_type)(LPSTR, DWORD, LPCSTR);
extern GetPrivateProfileSectionNamesA_type GetPrivateProfileSectionNamesA_reroute;

typedef DWORD (WINAPI *GetPrivateProfileSectionNamesW_type)(LPWSTR, DWORD, LPCWSTR);
extern GetPrivateProfileSectionNamesW_type GetPrivateProfileSectionNamesW_reroute;

typedef DWORD (WINAPI *GetPrivateProfileSectionA_type)(LPCSTR, LPSTR, DWORD, LPCSTR);
extern GetPrivateProfileSectionA_type GetPrivateProfileSectionA_reroute;

typedef DWORD (WINAPI *GetPrivateProfileSectionW_type)(LPCWSTR, LPWSTR, DWORD, LPCWSTR);
extern GetPrivateProfileSectionW_type GetPrivateProfileSectionW_reroute;

typedef UINT (WINAPI *GetPrivateProfileIntA_type)(LPCSTR, LPCSTR, INT, LPCSTR);
extern GetPrivateProfileIntA_type GetPrivateProfileIntA_reroute;

typedef UINT (WINAPI *GetPrivateProfileIntW_type)(LPCWSTR, LPCWSTR, INT, LPCWSTR);
extern GetPrivateProfileIntW_type GetPrivateProfileIntW_reroute;

typedef BOOL (WINAPI *WritePrivateProfileSectionA_type)(LPCSTR, LPCSTR, LPCSTR);
extern WritePrivateProfileSectionA_type WritePrivateProfileSectionA_reroute;

typedef BOOL (WINAPI *WritePrivateProfileSectionW_type)(LPCWSTR, LPCWSTR, LPCWSTR);
extern WritePrivateProfileSectionW_type WritePrivateProfileSectionW_reroute;

typedef BOOL (WINAPI *WritePrivateProfileStringA_type)(LPCSTR, LPCSTR, LPCSTR, LPCSTR);
extern WritePrivateProfileStringA_type WritePrivateProfileStringA_reroute;

typedef BOOL (WINAPI *WritePrivateProfileStringW_type)(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
extern WritePrivateProfileStringW_type WritePrivateProfileStringW_reroute;

typedef BOOL (WINAPI *WritePrivateProfileStructA_type)(LPCSTR, LPCSTR, LPVOID, UINT, LPCSTR);
extern WritePrivateProfileStructA_type WritePrivateProfileStructA_reroute;

typedef BOOL (WINAPI *WritePrivateProfileStructW_type)(LPCWSTR, LPCWSTR, LPVOID, UINT, LPCWSTR);
extern WritePrivateProfileStructW_type WritePrivateProfileStructW_reroute;

typedef HFILE (WINAPI *OpenFile_type)(LPCSTR, LPOFSTRUCT, UINT);
extern OpenFile_type OpenFile_reroute;

typedef DWORD (WINAPI *GetCurrentDirectoryW_type)(DWORD, LPWSTR);
extern GetCurrentDirectoryW_type GetCurrentDirectoryW_reroute;

typedef BOOL (WINAPI *SetCurrentDirectoryW_type)(LPCWSTR);
extern SetCurrentDirectoryW_type SetCurrentDirectoryW_reroute;

typedef BOOL (WINAPI *CopyFileA_type)(LPCSTR, LPCSTR, BOOL);
extern CopyFileA_type CopyFileA_reroute;

typedef BOOL (WINAPI *CopyFileW_type)(LPCWSTR, LPCWSTR, BOOL);
extern CopyFileW_type CopyFileW_reroute;

typedef DWORD (WINAPI *GetFullPathNameW_type)(LPCWSTR, DWORD, LPWSTR, LPWSTR*);
extern GetFullPathNameW_type GetFullPathNameW_reroute;

