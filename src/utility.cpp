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
#include "utility.h"
#include "logger.h"

#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include <ctype.h>
#include <string>
#include <locale>



bool Contains(LPCWSTR string, LPCWSTR subString)
{
  size_t stringLen = wcslen(string);
  size_t len = wcslen(subString);
  if (stringLen < len) {
    return false;
  }
  size_t matchLen = 0;
  for (size_t i = 0; i < stringLen; ++i) {
    if (string[i] == subString[matchLen]) {
      ++matchLen;
      if (matchLen == len) {
        return true;
      }
    } else {
      matchLen = 0;
    }
  }
  return false;
}

bool PathStartsWith(LPCSTR string, LPCSTR subString)
{
  size_t len = strlen(subString);
  if (strlen(string) < len) {
    return false;
  }

  std::locale loc;

  for (size_t i = 0; i < len; ++i) {
    if (std::tolower(string[i], loc) != std::tolower(subString[i], loc)) {
      return false;
    }
  }
  return (string[len] == '\0') || (string[len] == '/') || (string[len] == '\\');
}

bool PathStartsWith(LPCWSTR string, LPCWSTR subString)
{
  size_t len = wcslen(subString);
  if (wcslen(string) < len) {
    return false;
  }

  for (size_t i = 0; i < len; ++i) {
    if (towlower(string[i]) != towlower(subString[i])) {
      return false;
    }
  }
  return (string[len] == L'\0') || (string[len] == L'/') || (string[len] == L'\\');
}

bool StartsWith(LPCSTR string, LPCSTR subString)
{
  size_t len = strlen(subString);
  if (strlen(string) < len) {
    return false;
  }

  std::locale loc;

  for (size_t i = 0; i < len; ++i) {
    if (std::tolower(string[i], loc) != std::tolower(subString[i], loc)) {
      return false;
    }
  }
  return true;
}

bool StartsWith(LPCWSTR string, LPCWSTR subString)
{
  size_t len = wcslen(subString);
  if (wcslen(string) < len) {
    return false;
  }

  for (size_t i = 0; i < len; ++i) {
    if (towlower(string[i]) != towlower(subString[i])) {
      return false;
    }
  }
  return true;
}

bool EndsWith(LPCSTR string, LPCSTR subString)
{
  size_t slen = strlen(string);
  size_t len = strlen(subString);
  if (slen < len) {
    return false;
  }

  std::locale loc;

  for (size_t i = 0; i < len; ++i) {
    if (std::tolower(string[slen - i - 1], loc) != std::tolower(subString[len - i - 1], loc)) {
      return false;
    }
  }
  return true;
}

bool EndsWith(LPCWSTR string, LPCWSTR subString)
{
  size_t slen = wcslen(string);
  size_t len = wcslen(subString);
  if (slen < len) {
    return false;
  }

  for (size_t i = 0; i < len; ++i) {
    if (towlower(string[slen - len + i]) != towlower(subString[i])) {
      return false;
    }
  }
  return true;
}


LPCSTR GetBaseName(LPCSTR string)
{
  LPCSTR result = string + strlen(string) - 1;
  while (result > string) {
    if ((*result == '\\') || (*result == '/')) {
      ++result;
      break;
    } else {
      --result;
    }
  }
  return result;
}


LPCWSTR GetBaseName(LPCWSTR string)
{
  LPCWSTR result;
  if ((string == nullptr) || (string[0] == L'\0')) {
    result = string;
  } else {
    result = string + wcslen(string) - 1;
  }
  while (result > string) {
    if ((*result == L'\\') || (*result == L'/')) {
      ++result;
      break;
    } else {
      --result;
    }
  }
  return result;
}


LPWSTR GetBaseName(LPWSTR string)
{
  LPWSTR result = string + wcslen(string) - 1;
  while (result > string) {
    if ((*result == L'\\') || (*result == L'/')) {
      ++result;
      break;
    } else {
      --result;
    }
  }
  return result;
}


void Canonicalize(LPWSTR destination, LPCWSTR source, size_t bufferSize)
{
  int sourceLen = wcslen(source);
  size_t destinationLength = 0;
  bool wasBSlash = false;
  for (int i = 0; i < sourceLen && destinationLength < bufferSize -1; ++i) {
    if (source[i] == L'/') {
      if (!wasBSlash) {
        destination[destinationLength] = L'\\';
        ++destinationLength;
        wasBSlash = true;
      }
    } else if (source[i] != L'\\') {
      destination[destinationLength] = source[i];
      ++destinationLength;
      wasBSlash = false;
    } else if (!wasBSlash) {
      destination[destinationLength] = L'\\';
      ++destinationLength;
      if (i != 0) {
        // don't remove double-backslash at the begining of a UNC
        wasBSlash = true;
      }
    }
  }
  destination[destinationLength] = L'\0';
}


const wchar_t *wcsrpbrk(const wchar_t *string, const wchar_t *control)
{
  const wchar_t *lastPos = nullptr;
  while (*string != L'\0') {
    const wchar_t *iter = control;
    while (*iter != L'\0') {
      if (*iter++ == *string) {
        lastPos = string;
        break;
      }
    }
    ++string;
  }
  return lastPos;
}
