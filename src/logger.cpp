/*
Copyright (C) 2012 Sebastian Herbord. All rights reserved.

This file is part of Mod Organizer.

Mod Organizer is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Mod Organizer is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with Mod Organizer.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "stdafx.h"
#include "logger.h"
#include "reroutes.h"
#include <cstdlib>
#include <cstdio>
#include <error_report.h>
#include <ctime>
#include <Shlwapi.h>
#include <util.h>


Logger* Logger::s_Instance = NULL;


Logger& Logger::Instance()
{
  if (s_Instance == NULL) {
    s_Instance = new Logger(TEXT("modorganizer.log"), LEVEL_DEBUG);
  }

  return *s_Instance;
}


void Logger::Init(LPCTSTR basePath, int logLevel)
{
  static Logger instance(basePath, logLevel);
  if (s_Instance == NULL) {
    s_Instance = &instance;
  }
}


Logger::Logger(LPCTSTR logPath, int logLevel)
  : m_LogPath(logPath), m_LogLevel(logLevel), m_LogFile(INVALID_HANDLE_VALUE)
{
//  TCHAR temp[MAX_PATH];
//  _sntprintf(temp, MAX_PATH, TEXT("%s\\modorganizer.log"), basePath);
  // just in case...
  ::SetFileAttributes(logPath, FILE_ATTRIBUTE_NORMAL);
  int Tries = 5;
  while ((m_LogFile == INVALID_HANDLE_VALUE) && Tries > 0) {
    m_LogFile = CreateFile(logPath,
          FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_LogFile == INVALID_HANDLE_VALUE) {
      Sleep(1);
    }
    --Tries;
  }

  if (m_LogFile == INVALID_HANDLE_VALUE) {
    reportError(TEXT("failed to create log file (%s), no log available: %s (%d)"), logPath, getCurrentErrorString().c_str(), ::GetLastError());
  } else {
    DWORD sizeWritten = 0;
    static const char Header[] = "-------------------------------\r\n";
    ::WriteFile(m_LogFile, Header, strlen(Header), &sizeWritten, NULL);
  }
}

Logger::~Logger()
{
  DWORD sizeWritten = 0;
  static const char Footer[] = "----------- LOG END -----------\r\n";
  ::WriteFile(m_LogFile, Footer, strlen(Footer), &sizeWritten, NULL);
  ::CloseHandle(m_LogFile);

  wrapUpLog();
  s_Instance = NULL;
}


void Logger::wrapUpLog()
{
  HANDLE testHandle = CreateFileW_reroute(m_LogPath.c_str(),
                                   FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (testHandle != INVALID_HANDLE_VALUE) {
    // file opened exclusively so we're probably the last process accessing it.
    FILETIME fileTime;
    ::GetFileTime(testHandle, &fileTime, NULL, NULL);
    SYSTEMTIME time;
    FileTimeToSystemTime(&fileTime, &time);
    TCHAR localDate[255];
    TCHAR localTime[255];
    ::GetDateFormat(LOCALE_USER_DEFAULT, 0, &time, TEXT("yy'_'MM'_'dd"), localDate, 255);
    ::GetTimeFormat(LOCALE_USER_DEFAULT, 0, &time, TEXT("HH'_'mm"), localTime, 255);

    std::basic_string<TCHAR> temp = m_LogPath.substr(0, m_LogPath.length() - 4)
                                             .append(TEXT("_"))
                                             .append(localDate)
                                             .append(TEXT("_"))
                                             .append(localTime)
                                             .append(TEXT(".log"));

    ::CloseHandle(testHandle);

    int counter = 0;
    // TODO: this code contains a race condition where two processes assume they are last and try to move the file.
    // This is however quite unlikely and most of all, it wouldn't cause harm, the second move would fail and that's that
    while (!::MoveFile(m_LogPath.c_str(), temp.c_str()) && (::GetLastError() == ERROR_ALREADY_EXISTS)) {
      TCHAR buffer[10];
      _sntprintf(buffer, 10, TEXT("%d"), ++counter);
      temp  = m_LogPath.substr(0, m_LogPath.length() - 4)
          .append(TEXT("_"))
          .append(localDate)
          .append(TEXT("_"))
          .append(localTime)
          .append(TEXT("_"))
          .append(buffer)
          .append(TEXT(".log"));
    }
  }
}


void Logger::debug(const char* format, ...)
{
  if (m_LogLevel == LEVEL_DEBUG) {
    va_list argList;
    va_start(argList, format);

    log("DEBUG", format, argList);

    va_end(argList);
  }
}

void Logger::info(const char* format, ...)
{
  if (m_LogLevel != LEVEL_ERROR) {
    va_list argList;
    va_start(argList, format);

    log("INFO", format, argList);

    va_end(argList);
  }
}


void Logger::error(const char* format, ...)
{
  va_list argList;
  va_start(argList, format);

  log("ERROR", format, argList);

  va_end(argList);
  if (m_LogFile != INVALID_HANDLE_VALUE) {
    ::FlushFileBuffers(m_LogFile);
  }
}

static const int BUFFERSIZE = 1000;

void Logger::log(const char* prefix, const char* format, va_list argList)
{
  char buffer[BUFFERSIZE + 1];
  char buffer2[BUFFERSIZE + 51];
  memset(buffer, '\0', sizeof(char) * BUFFERSIZE + 1);
  memset(buffer2, '\0', sizeof(char) * BUFFERSIZE + 51);
  wvnsprintfA(buffer, BUFFERSIZE, format, argList);
//  vsnprintf(buffer, BUFFERSIZE, format, argList);
  SYSTEMTIME now;
  ::GetLocalTime(&now);
//  int len = _snprintf(buffer2, BUFFERSIZE + 50, "%s (%.2d:%.2d:%.2d.%.4d): %s\r\n", prefix, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, buffer);
  int len = wnsprintfA(buffer2, BUFFERSIZE + 50, "%s (%.2d:%.2d:%.2d.%.4d): %s\r\n", prefix, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, buffer);
  if (len < 0) {
    len = BUFFERSIZE + 50;
  }
  buffer2[len] = '\0';

  if (m_LogFile != INVALID_HANDLE_VALUE) {
    DWORD sizeWritten = 0;
    ::WriteFile(m_LogFile, buffer2, len, &sizeWritten, NULL);
  }
}


void log(const char* format, ...)
{
  va_list argList;
  va_start(argList, format);

  Logger::Instance().log("ERROR", format, argList);

  va_end(argList);
}
