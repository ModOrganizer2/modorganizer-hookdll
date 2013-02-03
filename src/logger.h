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

#include "stdafx.h"
#include <cstdarg>
#include <string>


#ifdef DEBUG_LOG
#define LOGDEBUG(...) Logger::Instance().debug(__VA_ARGS__)
#else
#define LOGDEBUG(...)
#endif


class Logger {

  friend struct __LoggerCleanup;
  friend void log(const char* format, ...);

public:

  enum LogLevel {
    LEVEL_DEBUG,
    LEVEL_INFO,
    LEVEL_ERROR
  };

public:
  static Logger& Instance();
  static void Init(LPCTSTR basePath, int logLevel);
  static bool IsInitialised() { return s_Instance != NULL; }
  ~Logger();

  void debug(const char* format, ...);
  void error(const char* format, ...);
  void info(const char* format, ...);

private:
  Logger(LPCTSTR basePath, int logLevel);
  void wrapUpLog();
  void log(const char* prefix, const char* format, va_list argList);

private:

  static Logger* s_Instance;
  std::basic_string<TCHAR> m_LogPath;
  int m_LogLevel;
  HANDLE m_LogFile;
};
