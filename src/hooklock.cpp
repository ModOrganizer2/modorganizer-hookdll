#include "hooklock.h"
#include "logger.h"


class __tlsCleanup {
public:
  __tlsCleanup() {
    m_Index = ::TlsAlloc();
  }
  ~__tlsCleanup() {
    ::TlsFree(m_Index);
  }

  DWORD index() {
    return m_Index;
  }
private:
  DWORD m_Index;
} s_TlsCleanup;


DWORD WINAPI GetTLS()
{
  LPVOID tlsData;
  DWORD *data;

  tlsData = ::TlsGetValue(s_TlsCleanup.index());
  if (tlsData != nullptr) {
    data = (DWORD*)tlsData;
    return *data;
  } else {
    // this happens if StoreTLS was never called. in this case the value can be assumed to be 0
    return 0UL;
  }
}


void WINAPI StoreTLS(DWORD value)
{
  LPVOID tlsData;
  DWORD *data;

  tlsData = ::TlsGetValue(s_TlsCleanup.index());
  if (tlsData == nullptr) {
    // this can happen for threads started before this dll was loaded
    tlsData = InitTLS();
    if (tlsData == nullptr) {
      Logger::Instance().error("failed to store tls data");
      return;
    }
  }

  data = (DWORD*)tlsData;

  (*data) = value;
}


LPVOID InitTLS()
{
  LPVOID tlsData = (LPVOID)::LocalAlloc(LPTR, 256);
  if (tlsData != nullptr) {
    ::TlsSetValue(s_TlsCleanup.index(), tlsData);
  } else {
    Logger::Instance().error("failed to init tls");
  }
  return tlsData;
}


HookLock::HookLock(DWORD group)
  : m_Owner(false), m_Group(group)
{
  DWORD currentMask = GetTLS();
  if ((currentMask & group) == 0UL) {
    StoreTLS(currentMask | group);
    m_Owner = true;
  }
}

HookLock::~HookLock() {
  if (m_Owner) {
    DWORD error = ::GetLastError();
    StoreTLS(GetTLS() & ~m_Group);
    ::SetLastError(error);
  }
}

bool HookLock::isLocked(DWORD group) {
  return (GetTLS() & group) != 0UL;
}
