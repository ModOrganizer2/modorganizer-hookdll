#ifndef THOOKLOCK_H
#define THOOKLOCK_H


#define WIN32_LEAN_AND_MEAN
#include <Windows.h>


class HookLock {
public:

  HookLock();
  ~HookLock() { if (m_Owner) m_Locked = false; }

  static bool isLocked() { return m_Locked; }

private:

  bool m_Owner;
  static __declspec(thread) bool m_Locked;

};



#endif // THOOKLOCK_H
