#include "hooklock.h"


bool HookLock::m_Locked = false;

HookLock::HookLock()
  : m_Owner(!m_Locked)
{
  if (m_Owner) {
    m_Locked = true;
  }
}
