#include "profile.h"
#include "logger.h"


std::map<const char*, TProfile::Time> TProfile::s_Times;
time_t TProfile::s_LastDisplay = time(NULL);


void TProfile::displayProfile()
{
  if (!s_Times.empty()) {
    double total = 0.0;
    for (std::map<const char*, Time>::const_iterator iter = s_Times.begin(); iter != s_Times.end(); ++iter) {
      Logger::Instance().info("%s: %lu calls, %d to %d us (total: %d us, avg: %d us)",
                              iter->first,
                              iter->second.m_Count,
                              static_cast<int>(iter->second.m_Min * 1000000),
                              static_cast<int>(iter->second.m_Max * 1000000),
                              static_cast<int>(iter->second.m_Sum * 1000000),
                              static_cast<int>((iter->second.m_Sum / static_cast<double>(iter->second.m_Count)) * 1000000));
      total += iter->second.m_Sum;
    }
    Logger::Instance().info("Total: %d ms", static_cast<int>(total * 1000));
    s_Times.clear();
  }
}

