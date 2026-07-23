#ifndef SERVICECORE_H
#define SERVICECORE_H

#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <unordered_set>

enum ServiceCommand : DWORD {
    CMD_NONE = 0,
    CMD_GET_STATUS = 1,
    CMD_ENABLE_PROTECT = 2,
    CMD_DISABLE_PROTECT = 3,
    CMD_GET_EVENT_LOG = 4,
};

struct ServiceResponse {
    DWORD status;
    DWORD protectedFiles;
    DWORD blockedThreats;
    DWORD eventsToday;
    DWORD padding;
};

class ServiceCore {
public:
    ServiceCore();
    ~ServiceCore();
    void start();
    void stop();
    HANDLE getStopEvent() const;
private:
    void pipeServerThread();
    void protectionThread();
    void processMonitorThread();
    void handleCommand(HANDLE pipe);
    void loadThreatDB();
    bool isThreatHash(const std::string& hash);
    std::string computeSHA256(const std::wstring& filePath);
    void blockProcess(DWORD pid, const std::wstring& name);

    HANDLE m_stopEvent;
    HANDLE m_pipeHandle;
    std::thread m_pipeThread;
    std::thread m_protectThread;
    std::thread m_processThread;
    std::atomic<bool> m_running;
    std::atomic<bool> m_protectionEnabled;
    std::atomic<DWORD> m_protectedFiles;
    std::atomic<DWORD> m_blockedThreats;
    std::atomic<DWORD> m_eventsToday;

    // Threat database
    std::unordered_set<std::string> m_threatHashes;
    std::unordered_set<std::wstring> m_knownProcesses;
};

#endif
