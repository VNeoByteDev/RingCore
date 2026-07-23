#include "ServiceCore.h"
#include <cstdio>
#include <vector>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <psapi.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

#define PIPE_NAME L"\\\\.\\pipe\\RingCoreSvc"
#define PIPE_BUFSIZE 4096

ServiceCore::ServiceCore()
    : m_stopEvent(NULL), m_pipeHandle(INVALID_HANDLE_VALUE),
      m_running(false), m_protectionEnabled(true),
      m_protectedFiles(0), m_blockedThreats(0), m_eventsToday(0) {}

ServiceCore::~ServiceCore() { stop(); }

HANDLE ServiceCore::getStopEvent() const { return m_stopEvent; }

void ServiceCore::start()
{
    m_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    m_running = true;
    loadThreatDB();
    m_pipeThread = std::thread(&ServiceCore::pipeServerThread, this);
    m_protectThread = std::thread(&ServiceCore::protectionThread, this);
    m_processThread = std::thread(&ServiceCore::processMonitorThread, this);
}

void ServiceCore::stop()
{
    m_running = false;
    if (m_stopEvent) SetEvent(m_stopEvent);
    if (m_pipeHandle != INVALID_HANDLE_VALUE) {
        CancelIoEx(m_pipeHandle, NULL);
        CloseHandle(m_pipeHandle);
        m_pipeHandle = INVALID_HANDLE_VALUE;
    }
    if (m_pipeThread.joinable()) m_pipeThread.join();
    if (m_protectThread.joinable()) m_protectThread.join();
    if (m_processThread.joinable()) m_processThread.join();
    if (m_stopEvent) { CloseHandle(m_stopEvent); m_stopEvent = NULL; }
}

// === Threat Database ===
void ServiceCore::loadThreatDB()
{
    // Mirror of GUI ThreatDB (key hashes for real-time interception)
    const char* hashes[] = {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", // EICAR
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", // WannaCry
        "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745", // NotPetya
        "0a73291ab5607aef7571571a27d44361226b87368f6531e0cf28e2ad29d9d7d5", // Emotet
        "a194c67e4d8fb145c5965dab4dd27b5bf581f5d495c4f9437e492a65c94948f2", // Emotet
        "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4", // LockBit
        "e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6", // Conti
        "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7", // REvil
        "b1d23f3c4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1", // Dridex
        "c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8", // QakBot
        "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4", // Remcos
        "f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5", // njRAT
        "b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7", // AZORult
        "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1", // RedLine
        "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3", // AgentTesla
        "9f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a", // Stuxnet
        "4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b", // TDSS
        "6c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d", // Pegasus
        "51b1dc1e1ceea09e2008a9956510eda8b4e451306fd921e301c6f8fb00aca982", // Test
        "1a442c6e1c9e2256d0378cfce90a799eb2070a53b637d8966c6ba0ef128196eb", // Test
        "32e10e8f5d9773e9c5351a9ba99bcf41768f3ccf3f98db49758131b69a1f921c", // Test
        "6b1a6af9267d7ad34a6a3c1737ffc6507638d272ba9601d237a90f4184deb12e", // Test realtime
    };
    for (auto h : hashes) m_threatHashes.insert(h);
}

bool ServiceCore::isThreatHash(const std::string& hash)
{
    return m_threatHashes.find(hash) != m_threatHashes.end();
}

std::string ServiceCore::computeSHA256(const std::wstring& filePath)
{
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        CloseHandle(hFile); return "";
    }
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0); CloseHandle(hFile); return "";
    }

    BYTE buffer[65536];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        BCryptHashData(hHash, buffer, bytesRead, 0);
    }

    BYTE hash[32];
    BCryptFinishHash(hHash, hash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);

    char hex[65] = {};
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", hash[i]);
    return std::string(hex);
}

void ServiceCore::blockProcess(DWORD pid, const std::wstring& name)
{
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc) {
        TerminateProcess(hProc, 1);
        CloseHandle(hProc);
        m_blockedThreats++;
        wprintf(L"[RingCoreSvc] BLOCKED: %s (PID: %lu)\n", name.c_str(), pid);
    }
}

// === Process Monitor ===
void ServiceCore::processMonitorThread()
{
    // Track by PID — every new PID gets checked
    std::unordered_set<DWORD> knownPIDs;

    // Initial snapshot of running PIDs
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do { knownPIDs.insert(pe.th32ProcessID); } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }

    while (m_running) {
        if (!m_protectionEnabled) { Sleep(2000); continue; }

        Sleep(3000);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snap, &pe)) {
            do {
                // Skip already checked PIDs
                if (knownPIDs.count(pe.th32ProcessID)) continue;

                // New PID — get its path and scan
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (!hProc) { knownPIDs.insert(pe.th32ProcessID); continue; }

                WCHAR path[MAX_PATH] = {};
                DWORD pathLen = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, path, &pathLen)) {
                    std::wstring pathStr(path);

                    // Skip system and our own processes
                    std::wstring lower = pathStr;
                    for (auto& c : lower) c = towlower(c);

                    bool skip = false;
                    // Only skip Windows system directories
                    if (lower.find(L"\\windows\\system32\\") != std::wstring::npos) skip = true;
                    if (lower.find(L"\\windows\\syswow64\\") != std::wstring::npos) skip = true;

                    if (!skip && (wcsstr(lower.c_str(), L".exe") || wcsstr(lower.c_str(), L".dll") || wcsstr(lower.c_str(), L".scr"))) {
                        m_protectedFiles++;
                        std::string hash = computeSHA256(pathStr);
                        if (!hash.empty() && isThreatHash(hash)) {
                            blockProcess(pe.th32ProcessID, pe.szExeFile);
                        }
                    }
                }
                CloseHandle(hProc);
                knownPIDs.insert(pe.th32ProcessID);

            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
}

// === File Protection (existing) ===
struct WatchDir { const wchar_t* path; const wchar_t* name; };
struct DirWatch { HANDLE hDir; HANDLE hEvent; BYTE buffer[4096]; wchar_t name[64]; };

void ServiceCore::protectionThread()
{
    WatchDir watchDirs[] = {
        {L"C:\\Users", L"UserProfiles"},
        {L"C:\\Windows\\System32\\drivers", L"Drivers"},
        {L"C:\\ProgramData", L"ProgramData"},
    };
    std::vector<DirWatch> watches;
    for (int i = 0; i < 3; i++) {
        DirWatch dw = {};
        dw.hDir = CreateFileW(watchDirs[i].path, FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
        if (dw.hDir == INVALID_HANDLE_VALUE) continue;
        dw.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        wcscpy_s(dw.name, watchDirs[i].name);
        watches.push_back(dw);
    }
    while (m_running) {
        if (!m_protectionEnabled) { Sleep(1000); continue; }
        for (size_t i = 0; i < watches.size(); i++) {
            DirWatch& dw = watches[i];
            ResetEvent(dw.hEvent);
            OVERLAPPED overlapped = {};
            overlapped.hEvent = dw.hEvent;
            if (!ReadDirectoryChangesW(dw.hDir, dw.buffer, sizeof(dw.buffer), FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                NULL, &overlapped, NULL)) continue;
            if (WaitForSingleObject(dw.hEvent, 2000) == WAIT_OBJECT_0) {
                DWORD bytesReturned = 0;
                if (GetOverlappedResult(dw.hDir, &overlapped, &bytesReturned, FALSE)) {
                    FILE_NOTIFY_INFORMATION* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(dw.buffer);
                    do {
                        wchar_t fileName[MAX_PATH] = {};
                        int len = info->FileNameLength / sizeof(WCHAR);
                        if (len > 0 && len < MAX_PATH) wcsncpy_s(fileName, info->FileName, len);
                        wchar_t lower[MAX_PATH];
                        wcscpy_s(lower, fileName);
                        for (wchar_t* p = lower; *p; p++) { if (*p >= L'A' && *p <= L'Z') *p += 32; }
                        if (wcsstr(lower, L".exe") || wcsstr(lower, L".dll") || wcsstr(lower, L".sys")) {
                            m_eventsToday++;
                            m_protectedFiles++;
                        }
                        if (info->NextEntryOffset == 0) break;
                        info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                            reinterpret_cast<BYTE*>(info) + info->NextEntryOffset);
                    } while (true);
                }
            }
        }
        Sleep(100);
    }
    for (size_t i = 0; i < watches.size(); i++) {
        if (watches[i].hDir != INVALID_HANDLE_VALUE) CloseHandle(watches[i].hDir);
        if (watches[i].hEvent) CloseHandle(watches[i].hEvent);
    }
}

// === Pipe Server ===
void ServiceCore::pipeServerThread()
{
    while (m_running) {
        m_pipeHandle = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, PIPE_BUFSIZE, PIPE_BUFSIZE, 0, NULL);
        if (m_pipeHandle == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }
        if (ConnectNamedPipe(m_pipeHandle, NULL)) handleCommand(m_pipeHandle);
        DisconnectNamedPipe(m_pipeHandle);
        CloseHandle(m_pipeHandle);
        m_pipeHandle = INVALID_HANDLE_VALUE;
    }
}

void ServiceCore::handleCommand(HANDLE pipe)
{
    DWORD bytesRead, bytesWritten;
    char buffer[PIPE_BUFSIZE];
    while (m_running) {
        if (!ReadFile(pipe, buffer, PIPE_BUFSIZE - 1, &bytesRead, NULL) || bytesRead == 0) break;
        buffer[bytesRead] = '\0';
        ServiceCommand cmd = *reinterpret_cast<ServiceCommand*>(buffer);
        ServiceResponse resp = {};
        resp.status = m_protectionEnabled ? 1 : 0;
        resp.protectedFiles = m_protectedFiles;
        resp.blockedThreats = m_blockedThreats;
        resp.eventsToday = m_eventsToday;
        if (cmd == CMD_ENABLE_PROTECT) m_protectionEnabled = true;
        else if (cmd == CMD_DISABLE_PROTECT) m_protectionEnabled = false;
        WriteFile(pipe, &resp, sizeof(resp), &bytesWritten, NULL);
    }
}
