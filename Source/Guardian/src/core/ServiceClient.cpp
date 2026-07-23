#include "ServiceClient.h"
#include <cstdio>

#define PIPE_NAME L"\\\\.\\pipe\\RingCoreSvc"

enum SvcCmd : DWORD {
    CMD_GET_STATUS = 1,
    CMD_ENABLE_PROTECT = 2,
    CMD_DISABLE_PROTECT = 3,
};

ServiceClient::ServiceClient(QObject *parent)
    : QObject(parent), m_pipe(INVALID_HANDLE_VALUE), m_connected(false) {}

ServiceClient::~ServiceClient() { disconnect(); }

bool ServiceClient::isConnected() const { return m_connected; }

bool ServiceClient::connectToService()
{
    QMutexLocker lock(&m_pipeMutex);
    if (m_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }

    m_pipe = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (m_pipe == INVALID_HANDLE_VALUE) {
        m_connected = false;
        return false;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(m_pipe, &mode, NULL, NULL);

    m_connected = true;
    emit connected();
    return true;
}

void ServiceClient::disconnect()
{
    QMutexLocker lock(&m_pipeMutex);
    if (m_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
    m_connected = false;
    emit disconnected();
}

ServiceResponse ServiceClient::getStatus()
{
    ServiceResponse resp = {};
    if (!m_connected) return resp;

    QMutexLocker lock(&m_pipeMutex);
    DWORD cmd = CMD_GET_STATUS;
    DWORD bytesWritten, bytesRead;
    if (!WriteFile(m_pipe, &cmd, sizeof(cmd), &bytesWritten, NULL) ||
        !ReadFile(m_pipe, &resp, sizeof(resp), &bytesRead, NULL)) {
        lock.unlock();
        disconnect();
        return resp;
    }
    return resp;
}

bool ServiceClient::enableProtection()
{
    if (!m_connected) return false;
    QMutexLocker lock(&m_pipeMutex);
    DWORD cmd = CMD_ENABLE_PROTECT;
    DWORD bytesWritten, bytesRead;
    ServiceResponse resp;
    if (!WriteFile(m_pipe, &cmd, sizeof(cmd), &bytesWritten, NULL) ||
        !ReadFile(m_pipe, &resp, sizeof(resp), &bytesRead, NULL)) {
        lock.unlock();
        disconnect();
        return false;
    }
    return resp.status == 1;
}

bool ServiceClient::disableProtection()
{
    if (!m_connected) return false;
    QMutexLocker lock(&m_pipeMutex);
    DWORD cmd = CMD_DISABLE_PROTECT;
    DWORD bytesWritten, bytesRead;
    ServiceResponse resp;
    if (!WriteFile(m_pipe, &cmd, sizeof(cmd), &bytesWritten, NULL) ||
        !ReadFile(m_pipe, &resp, sizeof(resp), &bytesRead, NULL)) {
        lock.unlock();
        disconnect();
        return false;
    }
    return resp.status == 0;
}
