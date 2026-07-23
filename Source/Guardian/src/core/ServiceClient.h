#ifndef SERVICECLIENT_H
#define SERVICECLIENT_H

#include <QObject>
#include <windows.h>
#include <atomic>
#include <QMutex>

enum ServiceCommand : DWORD;

struct ServiceResponse {
    DWORD status;
    DWORD protectedFiles;
    DWORD blockedThreats;
    DWORD eventsToday;
    DWORD padding;
};

class ServiceClient : public QObject
{
    Q_OBJECT
public:
    explicit ServiceClient(QObject *parent = nullptr);
    ~ServiceClient();

    bool connectToService();
    void disconnect();
    bool isConnected() const;

    ServiceResponse getStatus();
    bool enableProtection();
    bool disableProtection();

signals:
    void connected();
    void disconnected();

private:
    HANDLE m_pipe;
    std::atomic<bool> m_connected;
    QMutex m_pipeMutex;
};

#endif // SERVICECLIENT_H
