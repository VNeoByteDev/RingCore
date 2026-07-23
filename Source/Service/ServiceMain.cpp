#include <windows.h>
#include <cstdio>
#include <cstring>
#include "ServiceCore.h"

static ServiceCore* g_service = NULL;

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD ctrlCode);

int main(int argc, char* argv[])
{
    if (argc > 1 && strcmp(argv[1], "console") == 0) {
        printf("RingCore Service - Console Mode\n");
        ServiceCore service;
        g_service = &service;
        service.start();
        HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        WaitForSingleObject(hEvent, INFINITE);
        CloseHandle(hEvent);
        return 0;
    }

    SERVICE_TABLE_ENTRYW stEntry[] = {
        { (LPWSTR)L"RingCoreSvc", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherW(stEntry)) {
        ServiceCore service;
        g_service = &service;
        service.start();
        Sleep(INFINITE);
    }
    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    SERVICE_STATUS_HANDLE hStatus = RegisterServiceCtrlHandlerW(
        L"RingCoreSvc", ServiceCtrlHandler);
    if (!hStatus) return;

    SERVICE_STATUS ss;
    memset(&ss, 0, sizeof(ss));
    ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ss.dwCurrentState = SERVICE_START_PENDING;
    ss.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(hStatus, &ss);

    ServiceCore service;
    g_service = &service;
    service.start();

    ss.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ss);

    HANDLE hStopEvent = service.getStopEvent();
    WaitForSingleObject(hStopEvent, INFINITE);

    ss.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ss);
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    if (ctrlCode == SERVICE_CONTROL_STOP || ctrlCode == SERVICE_CONTROL_SHUTDOWN) {
        if (g_service) g_service->stop();
    }
}