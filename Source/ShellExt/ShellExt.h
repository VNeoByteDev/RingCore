#ifndef SHELLEXT_H
#define SHELLEXT_H

#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>

// RingCore Shell Extension - Context Menu Handler
// Registers "RingCore 扫描" in the right-click menu for files and folders

class RingCoreShellExt : public IShellExtInit, public IContextMenu
{
public:
    RingCoreShellExt();
    ~RingCoreShellExt();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void **ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();

    // IShellExtInit
    STDMETHODIMP Initialize(LPCITEMIDLIST pidlFolder, IDataObject *pDataObj, HKEY hKeyProgID);

    // IContextMenu
    STDMETHODIMP GetContextMenu(IContextMenu **ppcm);
    STDMETHODIMP QueryContextMenu(HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags);
    STDMETHODIMP InvokeCommand(LPCMINVOKECOMMANDINFO pici);
    STDMETHODIMP GetCommandString(UINT_PTR idCmd, UINT uFlags, UINT *pwReserved, LPSTR pszName, UINT cchMax);

private:
    LONG m_refCount;
    IDataObject *m_pDataObj;
    WCHAR m_szFilePath[MAX_PATH];

    static const UINT CMD_SCAN = 0;
};

// Class Factory
class RingCoreShellClassFactory : public IClassFactory
{
public:
    STDMETHODIMP QueryInterface(REFIID riid, void **ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();
    STDMETHODIMP CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppv);
    STDMETHODIMP LockServer(BOOL fLock);

private:
    LONG m_refCount;
};

// DLL Exports
STDAPI DllCanUnloadNow();
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void **ppv);
STDAPI DllRegisterServer();
STDAPI DllUnregisterServer();

#endif // SHELLEXT_H
