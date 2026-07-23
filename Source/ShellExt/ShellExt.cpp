// RingCore Shell Extension - Context Menu Handler
// Registers "RingCore 扫描" in the right-click menu for files and folders

#include "ShellExt.h"
#include <objbase.h>
#include <strsafe.h>

// CLSID for RingCore Shell Extension
// {E8A25D41-3C5B-4F7A-9B2E-1D8C6A3F5E7B}
static const CLSID CLSID_RingCoreShellExt = 
    {0xe8a25d41, 0x3c5b, 0x4f7a, {0x9b, 0x2e, 0x1d, 0x8c, 0x6a, 0x3f, 0x5e, 0x7b}};

static HINSTANCE g_hInstance = NULL;

// === RingCoreShellExt ===

RingCoreShellExt::RingCoreShellExt() : m_refCount(1), m_pDataObj(NULL)
{
    m_szFilePath[0] = L'\0';
}

RingCoreShellExt::~RingCoreShellExt()
{
    if (m_pDataObj) { m_pDataObj->Release(); m_pDataObj = NULL; }
}

HRESULT RingCoreShellExt::QueryInterface(REFIID riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;

    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IShellExtInit))
        *ppv = static_cast<IShellExtInit*>(this);
    else if (IsEqualIID(riid, IID_IContextMenu))
        *ppv = static_cast<IContextMenu*>(this);
    else
        return E_NOINTERFACE;

    AddRef();
    return S_OK;
}

ULONG RingCoreShellExt::AddRef() { return InterlockedIncrement(&m_refCount); }

ULONG RingCoreShellExt::Release()
{
    LONG ref = InterlockedDecrement(&m_refCount);
    if (ref == 0) delete this;
    return ref;
}

HRESULT RingCoreShellExt::Initialize(LPCITEMIDLIST pidlFolder, IDataObject *pDataObj, HKEY hKeyProgID)
{
    if (m_pDataObj) { m_pDataObj->Release(); m_pDataObj = NULL; }
    m_szFilePath[0] = L'\0';

    if (!pDataObj) return E_INVALIDARG;

    m_pDataObj = pDataObj;
    m_pDataObj->AddRef();

    FORMATETC fmt = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    STGMEDIUM stg = { TYMED_HGLOBAL };

    if (SUCCEEDED(m_pDataObj->GetData(&fmt, &stg))) {
        HDROP hDrop = (HDROP)GlobalLock(stg.hGlobal);
        if (hDrop) {
            DragQueryFileW(hDrop, 0, m_szFilePath, MAX_PATH);
            GlobalUnlock(stg.hGlobal);
        }
        ReleaseStgMedium(&stg);
    }

    return S_OK;
}

HRESULT RingCoreShellExt::GetContextMenu(IContextMenu **ppcm) { return E_NOTIMPL; }

HRESULT RingCoreShellExt::QueryContextMenu(HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags)
{
    if (uFlags & CMF_DEFAULTONLY) return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);

    WCHAR menuText[256];
    StringCchPrintfW(menuText, 256, L"\u2726  RingCore \u626B\u63CF"); // RingCore 扫描

    InsertMenuW(hMenu, indexMenu, MF_STRING | MF_BYPOSITION, idCmdFirst + CMD_SCAN, menuText);

    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 1);
}

HRESULT RingCoreShellExt::InvokeCommand(LPCMINVOKECOMMANDINFO pici)
{
    if (!pici || HIWORD(pici->lpVerb) != 0) return E_INVALIDARG;

    UINT cmd = LOWORD(pici->lpVerb);
    if (cmd != CMD_SCAN) return E_INVALIDARG;

    if (m_szFilePath[0] == L'\0') return E_FAIL;

    // Get exe path from DLL location
    WCHAR dllPath[MAX_PATH];
    GetModuleFileNameW(g_hInstance, dllPath, MAX_PATH);

    // Build full path: ShellExt dir -> ..\Guardian\RingCoreGuardian.exe
    WCHAR *lastSlash = wcsrchr(dllPath, L'\\');
    if (lastSlash) {
        *(lastSlash + 1) = L'\0';
        StringCchCatW(dllPath, MAX_PATH, L"..\\Guardian\\RingCoreGuardian.exe");
    }

    // Resolve relative path to absolute
    WCHAR fullPath[MAX_PATH];
    GetFullPathNameW(dllPath, MAX_PATH, fullPath, NULL);

    // Build command line
    WCHAR finalCmd[1024];
    StringCchPrintfW(finalCmd, 1024, L"\"%s\" --scan \"%s\"", fullPath, m_szFilePath);

    // Launch scan
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    CreateProcessW(NULL, finalCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    if (pi.hProcess) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }

    return S_OK;
}

HRESULT RingCoreShellExt::GetCommandString(UINT_PTR idCmd, UINT uFlags, UINT *pwReserved, LPSTR pszName, UINT cchMax)
{
    if (idCmd != CMD_SCAN) return E_INVALIDARG;

    if (uFlags == GCS_VALIDATEW) return S_OK;

    if (uFlags == GCS_VERBW) {
        if (cchMax < 32) return E_FAIL;
        StringCchCopyW((LPWSTR)pszName, cchMax, L"RingCoreScan");
        return S_OK;
    }

    return E_INVALIDARG;
}

// === RingCoreShellClassFactory ===

HRESULT RingCoreShellClassFactory::QueryInterface(REFIID riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;

    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory))
        *ppv = static_cast<IClassFactory*>(this);
    else
        return E_NOINTERFACE;

    AddRef();
    return S_OK;
}

ULONG RingCoreShellClassFactory::AddRef() { return InterlockedIncrement(&m_refCount); }

ULONG RingCoreShellClassFactory::Release()
{
    LONG ref = InterlockedDecrement(&m_refCount);
    if (ref == 0) delete this;
    return ref;
}

HRESULT RingCoreShellClassFactory::CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    if (pUnkOuter) return CLASS_E_NOAGGREGATION;

    RingCoreShellExt *pExt = new RingCoreShellExt();
    HRESULT hr = pExt->QueryInterface(riid, ppv);
    pExt->Release();
    return hr;
}

HRESULT RingCoreShellClassFactory::LockServer(BOOL fLock) { return S_OK; }

// === DLL Exports ===

STDAPI DllCanUnloadNow() { return S_FALSE; }

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void **ppv)
{
    if (!ppv) return E_POINTER;

    if (!IsEqualCLSID(rclsid, CLSID_RingCoreShellExt))
        return CLASS_E_CLASSNOTAVAILABLE;

    RingCoreShellClassFactory *pFactory = new RingCoreShellClassFactory();
    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();
    return hr;
}

static HRESULT SetRegKeyValue(HKEY hKeyParent, LPCWSTR subKey, LPCWSTR valueName, LPCWSTR value)
{
    HKEY hKey;
    HRESULT hr = RegCreateKeyExW(hKeyParent, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                                  KEY_SET_VALUE, NULL, &hKey, NULL);
    if (SUCCEEDED(hr)) {
        hr = RegSetValueExW(hKey, valueName, 0, REG_SZ,
                            (const BYTE*)value, (DWORD)((wcslen(value) + 1) * sizeof(WCHAR)));
        RegCloseKey(hKey);
    }
    return hr;
}

static HRESULT SetRegKeyValueDword(HKEY hKeyParent, LPCWSTR subKey, LPCWSTR valueName, DWORD value)
{
    HKEY hKey;
    HRESULT hr = RegCreateKeyExW(hKeyParent, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                                  KEY_SET_VALUE, NULL, &hKey, NULL);
    if (SUCCEEDED(hr)) {
        hr = RegSetValueExW(hKey, valueName, 0, REG_DWORD, (const BYTE*)&value, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    return hr;
}

STDAPI DllRegisterServer()
{
    HRESULT hr;
    WCHAR szCLSID[64];
    StringFromGUID2(CLSID_RingCoreShellExt, szCLSID, 64);

    // Register CLSID
    WCHAR regPath[256];
    StringCchPrintfW(regPath, 256, L"CLSID\\%s", szCLSID);
    hr = SetRegKeyValue(HKEY_CLASSES_ROOT, regPath, NULL, L"RingCore Shell Extension");
    if (FAILED(hr)) return hr;

    // Register InprocServer32
    WCHAR inprocPath[256];
    StringCchPrintfW(inprocPath, 256, L"CLSID\\%s\\InprocServer32", szCLSID);
    WCHAR dllPath[MAX_PATH];
    GetModuleFileNameW(g_hInstance, dllPath, MAX_PATH);
    hr = SetRegKeyValue(HKEY_CLASSES_ROOT, inprocPath, NULL, dllPath);
    if (FAILED(hr)) return hr;
    hr = SetRegKeyValue(HKEY_CLASSES_ROOT, inprocPath, L"ThreadingModel", L"Apartment");
    if (FAILED(hr)) return hr;

    // Register for all file types
    WCHAR fileHandler[256];
    StringCchPrintfW(fileHandler, 256, L"*\\ShellEx\\ContextMenuHandlers\\RingCoreScan");
    hr = SetRegKeyValue(HKEY_CLASSES_ROOT, fileHandler, NULL, szCLSID);
    if (FAILED(hr)) return hr;

    // Register for directory types
    WCHAR dirHandler[256];
    StringCchPrintfW(dirHandler, 256, L"Directory\\ShellEx\\ContextMenuHandlers\\RingCoreScan");
    hr = SetRegKeyValue(HKEY_CLASSES_ROOT, dirHandler, NULL, szCLSID);
    if (FAILED(hr)) return hr;

    // Register background (right-click on empty space in folder)
    WCHAR bgHandler[256];
    StringCchPrintfW(bgHandler, 256, L"Directory\\Background\\ShellEx\\ContextMenuHandlers\\RingCoreScan");
    hr = SetRegKeyValue(HKEY_CLASSES_ROOT, bgHandler, NULL, szCLSID);
    if (FAILED(hr)) return hr;

    // Set menu text via ProgID (optional - for custom text)
    WCHAR fileTypeHandler[256];
    StringCchPrintfW(fileTypeHandler, 256, L"*\\shell\\RingCoreScan");
    hr = SetRegKeyValue(HKEY_CLASSES_ROOT, fileTypeHandler, NULL, L"RingCore \u626B\u63CF");
    if (FAILED(hr)) return hr;

    WCHAR fileTypeCmd[256];
    StringCchPrintfW(fileTypeCmd, 256, L"*\\shell\\RingCoreScan\\command");
    WCHAR cmdLine[512];
    StringCchPrintfW(cmdLine, 512, L"\"C:\\wenzhou\\RingCore\\Build\\Guardian\\RingCoreGuardian.exe\" --scan \"%%1\"");
    hr = SetRegKeyValue(HKEY_CLASSES_ROOT, fileTypeCmd, NULL, cmdLine);

    return hr;
}

STDAPI DllUnregisterServer()
{
    WCHAR szCLSID[64];
    StringFromGUID2(CLSID_RingCoreShellExt, szCLSID, 64);

    // Remove CLSID
    WCHAR regPath[256];
    StringCchPrintfW(regPath, 256, L"CLSID\\%s", szCLSID);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, regPath);

    // Remove handlers
    RegDeleteKeyW(HKEY_CLASSES_ROOT, L"*\\ShellEx\\ContextMenuHandlers\\RingCoreScan");
    RegDeleteKeyW(HKEY_CLASSES_ROOT, L"Directory\\ShellEx\\ContextMenuHandlers\\RingCoreScan");
    RegDeleteKeyW(HKEY_CLASSES_ROOT, L"Directory\\Background\\ShellEx\\ContextMenuHandlers\\RingCoreScan");
    RegDeleteKeyW(HKEY_CLASSES_ROOT, L"*\\shell\\RingCoreScan\\command");
    RegDeleteKeyW(HKEY_CLASSES_ROOT, L"*\\shell\\RingCoreScan");

    return S_OK;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_hInstance = hModule;
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}
