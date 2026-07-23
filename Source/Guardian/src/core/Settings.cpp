#include "Settings.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCoreApplication>
#include <QDir>
#include <QDebug>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

Settings *g_settings = nullptr;

Settings::Settings(QObject *parent)
    : QObject(parent)
    , m_autoStart(true)
    , m_minimizeToTray(true)
    , m_autoUpdateDB(true)
    , m_processProtection(true)
    , m_fileProtection(true)
    , m_registryProtection(true)
    , m_networkProtection(true)
    , m_bootProtection(true)
    , m_threatNotify(true)
    , m_soundNotify(true)
    , m_scanCompleteNotify(true)
    , m_silentScan(false)
{
    load();
}

QString Settings::configPath() const
{
    // Store config next to the executable
    return QCoreApplication::applicationDirPath() + "/../../Config/settings.json";
}

void Settings::load()
{
    QFile file(configPath());
    if (!file.open(QIODevice::ReadOnly)) return;

    QByteArray data = file.readAll();
    file.close();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull() || !doc.isObject()) {
        qWarning() << "Settings: corrupt config, using defaults";
        return;
    }
    QJsonObject root = doc.object();

    m_autoStart = root["autoStart"].toBool(true);
    m_minimizeToTray = root["minimizeToTray"].toBool(true);
    m_autoUpdateDB = root["autoUpdateDB"].toBool(true);
    m_processProtection = root["processProtection"].toBool(true);
    m_fileProtection = root["fileProtection"].toBool(true);
    m_registryProtection = root["registryProtection"].toBool(true);
    m_networkProtection = root["networkProtection"].toBool(true);
    m_bootProtection = root["bootProtection"].toBool(true);
    m_threatNotify = root["threatNotify"].toBool(true);
    m_soundNotify = root["soundNotify"].toBool(true);
    m_scanCompleteNotify = root["scanCompleteNotify"].toBool(true);
    m_silentScan = root["silentScan"].toBool(false);
}

void Settings::save()
{
    QJsonObject root;
    root["autoStart"] = m_autoStart;
    root["minimizeToTray"] = m_minimizeToTray;
    root["autoUpdateDB"] = m_autoUpdateDB;
    root["processProtection"] = m_processProtection;
    root["fileProtection"] = m_fileProtection;
    root["registryProtection"] = m_registryProtection;
    root["networkProtection"] = m_networkProtection;
    root["bootProtection"] = m_bootProtection;
    root["threatNotify"] = m_threatNotify;
    root["soundNotify"] = m_soundNotify;
    root["scanCompleteNotify"] = m_scanCompleteNotify;
    root["silentScan"] = m_silentScan;

    QFile file(configPath());
    QDir().mkpath(QFileInfo(file.fileName()).absolutePath());
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(root).toJson());
    }
}

void Settings::setAutoStart(bool v)
{
    m_autoStart = v;
#ifdef Q_OS_WIN
    HKEY hKey;
    QString appPath = QCoreApplication::applicationFilePath().replace('/', '\\');
    QString regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    LPCWSTR path = reinterpret_cast<LPCWSTR>(regPath.utf16());
    if (RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (v)
            RegSetValueExW(hKey, L"RingCoreGuardian", 0, REG_SZ,
                          reinterpret_cast<const BYTE*>(appPath.utf16()), (appPath.size() + 1) * sizeof(wchar_t));
        else
            RegDeleteValueW(hKey, L"RingCoreGuardian");
        RegCloseKey(hKey);
    }
#endif
    save();
    emit settingChanged("autoStart", v);
}
void Settings::setMinimizeToTray(bool v) { m_minimizeToTray = v; save(); emit settingChanged("minimizeToTray", v); }
void Settings::setAutoUpdateDB(bool v) { m_autoUpdateDB = v; save(); emit settingChanged("autoUpdateDB", v); }
void Settings::setProcessProtection(bool v) { m_processProtection = v; save(); emit settingChanged("processProtection", v); emit protectionToggled("process", v); }
void Settings::setFileProtection(bool v) { m_fileProtection = v; save(); emit settingChanged("fileProtection", v); emit protectionToggled("file", v); }
void Settings::setRegistryProtection(bool v) { m_registryProtection = v; save(); emit settingChanged("registryProtection", v); emit protectionToggled("registry", v); }
void Settings::setNetworkProtection(bool v) { m_networkProtection = v; save(); emit settingChanged("networkProtection", v); emit protectionToggled("network", v); }
void Settings::setBootProtection(bool v) { m_bootProtection = v; save(); emit settingChanged("bootProtection", v); emit protectionToggled("boot", v); }
void Settings::setThreatNotify(bool v) { m_threatNotify = v; save(); emit settingChanged("threatNotify", v); }
void Settings::setSoundNotify(bool v) { m_soundNotify = v; save(); emit settingChanged("soundNotify", v); }
void Settings::setScanCompleteNotify(bool v) { m_scanCompleteNotify = v; save(); emit settingChanged("scanCompleteNotify", v); }
void Settings::setSilentScan(bool v) { m_silentScan = v; save(); emit settingChanged("silentScan", v); }
