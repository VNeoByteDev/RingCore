#ifndef SETTINGS_H
#define SETTINGS_H

#include <QObject>
#include <QString>

class Settings : public QObject
{
    Q_OBJECT
public:
    explicit Settings(QObject *parent = nullptr);

    void load();
    void save();

    // Getters
    bool autoStart() const { return m_autoStart; }
    bool minimizeToTray() const { return m_minimizeToTray; }
    bool autoUpdateDB() const { return m_autoUpdateDB; }
    bool processProtection() const { return m_processProtection; }
    bool fileProtection() const { return m_fileProtection; }
    bool registryProtection() const { return m_registryProtection; }
    bool networkProtection() const { return m_networkProtection; }
    bool bootProtection() const { return m_bootProtection; }
    bool threatNotify() const { return m_threatNotify; }
    bool soundNotify() const { return m_soundNotify; }
    bool scanCompleteNotify() const { return m_scanCompleteNotify; }
    bool silentScan() const { return m_silentScan; }

    // Setters
    void setAutoStart(bool v);
    void setMinimizeToTray(bool v);
    void setAutoUpdateDB(bool v);
    void setProcessProtection(bool v);
    void setFileProtection(bool v);
    void setRegistryProtection(bool v);
    void setNetworkProtection(bool v);
    void setBootProtection(bool v);
    void setThreatNotify(bool v);
    void setSoundNotify(bool v);
    void setScanCompleteNotify(bool v);
    void setSilentScan(bool v);

signals:
    void settingChanged(const QString &key, bool value);
    void protectionToggled(const QString &type, bool enabled);

private:
    QString configPath() const;

    bool m_autoStart;
    bool m_minimizeToTray;
    bool m_autoUpdateDB;
    bool m_processProtection;
    bool m_fileProtection;
    bool m_registryProtection;
    bool m_networkProtection;
    bool m_bootProtection;
    bool m_threatNotify;
    bool m_soundNotify;
    bool m_scanCompleteNotify;
    bool m_silentScan;
};

// Global instance
extern Settings *g_settings;

#endif // SETTINGS_H
