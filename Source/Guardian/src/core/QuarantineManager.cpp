#include "QuarantineManager.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCoreApplication>
#include <QCryptographicHash>

QuarantineManager::QuarantineManager(QObject *parent)
    : QObject(parent)
{
    m_quarantineDir = QCoreApplication::applicationDirPath() + "/../../Quarantine";
    QDir().mkpath(m_quarantineDir);
    loadEntries();
}

QString QuarantineManager::quarantineDir() const { return m_quarantineDir; }
int QuarantineManager::count() const { return m_entries.size(); }

quint64 QuarantineManager::totalSize() const
{
    quint64 size = 0;
    for (const auto &entry : m_entries)
        size += entry.fileSize;
    return size;
}

QList<QuarantineEntry> QuarantineManager::entries() const { return m_entries; }

QString QuarantineManager::generateQuarantineName(const QString &originalName)
{
    QDateTime now = QDateTime::currentDateTime();
    QString timestamp = now.toString("yyyyMMdd_HHmmss");
    QString baseName = QFileInfo(originalName).baseName();
    QString ext = QFileInfo(originalName).completeSuffix();
    return QString("%1_%2.%3").arg(baseName, timestamp, ext);
}

bool QuarantineManager::quarantineFile(const QString &filePath, const QString &threatName,
                                       const QString &threatType, int severity)
{
    QFileInfo fi(filePath);
    if (!fi.exists() || !fi.isFile()) return false;

    // Read file
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) return false;
    QByteArray data = file.readAll();
    file.close();

    // Compute SHA256
    QByteArray hash = QCryptographicHash::hash(data, QCryptographicHash::Sha256);
    QString sha256 = hash.toHex();

    // Generate quarantine name
    QString quarantineName = generateQuarantineName(fi.fileName());
    QString quarantinePath = m_quarantineDir + "/" + quarantineName;

    // Write quarantined file
    QFile qFile(quarantinePath);
    if (!qFile.open(QIODevice::WriteOnly)) return false;
    qFile.write(data);
    qFile.close();

    // Remove original file
    QFile::remove(filePath);

    // Create entry
    QuarantineEntry entry;
    entry.originalPath = filePath;
    entry.quarantinePath = quarantinePath;
    entry.sha256 = sha256;
    entry.threatName = threatName;
    entry.threatType = threatType;
    entry.severity = severity;
    entry.quarantineTime = QDateTime::currentDateTime();
    entry.fileSize = fi.size();

    m_entries.append(entry);
    saveEntries();

    emit fileQuarantined(entry);
    return true;
}

bool QuarantineManager::restoreFile(int index)
{
    if (index < 0 || index >= m_entries.size()) return false;

    QuarantineEntry entry = m_entries.at(index);

    // Ensure original directory exists
    QFileInfo fi(entry.originalPath);
    QDir().mkpath(fi.absolutePath());

    // Move file back
    if (!QFile::exists(entry.quarantinePath)) return false;
    if (!QFile::rename(entry.quarantinePath, entry.originalPath)) return false;

    // Remove from list
    m_entries.removeAt(index);
    saveEntries();

    emit fileRestored(entry.originalPath);
    return true;
}

bool QuarantineManager::deleteFile(int index)
{
    if (index < 0 || index >= m_entries.size()) return false;

    QuarantineEntry entry = m_entries.at(index);

    // Delete quarantined file
    QFile::remove(entry.quarantinePath);

    // Remove from list
    m_entries.removeAt(index);
    saveEntries();

    emit fileDeleted(entry.quarantinePath);
    return true;
}

void QuarantineManager::loadEntries()
{
    QString indexPath = m_quarantineDir + "/index.json";
    QFile file(indexPath);
    if (!file.open(QIODevice::ReadOnly)) return;

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();

    QJsonArray arr = doc.array();
    for (const auto &val : arr) {
        QJsonObject obj = val.toObject();
        QuarantineEntry entry;
        entry.originalPath = obj["originalPath"].toString();
        entry.quarantinePath = obj["quarantinePath"].toString();
        entry.sha256 = obj["sha256"].toString();
        entry.threatName = obj["threatName"].toString();
        entry.threatType = obj["threatType"].toString();
        entry.severity = obj["severity"].toInt();
        entry.quarantineTime = QDateTime::fromString(obj["quarantineTime"].toString(), Qt::ISODate);
        entry.fileSize = obj["fileSize"].toVariant().toULongLong();
        m_entries.append(entry);
    }
}

void QuarantineManager::saveEntries()
{
    QJsonArray arr;
    for (const auto &entry : m_entries) {
        QJsonObject obj;
        obj["originalPath"] = entry.originalPath;
        obj["quarantinePath"] = entry.quarantinePath;
        obj["sha256"] = entry.sha256;
        obj["threatName"] = entry.threatName;
        obj["threatType"] = entry.threatType;
        obj["severity"] = entry.severity;
        obj["quarantineTime"] = entry.quarantineTime.toString(Qt::ISODate);
        obj["fileSize"] = static_cast<qint64>(entry.fileSize);
        arr.append(obj);
    }

    QString indexPath = m_quarantineDir + "/index.json";
    QFile file(indexPath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(arr).toJson());
    }
}
