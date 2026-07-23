#include "JunkCleaner.h"
#include <QDir>
#include <QFileInfo>
#include <QDirIterator>
#include <QFile>
#include <QStandardPaths>
#include <QApplication>

// === JunkScanWorker ===

JunkScanWorker::JunkScanWorker(QObject *parent)
    : QThread(parent), m_stopFlag(false) {}

void JunkScanWorker::stop() { m_stopFlag = true; }

void JunkScanWorker::run()
{
    m_stopFlag = false;
    scanTempFiles();
    scanBrowserCache();
    scanWindowsTemp();
    scanLogFiles();
    emit scanFinished(0, 0);
}

void JunkScanWorker::scanTempFiles()
{
    if (m_stopFlag) return;
    QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    scanDirectory(tempPath, "临时文件");
}

void JunkScanWorker::scanBrowserCache()
{
    if (m_stopFlag) return;
    QString localApp = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);

    QStringList browsers = {
        localApp + "/Google/Chrome/User Data/Default/Cache",
        localApp + "/Google/Chrome/User Data/Default/Code Cache",
        localApp + "/Microsoft/Edge/User Data/Default/Cache",
        localApp + "/Microsoft/Edge/User Data/Default/Code Cache",
        localApp + "/Mozilla/Firefox/Profiles",
        localApp + "/BraveSoftware/Brave-Browser/User Data/Default/Cache",
    };

    for (const QString &path : browsers) {
        if (m_stopFlag) return;
        scanDirectory(path, "浏览器缓存");
    }
}

void JunkScanWorker::scanWindowsTemp()
{
    if (m_stopFlag) return;
    scanDirectory("C:\\Windows\\Temp", "Windows临时文件");
    scanDirectory("C:\\Windows\\Prefetch", "预读取文件");
}

void JunkScanWorker::scanLogFiles()
{
    if (m_stopFlag) return;
    scanDirectory("C:\\Windows\\Logs", "系统日志");

    QString localApp = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
    scanDirectory(localApp + "/CrashDumps", "崩溃转储");
}

void JunkScanWorker::scanRecycleBin()
{
    // Recycle bin is complex to access from user mode, skip for now
}

void JunkScanWorker::scanDirectory(const QString &dir, const QString &category)
{
    if (m_stopFlag) return;

    QDir directory(dir);
    if (!directory.exists()) return;

    QDirIterator it(dir, QDir::Files | QDir::NoSymLinks, QDirIterator::Subdirectories);
    int count = 0;
    QDateTime now = QDateTime::currentDateTime();

    while (it.hasNext()) {
        if (m_stopFlag) return;

        QString filePath = it.next();
        QFileInfo fi(filePath);

        if (!fi.isReadable()) continue;

        quint64 fileSize = fi.size();
        if (fileSize == 0) continue;

        // Safety: skip files modified in the last 5 minutes (might be in use)
        if (fi.lastModified().secsTo(now) < 300) continue;

        // Safety: skip very large files (>100MB, likely important)
        if (fileSize > 100 * 1024 * 1024) continue;

        // Safety: try to open the file to check if it's locked
        QFile testFile(filePath);
        if (!testFile.open(QIODevice::ReadOnly)) continue;
        testFile.close();

        JunkItem item;
        item.path = filePath;
        item.category = category;
        item.size = fileSize;
        item.selected = true;

        emit itemFound(item);
        count++;

        if (count % 50 == 0) {
            emit scanProgress(filePath, count);
        }

        // Limit scan time
        if (count > 5000) break;
    }
}

// === JunkCleaner ===

JunkCleaner::JunkCleaner(QObject *parent)
    : QObject(parent), m_worker(nullptr) {}

void JunkCleaner::startScan()
{
    if (m_worker && m_worker->isRunning()) {
        m_worker->stop();
        m_worker->wait(3000);
        m_worker->deleteLater();
        m_worker = nullptr;
    }
    m_items.clear();
    m_worker = new JunkScanWorker(this);

    connect(m_worker, &JunkScanWorker::itemFound, this, [this](const JunkItem &item) {
        QMutexLocker lock(&m_mutex);
        m_items.append(item);
        emit itemFound(item);
    });

    connect(m_worker, &JunkScanWorker::scanProgress, this, &JunkCleaner::scanProgress);
    connect(m_worker, &JunkScanWorker::scanFinished, this, [this](qint64, int) {
        QMutexLocker lock(&m_mutex);
        qint64 totalSize = 0;
        for (const auto &item : m_items) totalSize += item.size;
        emit scanFinished(totalSize, m_items.size());
    });

    connect(m_worker, &JunkScanWorker::finished, m_worker, &QObject::deleteLater);
    m_worker->start();
}

void JunkCleaner::stopScan()
{
    if (m_worker) {
        m_worker->stop();
        if (!m_worker->wait(3000)) {
            m_worker->terminate();
            m_worker->wait(1000);
        }
        m_worker->deleteLater();
        m_worker = nullptr;
    }
}

bool JunkCleaner::isScanning() const
{
    return m_worker && m_worker->isRunning();
}

const QVector<JunkItem>& JunkCleaner::items() const
{
    QMutexLocker lock(&m_mutex);
    return m_items;
}

void JunkCleaner::cleanSelected(const QVector<int> &indices)
{
    QMutexLocker lock(&m_mutex);
    qint64 freedBytes = 0;
    int cleanedCount = 0;
    QDateTime now = QDateTime::currentDateTime();

    for (int i = 0; i < indices.size(); i++) {
        if (i % 10 == 0) QApplication::processEvents();
        int idx = indices[i];
        if (idx < 0 || idx >= m_items.size()) continue;
        JunkItem &item = m_items[idx];
        if (!item.selected) continue;

        QFileInfo fi(item.path);

        // Safety: skip files modified in last 5 minutes
        if (fi.lastModified().secsTo(now) < 300) continue;

        // Safety: try to open to check if locked
        QFile testFile(item.path);
        if (!testFile.open(QIODevice::ReadOnly)) continue;
        testFile.close();

        // Delete
        QFile file(item.path);
        if (file.remove()) {
            freedBytes += item.size;
            cleanedCount++;
        }
    }

    emit cleanFinished(cleanedCount, freedBytes);
}
