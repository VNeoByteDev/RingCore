#ifndef JUNKCLEANER_H
#define JUNKCLEANER_H

#include <QObject>
#include <QThread>
#include <QString>
#include <QVector>
#include <QMutex>
#include <atomic>

struct JunkItem {
    QString path;
    QString category;
    quint64 size;
    bool selected;
};

class JunkScanWorker : public QThread
{
    Q_OBJECT
public:
    JunkScanWorker(QObject *parent = nullptr);
    void stop();

signals:
    void itemFound(const JunkItem &item);
    void scanProgress(const QString &currentPath, int filesScanned);
    void scanFinished(qint64 totalSize, int fileCount);

protected:
    void run() override;

private:
    void scanDirectory(const QString &dir, const QString &category);
    void scanTempFiles();
    void scanBrowserCache();
    void scanWindowsTemp();
    void scanLogFiles();
    void scanRecycleBin();

    std::atomic<bool> m_stopFlag;
};

class JunkCleaner : public QObject
{
    Q_OBJECT
public:
    explicit JunkCleaner(QObject *parent = nullptr);

    void startScan();
    void stopScan();
    void cleanSelected(const QVector<int> &indices);
    bool isScanning() const;
    const QVector<JunkItem>& items() const;

signals:
    void itemFound(const JunkItem &item);
    void scanProgress(const QString &currentPath, int filesScanned);
    void scanFinished(qint64 totalSize, int fileCount);
    void cleanFinished(int cleanedCount, qint64 freedBytes);

private:
    JunkScanWorker *m_worker;
    QVector<JunkItem> m_items;
    mutable QMutex m_mutex;
};

#endif // JUNKCLEANER_H
