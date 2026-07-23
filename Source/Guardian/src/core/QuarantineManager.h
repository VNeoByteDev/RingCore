#ifndef QUARANTINEMANAGER_H
#define QUARANTINEMANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QDateTime>

struct QuarantineEntry {
    QString originalPath;    // 原始文件路径
    QString quarantinePath;  // 隔离区中的路径
    QString sha256;          // 文件 SHA256
    QString threatName;      // 威胁名称
    QString threatType;      // 威胁类型
    int severity;            // 威胁等级 1-5
    QDateTime quarantineTime;// 隔离时间
    quint64 fileSize;        // 文件大小
};

class QuarantineManager : public QObject
{
    Q_OBJECT
public:
    explicit QuarantineManager(QObject *parent = nullptr);

    // 隔离文件
    bool quarantineFile(const QString &filePath, const QString &threatName,
                       const QString &threatType, int severity);

    // 恢复文件
    bool restoreFile(int index);

    // 删除隔离文件
    bool deleteFile(int index);

    // 获取隔离列表
    QList<QuarantineEntry> entries() const;

    // 获取隔离目录
    QString quarantineDir() const;

    // 获取统计信息
    int count() const;
    quint64 totalSize() const;

signals:
    void fileQuarantined(const QuarantineEntry &entry);
    void fileRestored(const QString &originalPath);
    void fileDeleted(const QString &quarantinePath);

private:
    QString m_quarantineDir;
    QList<QuarantineEntry> m_entries;

    void loadEntries();
    void saveEntries();
    QString generateQuarantineName(const QString &originalName);
};

#endif // QUARANTINEMANAGER_H
