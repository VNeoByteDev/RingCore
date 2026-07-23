#ifndef THREATDB_H
#define THREATDB_H

#include <QObject>
#include <QHash>
#include <QString>
#include <QMutex>

struct ThreatInfo {
    QString name;
    QString type;
    int severity;
};

class ThreatDB : public QObject
{
    Q_OBJECT
public:
    explicit ThreatDB(QObject *parent = nullptr);

    bool loadFromResource();
    bool loadFromFile(const QString &path);
    bool saveToFile(const QString &path);
    bool addHash(const QString &sha256, const QString &name, const QString &type, int severity);
    bool containsHash(const QString &sha256) const;
    ThreatInfo threatInfo(const QString &sha256) const;
    int threatCount() const;
    QString lastUpdateTime() const;
    QString databaseVersion() const;

signals:
    void databaseUpdated(int newCount);

private:
    QHash<QString, ThreatInfo> m_threats;
    mutable QMutex m_mutex;
    QString m_version;
    QString m_lastUpdate;
};

#endif // THREATDB_H
