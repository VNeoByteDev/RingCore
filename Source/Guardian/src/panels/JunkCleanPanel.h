#ifndef JUNKCLEANPANEL_H
#define JUNKCLEANPANEL_H

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QTreeWidget>
#include "../core/JunkCleaner.h"

class JunkCleanPanel : public QWidget
{
    Q_OBJECT

public:
    explicit JunkCleanPanel(QWidget *parent = nullptr);

private slots:
    void onScanJunk();
    void onCleanJunk();
    void onSelectAll();
    void onItemFound(const JunkItem &item);
    void onScanProgress(const QString &path, int count);
    void onScanFinished(qint64 totalSize, int fileCount);
    void onCleanFinished(int count, qint64 freed);

private:
    void setupUI();

    JunkCleaner *m_cleaner;
    QTreeWidget *m_junkTree;
    QLabel *m_sizeLabel;
    QLabel *m_statusLabel;
    QLabel *m_countLabel;
    QProgressBar *m_progressBar;
    QPushButton *m_scanBtn;
    QPushButton *m_cleanBtn;
    qint64 m_totalSize;
};

#endif
