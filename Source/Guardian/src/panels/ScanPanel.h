#ifndef SCANPANEL_H
#define SCANPANEL_H

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QTreeWidget>
#include <QTimer>
#include <QFileSystemWatcher>
#include "../engine/ShieldEngine.h"
#include "../core/QuarantineManager.h"

class ScanPanel : public QWidget
{
    Q_OBJECT

public:
    explicit ScanPanel(QWidget *parent = nullptr);

public slots:
    void startQuickScan();
    void startFullScan();

signals:
    void scanFinished(int totalFiles, int threatCount);

private slots:
    void onStartScan();
    void onStopScan();
    void onFileScanned(const ScanResult &result);
    void onProgressUpdated(int filesScanned, const QString &currentFile);
    void onScanFinished(int totalFiles, int threatCount);
    void onQuarantineAll();
    void onQuarantineSelected();
    void onRestoreSelected();
    // Folder monitoring slots
    void onAddMonitorFolder();
    void onRemoveMonitorFolder();
    void onDirectoryChanged(const QString &path);
    void onFileChanged(const QString &path);

private:
    void setupUI();
    void startMonitoring(const QString &folder);
    void stopMonitoring(const QString &folder);
    void scanNewFile(const QString &filePath);
    void updateScanStatus(const QString &text, const QString &color);
    void applyTreeRowStyle(QTreeWidgetItem *item, int row);

    ShieldEngine *m_shieldEngine;
    QuarantineManager *m_quarantineMgr;

    // Scan controls
    QPushButton *m_startBtn;
    QPushButton *m_stopBtn;
    QPushButton *m_quarantineAllBtn;
    QPushButton *m_quarantineSelBtn;
    QPushButton *m_restoreBtn;

    // Progress display
    QProgressBar *m_progressBar;
    QLabel *m_statusLabel;
    QLabel *m_statusBadge;
    QLabel *m_progressLabel;
    QLabel *m_progressPercent;
    QLabel *m_fileCountLabel;
    QLabel *m_threatCountLabel;
    QLabel *m_currentFileLabel;
    QLabel *m_scanIndicator;

    // Results
    QTreeWidget *m_resultTree;
    QLabel *m_resultHeaderLabel;

    // Animation
    QTimer *m_scanAnimTimer;
    int m_animFrame;

    // State
    int m_totalFiles;
    bool m_isScanning;
    int m_threatCount;
    int m_rowCounter;

    // Folder monitoring
    QFileSystemWatcher *m_watcher;
    QStringList m_monitoredFolders;
    QTreeWidget *m_monitorTree;
    QPushButton *m_addMonitorBtn;
    QPushButton *m_removeMonitorBtn;
    QLabel *m_monitorStatusLabel;
    QLabel *m_monitorCountLabel;
};

#endif // SCANPANEL_H
