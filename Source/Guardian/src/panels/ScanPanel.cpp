#include "ScanPanel.h"
#include "core/Settings.h"
#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QFile>
#include <QDir>
#include <QCryptographicHash>
#include <QSystemTrayIcon>
#include <QApplication>
#include <QIcon>
#include <QFileDialog>
#include <QDirIterator>
#include <QFrame>
#include <QScrollArea>
#include <QHeaderView>
#include "core/ThreatDB.h"

ScanPanel::ScanPanel(QWidget *parent)
    : QWidget(parent), m_shieldEngine(nullptr), m_quarantineMgr(nullptr),
      m_totalFiles(0), m_isScanning(false), m_threatCount(0), m_animFrame(0), m_rowCounter(0)
{
    m_shieldEngine = new ShieldEngine(this);
    m_quarantineMgr = new QuarantineManager(this);
    m_watcher = new QFileSystemWatcher(this);

    connect(m_shieldEngine, &ShieldEngine::fileScanned, this, &ScanPanel::onFileScanned);
    connect(m_shieldEngine, &ShieldEngine::progressUpdated, this, &ScanPanel::onProgressUpdated);
    connect(m_shieldEngine, &ShieldEngine::scanFinished, this, &ScanPanel::onScanFinished);
    connect(m_watcher, &QFileSystemWatcher::directoryChanged, this, &ScanPanel::onDirectoryChanged);
    connect(m_watcher, &QFileSystemWatcher::fileChanged, this, &ScanPanel::onFileChanged);

    m_scanAnimTimer = new QTimer(this);
    m_animFrame = 0;
    connect(m_scanAnimTimer, &QTimer::timeout, this, [this]() {
        static QStringList frames = {
            "\u25D0", "\u25D1", "\u25D2", "\u25D3",
            "\u25CE", "\u25CF", "\u25CE", "\u25D3"
        };
        m_animFrame = (m_animFrame + 1) % frames.size();
        if (m_scanIndicator) {
            m_scanIndicator->setText(frames[m_animFrame]);
            static QStringList pulseColors = {
                "#06B6D4", "#22D3EE", "#67E8F9", "#A5F3FC",
                "#22D3EE", "#06B6D4", "#0891B2", "#22D3EE"
            };
            m_scanIndicator->setStyleSheet(
                QString("font-size: 28px; color: %1; background: transparent; min-width: 36px;")
                    .arg(pulseColors[m_animFrame]));
        }
    });

    setupUI();
}

void ScanPanel::setupUI()
{
    // Main layout: top controls fixed, result tree fills space, monitor compact at bottom
    QVBoxLayout *main = new QVBoxLayout(this);
    main->setContentsMargins(24, 16, 24, 16);
    main->setSpacing(12);

    // ═══ TOP: Title + Status ═══
    QHBoxLayout *headerRow = new QHBoxLayout();
    headerRow->setSpacing(10);
    headerRow->setAlignment(Qt::AlignVCenter);

    QLabel *title = new QLabel("\u75C5\u6BD2\u626B\u63CF", this);
    title->setObjectName("pageTitle");
    headerRow->addWidget(title);

    m_statusBadge = new QLabel("\u5F85\u547D\u4EE4", this);
    m_statusBadge->setObjectName("statusBadge");
    headerRow->addWidget(m_statusBadge);
    headerRow->addStretch();

    m_statusLabel = new QLabel(
        QString("\u7B7E\u5E95\u5E93: %1 | \u542F\u53D1\u5F0F").arg(m_shieldEngine->signatureCount()), this);
    m_statusLabel->setStyleSheet("font-size: 11px; color: #64748B; background: transparent;");
    headerRow->addWidget(m_statusLabel);
    main->addLayout(headerRow);

    // ═══ PROGRESS CARD (compact) ═══
    QWidget *pCard = new QWidget(this);
    pCard->setObjectName("progressCard");
    pCard->setFixedHeight(90);
    QVBoxLayout *pcLay = new QVBoxLayout(pCard);
    pcLay->setContentsMargins(20, 12, 20, 12);
    pcLay->setSpacing(6);

    // Row 1: indicator + percent + status text + file count + threat count
    QHBoxLayout *topRow = new QHBoxLayout();
    topRow->setSpacing(12);
    topRow->setAlignment(Qt::AlignVCenter);

    m_scanIndicator = new QLabel("\u25CB", pCard);
    m_scanIndicator->setStyleSheet(
        "font-size: 28px; color: #22D3EE; background: transparent; min-width: 36px;");
    m_scanIndicator->setAlignment(Qt::AlignCenter);
    m_scanIndicator->setFixedWidth(36);
    m_scanIndicator->setVisible(false);
    topRow->addWidget(m_scanIndicator);

    m_progressPercent = new QLabel("0%", pCard);
    m_progressPercent->setStyleSheet(
        "font-size: 28px; font-weight: 800; color: #22D3EE; background: transparent; min-width: 70px;");
    topRow->addWidget(m_progressPercent);

    m_progressLabel = new QLabel("\u5F85\u626B\u63CF", pCard);
    m_progressLabel->setStyleSheet("font-size: 12px; color: #94A3B8; background: transparent;");
    topRow->addWidget(m_progressLabel);

    topRow->addStretch();

    m_fileCountLabel = new QLabel("\u5DF2\u626B\u63CF 0 \u4E2A\u6587\u4EF6", pCard);
    m_fileCountLabel->setStyleSheet("font-size: 11px; color: #94A3B8; background: transparent;");
    topRow->addWidget(m_fileCountLabel);

    QLabel *sep1 = new QLabel("|", pCard);
    sep1->setStyleSheet("color: #1E293B; background: transparent;");
    topRow->addWidget(sep1);

    m_threatCountLabel = new QLabel("\u5A01\u80C1 0", pCard);
    m_threatCountLabel->setStyleSheet("font-size: 11px; color: #34D399; background: transparent;");
    topRow->addWidget(m_threatCountLabel);

    pcLay->addLayout(topRow);

    // Row 2: progress bar + current file
    QHBoxLayout *barRow = new QHBoxLayout();
    barRow->setSpacing(8);

    m_progressBar = new QProgressBar(pCard);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setTextVisible(false);
    m_progressBar->setFixedHeight(6);
    barRow->addWidget(m_progressBar, 1);

    m_currentFileLabel = new QLabel("", pCard);
    m_currentFileLabel->setStyleSheet("font-size: 10px; color: #475569; background: transparent; max-width: 300px;");
    m_currentFileLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    barRow->addWidget(m_currentFileLabel, 0);

    pcLay->addLayout(barRow);
    main->addWidget(pCard);

    // ═══ CONTROLS BAR ═══
    QHBoxLayout *btnRow = new QHBoxLayout();
    btnRow->setSpacing(8);

    m_startBtn = new QPushButton("\u5F00\u59CB\u626B\u63CF", this);
    m_startBtn->setObjectName("primaryBtn");
    m_startBtn->setFixedHeight(36);
    m_startBtn->setMinimumWidth(120);
    m_startBtn->setCursor(Qt::PointingHandCursor);
    connect(m_startBtn, &QPushButton::clicked, this, &ScanPanel::onStartScan);
    btnRow->addWidget(m_startBtn);

    m_stopBtn = new QPushButton("\u505C\u6B62", this);
    m_stopBtn->setObjectName("dangerBtn");
    m_stopBtn->setFixedHeight(36);
    m_stopBtn->setMinimumWidth(90);
    m_stopBtn->setEnabled(false);
    m_stopBtn->setCursor(Qt::PointingHandCursor);
    connect(m_stopBtn, &QPushButton::clicked, this, &ScanPanel::onStopScan);
    btnRow->addWidget(m_stopBtn);

    btnRow->addSpacing(16);

    m_quarantineAllBtn = new QPushButton("\u9694\u79BB\u6240\u6709\u5A01\u80C1", this);
    m_quarantineAllBtn->setObjectName("dangerBtn");
    m_quarantineAllBtn->setFixedHeight(36);
    m_quarantineAllBtn->setCursor(Qt::PointingHandCursor);
    m_quarantineAllBtn->setVisible(false);
    connect(m_quarantineAllBtn, &QPushButton::clicked, this, &ScanPanel::onQuarantineAll);
    btnRow->addWidget(m_quarantineAllBtn);

    m_quarantineSelBtn = new QPushButton("\u9694\u79BB\u9009\u4E2D", this);
    m_quarantineSelBtn->setObjectName("secondaryBtn");
    m_quarantineSelBtn->setFixedHeight(36);
    m_quarantineSelBtn->setCursor(Qt::PointingHandCursor);
    m_quarantineSelBtn->setVisible(false);
    connect(m_quarantineSelBtn, &QPushButton::clicked, this, &ScanPanel::onQuarantineSelected);
    btnRow->addWidget(m_quarantineSelBtn);

    m_restoreBtn = new QPushButton("\u6062\u590D\u9009\u4E2D", this);
    m_restoreBtn->setObjectName("secondaryBtn");
    m_restoreBtn->setFixedHeight(36);
    m_restoreBtn->setCursor(Qt::PointingHandCursor);
    m_restoreBtn->setVisible(false);
    connect(m_restoreBtn, &QPushButton::clicked, this, &ScanPanel::onRestoreSelected);
    btnRow->addWidget(m_restoreBtn);

    btnRow->addStretch();
    main->addLayout(btnRow);

    // ═══ RESULT TREE (fills all remaining space) ═══
    m_resultTree = new QTreeWidget(this);
    m_resultTree->setHeaderLabels({"\u72B6\u6001", "\u6587\u4EF6\u8DEF\u5F84", "\u5927\u5C0F", "\u68C0\u6D4B\u65B9\u5F0F", "\u8BE6\u60C5"});
    m_resultTree->setRootIsDecorated(false);
    m_resultTree->setAlternatingRowColors(true);
    m_resultTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_resultTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_resultTree->setColumnWidth(0, 140);
    m_resultTree->setColumnWidth(1, 400);
    m_resultTree->setColumnWidth(2, 80);
    m_resultTree->setColumnWidth(3, 90);
    m_resultTree->setColumnWidth(4, 150);
    m_resultTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    main->addWidget(m_resultTree, 1);

    // ═══ MONITOR CARD (compact, fixed height) ═══
    QWidget *monitorCard = new QWidget(this);
    monitorCard->setObjectName("statCard");
    monitorCard->setFixedHeight(110);
    QVBoxLayout *monLay = new QVBoxLayout(monitorCard);
    monLay->setContentsMargins(16, 8, 16, 8);
    monLay->setSpacing(4);

    // Title row
    QHBoxLayout *monTitleRow = new QHBoxLayout();
    monTitleRow->setSpacing(8);

    QLabel *monTitle = new QLabel("\u5B9E\u65F6\u76D1\u63A7", monitorCard);
    monTitle->setStyleSheet("font-size: 13px; font-weight: 600; color: #E2E8F0; background: transparent;");
    monTitleRow->addWidget(monTitle);

    m_monitorStatusLabel = new QLabel("\u672A\u76D1\u63A7", monitorCard);
    m_monitorStatusLabel->setStyleSheet("font-size: 11px; color: #64748B; background: transparent;");
    monTitleRow->addWidget(m_monitorStatusLabel);

    monTitleRow->addStretch();

    m_monitorCountLabel = new QLabel("0 \u4E2A\u8DEF\u5F84", monitorCard);
    m_monitorCountLabel->setStyleSheet("font-size: 11px; color: #64748B; background: transparent;");
    monTitleRow->addWidget(m_monitorCountLabel);

    m_addMonitorBtn = new QPushButton("+ \u6DFB\u52A0", monitorCard);
    m_addMonitorBtn->setObjectName("primaryBtn");
    m_addMonitorBtn->setFixedHeight(28);
    m_addMonitorBtn->setMinimumWidth(80);
    m_addMonitorBtn->setCursor(Qt::PointingHandCursor);
    connect(m_addMonitorBtn, &QPushButton::clicked, this, &ScanPanel::onAddMonitorFolder);
    monTitleRow->addWidget(m_addMonitorBtn);

    m_removeMonitorBtn = new QPushButton("- \u79FB\u9664", monitorCard);
    m_removeMonitorBtn->setObjectName("secondaryBtn");
    m_removeMonitorBtn->setFixedHeight(28);
    m_removeMonitorBtn->setMinimumWidth(80);
    m_removeMonitorBtn->setCursor(Qt::PointingHandCursor);
    connect(m_removeMonitorBtn, &QPushButton::clicked, this, &ScanPanel::onRemoveMonitorFolder);
    monTitleRow->addWidget(m_removeMonitorBtn);

    monLay->addLayout(monTitleRow);

    // Monitor tree (very compact)
    m_monitorTree = new QTreeWidget(monitorCard);
    m_monitorTree->setHeaderLabels({"\u76D1\u63A7\u8DEF\u5F84", "\u6587\u4EF6\u6570", "\u5A01\u80C1\u6570"});
    m_monitorTree->setRootIsDecorated(false);
    m_monitorTree->setMaximumHeight(40);
    m_monitorTree->setHeaderHidden(true);
    m_monitorTree->setColumnWidth(0, 500);
    m_monitorTree->setColumnWidth(1, 70);
    m_monitorTree->setColumnWidth(2, 70);
    monLay->addWidget(m_monitorTree);

    main->addWidget(monitorCard);
}

// ═══════════════════════════════════════════════════════════════
//  Scan Status Helpers
// ═══════════════════════════════════════════════════════════════

void ScanPanel::updateScanStatus(const QString &text, const QString &color)
{
    m_statusLabel->setText(text);
    m_statusLabel->setStyleSheet(QString("font-size: 11px; color: %1; background: transparent;").arg(color));
}

void ScanPanel::applyTreeRowStyle(QTreeWidgetItem *item, int row)
{
    QColor bgColor = (row % 2 == 0) ? QColor("#0D1321") : QColor("#0F172A");
    for (int i = 0; i < item->columnCount(); ++i) {
        item->setBackground(i, bgColor);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Scan Actions
// ═══════════════════════════════════════════════════════════════

void ScanPanel::onStartScan()
{
    m_isScanning = true;
    m_totalFiles = 0;
    m_threatCount = 0;
    m_rowCounter = 0;
    m_resultTree->clear();

    m_startBtn->setEnabled(false);
    m_stopBtn->setEnabled(true);
    m_quarantineAllBtn->setVisible(false);
    m_quarantineSelBtn->setVisible(false);
    m_restoreBtn->setVisible(false);

    m_progressBar->setValue(0);
    m_progressPercent->setText("0%");
    m_progressPercent->setStyleSheet(
        "font-size: 28px; font-weight: 800; color: #22D3EE; background: transparent; min-width: 70px;");
    m_progressLabel->setText("\u626B\u63CF\u4E2D...");
    m_progressLabel->setStyleSheet("font-size: 12px; color: #FBBF24; background: transparent;");

    m_scanIndicator->setVisible(true);
    m_scanAnimTimer->start(120);

    m_statusBadge->setText("\u626B\u63CF\u4E2D");
    m_statusBadge->setStyleSheet(
        "font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 12px; "
        "background: rgba(251,191,36,0.12); color: #FBBF24; border: 1px solid rgba(251,191,36,0.25);");

    updateScanStatus("Shield Engine \u626B\u63CF\u4E2D...", "#FBBF24");
    m_threatCountLabel->setText("\u5A01\u80C1 0");
    m_threatCountLabel->setStyleSheet("font-size: 11px; color: #34D399; background: transparent;");

    QStringList allPaths = {
        QDir::homePath() + "/AppData/Local/Temp",
        QDir::homePath() + "/AppData/Local/Microsoft/Windows/INetCache",
        QDir::homePath() + "/Downloads",
        QDir::homePath() + "/Desktop",
        "C:/wenzhou/RingCore/TestFiles",
        "C:/wenzhou/RingCore/病毒样本",
    };
    // Only scan paths that actually exist
    QStringList paths;
    for (const QString &p : allPaths) {
        if (QDir(p).exists()) {
            paths.append(p);
        } else {
            updateScanStatus(QString("\u8DF3\u8FC7\u4E0D\u5B58\u5728\u7684\u76EE\u5F55: %1").arg(p), "#64748B");
        }
    }
    if (paths.isEmpty()) {
        updateScanStatus("\u6CA1\u6709\u53EF\u7528\u7684\u626B\u63CF\u76EE\u5F55", "#F87171");
        m_isScanning = false;
        m_startBtn->setEnabled(true);
        m_stopBtn->setEnabled(false);
        m_scanIndicator->setVisible(false);
        m_scanAnimTimer->stop();
        return;
    }
    m_shieldEngine->startScan(paths);
}

void ScanPanel::onStopScan()
{
    m_shieldEngine->stopScan();
    m_isScanning = false;
    m_startBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);

    m_scanIndicator->setVisible(false);
    m_scanAnimTimer->stop();

    m_progressLabel->setText("\u5DF2\u505C\u6B62");
    m_progressLabel->setStyleSheet("font-size: 12px; color: #94A3B8; background: transparent;");
    m_statusBadge->setText("\u5DF2\u505C\u6B62");
    m_statusBadge->setStyleSheet(
        "font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 12px; "
        "background: rgba(100,116,139,0.12); color: #64748B; border: 1px solid rgba(100,116,139,0.2);");

    updateScanStatus(
        QString("\u626B\u63CF\u5DF2\u505C\u6B62 \u2014 %1 \u4E2A\u6587\u4EF6").arg(m_totalFiles),
        "#FBBF24");
    m_currentFileLabel->setText("");
}

void ScanPanel::onFileScanned(const ScanResult &result)
{
    auto *item = new QTreeWidgetItem();
    QString status;
    QColor color;

    switch (result.threatLevel) {
    case ThreatLevel::Catastrophic:
        status = QString("\u26A0\u26A0 [L5] %1").arg(result.threatName);
        color = QColor("#DC2626"); break;
    case ThreatLevel::Critical:
        status = QString("\u26A0 [L4] %1").arg(result.threatName);
        color = QColor("#F87171"); break;
    case ThreatLevel::High:
        status = QString("\u26A0 [L3] %1").arg(result.threatName);
        color = QColor("#FB923C"); break;
    case ThreatLevel::Medium:
        status = QString("\u26A0 [L2] %1").arg(result.threatName);
        color = QColor("#FBBF24"); break;
    case ThreatLevel::Low:
        status = QString("\u26A0 [L1] %1").arg(result.threatName);
        color = QColor("#A3E635"); break;
    default:
        return;
    }

    QString src = result.source == DetectionSource::Signature ? "Signature" :
                  result.source == DetectionSource::Heuristic ? "Heuristic" : "Pattern";

    item->setText(0, status);
    item->setText(1, result.filePath);
    item->setText(2, QString("%1 B").arg(result.fileSize));
    item->setText(3, src);
    item->setText(4, result.indicators.isEmpty() ? result.threatType : result.indicators.first());
    item->setForeground(0, color);
    applyTreeRowStyle(item, m_rowCounter++);
    m_resultTree->addTopLevelItem(item);

    for (int i = 1; i < result.indicators.size() && i < 3; ++i) {
        auto *detail = new QTreeWidgetItem();
        detail->setText(4, result.indicators[i]);
        detail->setForeground(4, QColor("#475569"));
        applyTreeRowStyle(detail, m_rowCounter++);
        m_resultTree->addTopLevelItem(detail);
    }

    m_threatCount++;
    m_threatCountLabel->setText(QString("\u5A01\u80C1 %1").arg(m_threatCount));
    m_threatCountLabel->setStyleSheet(
        QString("font-size: 11px; color: %1; background: transparent;")
            .arg(m_threatCount > 0 ? "#F87171" : "#34D399"));

    if (g_settings && g_settings->soundNotify()) {
        QApplication::beep();
    }

    if (g_settings && g_settings->threatNotify() && result.threatLevel >= ThreatLevel::High) {
        static QSystemTrayIcon s_trayIcon;
        if (s_trayIcon.icon().isNull()) {
            s_trayIcon.setIcon(QIcon(":/images/shield.svg"));
        }
        QString level = (result.threatLevel == ThreatLevel::Catastrophic) ? "5\u7EA7\u707E\u96BE" :
                        (result.threatLevel == ThreatLevel::Critical) ? "4\u7EA7\u4E25\u91CD" : "3\u7EA7\u9AD8\u5371";
        s_trayIcon.showMessage("RingCore \u5A01\u80C1\u544A\u8B66",
            QString("\u68C0\u6D4B\u5230 %1 \u5A01\u80C1!\n%2\n%3").arg(level, result.threatName, result.filePath),
            QSystemTrayIcon::Critical, 5000);
    }
}

void ScanPanel::onProgressUpdated(int filesScanned, const QString &currentFile)
{
    m_totalFiles = filesScanned;
    m_fileCountLabel->setText(QString("\u5DF2\u626B\u63CF %1 \u4E2A\u6587\u4EF6").arg(filesScanned));

    QString shortName = currentFile;
    if (shortName.length() > 50) shortName = "..." + shortName.right(47);
    m_currentFileLabel->setText(shortName);

    int pct = qMin(95, (int)(20.0 * log10((double)filesScanned + 1)));
    m_progressBar->setValue(pct);
    m_progressPercent->setText(QString("%1%").arg(pct));
}

void ScanPanel::onScanFinished(int totalFiles, int threatCount)
{
    m_isScanning = false;
    m_startBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);
    m_scanIndicator->setVisible(false);
    m_scanAnimTimer->stop();

    m_progressBar->setValue(100);
    m_progressPercent->setText("100%");
    m_currentFileLabel->setText("");
    m_progressLabel->setText("\u626B\u63CF\u5B8C\u6210");
    m_progressLabel->setStyleSheet("font-size: 12px; color: #94A3B8; background: transparent;");

    int total = threatCount;

    if (total == 0) {
        updateScanStatus(
            QString("\u7CFB\u7EDF\u5B89\u5168 \u2014 %1 \u4E2A\u6587\u4EF6\u5DF2\u626B\u63CF").arg(totalFiles),
            "#34D399");
        m_statusBadge->setText("\u5B89\u5168");
        m_statusBadge->setStyleSheet(
            "font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 12px; "
            "background: rgba(52,211,153,0.12); color: #34D399; border: 1px solid rgba(52,211,153,0.25);");
        m_progressPercent->setStyleSheet(
            "font-size: 28px; font-weight: 800; color: #34D399; background: transparent; min-width: 70px;");
    } else {
        updateScanStatus(
            QString("\u53D1\u73B0 %1 \u4E2A\u5A01\u80C1").arg(total),
            "#F87171");
        m_statusBadge->setText(QString("\u53D1\u73B0 %1 \u5A01\u80C1").arg(total));
        m_statusBadge->setStyleSheet(
            "font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 12px; "
            "background: rgba(248,113,113,0.12); color: #F87171; border: 1px solid rgba(248,113,113,0.25);");
        m_progressPercent->setStyleSheet(
            "font-size: 28px; font-weight: 800; color: #F87171; background: transparent; min-width: 70px;");
        m_threatCountLabel->setText(QString("\u5A01\u80C1 %1").arg(total));
        m_threatCountLabel->setStyleSheet("font-size: 11px; color: #F87171; background: transparent;");

        m_quarantineAllBtn->setVisible(true);
        m_quarantineSelBtn->setVisible(true);
    }

    if (total > 0 && g_settings && g_settings->soundNotify()) {
        QApplication::beep();
    }

    emit scanFinished(totalFiles, total);
}

void ScanPanel::startQuickScan() { onStartScan(); }

void ScanPanel::startFullScan()
{
    m_isScanning = true;
    m_totalFiles = 0;
    m_threatCount = 0;
    m_rowCounter = 0;
    m_resultTree->clear();

    m_startBtn->setEnabled(false);
    m_stopBtn->setEnabled(true);
    m_quarantineAllBtn->setVisible(false);
    m_quarantineSelBtn->setVisible(false);
    m_restoreBtn->setVisible(false);

    m_progressBar->setValue(0);
    m_progressPercent->setText("0%");
    m_progressPercent->setStyleSheet(
        "font-size: 28px; font-weight: 800; color: #22D3EE; background: transparent; min-width: 70px;");
    m_progressLabel->setText("\u5168\u76D8\u626B\u63CF\u4E2D...");
    m_progressLabel->setStyleSheet("font-size: 12px; color: #FBBF24; background: transparent;");

    m_scanIndicator->setVisible(true);
    m_scanAnimTimer->start(120);

    m_statusBadge->setText("\u5168\u76D8\u626B\u63CF");
    m_statusBadge->setStyleSheet(
        "font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 12px; "
        "background: rgba(251,191,36,0.12); color: #FBBF24; border: 1px solid rgba(251,191,36,0.25);");

    updateScanStatus("Shield Engine \u5168\u76D8\u626B\u63CF\u4E2D...", "#FBBF24");
    m_threatCountLabel->setText("\u5A01\u80C1 0");
    m_threatCountLabel->setStyleSheet("font-size: 11px; color: #34D399; background: transparent;");

    QStringList paths;
    for (const auto &drive : QDir::drives()) {
        paths << drive.absolutePath();
    }
    m_shieldEngine->startScan(paths);
}

// ═══════════════════════════════════════════════════════════════
//  Quarantine Methods
// ═══════════════════════════════════════════════════════════════

void ScanPanel::onQuarantineAll()
{
    int count = 0;
    for (int i = 0; i < m_resultTree->topLevelItemCount(); i++) {
        QTreeWidgetItem *item = m_resultTree->topLevelItem(i);
        QString filePath = item->text(1);
        QString status = item->text(0);

        if (status.contains("L") && !filePath.isEmpty()) {
            QString threatName = status.section("] ", 1);
            int sev = 4;
            if (status.contains("L5")) sev = 5;
            else if (status.contains("L4")) sev = 4;
            else if (status.contains("L3")) sev = 3;
            else if (status.contains("L2")) sev = 2;

            if (m_quarantineMgr->quarantineFile(filePath, threatName, "Signature", sev)) {
                item->setText(0, "\u2714 \u5DF2\u9694\u79BB");
                item->setForeground(0, QColor("#64748B"));
                for (int j = 0; j < item->columnCount(); ++j) {
                    item->setBackground(j, QColor("#0D1321"));
                }
                count++;
            }
        }
    }

    if (count > 0) {
        updateScanStatus(QString("\u5DF2\u9694\u79BB %1 \u4E2A\u5A01\u80C1").arg(count), "#F87171");
    }
}

void ScanPanel::onQuarantineSelected()
{
    QList<QTreeWidgetItem*> selected = m_resultTree->selectedItems();
    int count = 0;

    for (QTreeWidgetItem *item : selected) {
        QString filePath = item->text(1);
        QString status = item->text(0);

        if (status.contains("L") && !filePath.isEmpty()) {
            QString threatName = status.section("] ", 1);
            int sev = 4;
            if (status.contains("L5")) sev = 5;
            else if (status.contains("L4")) sev = 4;
            else if (status.contains("L3")) sev = 3;
            else if (status.contains("L2")) sev = 2;

            if (m_quarantineMgr->quarantineFile(filePath, threatName, "Signature", sev)) {
                item->setText(0, "\u2714 \u5DF2\u9694\u79BB");
                item->setForeground(0, QColor("#64748B"));
                for (int j = 0; j < item->columnCount(); ++j) {
                    item->setBackground(j, QColor("#0D1321"));
                }
                count++;
            }
        }
    }

    if (count > 0) {
        updateScanStatus(QString("\u5DF2\u9694\u79BB %1 \u4E2A\u9009\u4E2D\u5A01\u80C1").arg(count), "#F87171");
    }
}

void ScanPanel::onRestoreSelected()
{
    int count = 0;

    for (int i = 0; i < m_resultTree->topLevelItemCount(); i++) {
        QTreeWidgetItem *item = m_resultTree->topLevelItem(i);
        if (item->isSelected() && item->text(0).contains("\u5DF2\u9694\u79BB")) {
            QString filePath = item->text(1);
            auto entries = m_quarantineMgr->entries();
            for (int j = 0; j < entries.size(); j++) {
                if (entries[j].originalPath == filePath) {
                    if (m_quarantineMgr->restoreFile(j)) {
                        item->setText(0, "\u2714 \u5DF2\u6062\u590D");
                        item->setForeground(0, QColor("#34D399"));
                        count++;
                    }
                    break;
                }
            }
        }
    }

    if (count > 0) {
        updateScanStatus(QString("\u5DF2\u6062\u590D %1 \u4E2A\u6587\u4EF6").arg(count), "#34D399");
    }
}

// ═══════════════════════════════════════════════════════════════
//  Folder Monitoring
// ═══════════════════════════════════════════════════════════════

void ScanPanel::onAddMonitorFolder()
{
    QString folder = QFileDialog::getExistingDirectory(this, "Select folder to monitor");
    if (folder.isEmpty()) return;

    if (m_monitoredFolders.contains(folder)) {
        updateScanStatus("\u8BE5\u6587\u4EF6\u5939\u5DF2\u5728\u76D1\u63A7\u4E2D", "#FBBF24");
        return;
    }

    startMonitoring(folder);
}

void ScanPanel::onRemoveMonitorFolder()
{
    QList<QTreeWidgetItem*> selected = m_monitorTree->selectedItems();
    if (selected.isEmpty()) {
        updateScanStatus("\u8BF7\u9009\u62E9\u8981\u79FB\u9664\u7684\u76D1\u63A7\u8DEF\u5F84", "#FBBF24");
        return;
    }

    for (QTreeWidgetItem *item : selected) {
        QString path = item->text(0);
        stopMonitoring(path);
    }
}

void ScanPanel::startMonitoring(const QString &folder)
{
    m_monitoredFolders.append(folder);
    m_watcher->addPath(folder);

    auto *item = new QTreeWidgetItem();
    item->setText(0, folder);
    item->setText(1, "0");
    item->setText(2, "0");
    item->setForeground(0, QColor("#CBD5E1"));
    m_monitorTree->addTopLevelItem(item);

    m_monitorStatusLabel->setText(QString("\u6B63\u5728\u76D1\u63A7 %1 \u4E2A\u6587\u4EF6\u5939")
        .arg(m_monitoredFolders.size()));
    m_monitorStatusLabel->setStyleSheet("font-size: 11px; color: #34D399; background: transparent;");
    m_monitorCountLabel->setText(QString("%1 \u4E2A\u8DEF\u5F84").arg(m_monitoredFolders.size()));
}

void ScanPanel::stopMonitoring(const QString &folder)
{
    m_monitoredFolders.removeOne(folder);
    m_watcher->removePath(folder);

    for (int i = 0; i < m_monitorTree->topLevelItemCount(); i++) {
        if (m_monitorTree->topLevelItem(i)->text(0) == folder) {
            delete m_monitorTree->takeTopLevelItem(i);
            break;
        }
    }

    if (m_monitoredFolders.isEmpty()) {
        m_monitorStatusLabel->setText("\u672A\u76D1\u63A7");
        m_monitorStatusLabel->setStyleSheet("font-size: 11px; color: #64748B; background: transparent;");
    } else {
        m_monitorStatusLabel->setText(
            QString("\u6B63\u5728\u76D1\u63A7 %1 \u4E2A\u6587\u4EF6\u5939").arg(m_monitoredFolders.size()));
    }
    m_monitorCountLabel->setText(QString("%1 \u4E2A\u8DEF\u5F84").arg(m_monitoredFolders.size()));
}

void ScanPanel::onDirectoryChanged(const QString &path)
{
    QDirIterator it(path, QDir::Files | QDir::NoSymLinks);
    while (it.hasNext()) {
        QString filePath = it.next();
        scanNewFile(filePath);
    }
}

void ScanPanel::onFileChanged(const QString &path)
{
    scanNewFile(path);
}

void ScanPanel::scanNewFile(const QString &filePath)
{
    if (m_isScanning) return;

    QFileInfo fi(filePath);
    if (!fi.exists() || fi.size() < 100) return;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) return;
    QByteArray data = file.read(4 * 1024 * 1024);
    file.close();

    QCryptographicHash hashAlgo(QCryptographicHash::Sha256);
    hashAlgo.addData(data);
    QString hashStr = hashAlgo.result().toHex();

    ThreatDB db;
    int threatLevel = 0;
    QString threatName;
    QString threatType;
    QStringList findings;

    if (db.containsHash(hashStr)) {
        ThreatInfo ti = db.threatInfo(hashStr);
        threatLevel = ti.severity;
        threatName = ti.name;
        threatType = "Signature";
        findings << "Known malware hash match";
    }

    if (threatLevel == 0) {
        QString lowerPath = filePath.toLower();
        if (lowerPath.endsWith(".bat") || lowerPath.endsWith(".cmd")) {
            QFile f(filePath);
            if (f.open(QIODevice::ReadOnly)) {
                QByteArray batData = f.readAll();
                f.close();
                QByteArray lowerBat = batData.toLower();
                if (lowerBat.contains("rd /s") || lowerBat.contains("format c:") ||
                    lowerBat.contains("reg delete") || lowerBat.contains("shutdown /s")) {
                    threatLevel = 4;
                    threatName = "Destructive.BatCommand";
                    threatType = "Heuristic";
                    findings << "Destructive batch commands detected";
                }
            }
        }
    }

    if (threatLevel == 0) {
        HeuristicAnalyzer analyzer;
        HeuristicAnalyzer::AnalysisResult analysis = analyzer.analyze(data, fi.fileName());
        if (analysis.riskScore >= 85) {
            threatLevel = 3;
            threatName = "Heuristic.Suspicious";
            threatType = "Heuristic";
            findings = analysis.findings;
        }
    }

    if (threatLevel > 0) {
        bool quarantined = m_quarantineMgr->quarantineFile(filePath, threatName, threatType, threatLevel);

        auto *item = new QTreeWidgetItem();
        QString levelStr = QString("L%1").arg(threatLevel);
        QColor color = (threatLevel >= 5) ? QColor("#DC2626") :
                       (threatLevel >= 4) ? QColor("#F87171") :
                       (threatLevel >= 3) ? QColor("#FB923C") : QColor("#FBBF24");
        item->setText(0, QString("\u26A0 [%1] %2").arg(levelStr, threatName));
        item->setText(1, filePath);
        item->setText(2, QString("%1 B").arg(fi.size()));
        item->setText(3, threatType);
        item->setText(4, quarantined ? "BLOCKED + QUARANTINED" : findings.join("; "));
        item->setForeground(0, color);
        applyTreeRowStyle(item, m_rowCounter++);
        m_resultTree->addTopLevelItem(item);
        m_threatCount++;

        for (int i = 0; i < m_monitorTree->topLevelItemCount(); i++) {
            QTreeWidgetItem *monItem = m_monitorTree->topLevelItem(i);
            if (filePath.startsWith(monItem->text(0))) {
                int threats = monItem->text(2).toInt() + 1;
                monItem->setText(2, QString::number(threats));
            }
        }

        if (g_settings && g_settings->threatNotify()) {
            static QSystemTrayIcon s_tray;
            if (s_tray.icon().isNull()) s_tray.setIcon(QIcon(":/images/shield.svg"));
            QString action = quarantined ? "\u5DF2\u81EA\u52A8\u9694\u79BB" : "\u5DF2\u68C0\u6D4B";
            s_tray.showMessage("RingCore \u5A01\u80C1\u62E6\u622A",
                QString("\u5B9E\u65F6\u76D1\u63A7 %3\n\n\u5A01\u80C1: %1\n\u6587\u4EF6: %2")
                    .arg(threatName, filePath, action),
                QSystemTrayIcon::Critical, 5000);
        }

        if (g_settings && g_settings->soundNotify()) {
            QApplication::beep();
        }
    }

    for (int i = 0; i < m_monitorTree->topLevelItemCount(); i++) {
        QTreeWidgetItem *monItem = m_monitorTree->topLevelItem(i);
        if (filePath.startsWith(monItem->text(0))) {
            int files = monItem->text(1).toInt() + 1;
            monItem->setText(1, QString::number(files));
        }
    }
}
