#include "JunkCleanPanel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>

JunkCleanPanel::JunkCleanPanel(QWidget *parent)
    : QWidget(parent), m_totalSize(0)
{
    m_cleaner = new JunkCleaner(this);

    connect(m_cleaner, &JunkCleaner::itemFound, this, &JunkCleanPanel::onItemFound);
    connect(m_cleaner, &JunkCleaner::scanProgress, this, &JunkCleanPanel::onScanProgress);
    connect(m_cleaner, &JunkCleaner::scanFinished, this, &JunkCleanPanel::onScanFinished);
    connect(m_cleaner, &JunkCleaner::cleanFinished, this, &JunkCleanPanel::onCleanFinished);

    setupUI();
}

void JunkCleanPanel::setupUI()
{
    QVBoxLayout *main = new QVBoxLayout(this);
    main->setContentsMargins(36, 28, 36, 28);
    main->setSpacing(16);

    // Title
    QLabel *title = new QLabel("垃圾清理", this);
    title->setObjectName("pageTitle");
    main->addWidget(title);

    m_statusLabel = new QLabel("扫描电脑中的临时文件、缓存和日志", this);
    m_statusLabel->setObjectName("pageSubtitle");
    main->addWidget(m_statusLabel);

    // Summary card
    QWidget *card = new QWidget(this);
    card->setObjectName("heroCard");
    card->setFixedHeight(100);
    QHBoxLayout *cl = new QHBoxLayout(card);
    cl->setContentsMargins(32, 20, 32, 20);
    cl->setSpacing(24);

    m_sizeLabel = new QLabel("0 B", card);
    m_sizeLabel->setStyleSheet("font-size: 36px; font-weight: bold; color: #38BDF8; background: transparent;");
    cl->addWidget(m_sizeLabel);

    QVBoxLayout *tl = new QVBoxLayout();
    QLabel *subLabel = new QLabel("可清理空间", card);
    subLabel->setStyleSheet("font-size: 13px; color: #64748B; background: transparent;");
    m_countLabel = new QLabel("0 个文件", card);
    m_countLabel->setStyleSheet("font-size: 12px; color: #94A3B8; background: transparent;");
    tl->addWidget(subLabel);
    tl->addWidget(m_countLabel);
    tl->addStretch();
    cl->addLayout(tl, 1);

    m_scanBtn = new QPushButton("  \u26B6  扫描垃圾", card);
    m_scanBtn->setObjectName("primaryBtn");
    m_scanBtn->setFixedHeight(42);
    m_scanBtn->setMinimumWidth(140);
    m_scanBtn->setCursor(Qt::PointingHandCursor);
    connect(m_scanBtn, &QPushButton::clicked, this, &JunkCleanPanel::onScanJunk);
    cl->addWidget(m_scanBtn);

    m_cleanBtn = new QPushButton("  \u2714  立即清理", card);
    m_cleanBtn->setObjectName("secondaryBtn");
    m_cleanBtn->setFixedHeight(42);
    m_cleanBtn->setMinimumWidth(140);
    m_cleanBtn->setEnabled(false);
    m_cleanBtn->setCursor(Qt::PointingHandCursor);
    connect(m_cleanBtn, &QPushButton::clicked, this, &JunkCleanPanel::onCleanJunk);
    cl->addWidget(m_cleanBtn);

    main->addWidget(card);

    // Progress bar
    m_progressBar = new QProgressBar(this);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setVisible(false);
    main->addWidget(m_progressBar);

    // Toolbar
    QHBoxLayout *toolRow = new QHBoxLayout();
    QLabel *listTitle = new QLabel("扫描结果", this);
    listTitle->setObjectName("progressTitle");
    toolRow->addWidget(listTitle);
    toolRow->addStretch();

    QPushButton *selectAllBtn = new QPushButton("全选", this);
    selectAllBtn->setObjectName("ghostBtn");
    selectAllBtn->setCursor(Qt::PointingHandCursor);
    connect(selectAllBtn, &QPushButton::clicked, this, &JunkCleanPanel::onSelectAll);
    toolRow->addWidget(selectAllBtn);
    main->addLayout(toolRow);

    // File list
    m_junkTree = new QTreeWidget(this);
    m_junkTree->setHeaderLabels({"选择", "类别", "文件路径", "大小"});
    m_junkTree->setRootIsDecorated(false);
    m_junkTree->setAlternatingRowColors(false);
    m_junkTree->setColumnWidth(0, 50);
    m_junkTree->setColumnWidth(1, 100);
    m_junkTree->setColumnWidth(2, 480);
    m_junkTree->setColumnWidth(3, 100);
    main->addWidget(m_junkTree, 1);
}

void JunkCleanPanel::onScanJunk()
{
    m_junkTree->clear();
    m_totalSize = 0;
    m_scanBtn->setEnabled(false);
    m_cleanBtn->setEnabled(false);
    m_progressBar->setVisible(true);
    m_progressBar->setValue(0);
    m_statusLabel->setText("正在扫描...");
    m_statusLabel->setStyleSheet("font-size: 12px; color: #FBBF24; background: transparent;");
    m_cleaner->startScan();
}

void JunkCleanPanel::onCleanJunk()
{
    QVector<int> selected;
    for (int i = 0; i < m_junkTree->topLevelItemCount(); i++) {
        QTreeWidgetItem *item = m_junkTree->topLevelItem(i);
        if (item->checkState(0) == Qt::Checked) {
            selected.append(i);
        }
    }
    if (selected.isEmpty()) return;

    m_cleanBtn->setEnabled(false);
    m_statusLabel->setText("正在清理...");
    m_statusLabel->setStyleSheet("font-size: 12px; color: #FBBF24; background: transparent;");
    m_cleaner->cleanSelected(selected);
}

void JunkCleanPanel::onSelectAll()
{
    Qt::CheckState state = (m_junkTree->topLevelItemCount() > 0 &&
        m_junkTree->topLevelItem(0)->checkState(0) == Qt::Checked) ?
        Qt::Unchecked : Qt::Checked;
    for (int i = 0; i < m_junkTree->topLevelItemCount(); i++) {
        m_junkTree->topLevelItem(i)->setCheckState(0, state);
    }
}

void JunkCleanPanel::onItemFound(const JunkItem &item)
{
    auto *treeItem = new QTreeWidgetItem();
    treeItem->setCheckState(0, Qt::Checked);
    treeItem->setText(1, item.category);
    treeItem->setText(2, item.path);

    QString sizeStr;
    if (item.size > 1024 * 1024 * 1024)
        sizeStr = QString("%1 GB").arg(item.size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    else if (item.size > 1024 * 1024)
        sizeStr = QString("%1 MB").arg(item.size / (1024.0 * 1024.0), 0, 'f', 1);
    else if (item.size > 1024)
        sizeStr = QString("%1 KB").arg(item.size / 1024.0, 0, 'f', 1);
    else
        sizeStr = QString("%1 B").arg(item.size);

    treeItem->setText(3, sizeStr);
    m_junkTree->addTopLevelItem(treeItem);
}

void JunkCleanPanel::onScanProgress(const QString &path, int count)
{
    m_countLabel->setText(QString("%1 个文件").arg(count));
}

void JunkCleanPanel::onScanFinished(qint64 totalSize, int fileCount)
{
    m_totalSize = totalSize;
    m_scanBtn->setEnabled(true);
    m_cleanBtn->setEnabled(fileCount > 0);
    m_progressBar->setVisible(false);
    m_statusLabel->setText(QString("扫描完成 — 发现 %1 个垃圾文件").arg(fileCount));
    m_statusLabel->setStyleSheet("font-size: 12px; color: #34D399; background: transparent;");

    QString sizeStr;
    if (totalSize > 1024 * 1024 * 1024)
        sizeStr = QString("%1 GB").arg(totalSize / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    else if (totalSize > 1024 * 1024)
        sizeStr = QString("%1 MB").arg(totalSize / (1024.0 * 1024.0), 0, 'f', 1);
    else
        sizeStr = QString("%1 KB").arg(totalSize / 1024.0, 0, 'f', 1);

    m_sizeLabel->setText(sizeStr);
    m_countLabel->setText(QString("%1 个文件").arg(fileCount));
}

void JunkCleanPanel::onCleanFinished(int count, qint64 freed)
{
    m_cleanBtn->setEnabled(false);
    QString sizeStr;
    if (freed > 1024*1024*1024) sizeStr = QString("%1 GB").arg(freed/1024.0/1024.0/1024.0, 0, 'f', 1);
    else if (freed > 1024*1024) sizeStr = QString("%1 MB").arg(freed/1024.0/1024.0, 0, 'f', 1);
    else if (freed > 1024) sizeStr = QString("%1 KB").arg(freed/1024.0, 0, 'f', 1);
    else sizeStr = QString("%1 B").arg(freed);
    m_statusLabel->setText(QString("清理完成 — 删除 %1 个文件，释放 %2").arg(count).arg(sizeStr));
    m_statusLabel->setStyleSheet("font-size: 12px; color: #34D399; background: transparent;");
    m_sizeLabel->setText("0 B");
    m_countLabel->setText("0 个文件");
    m_junkTree->clear();
}
