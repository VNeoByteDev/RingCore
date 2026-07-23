#include "ProcessPanel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>

#ifdef Q_OS_WIN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

ProcessPanel::ProcessPanel(QWidget *parent) : QWidget(parent)
{
    setupUI();
    loadProcesses();
}

void ProcessPanel::setupUI()
{
    QVBoxLayout *main = new QVBoxLayout(this);
    main->setContentsMargins(36, 28, 36, 28);
    main->setSpacing(16);

    // Header
    QHBoxLayout *header = new QHBoxLayout();
    QVBoxLayout *tl = new QVBoxLayout();
    QLabel *title = new QLabel("进程管理", this);
    title->setObjectName("pageTitle");
    m_countLabel = new QLabel("共 0 个进程", this);
    m_countLabel->setObjectName("pageSubtitle");
    tl->addWidget(title); tl->addWidget(m_countLabel);
    header->addLayout(tl); header->addStretch();

    m_searchBox = new QLineEdit(this);
    m_searchBox->setPlaceholderText("搜索进程名称...");
    m_searchBox->setFixedWidth(260);
    m_searchBox->setFixedHeight(38);
    connect(m_searchBox, &QLineEdit::textChanged, this, &ProcessPanel::onSearchChanged);
    header->addWidget(m_searchBox);

    QPushButton *refreshBtn = new QPushButton("  \u21BB  刷新", this);
    refreshBtn->setObjectName("secondaryBtn");
    refreshBtn->setFixedHeight(38);
    refreshBtn->setCursor(Qt::PointingHandCursor);
    connect(refreshBtn, &QPushButton::clicked, this, &ProcessPanel::onRefresh);
    header->addWidget(refreshBtn);

    QPushButton *endBtn = new QPushButton("  \u2716  结束进程", this);
    endBtn->setObjectName("dangerBtn");
    endBtn->setFixedHeight(38);
    endBtn->setCursor(Qt::PointingHandCursor);
    connect(endBtn, &QPushButton::clicked, this, &ProcessPanel::onEndProcess);
    header->addWidget(endBtn);

    main->addLayout(header);

    // Process tree
    m_processTree = new QTreeWidget(this);
    m_processTree->setHeaderLabels({"PID", "进程名称", "内存 (KB)", "路径"});
    m_processTree->setRootIsDecorated(false);
    m_processTree->setAlternatingRowColors(false);
    m_processTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_processTree->setSortingEnabled(true);
    m_processTree->setColumnWidth(0, 80);
    m_processTree->setColumnWidth(1, 220);
    m_processTree->setColumnWidth(2, 110);
    m_processTree->setColumnWidth(3, 500);
    main->addWidget(m_processTree, 1);
}

void ProcessPanel::loadProcesses()
{
    m_processTree->clear();
    m_allItems.clear();

#ifdef Q_OS_WIN
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            QString name = QString::fromWCharArray(pe.szExeFile);
            quint32 pid = pe.th32ProcessID;

            // Get memory info
            quint64 memKB = 0;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProc) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                    memKB = pmc.WorkingSetSize / 1024;
                }

                // Get full path
                WCHAR path[MAX_PATH] = {};
                DWORD pathLen = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, path, &pathLen)) {
                    // success
                } else {
                    wcscpy_s(path, MAX_PATH, L"");
                }
                CloseHandle(hProc);

                auto *item = new QTreeWidgetItem();
                item->setText(0, QString::number(pid));
                item->setText(1, name);
                item->setText(2, QString::number(memKB));
                item->setText(3, QString::fromWCharArray(path));
                item->setData(0, Qt::UserRole, pid);
                item->setData(2, Qt::UserRole, memKB);

                // Color system processes
                QStringList sysProcs = {"System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
                    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe"};
                if (sysProcs.contains(name, Qt::CaseInsensitive)) {
                    item->setForeground(1, QColor("#64748B"));
                }

                m_processTree->addTopLevelItem(item);
                m_allItems.append(item);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
#endif

    m_countLabel->setText(QString("共 %1 个进程").arg(m_processTree->topLevelItemCount()));
}

void ProcessPanel::onRefresh() { loadProcesses(); }

void ProcessPanel::onEndProcess()
{
    QTreeWidgetItem *item = m_processTree->currentItem();
    if (!item) return;

    quint32 pid = item->data(0, Qt::UserRole).toUInt();

#ifdef Q_OS_WIN
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc) {
        TerminateProcess(hProc, 0);
        CloseHandle(hProc);
        item->setText(3, "[已终止]");
        item->setForeground(1, QColor("#F87171"));
    }
#endif
}

void ProcessPanel::onSearchChanged(const QString &text)
{
    for (auto *item : m_allItems) {
        bool match = text.isEmpty() ||
                     item->text(1).contains(text, Qt::CaseInsensitive) ||
                     item->text(3).contains(text, Qt::CaseInsensitive);
        item->setHidden(!match);
    }
    int visible = 0;
    for (auto *item : m_allItems)
        if (!item->isHidden()) visible++;
    m_countLabel->setText(QString("显示 %1 / %2 个进程").arg(visible).arg(m_allItems.size()));
}
