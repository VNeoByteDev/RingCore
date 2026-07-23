#include "SettingPanel.h"
#include "core/Settings.h"
#include "../engine/ShieldEngine.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QCheckBox>
#include <QScrollArea>
#include <QPushButton>
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCoreApplication>
#include <QFrame>

SettingPanel::SettingPanel(QWidget *parent) : QWidget(parent), m_dbInfoLabel(nullptr), m_ruleCountLabel(nullptr), m_lastUpdateLabel(nullptr)
{
    setupUI();
}

void SettingPanel::setupUI()
{
    QVBoxLayout *main = new QVBoxLayout(this);
    main->setContentsMargins(32, 24, 32, 24);
    main->setSpacing(0);

    // ── Header ──
    QHBoxLayout *headerRow = new QHBoxLayout();
    headerRow->setSpacing(12);
    headerRow->setAlignment(Qt::AlignVCenter);

    QLabel *title = new QLabel("\u2699\uFE0F  \u8BBE\u7F6E", this);
    title->setObjectName("pageTitle");
    headerRow->addWidget(title);
    headerRow->addStretch();

    QLabel *versionTag = new QLabel("v1.0.0", this);
    versionTag->setStyleSheet(
        "font-size: 11px; font-weight: 600; color: #475569; "
        "background: rgba(100,116,139,0.08); border: 1px solid rgba(100,116,139,0.15); "
        "border-radius: 8px; padding: 3px 10px;");
    headerRow->addWidget(versionTag);
    main->addLayout(headerRow);

    // ── Separator ──
    QFrame *sep = new QFrame(this);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("background: rgba(56,189,248,0.06); max-height: 1px; margin: 12px 0 16px 0;");
    main->addWidget(sep);

    // ── Scroll Area ──
    QScrollArea *scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setStyleSheet("QScrollArea { background: transparent; border: none; }");

    QWidget *scrollContent = new QWidget();
    scrollContent->setStyleSheet("background: transparent;");
    QVBoxLayout *scrollLayout = new QVBoxLayout(scrollContent);
    scrollLayout->setContentsMargins(0, 0, 0, 0);
    scrollLayout->setSpacing(16);

    if (!g_settings) return;

    // ════════════════════════════════════════════
    //  GENERAL SETTINGS
    // ════════════════════════════════════════════
    QVector<QPair<QString, QString>> generalItems = {
        {"\u5F00\u673A\u81EA\u542F\u52A8", "\u7CFB\u7EDF\u542F\u52A8\u65F6\u81EA\u52A8\u8FD0\u884C\u62A4\u7406\u7A0B\u5E8F"},
        {"\u5173\u95ED\u65F6\u6700\u5C0F\u5316\u5230\u6258\u76D8", "\u5173\u95ED\u7A97\u53E3\u65F6\u6700\u5C0F\u5316\u5230\u7CFB\u7EDF\u6258\u76D8\u7EE7\u7EED\u540E\u53F0\u62A4\u536B"},
        {"\u81EA\u52A8\u66F4\u65B0\u75C5\u6BD2\u5E93", "\u81EA\u52A8\u4E0B\u8F7D\u6700\u65B0\u7684\u5A01\u80C1\u7279\u5F81\u5E93\u66F4\u65B0"},
    };
    QVector<bool> generalDefaults = {
        g_settings->autoStart(),
        g_settings->minimizeToTray(),
        g_settings->autoUpdateDB(),
    };
    std::vector<std::function<void(bool)>> generalSetters = {
        [](bool v){ if(g_settings) g_settings->setAutoStart(v); },
        [](bool v){ if(g_settings) g_settings->setMinimizeToTray(v); },
        [](bool v){ if(g_settings) g_settings->setAutoUpdateDB(v); },
    };

    QWidget *generalCard = new QWidget(this);
    generalCard->setObjectName("settingsSection");
    generalCard->setMinimumWidth(400);
    {
        QVBoxLayout *lay = new QVBoxLayout(generalCard);
        lay->setContentsMargins(24, 20, 24, 16);
        lay->setSpacing(0);

        // Section header
        QHBoxLayout *secHeader = new QHBoxLayout();
        secHeader->setSpacing(10);
        secHeader->setAlignment(Qt::AlignVCenter);
        QLabel *secIcon = new QLabel("\u2699", generalCard);
        secIcon->setStyleSheet("font-size: 16px; background: transparent;");
        secHeader->addWidget(secIcon);
        QLabel *secTitle = new QLabel("\u5E38\u89C4\u8BBE\u7F6E", generalCard);
        secTitle->setObjectName("sectionTitle");
        secHeader->addWidget(secTitle);
        secHeader->addStretch();
        lay->addLayout(secHeader);

        QLabel *secSub = new QLabel("\u57FA\u672C\u5E94\u7528\u884C\u4E3A\u914D\u7F6E", generalCard);
        secSub->setObjectName("sectionSubtitle");
        lay->addWidget(secSub);

        lay->addSpacing(12);

        for (int i = 0; i < generalItems.size(); ++i) {
            lay->addWidget(createSettingRow(generalItems[i].first, generalItems[i].second,
                generalDefaults[i], generalSetters[i]));
            if (i < generalItems.size() - 1) {
                QFrame *line = new QFrame(generalCard);
                line->setFrameShape(QFrame::HLine);
                line->setStyleSheet("background: rgba(26,35,50,0.5); max-height: 1px;");
                lay->addWidget(line);
            }
        }
    }
    scrollLayout->addWidget(generalCard);

    // ════════════════════════════════════════════
    //  PROTECTION SETTINGS
    // ════════════════════════════════════════════
    QVector<QPair<QString, QString>> protectItems = {
        {"\u8FDB\u7A0B\u9632\u62A4", "\u76D1\u63A7\u65B0\u8FDB\u7A0B\u542F\u52A8\uFF0C\u62E6\u622A\u6076\u610F\u8F6F\u4EF6"},
        {"\u6587\u4EF6\u9632\u62A4", "\u76D1\u63A7\u6587\u4EF6\u521B\u5EFA\u548C\u4FEE\u6539"},
        {"\u6CE8\u518C\u8868\u9632\u62A4", "\u76D1\u63A7\u6CE8\u518C\u8868\u5173\u952E\u4F4D\u7F6E"},
        {"\u7F51\u7EDC\u9632\u62A4", "\u76D1\u63A7\u7F51\u7EDC\u8FDE\u63A5"},
        {"\u542F\u52A8\u9879\u9632\u62A4", "\u9632\u6B62\u6076\u610F\u8F6F\u4EF6\u6DFB\u52A0\u5F00\u673A\u81EA\u542F"},
    };
    QVector<bool> protectDefaults = {
        g_settings->processProtection(),
        g_settings->fileProtection(),
        g_settings->registryProtection(),
        g_settings->networkProtection(),
        g_settings->bootProtection(),
    };
    std::vector<std::function<void(bool)>> protectSetters = {
        [](bool v){ if(g_settings) g_settings->setProcessProtection(v); },
        [](bool v){ if(g_settings) g_settings->setFileProtection(v); },
        [](bool v){ if(g_settings) g_settings->setRegistryProtection(v); },
        [](bool v){ if(g_settings) g_settings->setNetworkProtection(v); },
        [](bool v){ if(g_settings) g_settings->setBootProtection(v); },
    };

    QWidget *protectCard = new QWidget(this);
    protectCard->setObjectName("settingsSection");
    protectCard->setMinimumWidth(400);
    {
        QVBoxLayout *lay = new QVBoxLayout(protectCard);
        lay->setContentsMargins(24, 20, 24, 16);
        lay->setSpacing(0);

        QHBoxLayout *secHeader = new QHBoxLayout();
        secHeader->setSpacing(10);
        secHeader->setAlignment(Qt::AlignVCenter);
        QLabel *secIcon = new QLabel("\u2764", protectCard);
        secIcon->setStyleSheet("font-size: 16px; background: transparent;");
        secHeader->addWidget(secIcon);
        QLabel *secTitle = new QLabel("\u9632\u62A4\u8BBE\u7F6E", protectCard);
        secTitle->setObjectName("sectionTitle");
        secHeader->addWidget(secTitle);
        secHeader->addStretch();
        lay->addLayout(secHeader);

        QLabel *secSub = new QLabel("\u5B9E\u65F6\u9632\u62A4\u5F15\u64CE\u529F\u80FD\u5F00\u5173", protectCard);
        secSub->setObjectName("sectionSubtitle");
        lay->addWidget(secSub);

        lay->addSpacing(12);

        for (int i = 0; i < protectItems.size(); ++i) {
            lay->addWidget(createSettingRow(protectItems[i].first, protectItems[i].second,
                protectDefaults[i], protectSetters[i]));
            if (i < protectItems.size() - 1) {
                QFrame *line = new QFrame(protectCard);
                line->setFrameShape(QFrame::HLine);
                line->setStyleSheet("background: rgba(26,35,50,0.5); max-height: 1px;");
                lay->addWidget(line);
            }
        }
    }
    scrollLayout->addWidget(protectCard);

    // ════════════════════════════════════════════
    //  NOTIFICATION SETTINGS
    // ════════════════════════════════════════════
    QVector<QPair<QString, QString>> notifyItems = {
        {"\u5A01\u80C1\u544A\u8B66\u901A\u77E5", "\u53D1\u73B0\u5A01\u80C1\u65F6\u5F39\u51FA\u901A\u77E5"},
        {"\u64AD\u653E\u544A\u8B66\u97F3\u6548", "\u53D1\u73B0\u5A01\u80C1\u65F6\u64AD\u653E\u63D0\u793A\u97F3"},
        {"\u626B\u63CF\u5B8C\u6210\u901A\u77E5", "\u626B\u63CF\u5B8C\u6210\u540E\u5F39\u51FA\u901A\u77E5"},
        {"\u53F3\u952E\u626B\u63CF\u9759\u9ED8\u6A21\u5F0F", "\u626B\u63CF\u65F6\u4E0D\u5F39\u51FA\u7A97\u53E3\uFF0C\u4EC5\u6258\u76D8\u901A\u77E5"},
    };
    QVector<bool> notifyDefaults = {
        g_settings->threatNotify(),
        g_settings->soundNotify(),
        g_settings->scanCompleteNotify(),
        g_settings->silentScan(),
    };
    std::vector<std::function<void(bool)>> notifySetters = {
        [](bool v){ if(g_settings) g_settings->setThreatNotify(v); },
        [](bool v){ if(g_settings) g_settings->setSoundNotify(v); },
        [](bool v){ if(g_settings) g_settings->setScanCompleteNotify(v); },
        [](bool v){ if(g_settings) g_settings->setSilentScan(v); },
    };

    QWidget *notifyCard = new QWidget(this);
    notifyCard->setObjectName("settingsSection");
    notifyCard->setMinimumWidth(400);
    {
        QVBoxLayout *lay = new QVBoxLayout(notifyCard);
        lay->setContentsMargins(24, 20, 24, 16);
        lay->setSpacing(0);

        QHBoxLayout *secHeader = new QHBoxLayout();
        secHeader->setSpacing(10);
        secHeader->setAlignment(Qt::AlignVCenter);
        QLabel *secIcon = new QLabel("\u266B", notifyCard);
        secIcon->setStyleSheet("font-size: 16px; background: transparent;");
        secHeader->addWidget(secIcon);
        QLabel *secTitle = new QLabel("\u901A\u77E5\u8BBE\u7F6E", notifyCard);
        secTitle->setObjectName("sectionTitle");
        secHeader->addWidget(secTitle);
        secHeader->addStretch();
        lay->addLayout(secHeader);

        QLabel *secSub = new QLabel("\u63A7\u5236\u901A\u77E5\u548C\u58F0\u97F3\u63D0\u9192\u65B9\u5F0F", notifyCard);
        secSub->setObjectName("sectionSubtitle");
        lay->addWidget(secSub);

        lay->addSpacing(12);

        for (int i = 0; i < notifyItems.size(); ++i) {
            lay->addWidget(createSettingRow(notifyItems[i].first, notifyItems[i].second,
                notifyDefaults[i], notifySetters[i]));
            if (i < notifyItems.size() - 1) {
                QFrame *line = new QFrame(notifyCard);
                line->setFrameShape(QFrame::HLine);
                line->setStyleSheet("background: rgba(26,35,50,0.5); max-height: 1px;");
                lay->addWidget(line);
            }
        }
    }
    scrollLayout->addWidget(notifyCard);

    // ════════════════════════════════════════════
    //  DATABASE MANAGEMENT
    // ════════════════════════════════════════════
    scrollLayout->addWidget(createDbSection());

    // ════════════════════════════════════════════
    //  ABOUT
    // ════════════════════════════════════════════
    scrollLayout->addWidget(createAboutSection());

    scrollLayout->addStretch();

    scrollArea->setWidget(scrollContent);
    main->addWidget(scrollArea, 1);
}

// ═══════════════════════════════════════════════════════════════
//  Setting Row Factory
// ═══════════════════════════════════════════════════════════════

QWidget* SettingPanel::createSettingRow(const QString &label, const QString &desc,
    bool defaultValue, std::function<void(bool)> setter)
{
    QWidget *row = new QWidget(this);
    row->setObjectName("settingRow");
    row->setFixedHeight(56);

    QHBoxLayout *lay = new QHBoxLayout(row);
    lay->setContentsMargins(0, 8, 8, 8);
    lay->setSpacing(12);
    lay->setAlignment(Qt::AlignVCenter);

    // Text column
    QVBoxLayout *textCol = new QVBoxLayout();
    textCol->setSpacing(2);
    textCol->setContentsMargins(0, 0, 0, 0);

    QLabel *lbl = new QLabel(label, row);
    lbl->setObjectName("settingLabel");
    textCol->addWidget(lbl);

    QLabel *descLbl = new QLabel(desc, row);
    descLbl->setObjectName("settingDesc");
    textCol->addWidget(descLbl);

    lay->addLayout(textCol, 1);

    // Toggle switch (styled checkbox)
    QCheckBox *toggle = new QCheckBox(row);
    toggle->setChecked(defaultValue);
    toggle->setFixedSize(44, 24);
    connect(toggle, &QCheckBox::toggled, this, [setter](bool checked) {
        setter(checked);
    });
    lay->addWidget(toggle, 0, Qt::AlignRight);

    return row;
}

QWidget* SettingPanel::createSettingCard(const QString &icon, const QString &title,
    const QVector<QPair<QString, QString>> &items, const QVector<bool> &defaults)
{
    Q_UNUSED(icon); Q_UNUSED(title); Q_UNUSED(items); Q_UNUSED(defaults);
    return new QWidget(this);
}

// ═══════════════════════════════════════════════════════════════
//  Database Section
// ═══════════════════════════════════════════════════════════════

QWidget* SettingPanel::createDbSection()
{
    QWidget *card = new QWidget(this);
    card->setObjectName("settingsSection");
    card->setMinimumWidth(400);

    QVBoxLayout *lay = new QVBoxLayout(card);
    lay->setContentsMargins(24, 20, 24, 20);
    lay->setSpacing(14);

    // Section header
    QHBoxLayout *secHeader = new QHBoxLayout();
    secHeader->setSpacing(10);
    secHeader->setAlignment(Qt::AlignVCenter);
    QLabel *secIcon = new QLabel("\u2728", card);
    secIcon->setStyleSheet("font-size: 16px; background: transparent;");
    secHeader->addWidget(secIcon);
    QLabel *secTitle = new QLabel("\u75C5\u6BD2\u5E93\u7BA1\u7406", card);
    secTitle->setObjectName("sectionTitle");
    secHeader->addWidget(secTitle);
    secHeader->addStretch();
    lay->addLayout(secHeader);

    QLabel *secSub = new QLabel("\u5A01\u80C1\u7279\u5F81\u5E93\u7248\u672C\u4E0E\u7BA1\u7406", card);
    secSub->setObjectName("sectionSubtitle");
    lay->addWidget(secSub);

    // DB Info Bar
    QWidget *infoBar = new QWidget(card);
    infoBar->setObjectName("dbInfoBar");
    infoBar->setFixedHeight(44);
    {
        QHBoxLayout *infoLay = new QHBoxLayout(infoBar);
        infoLay->setContentsMargins(14, 0, 14, 0);
        infoLay->setSpacing(16);

        QLabel *dbIcon = new QLabel("\u2630", infoBar);
        dbIcon->setStyleSheet("font-size: 14px; background: transparent;");
        infoLay->addWidget(dbIcon);

        m_ruleCountLabel = new QLabel("\u89C4\u5219\u6570: \u52A0\u8F7D\u4E2D...", infoBar);
        m_ruleCountLabel->setObjectName("dbInfoText");
        infoLay->addWidget(m_ruleCountLabel);

        QLabel *dot1 = new QLabel("\u2022", infoBar);
        dot1->setStyleSheet("color: #334155; background: transparent; font-size: 10px;");
        infoLay->addWidget(dot1);

        m_lastUpdateLabel = new QLabel("\u4E0A\u6B21\u66F4\u65B0: 2026-07-19", infoBar);
        m_lastUpdateLabel->setObjectName("dbInfoText");
        infoLay->addWidget(m_lastUpdateLabel);

        infoLay->addStretch();

        QLabel *versionLabel = new QLabel("v5.0", infoBar);
        versionLabel->setStyleSheet(
            "font-size: 11px; font-weight: 600; color: #38BDF8; background: transparent;");
        infoLay->addWidget(versionLabel);
    }
    lay->addWidget(infoBar);

    // Action buttons
    QHBoxLayout *btnRow = new QHBoxLayout();
    btnRow->setSpacing(10);

    QPushButton *importBtn = new QPushButton("\u2B07  \u5BFC\u5165\u672C\u5730\u6587\u4EF6", card);
    importBtn->setObjectName("secondaryBtn");
    importBtn->setFixedHeight(38);
    importBtn->setCursor(Qt::PointingHandCursor);
    connect(importBtn, &QPushButton::clicked, this, &SettingPanel::onImportDB);
    btnRow->addWidget(importBtn);

    QPushButton *exportBtn = new QPushButton("\u2B06  \u5BFC\u51FA\u5F53\u524D\u5E93", card);
    exportBtn->setObjectName("secondaryBtn");
    exportBtn->setFixedHeight(38);
    exportBtn->setCursor(Qt::PointingHandCursor);
    connect(exportBtn, &QPushButton::clicked, this, &SettingPanel::onExportDB);
    btnRow->addWidget(exportBtn);

    QPushButton *updateBtn = new QPushButton("\u21BB  \u4ECE\u4E91\u7AEF\u66F4\u65B0", card);
    updateBtn->setObjectName("primaryBtn");
    updateBtn->setFixedHeight(38);
    updateBtn->setCursor(Qt::PointingHandCursor);
    connect(updateBtn, &QPushButton::clicked, this, &SettingPanel::onUpdateFromCloud);
    btnRow->addWidget(updateBtn);

    btnRow->addStretch();
    lay->addLayout(btnRow);

    return card;
}

// ═══════════════════════════════════════════════════════════════
//  About Section
// ═══════════════════════════════════════════════════════════════

QWidget* SettingPanel::createAboutSection()
{
    QWidget *card = new QWidget(this);
    card->setObjectName("settingsSection");

    QVBoxLayout *lay = new QVBoxLayout(card);
    lay->setContentsMargins(24, 20, 24, 20);
    lay->setSpacing(12);

    // Header
    QHBoxLayout *secHeader = new QHBoxLayout();
    secHeader->setSpacing(10);
    secHeader->setAlignment(Qt::AlignVCenter);
    QLabel *secIcon = new QLabel("\u2139\uFE0F", card);
    secIcon->setStyleSheet("font-size: 16px; background: transparent;");
    secHeader->addWidget(secIcon);
    QLabel *secTitle = new QLabel("\u5173\u4E8E", card);
    secTitle->setObjectName("sectionTitle");
    secHeader->addWidget(secTitle);
    secHeader->addStretch();
    lay->addLayout(secHeader);

    // Product name
    QLabel *name = new QLabel("RingCore Security Guardian", card);
    name->setStyleSheet(
        "font-size: 18px; font-weight: 700; color: #38BDF8; background: transparent;");
    lay->addWidget(name);

    // Description
    QLabel *desc = new QLabel("\u65E0\u5E7F\u544A\u3001\u65E0\u6346\u7ED1\u3001\u7EAF\u5B88\u62A4", card);
    desc->setStyleSheet("font-size: 12px; color: #64748B; background: transparent;");
    lay->addWidget(desc);

    lay->addSpacing(4);

    // Engine info
    QWidget *engineBar = new QWidget(card);
    engineBar->setStyleSheet(
        "background: rgba(14,165,233,0.04); border: 1px solid rgba(14,165,233,0.1); border-radius: 8px;");
    QHBoxLayout *engLay = new QHBoxLayout(engineBar);
    engLay->setContentsMargins(12, 8, 12, 8);
    engLay->setSpacing(8);

    QLabel *engIcon = new QLabel("\u2699\uFE0F", engineBar);
    engIcon->setStyleSheet("font-size: 12px; background: transparent;");
    engLay->addWidget(engIcon);

    QLabel *engInfo = new QLabel(
        "\u5F15\u64CE: Shield Engine v1.0 \u2014 \u7B7E\u540D + \u542F\u53D1\u5F0F + \u6A21\u5F0F\u5339\u914D + \u4E91\u7AEF", engineBar);
    engInfo->setStyleSheet("font-size: 11px; color: #94A3B8; background: transparent;");
    engLay->addWidget(engInfo);

    engLay->addStretch();
    lay->addWidget(engineBar);

    // Version footer
    QLabel *footer = new QLabel("Version 1.0.0 \u00A9 2026 RingCore", card);
    footer->setObjectName("versionText");
    lay->addWidget(footer);

    return card;
}

// ═══════════════════════════════════════════════════════════════
//  DB Actions
// ═══════════════════════════════════════════════════════════════

void SettingPanel::onImportDB()
{
    QString filePath = QFileDialog::getOpenFileName(this, "\u5BFC\u5165\u75C5\u6BD2\u5E93", "", "JSON (*.json);;All (*)");
    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) { QMessageBox::warning(this, "\u9519\u8BEF", "\u65E0\u6CD5\u6253\u5F00\u6587\u4EF6"); return; }
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    if (doc.isNull()) { QMessageBox::warning(this, "\u9519\u8BEF", "\u683C\u5F0F\u9519\u8BEF"); return; }

    int count = doc.object()["hashes"].toObject().size();
    QString dest = QCoreApplication::applicationDirPath() + "/../../Config/threats.json";
    QFile::remove(dest);
    if (QFile::copy(filePath, dest)) {
        updateDBInfo(count);
        QMessageBox::information(this, "\u6210\u529F", QString("\u5BFC\u5165 %1 \u6761\u89C4\u5219").arg(count));
    } else {
        QMessageBox::warning(this, "\u9519\u8BEF", "\u5BFC\u5165\u5931\u8D25\uFF0C\u65E0\u6CD5\u5199\u5165\u76EE\u6807\u6587\u4EF6");
    }
}

void SettingPanel::onExportDB()
{
    QString filePath = QFileDialog::getSaveFileName(this, "\u5BFC\u51FA\u75C5\u6BD2\u5E93", "threats.json", "JSON (*.json)");
    if (filePath.isEmpty()) return;

    QString srcPath = QCoreApplication::applicationDirPath() + "/../../Config/threats.json";
    QFile srcFile(srcPath);
    if (srcFile.exists() && srcFile.open(QIODevice::ReadOnly)) {
        QByteArray data = srcFile.readAll();
        srcFile.close();
        QFile destFile(filePath);
        if (destFile.open(QIODevice::WriteOnly)) {
            destFile.write(data);
            destFile.close();
            QMessageBox::information(this, "\u6210\u529F", "\u5DF2\u5BFC\u51FA: " + filePath);
        } else {
            QMessageBox::warning(this, "\u9519\u8BEF", "\u65E0\u6CD5\u5199\u5165\u6587\u4EF6: " + filePath);
        }
    } else {
        QMessageBox::warning(this, "\u9519\u8BEF", "\u672A\u627E\u5230 threats.json \u6570\u636E\u5E93\u6587\u4EF6");
    }
}

void SettingPanel::onUpdateFromCloud()
{
    QMessageBox::information(this, "\u4E91\u7AEF\u66F4\u65B0",
        "\u5F53\u524D\u7248\u672C: v5.0 (560+ \u89C4\u5219)\n\n"
        "\u652F\u6301\u7684\u66F4\u65B0\u65B9\u5F0F:\n"
        "1. \u5BFC\u5165\u5176\u4ED6\u5B89\u5168\u8F6F\u4EF6\u7684\u7279\u5F81\u5E93 JSON\n"
        "2. \u4E91\u7AEF\u67E5\u6740 (MalwareBazaar) \u81EA\u52A8\u8865\u5145\n\n"
        "\u63D0\u793A: \u626B\u63CF\u65F6\u4F1A\u81EA\u52A8\u67E5\u8BE2\u4E91\u7AEF\u6570\u636E\u5E93\u3002");
}

void SettingPanel::updateDBInfo(int signatureCount)
{
    if (m_ruleCountLabel)
        m_ruleCountLabel->setText(QString("\u89C4\u5219\u6570: %1").arg(signatureCount));
    if (m_dbInfoLabel)
        m_dbInfoLabel->setText(QString("\u7248\u672C: v5.0 | \u89C4\u5219\u6570: %1 | \u4E0A\u6B21\u66F4\u65B0: 2026-07-19").arg(signatureCount));
    if (m_lastUpdateLabel)
        m_lastUpdateLabel->setText("\u4E0A\u6B21\u66F4\u65B0: 2026-07-19");
}
