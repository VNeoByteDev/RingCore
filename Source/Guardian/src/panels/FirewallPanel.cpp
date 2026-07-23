#include "FirewallPanel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QInputDialog>

FirewallPanel::FirewallPanel(QWidget *parent) : QWidget(parent)
{
    setupUI();
    loadRules();
}

void FirewallPanel::setupUI()
{
    QVBoxLayout *main = new QVBoxLayout(this);
    main->setContentsMargins(36, 28, 36, 28);
    main->setSpacing(16);

    QHBoxLayout *header = new QHBoxLayout();
    QVBoxLayout *tl = new QVBoxLayout();
    QLabel *title = new QLabel("网络防火墙", this);
    title->setObjectName("pageTitle");
    m_ruleCountLabel = new QLabel("共 0 条规则", this);
    m_ruleCountLabel->setObjectName("pageSubtitle");
    tl->addWidget(title); tl->addWidget(m_ruleCountLabel);
    header->addLayout(tl); header->addStretch();

    QPushButton *addBtn = new QPushButton("  +  添加规则", this);
    addBtn->setObjectName("primaryBtn");
    addBtn->setFixedHeight(38);
    addBtn->setCursor(Qt::PointingHandCursor);
    connect(addBtn, &QPushButton::clicked, this, &FirewallPanel::onAddRule);
    header->addWidget(addBtn);

    QPushButton *delBtn = new QPushButton("  \u2716  删除", this);
    delBtn->setObjectName("dangerBtn");
    delBtn->setFixedHeight(38);
    delBtn->setCursor(Qt::PointingHandCursor);
    connect(delBtn, &QPushButton::clicked, this, &FirewallPanel::onRemoveRule);
    header->addWidget(delBtn);

    main->addLayout(header);

    m_ruleTree = new QTreeWidget(this);
    m_ruleTree->setHeaderLabels({"启用", "规则名称", "程序路径", "远程地址", "端口", "协议", "动作"});
    m_ruleTree->setRootIsDecorated(false);
    m_ruleTree->setAlternatingRowColors(false);
    m_ruleTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_ruleTree->setColumnWidth(0, 50);
    m_ruleTree->setColumnWidth(1, 160);
    m_ruleTree->setColumnWidth(2, 280);
    m_ruleTree->setColumnWidth(3, 150);
    m_ruleTree->setColumnWidth(4, 80);
    m_ruleTree->setColumnWidth(5, 80);
    main->addWidget(m_ruleTree, 1);
}

void FirewallPanel::loadRules()
{
    m_ruleTree->clear();
    struct R { QString en, name, path, addr, port, proto, act; };
    QVector<R> rules = {
        {"\u2714","允许系统服务",    "C:\\Windows\\System32\\svchost.exe","任何","任何","TCP/UDP","允许"},
        {"\u2714","允许浏览器",      "C:\\Program Files\\Google\\Chrome\\chrome.exe","任何","443","TCP","允许"},
        {"\u2714","阻止可疑连接",    "任何","10.0.0.0/8","任何","TCP","阻止"},
        {"\u2714","阻止挖矿端口",    "任何","任何","3333","TCP","阻止"},
        {"\u2714","允许RingCore更新","C:\\Program Files\\RingCore\\*","update.ringcore.com","443","TCP","允许"},
        {"\u2714","阻止远程桌面",    "任何","任何","3389","TCP","阻止"},
    };
    for (const auto &r : rules) {
        auto *item = new QTreeWidgetItem();
        item->setText(0,r.en); item->setText(1,r.name); item->setText(2,r.path);
        item->setText(3,r.addr); item->setText(4,r.port); item->setText(5,r.proto);
        item->setText(6,r.act);
        item->setForeground(6, r.act=="阻止" ? QColor("#F87171") : QColor("#34D399"));
        m_ruleTree->addTopLevelItem(item);
    }
    m_ruleCountLabel->setText(QString("共 %1 条规则").arg(m_ruleTree->topLevelItemCount()));
}

void FirewallPanel::onAddRule()
{
    bool ok;
    QString name = QInputDialog::getText(this, "添加规则", "规则名称:", QLineEdit::Normal, "", &ok);
    if (!ok || name.isEmpty()) return;

    QString path = QInputDialog::getText(this, "添加规则", "程序路径 (或 '任何'):", QLineEdit::Normal, "C:\\", &ok);
    if (!ok) return;

    QStringList actions = {"允许", "阻止"};
    QString action = QInputDialog::getItem(this, "添加规则", "动作:", actions, 0, false, &ok);
    if (!ok) return;

    auto *item = new QTreeWidgetItem();
    item->setText(0, "\u2714");
    item->setText(1, name);
    item->setText(2, path.isEmpty() ? "任何" : path);
    item->setText(3, "任何");
    item->setText(4, "任何");
    item->setText(5, "TCP");
    item->setText(6, action);
    item->setForeground(6, action=="阻止" ? QColor("#F87171") : QColor("#34D399"));
    m_ruleTree->addTopLevelItem(item);
    m_ruleCountLabel->setText(QString("共 %1 条规则").arg(m_ruleTree->topLevelItemCount()));
}

void FirewallPanel::onRemoveRule()
{
    QTreeWidgetItem *item = m_ruleTree->currentItem();
    if (!item) return;
    m_ruleTree->takeTopLevelItem(m_ruleTree->indexOfTopLevelItem(item));
    delete item;
    m_ruleCountLabel->setText(QString("共 %1 条规则").arg(m_ruleTree->topLevelItemCount()));
}
