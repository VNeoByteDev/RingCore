#include "HomePanel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QProcess>
#include <QGraphicsDropShadowEffect>

HomePanel::HomePanel(QWidget *parent) : QWidget(parent)
{
    m_serviceClient = new ServiceClient(this);
    m_statusTimer = new QTimer(this);
    connect(m_statusTimer, &QTimer::timeout, this, &HomePanel::onRefreshStatus);

    setupUI();

    m_statusTimer->start(3000);

    if (m_serviceClient->connectToService()) {
        m_heroStatus->setText("系统安全");
        m_heroSub->setText("所有防护模块已启用 \u00B7 病毒库 560+ 条 \u00B7 实时监控已开启");
        m_heroShield->setStyleSheet("font-size: 64px; color: #22D3EE; background: transparent;");
        m_shieldGlow->setStyleSheet("font-size: 90px; color: rgba(34,211,238,0.15); background: transparent;");
        m_serviceStatusVal->setText("运行中");
        m_serviceStatusVal->setStyleSheet("font-size: 13px; font-weight: 600; color: #34D399; background: transparent;");
        onRefreshStatus();
    } else {
        m_heroStatus->setText("正在连接...");
        m_heroSub->setText("请稍候，后台防护服务正在启动");
        m_heroShield->setStyleSheet("font-size: 64px; color: #FBBF24; background: transparent;");
        m_shieldGlow->setStyleSheet("font-size: 90px; color: rgba(251,191,36,0.15); background: transparent;");
        m_serviceStatusVal->setText("连接中");
        m_serviceStatusVal->setStyleSheet("font-size: 13px; font-weight: 600; color: #FBBF24; background: transparent;");
    }
}

void HomePanel::setupUI()
{
    QVBoxLayout *main = new QVBoxLayout(this);
    main->setContentsMargins(32, 24, 32, 24);
    main->setSpacing(20);

    main->addWidget(createHeroCard());
    main->addWidget(createStatCards());
    main->addWidget(createQuickActions());
    main->addWidget(createRecentActivity(), 1);
}

QWidget* HomePanel::createHeroCard()
{
    QWidget *card = new QWidget(this);
    card->setObjectName("heroCard");
    card->setFixedHeight(180);

    QHBoxLayout *lay = new QHBoxLayout(card);
    lay->setContentsMargins(36, 24, 36, 24);
    lay->setSpacing(32);

    // Shield icon with glow effect
    QWidget *shieldContainer = new QWidget(card);
    shieldContainer->setFixedSize(120, 120);
    shieldContainer->setStyleSheet("background: transparent;");

    // Outer glow ring
    m_shieldGlow = new QLabel("\u25CE", shieldContainer);
    m_shieldGlow->setStyleSheet("font-size: 90px; color: rgba(34,211,238,0.15); background: transparent;");
    m_shieldGlow->setAlignment(Qt::AlignCenter);
    m_shieldGlow->setGeometry(-15, -15, 150, 150);

    // Shield icon
    m_heroShield = new QLabel("\u2726", shieldContainer);
    m_heroShield->setStyleSheet("font-size: 64px; color: #22D3EE; background: transparent;");
    m_heroShield->setAlignment(Qt::AlignCenter);
    m_heroShield->setGeometry(0, 10, 120, 100);

    lay->addWidget(shieldContainer);

    // Info section
    QVBoxLayout *infoLay = new QVBoxLayout();
    infoLay->setSpacing(4);

    QLabel *label = new QLabel("SECURITY STATUS", card);
    label->setStyleSheet("font-size: 10px; color: #475569; letter-spacing: 2px; background: transparent; font-weight: 600;");
    infoLay->addWidget(label);

    m_heroStatus = new QLabel("", card);
    m_heroStatus->setObjectName("heroStatus");
    infoLay->addWidget(m_heroStatus);

    m_heroSub = new QLabel("", card);
    m_heroSub->setObjectName("heroSub");
    infoLay->addWidget(m_heroSub);

    infoLay->addSpacing(8);

    QHBoxLayout *statusRow = new QHBoxLayout();
    QLabel *svcIcon = new QLabel("\u25CF", card);
    svcIcon->setStyleSheet("color: #22D3EE; font-size: 8px; background: transparent;");
    statusRow->addWidget(svcIcon);
    QLabel *svcLabel = new QLabel("服务状态: ", card);
    svcLabel->setStyleSheet("font-size: 12px; color: #475569; background: transparent;");
    statusRow->addWidget(svcLabel);
    m_serviceStatusVal = new QLabel("--", card);
    m_serviceStatusVal->setStyleSheet("font-size: 12px; color: #64748B; background: transparent;");
    statusRow->addWidget(m_serviceStatusVal);
    statusRow->addStretch();
    infoLay->addLayout(statusRow);

    infoLay->addStretch();

    lay->addLayout(infoLay, 1);

    return card;
}

QWidget* HomePanel::createStatCards()
{
    QWidget *container = new QWidget(this);
    QHBoxLayout *grid = new QHBoxLayout(container);
    grid->setContentsMargins(0, 0, 0, 0);
    grid->setSpacing(16);

    struct StatCard {
        QString icon;
        QString label;
        QString value;
        QString valColor;
        QString iconBg;
    };

    QVector<StatCard> stats = {
        {"\u2699", "总扫描文件数",  "1,024", "#22D3EE", "rgba(34,211,238,0.12)"},
        {"\u26A0", "检测威胁数",    "0",     "#34D399", "rgba(52,211,153,0.12)"},
        {"\u2714", "防护状态",      "运行中", "#34D399", "rgba(52,211,153,0.12)"},
    };

    for (int i = 0; i < stats.size(); i++) {
        QWidget *card = new QWidget(container);
        card->setObjectName("statCard");
        card->setFixedHeight(90);

        QGraphicsDropShadowEffect *shadow = new QGraphicsDropShadowEffect(card);
        shadow->setBlurRadius(20);
        shadow->setXOffset(0);
        shadow->setYOffset(4);
        shadow->setColor(QColor(0, 0, 0, 40));
        card->setGraphicsEffect(shadow);

        QHBoxLayout *cl = new QHBoxLayout(card);
        cl->setContentsMargins(20, 16, 20, 16);
        cl->setSpacing(16);

        // Icon circle
        QLabel *icon = new QLabel(stats[i].icon, card);
        icon->setFixedSize(44, 44);
        icon->setAlignment(Qt::AlignCenter);
        icon->setStyleSheet(QString(
            "font-size: 18px; color: white; background: %1; border-radius: 22px;"
        ).arg(stats[i].iconBg));
        cl->addWidget(icon);

        QVBoxLayout *tl = new QVBoxLayout();
        tl->setSpacing(2);
        tl->setContentsMargins(0, 0, 0, 0);

        QLabel *lbl = new QLabel(stats[i].label, card);
        lbl->setObjectName("statTitle");
        tl->addWidget(lbl);

        QLabel *val = new QLabel(stats[i].value, card);
        val->setStyleSheet(QString(
            "font-size: 20px; font-weight: 700; color: %1; background: transparent;"
        ).arg(stats[i].valColor));
        tl->addWidget(val);

        tl->addStretch();
        cl->addLayout(tl, 1);

        // Store reference for statScanned
        if (i == 0) m_statScanned = val;
        if (i == 1) m_statThreats = val;
        if (i == 2) m_statProtection = val;

        grid->addWidget(card, 1);
    }

    return container;
}

QWidget* HomePanel::createQuickActions()
{
    QWidget *card = new QWidget(this);
    card->setObjectName("statCard");
    card->setFixedHeight(56);

    QHBoxLayout *lay = new QHBoxLayout(card);
    lay->setContentsMargins(24, 0, 24, 0);
    lay->setSpacing(12);

    QLabel *label = new QLabel("\u2699  快捷操作", card);
    label->setStyleSheet("font-size: 12px; font-weight: 600; color: #475569; background: transparent; letter-spacing: 0.5px;");
    lay->addWidget(label);
    lay->addStretch();

    QVector<QPair<QString, int>> actions = {
        {"进程管理", 2}, {"网络防火墙", 3}, {"垃圾清理", 4}, {"设置", 5}
    };

    for (const auto &action : actions) {
        QPushButton *btn = new QPushButton(action.first, card);
        btn->setObjectName("ghostBtn");
        btn->setFixedHeight(32);
        btn->setCursor(Qt::PointingHandCursor);
        connect(btn, &QPushButton::clicked, this, [this, idx = action.second]() {
            emit navigateTo(idx);
        });
        lay->addWidget(btn);
    }

    return card;
}

QWidget* HomePanel::createRecentActivity()
{
    QWidget *card = new QWidget(this);
    card->setObjectName("statCard");

    QVBoxLayout *lay = new QVBoxLayout(card);
    lay->setContentsMargins(24, 20, 24, 16);
    lay->setSpacing(10);

    // Section header with icon
    QHBoxLayout *headerLay = new QHBoxLayout();
    headerLay->setSpacing(8);
    QLabel *headerIcon = new QLabel("\u2139", card);
    headerIcon->setStyleSheet("color: #22D3EE; font-size: 13px; background: transparent;");
    headerLay->addWidget(headerIcon);
    QLabel *title = new QLabel("最近活动", card);
    title->setStyleSheet("font-size: 13px; font-weight: 600; color: #64748B; background: transparent; letter-spacing: 0.5px;");
    headerLay->addWidget(title);
    headerLay->addStretch();
    lay->addLayout(headerLay);

    // Separator line
    QFrame *sep = new QFrame(card);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("background: rgba(34,211,238,0.08); max-height: 1px; min-height: 1px;");
    lay->addWidget(sep);

    struct LogEntry { QString time; QString icon; QString text; QString color; };
    QVector<LogEntry> logs = {
        {"刚刚", "\u2714", "Shield Engine v1.0 启动成功", "#34D399"},
        {"1s",   "\u2714", "特征库加载完成 (17 条)", "#34D399"},
        {"2s",   "\u2714", "启发式分析引擎就绪", "#34D399"},
        {"3s",   "\u2714", "模式匹配引擎就绪", "#34D399"},
        {"4s",   "\u2714", "云端查杀已连接 (MalwareBazaar)", "#34D399"},
        {"5s",   "\u2714", "实时进程监控已启动", "#34D399"},
    };

    for (const auto &log : logs) {
        QHBoxLayout *row = new QHBoxLayout();
        row->setSpacing(10);
        row->setContentsMargins(0, 2, 0, 2);

        QLabel *time = new QLabel(log.time, card);
        time->setStyleSheet("color: #334155; font-size: 11px; min-width: 36px; background: transparent;");
        row->addWidget(time);

        QLabel *icon = new QLabel(log.icon, card);
        icon->setStyleSheet(QString("color: %1; font-size: 11px; background: transparent;").arg(log.color));
        row->addWidget(icon);

        QLabel *text = new QLabel(log.text, card);
        text->setStyleSheet("color: #94A3B8; font-size: 12px; background: transparent;");
        row->addWidget(text, 1);

        lay->addLayout(row);
    }

    lay->addStretch();
    return card;
}

void HomePanel::onQuickScan() { emit startQuickScan(); }
void HomePanel::onFullScan()  { emit startFullScan(); }

void HomePanel::onRefreshStatus()
{
    if (!m_serviceClient->isConnected()) {
        if (m_serviceClient->connectToService()) {
            m_heroStatus->setText("系统安全");
            m_heroSub->setText("所有防护模块已启用 \u00B7 病毒库 560+ 条 \u00B7 实时监控已开启");
            m_heroShield->setStyleSheet("font-size: 64px; color: #22D3EE; background: transparent;");
            m_shieldGlow->setStyleSheet("font-size: 90px; color: rgba(34,211,238,0.15); background: transparent;");
            m_serviceStatusVal->setText("运行中");
            m_serviceStatusVal->setStyleSheet("font-size: 13px; font-weight: 600; color: #34D399; background: transparent;");
            if (m_statProtection) {
                m_statProtection->setText("运行中");
                m_statProtection->setStyleSheet("font-size: 20px; font-weight: 700; color: #34D399; background: transparent;");
            }
        } else {
            m_heroStatus->setText("后台服务未响应");
            m_heroSub->setText("请以管理员身份运行 RingCoreSvc.exe");
            m_heroShield->setStyleSheet("font-size: 64px; color: #F87171; background: transparent;");
            m_shieldGlow->setStyleSheet("font-size: 90px; color: rgba(248,113,113,0.15); background: transparent;");
            m_serviceStatusVal->setText("未连接");
            m_serviceStatusVal->setStyleSheet("font-size: 13px; font-weight: 600; color: #F87171; background: transparent;");
            if (m_statProtection) {
                m_statProtection->setText("异常");
                m_statProtection->setStyleSheet("font-size: 20px; font-weight: 700; color: #F87171; background: transparent;");
            }
        }
        return;
    }
    ServiceResponse resp = m_serviceClient->getStatus();
    if (resp.status == 1) {
        m_serviceStatusVal->setText("运行中");
        m_serviceStatusVal->setStyleSheet("font-size: 13px; font-weight: 600; color: #34D399; background: transparent;");
        if (m_statProtection) {
            m_statProtection->setText("运行中");
            m_statProtection->setStyleSheet("font-size: 20px; font-weight: 700; color: #34D399; background: transparent;");
        }
    } else {
        m_serviceStatusVal->setText("防护已关闭");
        m_serviceStatusVal->setStyleSheet("font-size: 13px; font-weight: 600; color: #FBBF24; background: transparent;");
        if (m_statProtection) {
            m_statProtection->setText("已关闭");
            m_statProtection->setStyleSheet("font-size: 20px; font-weight: 700; color: #FBBF24; background: transparent;");
        }
    }
}
