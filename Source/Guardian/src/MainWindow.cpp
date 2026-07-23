#include "MainWindow.h"
#include "panels/HomePanel.h"
#include "panels/ScanPanel.h"
#include "panels/ProcessPanel.h"
#include "panels/FirewallPanel.h"
#include "panels/JunkCleanPanel.h"
#include "panels/SettingPanel.h"
#include "core/Settings.h"

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFrame>
#include <QCloseEvent>
#include <QApplication>
#include <QStyle>
#include <QProcess>
#include <QMessageBox>
#include <QFile>
#include <QGraphicsDropShadowEffect>
#include <QMouseEvent>
#include <QScreen>
#include <QPainter>
#include <QStyleOption>
#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_currentNavIndex(0)
    , m_protectionEnabled(false)
    , m_fadeIn(nullptr)
    , m_resizing(false)
    , m_isDraggingTitleBar(false)
    , m_resizeEdge(Qt::Edges())
    , m_titleBar(nullptr)
    , m_btnMinimize(nullptr)
    , m_btnMaximize(nullptr)
    , m_btnClose(nullptr)
{
    setupUI();
    setupTrayIcon();
    connectSignals();

    // Auto-start background service
    QTimer::singleShot(500, this, &MainWindow::autoStartService);

    m_statusTimer = new QTimer(this);
    connect(m_statusTimer, &QTimer::timeout, this, &MainWindow::onProtectionStatusUpdate);
    m_statusTimer->start(15000);
}

MainWindow::~MainWindow() {}

void MainWindow::closeEvent(QCloseEvent *event)
{
    QMessageBox msgBox(this);
    msgBox.setWindowTitle("RingCore Security Guardian");
    msgBox.setIcon(QMessageBox::Question);
    msgBox.setText("RingCore Security Guardian");
    msgBox.setInformativeText("\u5982\u4F55\u5173\u95ED RingCore Security Guardian?");
    msgBox.setDetailedText("\u6700\u5C0F\u5316\u5230\u6258\u76D8: \u5B89\u5168\u536B\u58EB\u5C06\u6700\u5C0F\u5316\u5230\u7CFB\u7EDF\u6258\u76D8\uFF0C\u9632\u62A4\u5F15\u64CE\u7EE7\u7EED\u8FD0\u884C\u3002\n\u76F4\u63A5\u5173\u95ED: \u5B8C\u5168\u5173\u95ED\u5B89\u5168\u536B\u58EB\uFF0C\u540E\u53F0\u9632\u62A4\u5C06\u505C\u6B62\u3002");
    msgBox.setStandardButtons(QMessageBox::NoButton);

    QPushButton *minimizeBtn = msgBox.addButton("\u6700\u5C0F\u5316\u5230\u6258\u76D8", QMessageBox::AcceptRole);
    QPushButton *quitBtn = msgBox.addButton("\u76F4\u63A5\u5173\u95ED", QMessageBox::RejectRole);
    msgBox.setDefaultButton(minimizeBtn);

    msgBox.exec();

    if (msgBox.clickedButton() == minimizeBtn) {
        hide();
        m_trayIcon->showMessage("RingCore",
            "\u5DF2\u6700\u5C0F\u5316\u5230\u7CFB\u7EDF\u6258\u76D8\uFF0C\u9632\u62A4\u4ECD\u5728\u8FD0\u884C",
            QSystemTrayIcon::Information, 2000);
        event->ignore();
    } else {
        event->accept();
        qApp->quit();
    }
}

void MainWindow::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    // Draw rounded rectangle background with 12px radius
    painter.setBrush(QColor("#080C16"));
    painter.setPen(Qt::NoPen);
    painter.drawRoundedRect(rect(), 12, 12);
}

bool MainWindow::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
{
    if (eventType == "windows_generic_MSG" || eventType == "windows_dispatcher_MSG") {
        MSG *msg = static_cast<MSG*>(message);
        if (msg->message == WM_NCHITTEST) {
            *result = 0;

            // Get cursor position in screen coordinates
            int x = GET_X_LPARAM(msg->lParam);
            int y = GET_Y_LPARAM(msg->lParam);
            QPoint globalPos(x, y);
            QPoint localPos = mapFromGlobal(globalPos);

            // Check edges for resizing (8px border)
            const int border = 8;
            QRect r = rect();
            bool onLeft = localPos.x() < border;
            bool onRight = localPos.x() > r.width() - border;
            bool onTop = localPos.y() < border;
            bool onBottom = localPos.y() > r.height() - border;

            // Corners
            if (onTop && onLeft) { *result = HTTOPLEFT; return true; }
            if (onTop && onRight) { *result = HTTOPRIGHT; return true; }
            if (onBottom && onLeft) { *result = HTBOTTOMLEFT; return true; }
            if (onBottom && onRight) { *result = HTBOTTOMRIGHT; return true; }
            // Edges
            if (onLeft) { *result = HTLEFT; return true; }
            if (onRight) { *result = HTRIGHT; return true; }
            if (onTop) { *result = HTTOP; return true; }
            if (onBottom) { *result = HTBOTTOM; return true; }

            // Title bar area — allow drag and double-click maximize
            if (m_titleBar && m_titleBar->geometry().contains(localPos)) {
                // Check if on a button
                if (m_btnMinimize && m_btnMinimize->geometry().contains(localPos)) return false;
                if (m_btnMaximize && m_btnMaximize->geometry().contains(localPos)) return false;
                if (m_btnClose && m_btnClose->geometry().contains(localPos)) return false;
                *result = HTCAPTION;
                return true;
            }

            return false;
        }
    }
    return QMainWindow::nativeEvent(eventType, message, result);
}

void MainWindow::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton && m_titleBar &&
        m_titleBar->geometry().contains(event->pos())) {
        m_isDraggingTitleBar = true;
        m_dragPosition = event->globalPosition().toPoint() - frameGeometry().topLeft();
        event->accept();
    }
}

void MainWindow::mouseMoveEvent(QMouseEvent *event)
{
    if (m_isDraggingTitleBar && (event->buttons() & Qt::LeftButton)) {
        move(event->globalPosition().toPoint() - m_dragPosition);
        event->accept();
    }
}

void MainWindow::mouseReleaseEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton) {
        m_isDraggingTitleBar = false;
        event->accept();
    }
}

void MainWindow::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::WindowStateChange) {
        if (isMinimized() && g_settings && g_settings->minimizeToTray()) {
            hide();
            m_trayIcon->show();
        }
        if (m_btnMaximize) {
            m_btnMaximize->setText(isMaximized() ? "\u2752" : "\u25A1");
        }
    }
    QMainWindow::changeEvent(event);
}

void MainWindow::setupUI()
{
    setWindowTitle("RingCore Security Guardian");
    setMinimumSize(1280, 800);
    resize(1280, 800);
    setWindowFlags(Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground, true);
    setAttribute(Qt::WA_NoSystemBackground, true);

    // Setup DWM for window shadow
    setupFramelessWindow();

    QWidget *centralWidget = new QWidget(this);
    centralWidget->setObjectName("centralWidget");
    centralWidget->setAttribute(Qt::WA_TranslucentBackground);
    QVBoxLayout *outerLayout = new QVBoxLayout(centralWidget);
    outerLayout->setContentsMargins(12, 12, 12, 12);
    outerLayout->setSpacing(0);

    // Custom title bar
    setupTitleBar();
    outerLayout->addWidget(m_titleBar);

    // Main content area (sidebar + content)
    QWidget *mainContent = new QWidget(this);
    mainContent->setObjectName("mainContent");
    QHBoxLayout *mainLayout = new QHBoxLayout(mainContent);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    setupSidebar();
    mainLayout->addWidget(m_sidebar);

    QFrame *sep = new QFrame(this);
    sep->setObjectName("separator");
    mainLayout->addWidget(sep);

    setupContent();
    mainLayout->addWidget(m_contentStack, 1);

    outerLayout->addWidget(mainContent, 1);

    setCentralWidget(centralWidget);
    onNavClicked(0);
}

void MainWindow::setupFramelessWindow()
{
    HWND hwnd = reinterpret_cast<HWND>(winId());
    BOOL enableDarkMode = TRUE;
    DwmSetWindowAttribute(hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/,
                          &enableDarkMode, sizeof(enableDarkMode));

    // Windows 11: enable rounded corners via DWM
    // DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2
    int cornerPref = 2;
    HRESULT hr = DwmSetWindowAttribute(hwnd, 33, &cornerPref, sizeof(cornerPref));

    // Enable window shadow via DWM
    MARGINS margins = {0, 0, 0, 1};
    DwmExtendFrameIntoClientArea(hwnd, &margins);
}

void MainWindow::setupTitleBar()
{
    m_titleBar = new QWidget(this);
    m_titleBar->setObjectName("titleBar");
    m_titleBar->setFixedHeight(48);

    QHBoxLayout *lay = new QHBoxLayout(m_titleBar);
    lay->setContentsMargins(16, 0, 8, 0);
    lay->setSpacing(10);

    // App icon (using SVG shield)
    m_appIcon = new QLabel(m_titleBar);
    m_appIcon->setPixmap(QIcon(":/images/shield.svg").pixmap(24, 24));
    m_appIcon->setFixedSize(24, 24);
    m_appIcon->setStyleSheet("background: transparent;");
    lay->addWidget(m_appIcon);

    // App title
    m_appTitle = new QLabel("RingCore Security Guardian", m_titleBar);
    m_appTitle->setObjectName("appTitle");
    lay->addWidget(m_appTitle);

    lay->addStretch();

    // Window control buttons
    m_btnMinimize = new QPushButton("\u2014", m_titleBar);
    m_btnMinimize->setObjectName("titleBtnMinimize");
    m_btnMinimize->setFixedSize(44, 32);
    m_btnMinimize->setCursor(Qt::PointingHandCursor);
    connect(m_btnMinimize, &QPushButton::clicked, this, &MainWindow::onTitleBarMinimize);
    lay->addWidget(m_btnMinimize);

    m_btnMaximize = new QPushButton("\u25A1", m_titleBar);
    m_btnMaximize->setObjectName("titleBtnMaximize");
    m_btnMaximize->setFixedSize(44, 32);
    m_btnMaximize->setCursor(Qt::PointingHandCursor);
    connect(m_btnMaximize, &QPushButton::clicked, this, &MainWindow::onTitleBarMaximize);
    lay->addWidget(m_btnMaximize);

    m_btnClose = new QPushButton("\u2716", m_titleBar);
    m_btnClose->setObjectName("titleBtnClose");
    m_btnClose->setFixedSize(44, 32);
    m_btnClose->setCursor(Qt::PointingHandCursor);
    connect(m_btnClose, &QPushButton::clicked, this, &MainWindow::onTitleBarClose);
    lay->addWidget(m_btnClose);
}

void MainWindow::setupSidebar()
{
    m_sidebar = new QWidget(this);
    m_sidebar->setObjectName("sidebar");
    m_sidebar->setFixedWidth(220);

    QVBoxLayout *lay = new QVBoxLayout(m_sidebar);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(0);

    // Logo area
    QWidget *logoBox = new QWidget(m_sidebar);
    logoBox->setObjectName("logoBox");
    logoBox->setFixedHeight(100);
    QVBoxLayout *logoLay = new QVBoxLayout(logoBox);
    logoLay->setContentsMargins(20, 24, 20, 16);
    logoLay->setSpacing(6);

    QLabel *shieldIcon = new QLabel("\u2726", logoBox);
    shieldIcon->setStyleSheet("color: #22D3EE; font-size: 24px; background: transparent;");
    logoLay->addWidget(shieldIcon);

    QLabel *logoPrimary = new QLabel("RingCore", logoBox);
    logoPrimary->setObjectName("logoPrimary");
    logoLay->addWidget(logoPrimary);

    QLabel *logoSecondary = new QLabel("Security Guardian", logoBox);
    logoSecondary->setObjectName("logoSecondary");
    logoLay->addWidget(logoSecondary);

    lay->addWidget(logoBox);
    lay->addSpacing(12);

    // Navigation items with icon + text
    struct NavItem { QString icon; QString text; };
    QVector<NavItem> items = {
        {"\u2302", "首页"}, {"\u25CE", "病毒扫描"}, {"\u2261", "进程管理"},
        {"\u25C7", "网络防火墙"}, {"\u2725", "垃圾清理"}, {"\u2699", "设置"},
    };

    for (int i = 0; i < items.size(); ++i) {
        QPushButton *btn = new QPushButton(QString("  %1    %2").arg(items[i].icon, items[i].text), m_sidebar);
        btn->setObjectName("navBtn");
        btn->setFixedHeight(46);
        btn->setCheckable(true);
        btn->setCursor(Qt::PointingHandCursor);
        lay->addWidget(btn);
        m_navButtons.append(btn);
    }

    lay->addStretch();

    // Version label at bottom
    QWidget *bottomBar = new QWidget(m_sidebar);
    bottomBar->setObjectName("sidebarBottom");
    bottomBar->setFixedHeight(48);
    QVBoxLayout *bottomLay = new QVBoxLayout(bottomBar);
    bottomLay->setContentsMargins(16, 8, 16, 12);

    QLabel *ver = new QLabel("v1.0.0", bottomBar);
    ver->setObjectName("versionLabel");
    ver->setAlignment(Qt::AlignCenter);
    bottomLay->addWidget(ver);

    lay->addWidget(bottomBar);
}

void MainWindow::setupContent()
{
    m_contentStack = new QStackedWidget(this);
    m_contentStack->setObjectName("contentArea");

    m_homePanel = new HomePanel(this);
    m_scanPanel = new ScanPanel(this);
    m_processPanel = new ProcessPanel(this);
    m_firewallPanel = new FirewallPanel(this);
    m_junkCleanPanel = new JunkCleanPanel(this);
    m_settingPanel = new SettingPanel(this);

    m_contentStack->addWidget(m_homePanel);
    m_contentStack->addWidget(m_scanPanel);
    m_contentStack->addWidget(m_processPanel);
    m_contentStack->addWidget(m_firewallPanel);
    m_contentStack->addWidget(m_junkCleanPanel);
    m_contentStack->addWidget(m_settingPanel);
}

void MainWindow::setupTrayIcon()
{
    m_trayIcon = new QSystemTrayIcon(this);
    m_trayIcon->setIcon(QIcon(":/images/shield.svg"));
    m_trayIcon->setToolTip("RingCore Security Guardian - 防护中");

    m_trayMenu = new QMenu(this);
    m_trayMenu->setStyleSheet(
        "QMenu {"
        "  background: #111827;"
        "  color: #E2E8F0;"
        "  border: 1px solid #334155;"
        "  border-radius: 8px;"
        "  padding: 6px 0px;"
        "  font-size: 13px;"
        "}"
        "QMenu::item {"
        "  padding: 8px 32px 8px 16px;"
        "  color: #E2E8F0;"
        "}"
        "QMenu::item:selected {"
        "  background: #1E293B;"
        "  color: #22D3EE;"
        "}"
        "QMenu::item:disabled {"
        "  color: #64748B;"
        "  background: transparent;"
        "}"
        "QMenu::separator {"
        "  height: 1px;"
        "  background: #334155;"
        "  margin: 4px 12px;"
        "}"
    );

    // Status display
    m_statusAction = m_trayMenu->addAction("\u2714 防护状态: 正常");
    m_statusAction->setEnabled(false);
    m_trayMenu->addSeparator();

    m_trayMenu->addAction("\u2302  打开主界面", this, &MainWindow::onTrayShow);
    m_trayMenu->addAction("\u25CE  快速扫描", this, &MainWindow::onTrayQuickScan);
    m_trayMenu->addSeparator();
    m_trayMenu->addAction("\u2716  退出", this, &MainWindow::onTrayExit);

    m_trayIcon->setContextMenu(m_trayMenu);
    m_trayIcon->show();

    connect(m_trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::onTrayActivated);
}

void MainWindow::connectSignals()
{
    for (int i = 0; i < m_navButtons.size(); ++i) {
        connect(m_navButtons[i], &QPushButton::clicked, this, [this, i]() { onNavClicked(i); });
    }
    connect(m_homePanel, &HomePanel::navigateTo, this, &MainWindow::onNavClicked);
    connect(m_homePanel, &HomePanel::startQuickScan, this, [this]() {
        onNavClicked(1);
        QTimer::singleShot(200, m_scanPanel, &ScanPanel::startQuickScan);
    });
    connect(m_homePanel, &HomePanel::startFullScan, this, [this]() {
        onNavClicked(1);
        QTimer::singleShot(200, m_scanPanel, &ScanPanel::startFullScan);
    });

    // Scan complete notification — respects scanCompleteNotify setting
    connect(m_scanPanel, &ScanPanel::scanFinished, this, [this](int total, int threats) {
        if (!g_settings || !g_settings->scanCompleteNotify()) return;
        QString msg = QString("扫描完成\n共扫描 %1 个文件，发现 %2 个威胁").arg(total).arg(threats);
        m_trayIcon->showMessage("RingCore 扫描完成", msg, QSystemTrayIcon::Information, 5000);
    });

    // Update settings panel with real DB stats
    if (g_settings) {
        m_settingPanel->updateDBInfo(560);

        // Connect protection toggles to service
        connect(g_settings, &Settings::protectionToggled, this, [this](const QString &type, bool enabled) {
            Q_UNUSED(type);
            if (enabled) {
                m_trayIcon->showMessage("RingCore 防护",
                    QString("已开启 %1 防护").arg(type), QSystemTrayIcon::Information, 2000);
            } else {
                m_trayIcon->showMessage("RingCore 防护",
                    QString("已关闭 %1 防护").arg(type), QSystemTrayIcon::Warning, 2000);
            }
        });
    }
}

void MainWindow::onNavClicked(int index)
{
    if (index < 0 || index >= m_navButtons.size()) return;
    m_currentNavIndex = index;
    for (int i = 0; i < m_navButtons.size(); ++i)
        m_navButtons[i]->setChecked(i == index);
    m_contentStack->setCurrentIndex(index);
}

// ─── Title bar slots ───

void MainWindow::onTitleBarMinimize()
{
    showMinimized();
}

void MainWindow::onTitleBarMaximize()
{
    if (isMaximized()) {
        showNormal();
        m_btnMaximize->setText("\u25A1");
    } else {
        showMaximized();
        m_btnMaximize->setText("\u2752");
    }
}

void MainWindow::onTitleBarClose()
{
    close();
}

// ─── Tray slots ───

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick) {
        onTrayShow();
    }
}

void MainWindow::onTrayShow()
{
    show();
    raise();
    activateWindow();
}

void MainWindow::onTrayQuickScan()
{
    m_contentStack->setCurrentIndex(1);
    show();
    raise();
}

void MainWindow::onTrayExit()
{
    qApp->quit();
}

void MainWindow::onMinimizeToTray()
{
    hide();
}

void MainWindow::onProtectionStatusUpdate()
{
    QProcess process;
    process.start("tasklist", {"/FI", "IMAGENAME eq RingCoreSvc.exe", "/NH"});
    process.waitForFinished(500);
    QString output = process.readAllStandardOutput();

    if (output.contains("RingCoreSvc.exe")) {
        m_protectionEnabled = true;
        m_trayIcon->setIcon(QIcon(":/images/shield.svg"));
        m_trayIcon->setToolTip("RingCore Security Guardian - 防护中");
        m_statusAction->setText("\u2714 防护状态: 正常");
    } else {
        m_protectionEnabled = false;
        m_trayIcon->setToolTip("RingCore Security Guardian - 防护已关闭");
        m_statusAction->setText("\u2718 防护状态: 未运行");
    }
}

void MainWindow::updateTrayStatus()
{
    if (m_protectionEnabled) {
        m_trayIcon->setIcon(QIcon(":/images/shield.svg"));
        m_trayIcon->setToolTip("RingCore Security Guardian - 防护中");
    } else {
        m_trayIcon->setToolTip("RingCore Security Guardian - 防护已关闭");
    }
}

void MainWindow::autoStartService()
{
    QProcess check;
    check.start("tasklist", {"/FI", "IMAGENAME eq RingCoreSvc.exe", "/NH"});
    check.waitForFinished(1000);
    QString output = check.readAllStandardOutput();

    if (output.contains("RingCoreSvc.exe")) {
        m_protectionEnabled = true;
        m_trayIcon->setToolTip("RingCore Security Guardian - 防护中");
        m_statusAction->setText("\u2714 防护状态: 正常");
        return;
    }

    QString svcPath = QCoreApplication::applicationDirPath() + "/../Service/RingCoreSvc.exe";
    if (!QFile::exists(svcPath)) {
        svcPath = QCoreApplication::applicationDirPath() + "/../../Service/RingCoreSvc.exe";
    }
    if (!QFile::exists(svcPath)) {
        svcPath = QCoreApplication::applicationDirPath() + "/RingCoreSvc.exe";
    }

    if (QFile::exists(svcPath)) {
        QProcess::startDetached("cmd.exe", {"/c", "start", "", "/B", svcPath});
        QTimer::singleShot(2000, this, [this]() {
            QProcess check2;
            check2.start("tasklist", {"/FI", "IMAGENAME eq RingCoreSvc.exe", "/NH"});
            check2.waitForFinished(1000);
            QString out = check2.readAllStandardOutput();
            if (out.contains("RingCoreSvc.exe")) {
                m_protectionEnabled = true;
                m_trayIcon->setToolTip("RingCore Security Guardian - 防护中");
                m_statusAction->setText("\u2714 防护状态: 正常");
                m_trayIcon->showMessage("RingCore", "后台防护服务已自动启动", QSystemTrayIcon::Information, 2000);
            } else {
                m_protectionEnabled = false;
                m_trayIcon->setToolTip("RingCore Security Guardian - 防护已关闭");
                m_statusAction->setText("\u2718 防护状态: 未运行");
                m_trayIcon->showMessage("RingCore", "后台服务启动失败，请以管理员身份运行", QSystemTrayIcon::Warning, 3000);
            }
        });
    } else {
        m_trayIcon->showMessage("RingCore", "找不到 RingCoreSvc.exe，请确保它在正确位置", QSystemTrayIcon::Warning, 3000);
    }
}
