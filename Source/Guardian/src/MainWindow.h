#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include <QLabel>
#include <QPushButton>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QTimer>
#include <QPropertyAnimation>
#include <QPoint>
#include <QFrame>
#include <QPaintEvent>

class HomePanel;
class ScanPanel;
class ProcessPanel;
class FirewallPanel;
class JunkCleanPanel;
class SettingPanel;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent *event) override;
    void changeEvent(QEvent *event) override;
    void paintEvent(QPaintEvent *event) override;
    bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;

private slots:
    void onNavClicked(int index);
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void onTrayShow();
    void onTrayQuickScan();
    void onTrayExit();
    void onMinimizeToTray();
    void onProtectionStatusUpdate();
    void autoStartService();
    void onTitleBarMinimize();
    void onTitleBarMaximize();
    void onTitleBarClose();

private:
    void setupUI();
    void setupFramelessWindow();
    void setupTitleBar();
    void setupSidebar();
    void setupContent();
    void setupTrayIcon();
    void connectSignals();
    void updateTrayStatus();

    // Frameless window handling
    bool m_resizing;
    QPoint m_dragPosition;
    bool m_isDraggingTitleBar;
    Qt::Edges m_resizeEdge;

    // Title bar
    QWidget *m_titleBar;
    QLabel *m_appIcon;
    QLabel *m_appTitle;
    QPushButton *m_btnMinimize;
    QPushButton *m_btnMaximize;
    QPushButton *m_btnClose;

    // Sidebar
    QWidget *m_sidebar;
    QStackedWidget *m_contentStack;
    QList<QPushButton*> m_navButtons;
    int m_currentNavIndex;

    // Content panels
    HomePanel *m_homePanel;
    ScanPanel *m_scanPanel;
    ProcessPanel *m_processPanel;
    FirewallPanel *m_firewallPanel;
    JunkCleanPanel *m_junkCleanPanel;
    SettingPanel *m_settingPanel;

    // System tray
    QSystemTrayIcon *m_trayIcon;
    QMenu *m_trayMenu;
    QAction *m_statusAction;
    QTimer *m_statusTimer;
    bool m_protectionEnabled;
    QPropertyAnimation *m_fadeIn;
};

#endif // MAINWINDOW_H
