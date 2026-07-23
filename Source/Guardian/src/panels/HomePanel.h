#ifndef HOMEPANEL_H
#define HOMEPANEL_H

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include "../core/ServiceClient.h"

class HomePanel : public QWidget
{
    Q_OBJECT
public:
    explicit HomePanel(QWidget *parent = nullptr);

signals:
    void navigateTo(int index);
    void startQuickScan();
    void startFullScan();

private slots:
    void onQuickScan();
    void onFullScan();
    void onRefreshStatus();

private:
    void setupUI();
    QWidget* createHeroCard();
    QWidget* createStatCards();
    QWidget* createQuickActions();
    QWidget* createRecentActivity();

    ServiceClient *m_serviceClient;
    QTimer *m_statusTimer;

    // Hero card elements
    QLabel *m_heroShield;
    QLabel *m_heroStatus;
    QLabel *m_heroSub;
    QLabel *m_shieldGlow;

    // Stat card elements
    QLabel *m_statScanned;
    QLabel *m_statThreats;
    QLabel *m_statProtection;

    QLabel *m_serviceStatusVal;
};

#endif
