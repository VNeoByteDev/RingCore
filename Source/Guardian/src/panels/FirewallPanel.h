#ifndef FIREWALLPANEL_H
#define FIREWALLPANEL_H

#include <QWidget>
#include <QTreeWidget>
#include <QPushButton>
#include <QLabel>

class FirewallPanel : public QWidget
{
    Q_OBJECT

public:
    explicit FirewallPanel(QWidget *parent = nullptr);

private slots:
    void onAddRule();
    void onRemoveRule();

private:
    void setupUI();
    void loadRules();

    QTreeWidget *m_ruleTree;
    QLabel *m_ruleCountLabel;
};

#endif // FIREWALLPANEL_H
