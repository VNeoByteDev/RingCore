#ifndef PROCESSPANEL_H
#define PROCESSPANEL_H

#include <QWidget>
#include <QTreeWidget>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>

class ProcessPanel : public QWidget
{
    Q_OBJECT

public:
    explicit ProcessPanel(QWidget *parent = nullptr);

private slots:
    void onRefresh();
    void onEndProcess();
    void onSearchChanged(const QString &text);

private:
    void setupUI();
    void loadProcesses();

    QTreeWidget *m_processTree;
    QLineEdit *m_searchBox;
    QLabel *m_countLabel;
    QVector<QTreeWidgetItem*> m_allItems;
};

#endif // PROCESSPANEL_H
