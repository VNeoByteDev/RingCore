#ifndef SETTINGPANEL_H
#define SETTINGPANEL_H

#include <QWidget>
#include <QVector>
#include <QPair>
#include <QCheckBox>
#include <QLabel>

class SettingPanel : public QWidget
{
    Q_OBJECT
public:
    explicit SettingPanel(QWidget *parent = nullptr);
    void updateDBInfo(int signatureCount);

private slots:
    void onImportDB();
    void onExportDB();
    void onUpdateFromCloud();

private:
    void setupUI();
    QWidget* createSettingCard(const QString &icon, const QString &title,
        const QVector<QPair<QString, QString>> &items, const QVector<bool> &defaults);
    QWidget* createSettingRow(const QString &label, const QString &desc,
        bool defaultValue, std::function<void(bool)> setter);
    QWidget* createDbSection();
    QWidget* createAboutSection();

    QLabel *m_dbInfoLabel;
    QLabel *m_ruleCountLabel;
    QLabel *m_lastUpdateLabel;
};

#endif
