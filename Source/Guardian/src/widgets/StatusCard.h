#ifndef STATUSCARD_H
#define STATUSCARD_H

#include <QWidget>
#include <QLabel>

class StatusCard : public QWidget
{
    Q_OBJECT

public:
    explicit StatusCard(
        const QString &icon,
        const QString &title,
        const QString &value,
        const QString &accentColor,
        const QString &bgColor,
        QWidget *parent = nullptr);

    void setValue(const QString &value);
    void setIcon(const QString &icon);

private:
    QLabel *m_iconLabel;
    QLabel *m_titleLabel;
    QLabel *m_valueLabel;
};

#endif // STATUSCARD_H
