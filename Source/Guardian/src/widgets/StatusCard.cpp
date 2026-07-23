#include "StatusCard.h"

#include <QVBoxLayout>
#include <QHBoxLayout>

StatusCard::StatusCard(
    const QString &icon,
    const QString &title,
    const QString &value,
    const QString &accentColor,
    const QString &bgColor,
    QWidget *parent)
    : QWidget(parent)
{
    setFixedHeight(110);
    setMinimumWidth(200);

    QString styleSheet = QString(
        "StatusCard {"
        "  background-color: %1;"
        "  border-radius: 12px;"
        "  border-left: 4px solid %2;"
        "}"
    ).arg(bgColor, accentColor);
    setStyleSheet(styleSheet);

    QHBoxLayout *mainLayout = new QHBoxLayout(this);
    mainLayout->setContentsMargins(20, 16, 20, 16);
    mainLayout->setSpacing(16);

    // 图标
    m_iconLabel = new QLabel(icon, this);
    m_iconLabel->setFixedSize(44, 44);
    m_iconLabel->setAlignment(Qt::AlignCenter);
    m_iconLabel->setStyleSheet(QString(
        "font-size: 22px;"
        "background-color: %1;"
        "color: white;"
        "border-radius: 22px;"
    ).arg(accentColor));
    mainLayout->addWidget(m_iconLabel);

    // 文字
    QVBoxLayout *textLayout = new QVBoxLayout();
    textLayout->setSpacing(4);

    m_titleLabel = new QLabel(title, this);
    m_titleLabel->setStyleSheet("font-size: 12px; color: #78909C; background: transparent;");

    m_valueLabel = new QLabel(value, this);
    m_valueLabel->setStyleSheet("font-size: 15px; font-weight: bold; color: #1A1F36; background: transparent;");

    textLayout->addWidget(m_titleLabel);
    textLayout->addWidget(m_valueLabel);
    textLayout->addStretch();

    mainLayout->addLayout(textLayout, 1);
}

void StatusCard::setValue(const QString &value)
{
    m_valueLabel->setText(value);
}

void StatusCard::setIcon(const QString &icon)
{
    m_iconLabel->setText(icon);
}
