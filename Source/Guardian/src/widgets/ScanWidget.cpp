#include "ScanWidget.h"

#include <QVBoxLayout>

ScanWidget::ScanWidget(QWidget *parent)
    : QWidget(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);

    m_statusLabel = new QLabel("准备就绪", this);
    m_statusLabel->setStyleSheet("font-size: 14px; font-weight: bold; color: #1A1F36;");
    layout->addWidget(m_statusLabel);

    m_progressBar = new QProgressBar(this);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setFixedHeight(6);
    m_progressBar->setTextVisible(false);
    layout->addWidget(m_progressBar);
}

void ScanWidget::setProgress(int percent)
{
    m_progressBar->setValue(percent);
}

void ScanWidget::setStatus(const QString &status)
{
    m_statusLabel->setText(status);
}
