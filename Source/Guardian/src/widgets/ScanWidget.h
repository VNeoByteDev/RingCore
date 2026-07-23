#ifndef SCANWIDGET_H
#define SCANWIDGET_H

#include <QWidget>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>

class ScanWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ScanWidget(QWidget *parent = nullptr);

    void setProgress(int percent);
    void setStatus(const QString &status);

private:
    QLabel *m_statusLabel;
    QProgressBar *m_progressBar;
};

#endif // SCANWIDGET_H
