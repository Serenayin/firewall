#ifndef LOGPROCESS_H
#define LOGPROCESS_H

#include <QWidget>

namespace Ui {
class logProcess;
}

class logProcess : public QWidget
{
    Q_OBJECT

public:
    explicit logProcess(QWidget *parent = 0);
    ~logProcess();

private slots:
    void on_findButton_clicked();

    void on_openButton_clicked();

    void on_checkButton_clicked();

private:
    Ui::logProcess *ui;
    void loadTextFile();
};

#endif // LOGPROCESS_H
