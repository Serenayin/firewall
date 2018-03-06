#include "logprocess.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    logProcess w;
    w.show();

    return a.exec();
}
