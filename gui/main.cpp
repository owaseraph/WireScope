#include "main_window.hpp"

#include <QApplication>
#include <QFont>

int main(int argc, char* argv[]) {
    QApplication application(argc, argv);
    application.setApplicationName(QStringLiteral("WireScope"));
    application.setOrganizationName(QStringLiteral("WireScope"));
    application.setApplicationVersion(QStringLiteral("1.1.0"));
    application.setFont(QFont(QStringLiteral("Noto Sans"), 10));

    MainWindow window;
    window.show();
    return application.exec();
}
