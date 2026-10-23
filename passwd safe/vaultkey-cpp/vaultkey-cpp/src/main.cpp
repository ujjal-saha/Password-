#include <QApplication>
#include <QMainWindow>
#include <QWebEngineView>
#include <QWebEngineSettings>
#include <QWebEngineProfile>
#include <QWebChannel>
#include <QUrl>
#include <QDir>
#include <QStandardPaths>
#include <QFile>

#include "backend.h"
#include "database.h"

namespace {

// Store vault.db in the OS-standard per-user app-data location instead of
// next to the executable. Keeps it out of paths that are commonly
// world-readable (e.g. Program Files) and out of the install directory,
// which some AV/EDR products flag when a "signed" app writes near itself.
QString resolveDbPath() {
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir + "/vault.db";
}

} // namespace

class MainWindow : public QMainWindow {
public:
    MainWindow() {
        setWindowTitle("VaultKey");
        resize(1100, 720);

        db_ = std::make_unique<Database>(resolveDbPath());
        backend_ = std::make_unique<Backend>(db_.get());

        view_ = new QWebEngineView(this);
        setCentralWidget(view_);

        // ---------------- security hardening on the embedded browser ----------------
        QWebEngineSettings *settings = view_->settings();
        // Local (file://) pages must not be able to fetch or navigate to
        // remote URLs - this app has no business talking to the network at
        // the WebEngine layer at all; everything goes through the Backend
        // bridge instead.
        settings->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, false);
        // No browser plugins, no Flash-era attack surface.
        settings->setAttribute(QWebEngineSettings::PluginsEnabled, false);
        // Prevent pages from spawning extra top-level windows/popups.
        settings->setAttribute(QWebEngineSettings::JavascriptCanOpenWindows, false);
        settings->setAttribute(QWebEngineSettings::JavascriptCanAccessClipboard, true); // needed for the copy button
        settings->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, true); // needed to navigate login.html <-> dashboard.html
        settings->setAttribute(QWebEngineSettings::AllowRunningInsecureContent, false);

        // Right-click "Inspect Element" would otherwise expose the whole
        // page (and indirectly, the loaded JS) to casual tampering.
        view_->setContextMenuPolicy(Qt::NoContextMenu);

        channel_ = new QWebChannel(view_->page());
        channel_->registerObject("backend", backend_.get());
        view_->page()->setWebChannel(channel_);

        QString loginPath = QDir(QApplication::applicationDirPath()).filePath("login.html");
        if (!QFile::exists(loginPath)) {
            qFatal("login.html not found next to the executable (%s)",
                   qUtf8Printable(loginPath));
        }
        view_->load(QUrl::fromLocalFile(loginPath));
    }

private:
    QWebEngineView *view_ = nullptr;
    QWebChannel *channel_ = nullptr;
    std::unique_ptr<Database> db_;
    std::unique_ptr<Backend> backend_;
};

int main(int argc, char *argv[]) {
    // Never open a remote-debugging port in a shipped build - that's a
    // trivially exploitable local attack surface (anything on the machine
    // can attach to it and read/execute JS in the app's context).
    qunsetenv("QTWEBENGINE_REMOTE_DEBUGGING");

    QApplication app(argc, argv);
    app.setApplicationName("VaultKey");
    app.setOrganizationName("VaultKey");

    MainWindow window;
    window.show();
    return app.exec();
}
