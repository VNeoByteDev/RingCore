#include <QApplication>
#include <QFont>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDirIterator>
#include <QMessageBox>
#include <QCryptographicHash>
#include <QIcon>
#include <QProcess>
#include <QTemporaryDir>
#include <windows.h>
#include <shellapi.h>
#include "MainWindow.h"
#include "core/ThreatDB.h"
#include "core/Settings.h"
#include "engine/ShieldEngine.h"

// Check if file is an archive
static bool isArchive(const QString &path)
{
    QString ext = QFileInfo(path).suffix().toLower();
    return (ext == "zip" || ext == "rar" || ext == "7z" || ext == "gz" || ext == "tar" || ext == "tgz");
}

// Extract archive to temp directory, returns list of extracted file paths
static QStringList extractArchive(const QString &archivePath, const QString &destDir)
{
    QStringList extractedFiles;
    QString ext = QFileInfo(archivePath).suffix().toLower();

    if (ext == "zip") {
        // Use PowerShell's Expand-Archive for ZIP extraction
        QProcess proc;
        QString srcPath = archivePath;
        QString dstPath = destDir;
        QString psCmd = QString(
            "Expand-Archive -Path '%1' -DestinationPath '%2' -Force"
        ).arg(srcPath.replace('/', '\\'), dstPath.replace('/', '\\'));
        proc.start("powershell.exe", {"-NoProfile", "-Command", psCmd});
        proc.waitForFinished(30000); // 30s timeout
    } else if (ext == "7z" || ext == "rar" || ext == "gz" || ext == "tar" || ext == "tgz") {
        // Try 7-Zip if available
        QString sevenZipPaths[] = {
            "C:\\Program Files\\7-Zip\\7z.exe",
            "C:\\Program Files (x86)\\7-Zip\\7z.exe"
        };
        bool found = false;
        for (const QString &p : sevenZipPaths) {
            if (QFile::exists(p)) {
                QProcess proc;
                QString srcPath = archivePath;
                QString dstPath = destDir;
                QStringList args;
                args << "x" << srcPath.replace('/', '\\')
                     << QString("-o%1").arg(dstPath.replace('/', '\\'))
                     << "-y";
                proc.start(p, args);
                proc.waitForFinished(60000);
                found = true;
                break;
            }
        }
        if (!found) {
            return extractedFiles; // Can't extract
        }
    }

    // Collect all extracted files
    QDirIterator it(destDir, QDir::Files | QDir::NoSymLinks, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        extractedFiles.append(it.next());
    }
    return extractedFiles;
}

// Scan a single file and show result dialog
// Uses ShieldEngine for full detection capabilities
// Supports files, folders, and archives (ZIP/RAR/7z)
int scanSingleFile(const QString &filePath)
{
    QFileInfo fi(filePath);
    if (!fi.exists()) {
        QMessageBox::critical(NULL, "RingCore", "Path not found: " + filePath);
        return 1;
    }

    // Check if directory exists before scanning
    if (fi.isDir() && !fi.isReadable()) {
        QMessageBox::warning(NULL, "RingCore", "Cannot access directory: " + filePath);
        return 1;
    }

    // If it's a directory, scan all files recursively
    if (fi.isDir()) {
        QStringList threats;
        int scanned = 0;

        HeuristicAnalyzer analyzer;
        ThreatDB db;

        QDirIterator it(filePath, QDir::Files | QDir::NoSymLinks, QDirIterator::Subdirectories);
        while (it.hasNext()) {
            QString fPath = it.next();
            scanned++;

            QFile file(fPath);
            if (!file.open(QIODevice::ReadOnly)) continue;
            QByteArray data = file.read(4 * 1024 * 1024);
            file.close();

            // Hash
            QCryptographicHash hashAlgo(QCryptographicHash::Sha256);
            QFile hashFile(fPath);
            if (hashFile.open(QIODevice::ReadOnly)) {
                while (!hashFile.atEnd()) hashAlgo.addData(hashFile.read(4 * 1024 * 1024));
                hashFile.close();
            }
            QString hashStr = hashAlgo.result().toHex();

            if (db.containsHash(hashStr)) {
                ThreatInfo ti = db.threatInfo(hashStr);
                threats.append(QString("[SIGNATURE] %1 - %2").arg(QFileInfo(fPath).fileName(), ti.name));
                continue;
            }

            // Heuristic
            HeuristicAnalyzer::AnalysisResult analysis = analyzer.analyze(data, QFileInfo(fPath).fileName());
            if (analysis.riskScore >= 85) {
                threats.append(QString("[HEURISTIC %1] %2").arg(analysis.riskScore).arg(QFileInfo(fPath).fileName()));
            }
        }

        // Show directory scan result
        QString title = threats.isEmpty() ? "Directory Safe" : "Threats Found in Directory";
        QString message = QString("Directory: %1\nFiles scanned: %2\nThreats found: %3\n")
            .arg(filePath).arg(scanned).arg(threats.size());
        if (!threats.isEmpty()) {
            message += "\n\nThreats:\n" + threats.join("\n");
        }
        QMessageBox::Icon icon = threats.isEmpty() ? QMessageBox::Information : QMessageBox::Warning;
        QMessageBox msg(icon, title, message, QMessageBox::Ok);

        bool silent = g_settings && g_settings->silentScan();
        if (silent) {
            static QSystemTrayIcon s_tray;
            if (s_tray.icon().isNull()) s_tray.setIcon(QIcon(":/images/shield.svg"));
            s_tray.showMessage("RingCore Directory Scan", message.left(200),
                threats.isEmpty() ? QSystemTrayIcon::Information : QSystemTrayIcon::Warning, 5000);
        } else {
            msg.exec();
        }
        return threats.isEmpty() ? 0 : 1;
    }

    // Single file scan
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        // Silently skip files that can't be opened (locked by other processes, permissions, etc.)
        return 0;
    }

    // Check if it's an archive - extract and scan contents
    if (isArchive(filePath)) {
        QTemporaryDir tempDir;
        if (!tempDir.isValid()) {
            QMessageBox::critical(NULL, "RingCore", "Cannot create temp directory");
            return 1;
        }

        QStringList extracted = extractArchive(filePath, tempDir.path());
        if (extracted.isEmpty()) {
            QMessageBox::warning(NULL, "RingCore",
                "Cannot extract archive: " + QFileInfo(filePath).fileName() +
                "\n\nSupported formats: ZIP (native)\nRAR/7z require 7-Zip to be installed.");
            return 1;
        }

        // Scan all extracted files
        QStringList threats;
        int scanned = 0;
        ThreatDB db;
        HeuristicAnalyzer analyzer;

        for (const QString &fPath : extracted) {
            scanned++;
            QFile f(fPath);
            if (!f.open(QIODevice::ReadOnly)) continue;
            QByteArray data = f.read(4 * 1024 * 1024);
            f.close();

            QCryptographicHash hashAlgo(QCryptographicHash::Sha256);
            QFile hashFile(fPath);
            if (hashFile.open(QIODevice::ReadOnly)) {
                while (!hashFile.atEnd()) hashAlgo.addData(hashFile.read(4 * 1024 * 1024));
                hashFile.close();
            }
            QString hashStr = hashAlgo.result().toHex();

            if (db.containsHash(hashStr)) {
                ThreatInfo ti = db.threatInfo(hashStr);
                threats.append(QString("[SIGNATURE] %1 - %2").arg(QFileInfo(fPath).fileName(), ti.name));
                continue;
            }

            HeuristicAnalyzer::AnalysisResult analysis = analyzer.analyze(data, QFileInfo(fPath).fileName());
            if (analysis.riskScore >= 85) {
                threats.append(QString("[HEURISTIC %1] %2").arg(analysis.riskScore).arg(QFileInfo(fPath).fileName()));
            }
        }

        // Show archive scan result
        QString title = threats.isEmpty() ? "Archive Safe" : "Threats Found in Archive";
        QString message = QString("Archive: %1\nFiles extracted: %2\nThreats found: %3\n")
            .arg(QFileInfo(filePath).fileName()).arg(scanned).arg(threats.size());
        if (!threats.isEmpty()) {
            message += "\n\nThreats:\n" + threats.join("\n");
        }
        QMessageBox::Icon icon = threats.isEmpty() ? QMessageBox::Information : QMessageBox::Warning;
        QMessageBox msg(icon, title, message, QMessageBox::Ok);

        bool silent = g_settings && g_settings->silentScan();
        if (silent) {
            static QSystemTrayIcon s_tray;
            if (s_tray.icon().isNull()) s_tray.setIcon(QIcon(":/images/shield.svg"));
            s_tray.showMessage("RingCore Archive Scan", message.left(200),
                threats.isEmpty() ? QSystemTrayIcon::Information : QSystemTrayIcon::Warning, 5000);
        } else {
            msg.exec();
        }
        return threats.isEmpty() ? 0 : 1;
    }

    // Read file data (up to 4MB for analysis)
    QByteArray data = file.read(4 * 1024 * 1024);
    file.close();

    // Layer 1: SHA256 signature matching
    QCryptographicHash hashAlgo(QCryptographicHash::Sha256);
    QFile hashFile(filePath);
    if (hashFile.open(QIODevice::ReadOnly)) {
        while (!hashFile.atEnd())
            hashAlgo.addData(hashFile.read(4 * 1024 * 1024));
        hashFile.close();
    }
    QString hashStr = hashAlgo.result().toHex();

    ThreatDB db;
    bool isThreat = db.containsHash(hashStr);
    ThreatInfo threatInfo;
    if (isThreat) threatInfo = db.threatInfo(hashStr);

    // Layer 2: ShieldEngine Heuristic Analysis (full 23-category engine)
    HeuristicAnalyzer analyzer;
    HeuristicAnalyzer::AnalysisResult analysis = analyzer.analyze(data, QFileInfo(filePath).fileName());

    // Build result
    QString title, message;
    QMessageBox::Icon icon;

    if (isThreat) {
        title = "Threat Detected!";
        message = QString("File: %1\nSHA256: %2...\n\nThreat: %3\nType: %4\nSeverity: L%5\n\nRecommended: Quarantine immediately.").arg(
            QFileInfo(filePath).fileName(), hashStr.left(32),
            threatInfo.name, threatInfo.type).arg(threatInfo.severity);
        icon = QMessageBox::Critical;
    } else if (analysis.riskScore >= 85) {
        title = "Suspicious File";
        message = QString("File: %1\nSHA256: %2...\n\nHeuristic findings:\n%3\n\nRisk Score: %4/100").arg(
            QFileInfo(filePath).fileName(), hashStr.left(32),
            analysis.findings.join("\n")).arg(analysis.riskScore);
        icon = QMessageBox::Warning;
    } else {
        title = "File Safe";
        message = QString("File: %1\nSHA256: %2...\n\nSignature DB: Safe\nHeuristic: Safe (score: %3)").arg(
            QFileInfo(filePath).fileName(), hashStr.left(32)).arg(analysis.riskScore);
        icon = QMessageBox::Information;
    }

    QMessageBox msgBox(icon, title, message, QMessageBox::Ok);
    
    bool silent = g_settings && g_settings->silentScan();
    
    if (silent) {
        static QSystemTrayIcon trayIcon;
        if (trayIcon.icon().isNull()) trayIcon.setIcon(QIcon(":/images/shield.svg"));
        if (isThreat) {
            trayIcon.showMessage("RingCore Threat", message, QSystemTrayIcon::Critical, 5000);
        } else if (analysis.riskScore >= 85) {
            trayIcon.showMessage("RingCore Suspicious", message, QSystemTrayIcon::Warning, 3000);
        } else {
            trayIcon.showMessage("RingCore Safe", message, QSystemTrayIcon::Information, 2000);
        }
    } else {
        msgBox.exec();
    }
    
    return isThreat ? 1 : 0;
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("RingCore Security Guardian");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("RingCore Security");

    // Single instance check via named mutex
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"RingCoreSecurityGuardian_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Another instance is running — bring it to front
        HWND hwnd = FindWindowW(NULL, L"RingCore Security Guardian");
        if (hwnd) {
            SetForegroundWindow(hwnd);
            ShowWindow(hwnd, SW_RESTORE);
        }
        return 0;
    }

    QFont defaultFont("Microsoft YaHei UI", 9);
    app.setFont(defaultFont);

    // Set application icon
    app.setWindowIcon(QIcon(":/images/shield.svg"));

    // Initialize global settings
    g_settings = new Settings(&app);

    // Command-line scan mode: RingCoreGuardian.exe --scan "filepath"
    // Use Windows Unicode API to handle Chinese paths correctly
    int wArgc;
    LPWSTR *wArgv = CommandLineToArgvW(GetCommandLineW(), &wArgc);
    if (wArgv && wArgc >= 3 && QString::fromWCharArray(wArgv[1]) == "--scan") {
        QString filePath = QString::fromWCharArray(wArgv[2]);
        LocalFree(wArgv);
        return scanSingleFile(filePath);
    }
    if (wArgv) LocalFree(wArgv);

    QFile styleFile(":/styles/main.qss");
    if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
        app.setStyleSheet(styleFile.readAll());
        styleFile.close();
    }

    MainWindow window;
    window.show();

    return app.exec();
}
