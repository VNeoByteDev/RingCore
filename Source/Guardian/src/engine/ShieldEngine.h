#ifndef SHIELDENGINE_H
#define SHIELDENGINE_H

#include <QObject>
#include <QString>
#include <QVector>
#include <QHash>
#include <QThread>
#include <QMutex>
#include <atomic>

// ============================================
// Shield Engine - 自研杀毒引擎
// Layer 1: Signature (SHA256 hash matching)
// Layer 2: Heuristic (code analysis)
// Layer 3: Pattern (byte pattern matching)
// Layer 4: Entropy (entropy analysis)
// ============================================

enum class ThreatLevel { Safe = 0, Low = 1, Medium = 2, High = 3, Critical = 4, Catastrophic = 5 };
enum class DetectionSource { None, Signature, Heuristic, Pattern, Entropy, Cloud };

struct ScanResult {
    QString filePath;
    quint64 fileSize;
    QString sha256;
    ThreatLevel threatLevel;
    DetectionSource source;
    QString threatName;
    QString threatType;
    int riskScore;
    QStringList indicators;
};

// ============================================
// Signature Database
// ============================================
class SignatureDB
{
public:
    bool loadBuiltins();
    bool contains(const QString &hash) const;
    QString threatName(const QString &hash) const;
    int threatSeverity(const QString &hash) const;
    int count() const;

private:
    QHash<QString, QPair<QString, int>> m_hashes; // hash -> (name, severity)
};

// ============================================
// Heuristic Analyzer
// ============================================
class HeuristicAnalyzer
{
public:
    struct AnalysisResult {
        int riskScore;
        QStringList findings;
        bool isPacked;
        bool hasSuspiciousAPIs;
        bool hasAntiAnalysis;
        bool hasShellcode;
        bool isKnownPacker;
        double entropy;
    };

    AnalysisResult analyze(const QByteArray &data, const QString &fileName);
    bool isPEFile(const QByteArray &data);
    double calculateEntropy(const QByteArray &data);

private:
    bool checkSuspiciousAPIs(const QByteArray &lower);
    bool checkPackerSignatures(const QByteArray &lower);
    bool checkAntiVM(const QByteArray &lower);
    bool checkShellcodePatterns(const QByteArray &lower);
    bool checkRansomwareBehavior(const QByteArray &lower);
    bool checkCredentialTheft(const QByteArray &lower);
    bool checkPersistenceMechanisms(const QByteArray &lower);
    bool checkLotLAbuse(const QByteArray &lower);
    bool checkC2Beacon(const QByteArray &lower);
    bool checkDataExfiltration(const QByteArray &lower);
    bool checkPEAnomalies(const QByteArray &data);
    bool checkScriptObfuscation(const QByteArray &lower);
    bool checkImportTableAnalysis(const QByteArray &lower);
    bool checkStringAnalysis(const QByteArray &lower);
    bool checkSectionAnalysis(const QByteArray &data);
    bool checkFileSystemBehavior(const QByteArray &lower);
    bool checkRegistryBehavior(const QByteArray &lower);
    bool checkProcessBehavior(const QByteArray &lower);
    bool checkJarApkAnalysis(const QByteArray &lower, const QString &fileName);
    bool checkEncryptionObfuscation(const QByteArray &lower);
};

// ============================================
// Pattern Matcher (Yara-like)
// ============================================
struct PatternRule {
    QString name;
    QString category;
    int severity;
    QByteArray hexPattern;  // hex-encoded byte pattern
    QByteArray mask;        // mask for wildcards
};

class PatternMatcher
{
public:
    bool loadBuiltins();
    QVector<QString> match(const QByteArray &data) const;
    int ruleCount() const;

private:
    QVector<PatternRule> m_rules;
};

// ============================================
// Shield Engine (Main)
// ============================================
class ShieldScanWorker : public QThread
{
    Q_OBJECT
public:
    ShieldScanWorker(const QStringList &paths, QObject *parent = nullptr);
    void stop();

signals:
    void fileScanned(const ScanResult &result);
    void progressUpdated(int filesScanned, const QString &currentFile);
    void scanFinished(int totalFiles, int threatCount);

protected:
    void run() override;

private:
    void scanDirectory(const QString &dir);
    ScanResult scanFile(const QString &filePath);

    QStringList m_scanPaths;
    SignatureDB m_sigDB;
    HeuristicAnalyzer m_heuristic;
    PatternMatcher m_patternMatcher;
    std::atomic<bool> m_stopFlag;
    int m_filesScanned;
    int m_threatCount;
};

class ShieldEngine : public QObject
{
    Q_OBJECT
public:
    explicit ShieldEngine(QObject *parent = nullptr);

    void startScan(const QStringList &paths);
    void stopScan();
    bool isScanning() const;

    SignatureDB* signatureDB();
    int signatureCount() const;

signals:
    void fileScanned(const ScanResult &result);
    void progressUpdated(int filesScanned, const QString &currentFile);
    void scanFinished(int totalFiles, int threatCount);

private:
    ShieldScanWorker *m_worker;
    SignatureDB m_sigDB;
};

#endif // SHIELDENGINE_H
