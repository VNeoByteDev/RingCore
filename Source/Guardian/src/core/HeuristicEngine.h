#ifndef HEURISTICENGINE_H
#define HEURISTICENGINE_H

#include <QString>
#include <QList>

struct HeuristicResult {
    int riskScore;          // 0-100
    QString riskLevel;      // "safe", "low", "medium", "high", "critical"
    QStringList findings;   // list of suspicious indicators
    bool isPacked;
    bool hasSuspiciousAPIs;
    bool isKnownPacker;
    double entropy;
};

class HeuristicEngine
{
public:
    HeuristicEngine();

    HeuristicResult analyze(const QString &filePath);
    HeuristicResult analyzeBuffer(const QByteArray &data, const QString &fileName);

private:
    bool isPEFile(const QByteArray &data);
    bool checkSuspiciousAPIs(const QByteArray &lowerData);
    bool checkPackerSignatures(const QByteArray &lowerData);
    double calculateEntropy(const QByteArray &data);
    bool checkAntiVM(const QByteArray &lowerData);
    bool checkShellcodePatterns(const QByteArray &data);

    // --- New detection categories ---
    bool checkRansomwareBehavior(const QByteArray &lowerData);
    bool checkCredentialTheft(const QByteArray &lowerData);
    bool checkPersistenceMechanisms(const QByteArray &lowerData);
    bool checkLotLAbuse(const QByteArray &lowerData);
    bool checkC2Beacon(const QByteArray &lowerData);
    bool checkDataExfiltration(const QByteArray &lowerData);
    bool checkPEAnomalies(const QByteArray &data);
    bool checkScriptObfuscation(const QByteArray &lowerData);

    // --- Advanced detection categories ---
    bool checkImportTableAnalysis(const QByteArray &lowerData);
    bool checkStringAnalysis(const QByteArray &lowerData);
    bool checkSectionAnalysis(const QByteArray &data);
    bool checkFileSystemBehavior(const QByteArray &lowerData);
    bool checkRegistryBehavior(const QByteArray &lowerData);
    bool checkProcessBehavior(const QByteArray &lowerData);
};

#endif // HEURISTICENGINE_H
