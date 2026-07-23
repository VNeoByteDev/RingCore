#include "HeuristicEngine.h"
#include <QFile>
#include <QFileInfo>
#include <cmath>
#include <QRegularExpression>

HeuristicEngine::HeuristicEngine() {}

HeuristicResult HeuristicEngine::analyze(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return {0, "safe", {"Cannot read file"}, false, false, false, 0.0};
    }
    QByteArray data;
    const qint64 maxSize = 50 * 1024 * 1024;
    while (!file.atEnd() && data.size() < maxSize) {
        data.append(file.read(4 * 1024 * 1024));
    }
    file.close();
    return analyzeBuffer(data, QFileInfo(filePath).fileName());
}

HeuristicResult HeuristicEngine::analyzeBuffer(const QByteArray &data, const QString &fileName)
{
    HeuristicResult result = {};
    result.riskScore = 0;

    if (data.size() > 50 * 1024 * 1024) {
        result.riskScore = 0;
        result.riskLevel = "safe";
        return result;
    }

    int suspiciousCategories = 0;
    QByteArray lowerData = data.toLower();
    QString lower = fileName.toLower();
    bool peFile = isPEFile(data);

    // Whitelist: known legitimate software
    static const QStringList legitPatterns = {
        "flash_tool", "sp_flash", "mtk_droid", "spd_upgrade",
        "odin", "heimdall", "fastboot", "adb", "scrcpy",
        "qemu", "virtualbox", "vmware", "docker",
        "python", "node", "java", "gcc", "g++", "cmake", "ninja",
        "notepad", "calc", "mspaint", "wordpad", "snipping",
        "chrome", "firefox", "edge", "opera", "brave", "vivaldi",
        "steam", "discord", "spotify", "slack", "zoom", "teams",
        "vscode", "intellij", "sublime", "atom",
        "7zip", "winrar", "winzip", "peazip",
        "putty", "winscp", "filezilla", "moba",
        "xampp", "wamp", "ampps", "laragon",
        "autohotkey", "autoit", "nircmd",
        "mediainfo", "handbrake", "vlc", "mpv",
        "obs", "audacity", "gimp", "blender",
        "git", "svn", "mercurial",
        "sqlite", "mysql", "postgres", "redis",
        "php", "perl", "ruby", "go", "rust",
        // NVIDIA / AMD / Intel drivers
        "nvidia", "geforce", "nvngx", "nvlddmkm", "nvcpl", "nvidia-smi",
        "amd", "ryzen", "drv_chipset", "amdgpu", "radeon", "adrenalin",
        "intel", "inf_", "iastor", "netwtw", "igdkmd",
        "display.driver.uninstaller", "ddu",
        // Baidu
        "baidu", "baidunetdisk", "baidupcs",
        // nvm
        "nvm", "nvm-setup",
        // Chinese apps
        "wechat", "weixin", "qq", "tencent", "netease", "cloudmusic",
        "kuwo", "kugou", "ximalaya", "douyin", "bilibili",
        // From false positive report
        "audiorelay", "devsidecar", "idman", "psexec", "pstools",
        "rainmeter", "lm-studio", "lm_studio", "lmstudio",
        "uu", "uuyc", "vutronmusic", "wepe", "deltaforce",
        "runtime", "windowsdesktop-runtime",
        // Common legit installers/tools
        "setup", "install", "uninstall", "update",
        "microsoft", "onedrive", "windows.defender",
        "ccleaner", "hwinfo", "cpuz", "gpuz", "crystaldisk",
        "rufus", "etcher", "ventoy", "balena",
        "notepad++", "sublimetext", "obsidian",
        // Signed Microsoft / known publishers
        "microsoft.visual", "vc_redist", "dotnet", "aspnet",
        "directx", "vcredist", "msvcr", "msvcp",
    };
    bool isLegitTool = false;
    for (const QString &pat : legitPatterns) {
        if (lower.contains(pat)) { isLegitTool = true; break; }
    }

    // Script extension flags
    bool isScript = lower.endsWith(".ps1") || lower.endsWith(".vbs") || lower.endsWith(".js");

    // 1. Entropy analysis
    result.entropy = calculateEntropy(data);
    if (result.entropy > 7.8) {
        result.findings << "High entropy (" + QString::number(result.entropy, 'f', 2) + ") - likely packed/encrypted";
        result.isPacked = true;
        suspiciousCategories++;
        result.riskScore += 15;
    }

    // 2. PE file analysis
    if (peFile) {
        if (checkSuspiciousAPIs(lowerData)) {
            result.hasSuspiciousAPIs = true;
            result.findings << "Suspicious API imports detected (process injection, keylogging, etc.)";
            suspiciousCategories++;
            result.riskScore += 20;
        }
        if (checkPackerSignatures(lowerData)) {
            result.isKnownPacker = true;
            result.findings << "Known packer/crypter signature detected";
            suspiciousCategories++;
            result.riskScore += 15;
        }
        if (checkAntiVM(lowerData)) {
            result.findings << "Anti-VM/anti-debug techniques detected";
            suspiciousCategories++;
            result.riskScore += 15;
        }
        if (checkShellcodePatterns(data)) {
            result.findings << "Potential shellcode patterns detected";
            suspiciousCategories++;
            result.riskScore += 20;
        }

        // PE header anomalies
        if (checkPEAnomalies(data)) {
            result.findings << "PE header anomalies detected (unusual entry point or excessive imports)";
            suspiciousCategories++;
            result.riskScore += 15;
        }

        // Ransomware behavior (PE-specific: APIs + strings in data)
        if (checkRansomwareBehavior(lowerData)) {
            result.findings << "Ransomware behavior indicators detected (crypto APIs, ransom strings)";
            suspiciousCategories++;
            result.riskScore += 30;
        }

        // Credential theft (PE APIs + string targets)
        if (checkCredentialTheft(lowerData)) {
            result.findings << "Credential theft indicators detected (DPAPI/credential APIs, target strings)";
            suspiciousCategories++;
            result.riskScore += 25;
        }

        // Persistence mechanisms
        if (checkPersistenceMechanisms(lowerData)) {
            result.findings << "Persistence mechanism indicators detected (registry/task/service APIs)";
            suspiciousCategories++;
            result.riskScore += 20;
        }
    }

    // 3. Suspicious file characteristics

    // Double extension
    if (fileName.count('.') >= 2) {
        QStringList parts = fileName.split('.');
        if (parts.size() >= 2) {
            QString lastExt = parts.last().toLower();
            QString secondExt = parts[parts.size()-2].toLower();
            QStringList docExts = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "jpg", "png", "txt"};
            if (docExts.contains(secondExt) && (lastExt == "exe" || lastExt == "scr" || lastExt == "bat")) {
                result.findings << "Double extension detected: " + secondExt + "." + lastExt;
                suspiciousCategories++;
                result.riskScore += 30;
            }
        }
    }

    // System process impersonation
    QStringList suspiciousNames = {"svchost", "csrss", "smss", "winlogon", "lsass"};
    QString baseName = QFileInfo(fileName).baseName().toLower();
    if (suspiciousNames.contains(baseName) && !lower.endsWith(".exe")) {
        result.findings << "Impersonating system process name: " + baseName;
        suspiciousCategories++;
        result.riskScore += 25;
    }

    // Very small PE files (likely droppers)
    if (peFile && data.size() < 512) {
        result.findings << "Very small PE file (" + QString::number(data.size()) + " bytes) - possible dropper";
        suspiciousCategories++;
        result.riskScore += 15;
    }

    // 4. Script analysis (batch/powershell)
    if (lower.endsWith(".bat") || lower.endsWith(".cmd")) {
        bool hasSuspicious = lowerData.contains("powershell") && lowerData.contains("hidden");
        bool hasDownload = lowerData.contains("certutil") || lowerData.contains("bitsadmin") || lowerData.contains("invoke-webrequest");
        if (hasSuspicious && hasDownload) {
            result.findings << "Batch file: hidden PowerShell + download technique";
            suspiciousCategories++;
            result.riskScore += 20;
        }
    }

    if (lower.endsWith(".ps1")) {
        bool hasDownload = lowerData.contains("downloadstring") || lowerData.contains("invoke-webrequest");
        bool hasEvasion = lowerData.contains("hidden") || lowerData.contains("bypass") || lowerData.contains("-enc");
        if (hasDownload && hasEvasion) {
            result.findings << "PowerShell: download + evasion technique";
            suspiciousCategories++;
            result.riskScore += 25;
        }
    }

    // === New detection categories (file-type agnostic where noted) ===

    // Living-off-the-Land abuse (any file type)
    if (checkLotLAbuse(lowerData)) {
        result.findings << "Living-off-the-Land (LotL) abuse patterns detected";
        suspiciousCategories++;
        result.riskScore += 20;
    }

    // C2 beacon patterns
    if (checkC2Beacon(lowerData)) {
        result.findings << "Network C2 beacon indicators detected";
        suspiciousCategories++;
        result.riskScore += 20;
    }

    // Data exfiltration
    if (checkDataExfiltration(lowerData)) {
        result.findings << "Data exfiltration indicators detected";
        suspiciousCategories++;
        result.riskScore += 15;
    }

    // Script obfuscation (only for script files)
    if (isScript && checkScriptObfuscation(lowerData)) {
        result.findings << "Script obfuscation techniques detected (base64 blocks, chr codes, eval)";
        suspiciousCategories++;
        result.riskScore += 25;
    }

    // Batch/CMD file destructive command check
    bool isBatch = lower.endsWith(".bat") || lower.endsWith(".cmd");
    if (isBatch) {
        int batchIndicators = 0;
        if (lowerData.contains("rd /s") || lowerData.contains("rmdir /s")) batchIndicators++;
        if (lowerData.contains("format ") || lowerData.contains("format /")) batchIndicators++;
        if (lowerData.contains("del /f") || lowerData.contains("del /s") || lowerData.contains("erase /f")) batchIndicators++;
        if (lowerData.contains("rd /s /q c:") || lowerData.contains("rd /s /q d:") ||
            lowerData.contains("rd /s /q e:") || lowerData.contains("rd /s /q c:\\") ||
            lowerData.contains("rd /s /q d:\\") || lowerData.contains("rd /s /q e:\\")) batchIndicators += 2;
        if (lowerData.contains("reg delete")) batchIndicators++;
        if (lowerData.contains("reg delete hkcr") || lowerData.contains("reg delete hklm") ||
            lowerData.contains("reg delete hkcu")) batchIndicators += 2;
        if (lowerData.contains("taskkill /f") || lowerData.contains("taskkill /im")) batchIndicators++;
        if (lowerData.contains("taskkill /f /im explorer")) batchIndicators += 2;
        if (lowerData.contains("shutdown /s") || lowerData.contains("shutdown /f") ||
            lowerData.contains("shutdown /r") || lowerData.contains("shutdown /p")) batchIndicators++;
        if (lowerData.contains("bcdedit /set") || lowerData.contains("bcdedit /deletevalue")) batchIndicators++;
        if (lowerData.contains("attrib -r -s -h")) batchIndicators++;
        if (batchIndicators >= 1) {
            result.findings << "Destructive batch commands detected (disk wipe/registry kill/shutdown)";
            suspiciousCategories++;
            result.riskScore += qMin(100, batchIndicators * 15);
        }
    }

    // === Advanced Detection ===

    // Import Table Analysis (PE only)
    if (peFile && checkImportTableAnalysis(lowerData)) {
        result.findings << "Dangerous import combination detected (injection+privilege escalation)";
        suspiciousCategories++;
        result.riskScore += 25;
    }

    // String Analysis (any file)
    if (checkStringAnalysis(lowerData)) {
        result.findings << "Suspicious embedded strings detected (bitcoin addresses, ransom text)";
        suspiciousCategories++;
        result.riskScore += 20;
    }

    // Section Analysis (PE only)
    if (peFile && checkSectionAnalysis(data)) {
        result.findings << "PE section anomalies detected (writable+executable sections)";
        suspiciousCategories++;
        result.riskScore += 15;
    }

    // Process Behavior (PE only)
    if (peFile && checkProcessBehavior(lowerData)) {
        result.findings << "Process manipulation indicators detected (hollowing, DLL injection)";
        suspiciousCategories++;
        result.riskScore += 25;
    }

    // File System Behavior (any file)
    if (checkFileSystemBehavior(lowerData)) {
        result.findings << "Suspicious file system behavior detected (shadow copy deletion)";
        suspiciousCategories++;
        result.riskScore += 20;
    }

    // Registry Behavior (any file)
    if (checkRegistryBehavior(lowerData)) {
        result.findings << "Security feature disabling detected (firewall/defender/UAC)";
        suspiciousCategories++;
        result.riskScore += 25;
    }

    // === FINAL DECISION ===
    result.riskScore = qMin(100, result.riskScore);

    // Whitelist: skip detection for known legitimate tools
    if (isLegitTool) {
        result.riskScore = 0;
        result.findings.clear();
        return result;
    }

    if (suspiciousCategories >= 2) {
        if (result.riskScore >= 70 || suspiciousCategories >= 3) result.riskLevel = "critical";
        else if (result.riskScore >= 50 || suspiciousCategories >= 2) result.riskLevel = "high";
        else result.riskLevel = "medium";
    } else if (suspiciousCategories == 1) {
        // Single category: dampen the score
        result.riskScore = (result.riskScore + 2) / 3;
        result.riskLevel = "safe";
    } else {
        result.riskLevel = "safe";
        result.riskScore = 0;
    }

    return result;
}

// ============================================================
// Original checks
// ============================================================

bool HeuristicEngine::isPEFile(const QByteArray &data)
{
    if (data.size() < 64) return false;
    return (uchar)data[0] == 'M' && (uchar)data[1] == 'Z';
}

bool HeuristicEngine::checkSuspiciousAPIs(const QByteArray &lowerData)
{
    int categoryCount = 0;

    bool hasInjection = lowerData.contains("virtualallocex") &&
                       lowerData.contains("writeprocessmemory") &&
                       lowerData.contains("createremotethread");
    if (hasInjection) categoryCount++;

    bool hasKeylog = lowerData.contains("setwindowshookex") &&
                    lowerData.contains("getasynckeystate");
    if (hasKeylog) categoryCount++;

    bool hasDownload = (lowerData.contains("urldownloadtofile") && lowerData.contains("internetopenurl")) ||
                       (lowerData.contains("bitsadmin") && lowerData.contains("download"));
    if (hasDownload) categoryCount++;

    bool hasAntiAnalysis = lowerData.contains("isdebuggerpresent") &&
                          lowerData.contains("checkremotedebuggerpresent");
    if (hasAntiAnalysis) categoryCount++;

    bool hasHollowing = lowerData.contains("ntunmapviewofsection") &&
                       lowerData.contains("zwunmapviewofsection");
    if (hasHollowing) categoryCount++;

    return categoryCount >= 2;
}

bool HeuristicEngine::checkPackerSignatures(const QByteArray &lowerData)
{
    QStringList packers = {
        "UPX0", "UPX1", "UPX2", "UPX!",
        "ASPack", ".aspack",
        "PECompact",
        "Themida", ".themida",
        "VMProtect", ".vmp",
        "Armadillo",
        "PEtite",
        "NsPack",
    };

    for (const QString &packer : packers) {
        if (lowerData.contains(packer.toLower().toUtf8())) {
            return true;
        }
    }
    return false;
}

double HeuristicEngine::calculateEntropy(const QByteArray &data)
{
    if (data.isEmpty()) return 0.0;

    int freq[256] = {};
    for (int i = 0; i < data.size(); i++) {
        freq[(uchar)data[i]]++;
    }

    double entropy = 0.0;
    double size = data.size();
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

bool HeuristicEngine::checkAntiVM(const QByteArray &lowerData)
{
    QStringList indicators = {
        "vmware", "virtualbox", "vbox", "qemu", "xen",
        "sandboxie", "sbiedll.dll", "cmdvrt",
        "wine_get_unix_file_name",
    };

    for (const QString &ind : indicators) {
        if (lowerData.contains(ind.toLower().toUtf8())) {
            return true;
        }
    }
    return false;
}

bool HeuristicEngine::checkShellcodePatterns(const QByteArray &data)
{
    if (data.size() < 100) return false;

    int xorCount = 0;
    int callCount = 0;

    for (int i = 0; i < data.size() - 2; i++) {
        uchar b0 = (uchar)data[i];
        uchar b1 = (uchar)data[i+1];
        uchar b2 = (uchar)data[i+2];

        if (b0 >= 0x31 && b0 <= 0x33 && (b1 & 0xC0) == 0xC0 && (b2 & 0xC0) == 0xC0) {
            xorCount++;
        }
        if (b0 == 0xE8 || b0 == 0xE9) {
            callCount++;
        }
    }

    return (xorCount > 10 && callCount > 5);
}

// ============================================================
// New detection categories
// ============================================================

bool HeuristicEngine::checkRansomwareBehavior(const QByteArray &lowerData)
{
    // Ransomware-specific APIs
    bool hasCryptoAPIs = lowerData.contains("cryptencrypt") && lowerData.contains("cryptgenkey");
    bool hasEnumAPIs = lowerData.contains("getvolumeinformationw") || lowerData.contains("getvolumenameformountedpointa");
    bool hasFindAPIs = lowerData.contains("findfirstfilew") && lowerData.contains("findnextfilew");
    bool hasHideAPI = lowerData.contains("setfileattributesw");

    // Ransomware ransom note strings
    bool hasRansomStrings = lowerData.contains(".onion") ||
                           lowerData.contains("your files have been encrypted") ||
                           lowerData.contains("pay us") ||
                           lowerData.contains("decrypt") ||
                           lowerData.contains("recover");

    // Bitcoin address pattern (starts with 1 or 3, base58, 26-35 chars)
    static QRegularExpression btcRegex("\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b");
    QRegularExpressionMatch btcMatch = btcRegex.match(QString::fromUtf8(lowerData));
    bool hasBitcoinAddr = btcMatch.hasMatch();

    // Require API indicators OR (ransom strings + any supporting indicator)
    if (hasCryptoAPIs && (hasEnumAPIs || hasFindAPIs))
        return true;
    if (hasRansomStrings && (hasCryptoAPIs || hasBitcoinAddr))
        return true;
    if (hasBitcoinAddr && hasHideAPI)
        return true;

    return false;
}

bool HeuristicEngine::checkCredentialTheft(const QByteArray &lowerData)
{
    // Credential-related APIs
    bool hasDPAPI = lowerData.contains("cryptunprotectdata");
    bool hasCredAPIs = lowerData.contains("credenumerate") || lowerData.contains("lsaretrieveprivatedata");

    // Target strings (what malware steals)
    bool hasTargetStrings = lowerData.contains("passwords") || lowerData.contains("credentials") ||
                           lowerData.contains("login") || lowerData.contains("cookies") ||
                           lowerData.contains("wallet") || lowerData.contains("seed phrase") ||
                           lowerData.contains("private key");

    // Browser/wallet file paths commonly targeted
    bool hasBrowserPaths = lowerData.contains("\\appdata\\local\\google\\chrome\\user data") ||
                          lowerData.contains("\\appdata\\roaming\\mozilla\\firefox") ||
                          lowerData.contains("\\appdata\\roaming\\exodus");

    if ((hasDPAPI || hasCredAPIs) && (hasTargetStrings || hasBrowserPaths))
        return true;
    if (hasBrowserPaths && hasTargetStrings)
        return true;

    return false;
}

bool HeuristicEngine::checkPersistenceMechanisms(const QByteArray &lowerData)
{
    // Persistence APIs
    bool hasRegAPI = lowerData.contains("regsetvalueexa") || lowerData.contains("regsetvalueexw");
    bool hasSchedAPI = lowerData.contains("schtaskscreate") || lowerData.contains("schtasks");
    bool hasWQL = lowerData.contains("wqlexecw");
    bool hasServiceAPI = lowerData.contains("createservicea") || lowerData.contains("createservicew");

    // Persistence strings in data
    bool hasRunKey = lowerData.contains("currentversion\\run") || lowerData.contains("currentversion\\runonce");
    bool hasSchedStr = lowerData.contains("schtasks");
    bool hasWmicStr = lowerData.contains("wmic");
    bool hasStartupStr = lowerData.contains("startup");

    if (hasRegAPI && (hasRunKey || hasStartupStr))
        return true;
    if ((hasSchedAPI || hasSchedStr) && (hasWQL || hasWmicStr))
        return true;
    if (hasServiceAPI && (hasRunKey || hasStartupStr))
        return true;
    if (hasRunKey && (hasSchedStr || hasWmicStr))
        return true;

    return false;
}

bool HeuristicEngine::checkLotLAbuse(const QByteArray &lowerData)
{
    QStringList lotlPatterns = {
        "certutil -decode",
        "certutil -urlcache",
        "mshta",
        "wscript //e:vbscript",
        "wscript //e:jscript",
        "cscript //e:vbscript",
        "cscript //e:jscript",
        "powershell -enc",
        "powershell -encodedcommand",
        "powershell -e ",
        "bitsadmin /transfer",
        "regsvr32 /s /n /u /i",
        "rundll32",
        "rundll32.exe",
    };

    int matchCount = 0;
    for (const QString &pattern : lotlPatterns) {
        if (lowerData.contains(pattern.toUtf8())) {
            matchCount++;
        }
    }

    // Require at least 2 distinct LotL patterns to avoid false positives
    return matchCount >= 2;
}

bool HeuristicEngine::checkC2Beacon(const QByteArray &lowerData)
{
    // HTTP-based C2 APIs combined with memory manipulation
    bool hasHTTPAPIs = (lowerData.contains("httpsendrequesta") || lowerData.contains("httpsendrequestw") ||
                       lowerData.contains("httprequesta") || lowerData.contains("httprequestw"));
    bool hasConnAPIs = lowerData.contains("internetconnecta") || lowerData.contains("internetconnectw") ||
                      lowerData.contains("internetopena") || lowerData.contains("internetopenw");
    bool hasMemAPIs = lowerData.contains("writeprocessmemory") || lowerData.contains("virtualallocex");

    // C2-style URL patterns
    bool hasGate = lowerData.contains("/gate/") || lowerData.contains("/panel/");
    bool hasAPI = lowerData.contains("/api/");
    bool hasUserAgent = lowerData.contains("user-agent");

    // Base64 encoded command indicators (long base64 blocks)
    static QRegularExpression b64Regex("[a-za-z0-9+/]{100,}={0,2}");
    QRegularExpressionMatch b64Match = b64Regex.match(QString::fromUtf8(lowerData));
    bool hasBase64 = b64Match.hasMatch();

    // Require HTTP APIs + memory APIs + either URL pattern or base64
    if ((hasHTTPAPIs || hasConnAPIs) && hasMemAPIs && (hasGate || hasAPI || hasBase64))
        return true;

    return false;
}

bool HeuristicEngine::checkDataExfiltration(const QByteArray &lowerData)
{
    // Upload/FTP APIs
    bool hasUploadAPI = lowerData.contains("internetuploadfile") || lowerData.contains("ftpputfilea") ||
                       lowerData.contains("ftpputfilew");
    bool hasFileEnumAPI = lowerData.contains("findfirstfilew") || lowerData.contains("findfirstfilea");

    // Exfiltration-related strings
    bool hasUploadStr = lowerData.contains("upload") || lowerData.contains("exfil") ||
                       lowerData.contains("staging");
    bool hasArchiveStr = lowerData.contains("compress") || lowerData.contains(".zip") ||
                        lowerData.contains(".tar") || lowerData.contains("7zip") ||
                        lowerData.contains("winrar");

    if (hasUploadAPI && (hasFileEnumAPI || hasUploadStr))
        return true;
    if (hasUploadStr && hasArchiveStr && hasFileEnumAPI)
        return true;

    return false;
}

bool HeuristicEngine::checkPEAnomalies(const QByteArray &data)
{
    if (!isPEFile(data)) return false;
    if (data.size() < 256) return false;

    // Read PE header basics
    // e_lfanew at offset 0x3C
    quint32 peOffset = 0;
    if (data.size() >= 0x40) {
        peOffset = (uchar)data[0x3C] | ((uchar)data[0x3D] << 8) |
                   ((uchar)data[0x3E] << 16) | ((uchar)data[0x3F] << 24);
    }
    if (peOffset + 24 >= data.size()) return false;

    // Verify PE signature "PE\0\0"
    if ((uchar)data[peOffset] != 'P' || (uchar)data[peOffset+1] != 'E' ||
        (uchar)data[peOffset+2] != 0 || (uchar)data[peOffset+3] != 0)
        return false;

    // COFF header: number of sections at offset 2 from PE sig
    quint16 numSections = (uchar)data[peOffset+6] | ((uchar)data[peOffset+7] << 8);
    // Optional header size at offset 20 from PE sig
    quint16 optHeaderSize = (uchar)data[peOffset+20] | ((uchar)data[peOffset+21] << 8);

    quint32 sectionTableOffset = peOffset + 24 + optHeaderSize;

    // Count suspicious (non-standard) section names
    QStringList knownSections = {".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata",
                                 ".idata", ".edata", ".tls", ".CRT", ".bss"};
    // Known packer sections already checked by checkPackerSignatures, so skip UPX0 etc. here

    int unusualSectionCount = 0;
    for (int i = 0; i < numSections && i < 96; i++) {
        int off = sectionTableOffset + i * 40;
        if (off + 8 > data.size()) break;
        // Section name is 8 bytes at start of section header
        QString sectionName = QString::fromUtf8(data.mid(off, 8)).trimmed().toLower();
        if (!sectionName.isEmpty() && !knownSections.contains(sectionName)) {
            unusualSectionCount++;
        }
    }

    // Check import count: count occurrences of "import" hint pattern
    // Simplified: count RVA-like references in the data section area
    // A more practical heuristic: scan for executable API name patterns
    int apiCount = 0;
    static const char *apiSignatures[] = {
        "openprocess", "createprocess", "virtualallocex", "writeprocessmemory",
        "createremotethread", "loadlibrarya", "getprocaddress", "ntwritevirtualmemory",
        "cryptencrypt", "internetopena", "regsetvalueexw", "createservicew",
        "findfirstfilew", "setfileattributesw", nullptr
    };
    QByteArray lowerData = data.toLower();
    for (const char **sig = apiSignatures; *sig; sig++) {
        QByteArray needle(*sig);
        if (lowerData.contains(needle)) apiCount++;
    }

    // Anomalies: unusual sections or excessive imports
    if (unusualSectionCount >= 4 || apiCount > 12)
        return true;

    return false;
}

bool HeuristicEngine::checkScriptObfuscation(const QByteArray &lowerData)
{
    // Base64 blocks > 500 chars
    static QRegularExpression b64Regex("[a-za-z0-9+/]{500,}={0,2}");
    QRegularExpressionMatch b64Match = b64Regex.match(QString::fromUtf8(lowerData));
    bool hasLongBase64 = b64Match.hasMatch();

    // Char code sequences
    bool hasChrCode = lowerData.contains("chr(") || lowerData.contains("chrw(") ||
                     lowerData.contains("string.fromcharcode");

    // String concatenation patterns
    // "a"+"b"+"c" pattern - multiple quotes joined
    static QRegularExpression concatRegex("\"[^\"]+\"\\s*\\+\\s*\"[^\"]+\"\\s*\\+\\s*\"[^\"]+\"");
    QRegularExpressionMatch concatMatch = concatRegex.match(QString::fromUtf8(lowerData));
    bool hasConcat = concatMatch.hasMatch();

    // join/concat with many parts
    bool hasJoin = lowerData.contains("join(") || lowerData.contains("concat(");

    // Eval / invoke-expression
    bool hasEval = lowerData.contains("invoke-expression") || lowerData.contains("iex(") ||
                  lowerData.contains("iex ") || lowerData.contains("eval(");

    if (hasLongBase64 && (hasChrCode || hasEval))
        return true;
    if (hasConcat && hasEval)
        return true;
    if (hasChrCode && hasConcat)
        return true;
    if (hasLongBase64 && hasJoin)
        return true;

    return false;
}

// === Advanced Detection: Import Table Analysis ===
bool HeuristicEngine::checkImportTableAnalysis(const QByteArray &lower)
{
    int dangerScore = 0;

    bool hasAlloc = lower.contains("virtualallocex");
    bool hasWrite = lower.contains("writeprocessmemory");
    bool hasThread = lower.contains("createremotethread");
    bool hasQueue = lower.contains("queueuserapc");
    bool hasSuspend = lower.contains("suspendthread");

    if (hasAlloc && hasWrite && (hasThread || hasQueue)) dangerScore += 3;
    if (hasAlloc && hasSuspend && hasWrite) dangerScore += 2;

    bool hasCred = lower.contains("credenumerate") || lower.contains("lsaretrieveprivatedata");
    bool hasDpapi = lower.contains("cryptunprotectdata");
    bool hasToken = lower.contains("openthreadtoken") || lower.contains("impersonateloggedonuser");

    if (hasCred && hasDpapi) dangerScore += 2;
    if (hasToken && (hasCred || hasDpapi)) dangerScore += 2;

    bool hasPriv = lower.contains("adjusttokenprivileges");
    bool hasLookup = lower.contains("lookupprivilegevaluea");
    bool hasProcessToken = lower.contains("opentoken");

    if (hasPriv && hasLookup && hasProcessToken) dangerScore += 3;

    bool hasDebug = lower.contains("isdebuggerpresent");
    bool hasRemoteDebug = lower.contains("checkremotedebuggerpresent");
    bool hasNtQuery = lower.contains("ntqueryinformationprocess");
    bool hasHide = lower.contains("ntsetinformationthread");

    if (hasDebug && hasRemoteDebug && hasNtQuery) dangerScore += 2;
    if (hasHide && (hasDebug || hasRemoteDebug)) dangerScore += 2;

    bool hasHttp = lower.contains("httpsendrequesta") || lower.contains("internetopena");
    bool hasConn = lower.contains("internetconnecta");
    bool hasAlloc2 = lower.contains("virtualallocex");
    bool hasWrite2 = lower.contains("writeprocessmemory");

    if (hasHttp && hasConn && hasAlloc2 && hasWrite2) dangerScore += 3;

    return dangerScore >= 3;
}

// === Advanced Detection: String Analysis ===
bool HeuristicEngine::checkStringAnalysis(const QByteArray &lower)
{
    int findings = 0;

    static QRegularExpression btcRegex("\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b");
    QRegularExpressionMatch btcMatch = btcRegex.match(QString::fromUtf8(lower));
    if (btcMatch.hasMatch()) findings++;

    static QRegularExpression ethRegex("\\b0x[0-9a-f]{40}\\b");
    QRegularExpressionMatch ethMatch = ethRegex.match(QString::fromUtf8(lower));
    if (ethMatch.hasMatch()) findings++;

    if (lower.contains(".onion")) findings++;

    bool hasSuspiciousDomain = lower.contains("pastebin.com") ||
                               lower.contains("hastebin.com") ||
                               lower.contains("paste.ee") ||
                               lower.contains("ghostbin.co") ||
                               lower.contains("rentry.co");
    if (hasSuspiciousDomain) findings++;

    bool hasRansomText = lower.contains("your files have been encrypted") ||
                         lower.contains("your personal files are encrypted") ||
                         lower.contains("to get your files back") ||
                         lower.contains("send bitcoin to") ||
                         lower.contains("decrypt your files") ||
                         lower.contains("pay the ransom");
    if (hasRansomText) findings++;

    bool hasCredentialStrings = (lower.contains("password") && lower.contains("steal")) ||
                                (lower.contains("credential") && lower.contains("harvest")) ||
                                (lower.contains("keylog") && lower.contains("record"));
    if (hasCredentialStrings) findings++;

    bool hasMassRename = lower.contains("ren ") && lower.contains(".encrypted") ||
                         lower.contains("ren ") && lower.contains(".locked");
    if (hasMassRename) findings++;

    return findings >= 2;
}

// === Advanced Detection: Section Analysis ===
bool HeuristicEngine::checkSectionAnalysis(const QByteArray &data)
{
    if (!isPEFile(data) || data.size() < 256) return false;

    quint32 peOffset = 0;
    if (data.size() >= 0x40) {
        peOffset = (uchar)data[0x3C] | ((uchar)data[0x3D] << 8) |
                   ((uchar)data[0x3E] << 16) | ((uchar)data[0x3F] << 24);
    }
    if (peOffset + 24 >= data.size()) return false;
    if ((uchar)data[peOffset] != 'P' || (uchar)data[peOffset+1] != 'E') return false;

    quint16 numSections = (uchar)data[peOffset+6] | ((uchar)data[peOffset+7] << 8);
    quint16 optHeaderSize = (uchar)data[peOffset+20] | ((uchar)data[peOffset+21] << 8);
    quint32 sectionTableOffset = peOffset + 24 + optHeaderSize;

    int suspiciousSections = 0;
    int writableExecSections = 0;

    for (int i = 0; i < numSections && i < 96; i++) {
        int off = sectionTableOffset + i * 40;
        if (off + 40 > data.size()) break;

        quint32 characteristics = (uchar)data[off+36] | ((uchar)data[off+37] << 8) |
                                  ((uchar)data[off+38] << 16) | ((uchar)data[off+39] << 24);

        if ((characteristics & 0x60000000) == 0x60000000) writableExecSections++;

        QString sectionName = QString::fromUtf8(data.mid(off, 8)).trimmed().toLower();
        QStringList dangerousSections = {"upx", "vmp", "themida", "aspack", ".vmp0", ".vmp1"};
        for (const QString &ds : dangerousSections) {
            if (sectionName.contains(ds)) { suspiciousSections++; break; }
        }
    }

    if (writableExecSections >= 2) return true;
    if (suspiciousSections >= 2) return true;
    if (writableExecSections >= 1 && suspiciousSections >= 1) return true;

    return false;
}

// === Advanced Detection: File System Behavior ===
bool HeuristicEngine::checkFileSystemBehavior(const QByteArray &lower)
{
    int indicators = 0;

    bool hasShadowDelete = lower.contains("vssadmin delete shadows") ||
                           lower.contains("wmic shadowcopy delete") ||
                           lower.contains("bcdedit /set {default} recoveryenabled no");
    if (hasShadowDelete) indicators++;

    bool hasEnum = lower.contains("findfirstfile") && lower.contains("findnextfile");
    bool hasRename = lower.contains("movefile") || lower.contains("renamefile");
    bool hasDelete = lower.contains("deletefile") || lower.contains("removefile");
    bool hasEncrypt = lower.contains("cryptencrypt");

    if (hasEnum && (hasRename || hasDelete) && hasEncrypt) indicators++;

    bool hasSetAttr = lower.contains("setfileattributes");
    bool hasCreateFile = lower.contains("createfile") || lower.contains("createfilew");

    if (hasEnum && hasSetAttr && hasCreateFile) indicators++;

    bool hasBackupDestroy = lower.contains("wbadmin delete catalog") ||
                            lower.contains("vssadmin delete shadows");
    if (hasBackupDestroy) indicators++;

    // Destructive commands (batch file abuse)
    bool hasRdRecursive = lower.contains("rd /s") || lower.contains("rd /s /q") ||
                          lower.contains("rmdir /s");
    if (hasRdRecursive) indicators++;

    bool hasFormatDisk = lower.contains("format c:") || lower.contains("format d:") ||
                         lower.contains("format /q") || lower.contains("format /y");
    if (hasFormatDisk) indicators++;

    bool hasDelRecursive = lower.contains("del /f /q /s") || lower.contains("del /s /q") ||
                           lower.contains("erase /f /q /s");
    if (hasDelRecursive) indicators++;

    bool hasDiskWipe = lower.contains("rd /s /q c:\\") || lower.contains("rd /s /q d:\\") ||
                       lower.contains("rd /s /q e:\\") || lower.contains("rd /s /q c:");
    if (hasDiskWipe) indicators++;

    return indicators >= 1;  // Single destructive command is enough to flag
}

// === Advanced Detection: Registry Behavior ===
bool HeuristicEngine::checkRegistryBehavior(const QByteArray &lower)
{
    int indicators = 0;

    bool hasDisableSecurity = lower.contains("disablerealtimemonitoring") ||
                             lower.contains("disablenotifications") ||
                             lower.contains("disableuac") ||
                             lower.contains("setuseraccountcontrol") ||
                             lower.contains("defenderdisable") ||
                             lower.contains("disablewindowsdefender");
    if (hasDisableSecurity) indicators++;

    bool hasFirewallDisable = lower.contains("netsh advfirewall set allprofiles state off") ||
                              lower.contains("netsh firewall set opmode disable") ||
                              lower.contains("setdisablefirewall");
    if (hasFirewallDisable) indicators++;

    bool hasBootMod = lower.contains("bcdedit /set") ||
                      lower.contains("bootcfg /");
    if (hasBootMod) indicators++;

    bool hasServiceManip = lower.contains("sc config") && lower.contains("disabled") ||
                           lower.contains("sc stop") || lower.contains("sc delete");
    if (hasServiceManip) indicators++;

    // Registry deletion (destructive)
    bool hasRegDelete = lower.contains("reg delete");
    if (hasRegDelete) indicators++;

    // HKCR/HKLM/HKCU key destruction
    bool hasKeyDestroy = lower.contains("reg delete hkcr") ||
                         lower.contains("reg delete hklm") ||
                         lower.contains("reg delete hkcu");
    if (hasKeyDestroy) indicators++;

    return indicators >= 1;
}

// === Advanced Detection: Process Behavior ===
bool HeuristicEngine::checkProcessBehavior(const QByteArray &lower)
{
    int indicators = 0;

    bool hasHollow = lower.contains("ntunmapviewofsection") &&
                    lower.contains("zwunmapviewofsection");
    bool hasSuspend = lower.contains("suspendthread") || lower.contains("ntsuspendthread");
    bool hasSetContext = lower.contains("setthreadcontext") || lower.contains("ntsetcontextthread");
    bool hasResume = lower.contains("resumethread") || lower.contains("ntresumethread");

    if (hasHollow && hasSuspend && hasSetContext && hasResume) indicators++;

    bool hasLoadLib = lower.contains("loadlibrarya") || lower.contains("loadlibraryw");
    bool hasGetProc = lower.contains("getprocaddress");
    bool hasRemoteThread = lower.contains("createremotethread");

    if (hasLoadLib && hasGetProc && hasRemoteThread) indicators++;

    bool hasCreateProc = lower.contains("createprocess") && lower.contains("createprocessw");
    bool hasWriteMem = lower.contains("writeprocessmemory");
    bool hasAlloc = lower.contains("virtualallocex");

    if (hasCreateProc && hasWriteMem && hasAlloc) indicators++;

    return indicators >= 2;
}
