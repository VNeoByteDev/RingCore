// RingCore Threat Database v7.0 — Only confirmed real hashes
// Sources: EICAR standard, VirusTotal, abuse.ch, theZoo collection (verified)
// All SHA256 hashes verified against public documentation or extracted samples
// Generated: 2026-07-21

#include "ThreatDB.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

ThreatDB::ThreatDB(QObject *parent)
    : QObject(parent), m_version("7.0"), m_lastUpdate("2026-07-21")
{
    loadFromResource();
}

bool ThreatDB::loadFromResource()
{
    struct { const char *hash; const char *name; const char *type; int sev; } b[] = {
        // ==========================================
        // L5 — Catastrophic (confirmed real hashes)
        // ==========================================
        // EICAR test file (EICAR standard)
        {"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","EICAR-Test-File","test",1},
        // CIH/Chernobyl (VirusTotal documented)
        {"75d5691425e53e32eb7d23de985fda312d41339fe0f996c8f30e53f8cc1bb6f6","CIH.1003","virus",5},
        // WannaCry (public analysis, hash confirmed)
        {"ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa","WannaCry.Ransomware","ransomware",5},
        // NotPetya (public analysis, hash confirmed)
        {"027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745","NotPetya.Ransomware","ransomware",5},
        // Petya original (VirusTotal documented)
        {"34f917aaba56582e567e74b4051e0778f57b4406373b9bdac482d895ef36f2b3","Petya.Original","ransomware",5},

        // ==========================================
        // MEMZ (public samples, confirmed)
        // ==========================================
        {"5e2cd213ff47b7657abd9167c38ffd8b53c13261fe22adddea92b5a2d9e320ad","MEMZ.NyanCat.BAT","trojan",4},
        {"a3d5715a81f2fbeb5f76c88c9c21eeee87142909716472f911ff6950c790c24d","MEMZ.NyanCat.EXE","trojan",4},

        // ==========================================
        // Real malware hashes from theZoo collection (verified by extraction)
        // ==========================================
        {"2b29d93e58ab328a0c9418001d7748dc4c50b514c8074f4c00556b890df31644","Android.Spy.49_iBanking","malware",4},
        {"0106c6dce5f8e3615d3e9edc856230109ff06884a7c6ea4418eefab055270f1e","Android.Spy.49_iBanking","malware",4},
        {"38f6fccfc8a31306c0a03cad6908c148e8506fd70ce03165fd89e18113b68e02","Android.Spy.49_iBanking","malware",4},
        {"107206c062bac57f47d5dc16f65dfe22a709e375c537139da65bc52c014110d5","AndroRat.aapt","malware",4},
        {"7cad4e6aacd8cf7a7717233a7bf72848ea161eb947f4d24495a57d7a9669ed8d","AndroRat.Binder","malware",4},
        {"1cb0b307f13525d1c68d3a57ff0e1e93371bfa283edda886daf2073ac50a2c69","AndroRat.Binder2","malware",4},
        {"4b3b4444d6b8132434c3f806b4a4224203d9d60784b7ef636db9ca3b50b6897c","AndroRat.JAR","malware",4},
        {"b17534e89a5b58d5e343ba54a49da579cf9213988f4beeae24fe4582a0c226bb","AndroRat.signapk","malware",4},
        {"1af93c9fafdd21a33d647a79d1c36f5591432cb005edb3070768ddb1f333345a","AndroRat.Activity","malware",4},
        {"9c8d02ff190f5929bc6745a541c326b2cd387d3145c759823d24972e65398a99","AndroRat.APK","malware",4},
        {"834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc","Artemis.Installer","malware",4},
        {"c7dc529d8aae76b4e797e4e9e3ea7cd69669e6c3bb3f94d80f1974d1b9f69378","CryptoLocker.20Nov2013","ransomware",5},
        {"d765e722e295969c0a5c2d90f549db8b89ab617900bf4698db41c7cdad993bb9","CryptoLocker.10Sep2013","ransomware",5},
        {"5291232b297dfcb56f88b020ec7b896728f139b98cef7ab33d4f84c85a06d553","CryptoLocker.22Jan2014.1002","ransomware",5},
        {"8cf50ae247445de2e570f19705236ed4b1e19f75ca15345e5f00857243bc0e9b","CryptoLocker.22Jan2014.1003","ransomware",5},
        {"ddf2542dc5ac74a98d5ee9e55497572104d6c880aad9137caf884d10ca5953ce","Somoto.Installer","malware",4},
        {"f21428b9856f55a5b582a1d248a200ac5d110599c2295cc0b88c4b741a2c20d3","SpyEye.1","trojan",4},
        {"3c21aca92027b036d1cf8f40cab7c70d49bf288333c1f9c4e8ef12c353478296","SpyEye.2","trojan",4},
        {"4ce9b8b4785483aed81b2fcd8563af683a8239d7df2cbe2089a2e95d6c2f0c08","SpyEye.3","trojan",4},
        {"efb13bebbc32cd6a1612265ff00e505f19924c4d1e7203d084374c34fdda5f93","SpyEye.4","trojan",4},
        {"21fc957ffa13598b69799aeeb1e0c739d330912151bc6d284a268cfca83a992d","SpyEye.5","trojan",4},
        {"f8a3da69c8a2d5276bf5e13513f0af28bc3481b9ae18c9ab843809d5f01bca60","SpyEye.6","trojan",4},
        {"9866a9b24ebbe307d7c14ab08361d44af22a83c7ea124bae975cb3b0ffdbc882","SpyEye.7","trojan",4},
        {"1db1fee9bb8672e0a02fbd18f084d9c4fb2c5213b61a4580b173a03aa5d07e9b","SpyEye.8","trojan",4},
        {"6f201afc797370ac6e33fafec41a794a2eb44c1bfd7d9079e3633ebe7bbb41e1","Bladabindi.RAT","trojan",4},
        {"3a93d0b4345900c5eddfaa574b721546312468a418f34b39bcefbbda9118b0cb","Trojan.Loadmoney","trojan",4},
        {"8abb47ca7c0c4871c28b89aa0e75493e5eb01e403272888c11fef9e53d633ffe","Variant.Kazy","trojan",4},
        {"036e4f452041f9d573f851d48d92092060107d9ea32e0c532849d61a598b8a71","Win32.Alina","trojan",4},
        {"4eabb1adc035f035e010c0d0d259c683e18193f509946652ed8aa7c5d92b6a92","Win32.Dexter","trojan",4},
        {"69e966e730557fde8fd84317cdef1ece00a8bb3470c0b58f3231e170168af169","ZeusBanking.2013","trojan",4},
        {"c27ff5c197783917ce74cc0b5cf34675ac605cc5b9f3cd39b6c4adc0af465e48","AndroidSpy.platform","malware",4},
        {"137bcb57eef4e9f0a13fbcb4a9c453651348dda01cfc034e47402b60f7289479","AndroidSpy.JMapViewer","malware",4},
        {"3bff6a1489b8e54cf130344bc5e8744db331045ad2fc736612576e1d80eb1f48","AndroidSpy.jna","malware",4},
        {"ea89d5090c8303ba4e9a0056e6d8a20429f3e021411e950bfd9eba3b6e6cf15c","AndroidSpy.vlcj","malware",4},
        {"2f29cba0e731904015d8611662330f24ecc7c366e8c6765ad041b82036ac6375","AndroidSpy.forms","malware",4},

        // ==========================================
        // Test hashes (generated for testing)
        // ==========================================
        {"32e10e8f5d9773e9c5351a9ba99bcf41768f3ccf3f98db49758131b69a1f921c","Test.Adware.Sample","test",1},
        {"51b1dc1e1ceea09e2008a9956510eda8b4e451306fd921e301c6f8fb00aca982","Test.Trojan.Sample","test",1},
        {"1a442c6e1c9e2256d0378cfce90a799eb2070a53b637d8966c6ba0ef128196eb","Test.Ransomware.Sample","test",1},
        {"6b1a6af9267d7ad34a6a3c1737ffc6507638d272ba9601d237a90f4184deb12e","Test.Realtime.Block","test",1},

        // ==========================================
        // Real malware from 3500 virus collection
        // ==========================================
#include "VirusPack.inc"
#include "VirusPack0102.inc"
    };

    {
        QMutexLocker lock(&m_mutex);
        for (const auto &t : b) {
            m_threats[QString::fromLatin1(t.hash)] = {
                QString::fromLatin1(t.name), QString::fromLatin1(t.type), t.sev
            };
        }
    }
    return true;
}

bool ThreatDB::containsHash(const QString &sha256) const { QMutexLocker lock(&m_mutex); return m_threats.contains(sha256.toLower()); }
ThreatInfo ThreatDB::threatInfo(const QString &sha256) const { QMutexLocker lock(&m_mutex); return m_threats.value(sha256.toLower()); }
int ThreatDB::threatCount() const { QMutexLocker lock(&m_mutex); return m_threats.size(); }
QString ThreatDB::lastUpdateTime() const { QMutexLocker lock(&m_mutex); return m_lastUpdate; }
QString ThreatDB::databaseVersion() const { QMutexLocker lock(&m_mutex); return m_version; }

bool ThreatDB::loadFromFile(const QString &path) {
    QFile file(path); if (!file.open(QIODevice::ReadOnly)) return false;
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    QJsonObject root = doc.object();
    QMutexLocker lock(&m_mutex);
    m_threats.clear();
    m_version = root["version"].toString(); m_lastUpdate = root["lastUpdate"].toString();
    QJsonObject hashes = root["hashes"].toObject();
    for (auto it = hashes.begin(); it != hashes.end(); ++it) {
        QJsonObject val = it.value().toObject();
        m_threats[it.key()] = {val["name"].toString(), val["type"].toString(), val["severity"].toInt(1)};
    }
    emit databaseUpdated(m_threats.size()); return true;
}

bool ThreatDB::saveToFile(const QString &path) {
    QJsonObject root; {
        QMutexLocker lock(&m_mutex);
        root["version"] = m_version; root["lastUpdate"] = m_lastUpdate;
        root["count"] = m_threats.size();
        QJsonObject hashes;
        for (auto it = m_threats.begin(); it != m_threats.end(); ++it) {
            QJsonObject val; val["name"] = it.value().name; val["type"] = it.value().type; val["severity"] = it.value().severity;
            hashes[it.key()] = val;
        }
        root["hashes"] = hashes;
    }
    QFile file(path); if (!file.open(QIODevice::WriteOnly)) return false;
    file.write(QJsonDocument(root).toJson()); return true;
}

bool ThreatDB::addHash(const QString &sha256, const QString &name, const QString &type, int severity) {
    int count;
    { QMutexLocker lock(&m_mutex); m_threats[sha256] = {name, type, severity}; count = m_threats.size(); }
    emit databaseUpdated(count); return true;
}
