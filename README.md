<div align="center">

# RingCore Security Guardian

**下一代智能防御引擎 — 面向 Windows 平台的开源安全解决方案**

[![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square)](https://github.com/VNeoByteDev/RingCore)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Qt](https://img.shields.io/badge/Qt-6.7.2-41CD52?style=flat-square&logo=qt)](https://www.qt.io/)
[![Platform](https://img.shields.io/badge/Platform-Windows_10/11-0078D4?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![C++](https://img.shields.io/badge/C++-17-00599C?style=flat-square&logo=cplusplus)](https://isocpp.org/)
[![VS](https://img.shields.io/badge/VS_2022-Enterprise-68217A?style=flat-square&logo=visualstudio)](https://visualstudio.microsoft.com/)

<br/>

![RingCore Security Guardian](https://github.com/VNeoByteDev/RingCore/raw/main/website/index.html)

</div>

---

## 概述

RingCore Security Guardian 是一款基于 **23 类启发式分析引擎** 和 **172+ 条真实恶意软件特征库** 的 Windows 安全防护软件。采用 Qt 6 + C++ 构建，提供实时盾防护、智能文件扫描、右键集成、自动隔离等完整安全能力。

> **免责声明**: 本项目由一名五年级小学生作为编程学习项目开发，按「现状」提供，不附带任何保证。使用风险由用户自行承担。

## 核心特性

### 安全引擎

| 能力 | 描述 |
|------|------|
| **23 类启发式分析** | 熵分析、API 导入、Shellcode 检测、PE 头部异常、勒索软件行为、凭证窃取、持久化、LotL、C2 通信、数据外泄、加密混淆、脚本混淆、文件系统行为、注册表行为、进程行为等 |
| **SHA256 特征匹配** | 172+ 条从真实恶意软件样本提取的 SHA256 哈希，双重数据库架构（内置 + ThreatDB 外部库） |
| **3+ 类别触发阈值** | 只有同时触发 3 个以上检测类别才判定为威胁，有效消除误报 |
| **白名单系统** | 100+ 条已知合法软件模式，自动跳过检测 |

### 防护能力

| 功能 | 描述 |
|------|------|
| **实时盾引擎** | `RingCoreSvc.exe` 后台服务 7×24 小时监控文件系统变化 |
| **智能文件扫描** | 支持单文件、文件夹递归扫描、压缩包解压扫描（ZIP/RAR/7z） |
| **右键扫描集成** | Windows 资源管理器上下文菜单集成，一键扫描任意文件/文件夹 |
| **文件夹实时监控** | QFileSystemWatcher 监控指定文件夹，新文件自动触发扫描 |
| **自动威胁隔离** | 检测到威胁后毫秒级移入安全隔离区，支持一键恢复 |
| **系统垃圾清理** | 临时文件、浏览器缓存、回收站一键清理 |
| **进程管理** | 实时进程列表查看，危险进程终止 |
| **防火墙管理** | 入站/出站规则管理 |

## 技术架构

```
┌─────────────────────────────────────────────────────┐
│                 RingCoreGuardian.exe                  │
│            (Qt 6 GUI · C++17 · Windows)              │
├──────────┬──────────┬──────────┬────────────────────┤
│ HomePanel│ ScanPanel│ Process  │ Firewall / Settings│
├──────────┴──────────┴──────────┴────────────────────┤
│              ShieldEngine (核心检测引擎)              │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │SignatureDB│  │HeuristicAnlz │  │PatternMatcher │  │
│  │ 172+ 哈希 │  │ 23 类分析    │  │ API 模式匹配  │  │
│  └──────────┘  └──────────────┘  └───────────────┘  │
├─────────────────────────────────────────────────────┤
│                    ThreatDB (外部特征库)              │
│              VirusPack.inc · VirusPack0102.inc       │
├──────────┬──────────┬───────────────────────────────┤
│Quarantine│Settings  │    RingCoreSvc.exe            │
│Manager   │Manager   │  (Windows Service · 后台防护) │
└──────────┴──────────┴───────────────────────────────┘
```

## 项目结构

```
RingCore/
├── Source/
│   ├── Guardian/           # 主程序 (Qt GUI)
│   │   ├── src/
│   │   │   ├── main.cpp           # 入口 + 命令行扫描
│   │   │   ├── MainWindow.cpp/h   # 无边框窗口 + 侧边栏
│   │   │   ├── panels/            # 各功能面板
│   │   │   ├── engine/            # ShieldEngine 核心引擎
│   │   │   ├── core/              # ThreatDB, Settings, Quarantine 等
│   │   │   └── widgets/           # 可复用组件
│   │   ├── resources/             # QSS 样式 + SVG 图标
│   │   └── CMakeLists.txt
│   ├── Service/             # RingCoreSvc.exe (Windows 服务)
│   └── ShellExt/            # RingCoreShellExt.dll (右键菜单)
├── Build/                   # 构建输出 (gitignored)
├── Installer/               # NSIS 安装包脚本 + 素材
├── Config/                  # 配置文件
├── Script/                  # 辅助脚本
├── website/                 # 官网 (GitHub Pages)
├── Cert/                    # 自签名证书
├── LICENSE                  # MIT License
└── .github/workflows/       # CI/CD (GitHub Actions)
```

## 快速开始

### 环境要求

| 依赖 | 版本 | 说明 |
|------|------|------|
| **Visual Studio** | 2022 | C++ 桌面开发工作负载 |
| **Qt** | 6.7.2 | MSVC 2022 64-bit |
| **CMake** | ≥ 3.20 | Qt 6 自带或独立安装 |
| **Ninja** | ≥ 1.11 | Qt 6 默认构建系统 |

### 构建

```bash
# 1. 打开 VS 2022 x64 Native Tools Command Prompt
# 或使用 vcvarsall.bat
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

# 2. 配置 CMake
cd Source/Guardian
cmake -B Build -G Ninja -DCMAKE_BUILD_TYPE=Release

# 3. 构建
cmake --build Build --config Release --parallel

# 4. 运行
Build\RingCoreGuardian.exe
```

### 命令行扫描

```bash
# 扫描单个文件
RingCoreGuardian.exe --scan "C:\path\to\file.exe"

# 扫描文件夹（递归）
RingCoreGuardian.exe --scan "C:\path\to\folder"

# 扫描压缩包
RingCoreGuardian.exe --scan "C:\path\to\archive.zip"
```

## 检测引擎详解

### 23 类启发式分析

| # | 类别 | 描述 | 权重 |
|---|------|------|------|
| 1 | 熵分析 | 文件熵值异常（加密/压缩/混淆） | 高 |
| 2 | API 导入 | 可疑 Windows API 组合检测 | 高 |
| 3 | 壳代码 | x86/x64 shellcode 字节模式匹配 | 高 |
| 4 | PE 头部 | 入口点异常 / 头部篡改 | 中 |
| 5 | 加壳签名 | UPX / VMP / Themida 等 | 中 |
| 6 | 反虚拟机 | VM 检测 API / 环境探测 | 中 |
| 7 | 勒索软件 | 加密 API + 勒索字符串 | 高 |
| 8 | 凭证窃取 | CryptAPI + CredEnumerate | 高 |
| 9 | 持久化 | 注册表启动项 / 计划任务 | 中 |
| 10 | LotL | Living-off-the-Land 技术 | 高 |
| 11 | C2 通信 | 远程连接 API 模式 | 高 |
| 12 | 数据外泄 | HTTP/FTP/DNS 数据传输 | 中 |
| 13 | PE 异常 | 节区权限 / 导入表异常 | 中 |
| 14 | 脚本混淆 | PowerShell / JS / VBS 混淆 | 中 |
| 15 | 字符串分析 | 可疑字符串模式匹配 | 低 |
| 16 | 节区分析 | W+X 节区 / 可疑节名 | 中 |
| 17 | 文件系统行为 | 批量删除 / 加密操作 | 高 |
| 18 | 注册表行为 | 安全设置篡改 | 高 |
| 19 | 进程行为 | 进程注入 / 提权 | 高 |
| 20 | 破坏性命令 | `format`, `rd /s`, `reg delete` | 高 |
| 21 | JAR/APK 分析 | Android 恶意应用检测 | 中 |
| 22 | 加密混淆 | AES/RSA 加密混淆检测 | 中 |
| 23 | 导入表分析 | 可疑 DLL 导入组合 | 中 |

### 白名单

引擎内置 100+ 条已知合法软件模式，匹配到白名单的文件直接跳过检测：

```
NVIDIA / AMD / Intel 驱动 · 微信 / QQ / 网易云音乐
百度网盘 · Chrome / Firefox / Edge · Visual Studio Code
7-Zip / WinRAR · PuTTY / WinSCP · Rainmeter
Obsidian · DDU · nvm · PsExec / Sysinternals
Microsoft Visual C++ Runtime · .NET Runtime ...
```

## 界面截图

软件采用自定义无边框窗口 + 深色网络安全主题：

- **首页仪表盘** — 盾牌光环 + 3 统计卡片 + 快捷操作
- **病毒扫描** — 渐变进度条 + 动画状态 + 结果树
- **实时监控** — 文件夹监控 + 自动隔离
- **设置页** — 开关式切换 + 分组卡片

## 安装包

使用 NSIS 构建的专业安装程序：

- 语言选择对话框（中文 / English）
- 品牌化头图 + 侧栏辉光
- 自动注册右键菜单 + 后台服务
- 桌面 + 开始菜单快捷方式
- 完整卸载支持

```bash
# 构建安装包
"C:\Program Files (x86)\NSIS\makensis.exe" Installer\RingCoreGuardian.nsi
```

## CI/CD

GitHub Actions 自动化流水线：

- **触发条件**: 推送 `v*` 标签
- **构建**: Windows Runner + Qt 6 + CMake + Ninja
- **签名**: Sigstore OIDC 签名（无密钥）
- **发布**: 自动创建 GitHub Release + 上传安装包

## 贡献

欢迎贡献代码、报告 Bug 或提出建议。

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 许可证

本项目基于 [MIT License](LICENSE) 开源。

## 致谢

- [Qt 6](https://www.qt.io/) — 跨平台 GUI 框架
- [NSIS](https://nsis.sourceforge.io/) — Windows 安装程序
- [GitHub Actions](https://github.com/features/actions) — CI/CD
- [Sigstore](https://www.sigstore.dev/) — 代码签名

---

<div align="center">

**Built with ♥ by [VNeoByteDev](https://github.com/VNeoByteDev)**

*"It's not about age. It's about passion."*

</div>
