# 🔍 Lots-of-POC

欢迎来到 **LOTS-OF-POC** 项目！🎉 这是一个专注于对 Nuclei 和 Goby 的 POC 进行收集、整理和分类的仓库，帮助网络安全研究人员更快、更有效地使用这些工具进行漏洞扫描和渗透测试。

## 🚀 项目简介

本项目致力于收集和维护大量高质量的 POC，包括但不限于以下内容：

- **Nuclei POC**：Nuclei 是一个基于模板的漏洞扫描工具，支持自定义漏洞模板。本项目整理了 Nuclei 社区的公开模板，并对其进行分类和优化。
- **Goby POC**：Goby 是一款强大的网络安全评估工具，支持多种漏洞类型的扫描。本项目收集了 Goby 官方和社区的 POC，并根据漏洞类型进行分类。
- **……**：其他引擎目前不打算编写、整理、收集（可以推荐）
我们对收集的每个 POC 进行了详细的注释和分类，确保易于理解和使用。

## 📦 安装与使用

### 环境要求

- [Nuclei](https://github.com/projectdiscovery/nuclei) >= v2.8.0
- [Goby](https://gobysec.net/) >= v1.9.325
- Python 3.8+（可选，用于开发工具）

### 安装步骤

1. **克隆仓库**

   ```bash
   git clone https://github.com/zhxknb1/Lots-of-POC.git
   ```

2. **下载 Nuclei 和 Goby**

   确保已安装最新版本的 Nuclei 和 Goby，或使用下列命令安装 Nuclei：

   ```bash
   go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
   ```

3. **使用 POC 进行扫描**

   - **Nuclei**: 使用以下命令加载自定义 POC 模板进行扫描：

     ```bash
     nuclei -t /path/to/nuclei/templates -l targets.txt
     ```

   - **Goby**: 将 POC 导入 Goby 后使用内置功能进行扫描。

## 📁 POC 分类

我们按照以下分类整理 POC：

- **Nuclei**
  - 按权重最高tags字段进行分类
- **Goby**
  - 按VulType字段进行分类

## 📜 许可证

本项目使用 [MIT License](LICENSE) 进行授权。请自由地享受和参与项目！

## ❤️ 致谢

感谢所有为本项目做出贡献的社区成员，以及 [Nuclei](https://github.com/projectdiscovery/nuclei) 和 [Goby](https://gobysec.net/) 的开发团队。

---

如果您觉得本项目对您有帮助，请给我们一个 ⭐️ Star！我们非常欢迎您的反馈和建议！😊

```

### 说明

1. **项目简介**部分简要介绍了项目的目的和内容。
2. **安装与使用**部分提供了如何安装和使用项目中的 POC。
3. **POC 分类**部分列出了整理的 POC 类型。
5. **许可证和致谢**提供了项目的版权信息和感谢声明。