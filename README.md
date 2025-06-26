# QaFuzz - 测试域名自动化挖掘工具

[![GitHub Stars](https://img.shields.io/github/stars/darkfiv/QaFuzz?style=for-the-badge)](https://github.com/darkfiv/QaFuzz/stargazers)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/darkfiv/QaFuzz?style=for-the-badge)](https://github.com/darkfiv/QaFuzz/commits/main)


## 工具概述
QaFuzz是一款专为安全研究人员设计的自动化工具，用于发现企业测试环境暴露在公网的子域名。通过智能生成测试域名、验证DNS解析和响应状态，帮助挖掘潜在的安全漏洞。

## ✨ 功能特性

<div align="center">

| 🎯 智能生成 | 🔍 精准验证 | 🤝 工具联动 |
|------------|------------|------------|
| 自动组合test/dev/stage等子域名 | 验证DNS解析为外网IP | OneScan｜APiKit等 |


</div>



## 运行效果
![运行示例](/img/vuln1.png)  <!-- 请将截图保存至此路径 -->

## 工具安装
### Burp Suite插件导入即可
1. 安装`QaFuzz`的Burp扩展
2. 在Burp中右键目标域名 → "Send to QaFuzz"

## 最佳实践
1. 结合Burp Suite使用：将发现的可疑请求直接发送到QaFuzz
2. 联动漏洞扫描工具：将QaFuzz扫描结果发送到OneScan/ApiKit等工具
3. 定期更新子域名字典：添加企业特有的测试环境命名习惯

## 贡献
欢迎提交Issue或Pull Request


## 📊 项目统计
![GitHub Star趋势图](https://starchart.cc/darkfiv/QaFuzz.svg)
