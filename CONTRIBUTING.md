# Contributing

保持提交可审计：每个提交应只解决一个可描述的问题，并包含对应测试或文档。提交前运行：

```text
moon fmt
moon check --deny-warn
moon test
moon run cmd/main
```

不要把私有密钥、真实证书或未公开日志数据提交到仓库。新增协议能力时，先更新 `docs/protocol-boundary.md` 和负面测试，再更新 README。
