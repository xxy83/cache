# POC 使用指南

## 快速开始

### 一键运行所有POC

```bash
cd poc_demo
./run_poc.sh
```

这将运行两个POC演示：
1. **对比POC**: 展示有漏洞版本 vs 修复版本
2. **库测试POC**: 验证当前jwkset库是否已修复

## 单独运行POC

### POC 1: 漏洞对比演示（推荐新手）

这个POC最容易理解，清楚地展示了问题所在：

```bash
cd poc_demo
go run -mod=mod vulnerable_version.go
```

**你会看到什么**:
- TEST 1显示有漏洞的实现，会输出"🔥 VULNERABILITY CONFIRMED"
- TEST 2显示修复后的实现，会输出"✅ CORRECT"

### POC 2: 真实库测试

测试实际的jwkset库（已修复）：

```bash
cd poc_demo
go run -mod=mod main.go
```

**你会看到什么**:
- 8个步骤的测试流程
- 最后显示"✓ No vulnerability detected"

## 文件说明

```
poc_demo/
├── run_poc.sh              # 一键运行脚本
├── vulnerable_version.go   # 对比演示POC（推荐看这个）
├── main.go                 # 真实库测试POC
├── README.md              # 详细技术文档
└── USAGE.md               # 本文件（使用指南）
```

## POC原理

### 漏洞场景

1. **初始状态**: 服务器有一个密钥 "old"
2. **密钥轮换**: 服务器切换到新密钥集（不包含"old"）
3. **自动刷新**: 客户端定期刷新JWKS
4. **Race Condition**: 在有漏洞的版本中，新密钥和旧密钥会短暂共存

### 核心问题

```go
// ❌ 错误顺序
写入新密钥()
删除旧密钥()  // 在这之前，old和new共存！

// ✅ 正确顺序  
删除旧密钥()  // 先清空
写入新密钥()  // 再写入，确保原子性
```

## 验证方法

### 验证有漏洞版本

在`vulnerable_version.go`的输出中查找：

```
❌ Key 'old' is STILL READABLE!
🔥 VULNERABILITY CONFIRMED 🔥
```

### 验证修复版本

在`vulnerable_version.go`的输出中查找：

```
✅ CORRECT: Revoked key properly removed before new keys added
```

或在`main.go`的输出中查找：

```
✓ No vulnerability detected - revoked key properly removed
```

## 自定义测试

### 调整新密钥数量

编辑`vulnerable_version.go`或`main.go`，修改：

```go
const n = 100  // 改为你想要的数量
```

- **更多密钥** = 更大的时间窗口 = 更容易捕获race condition
- **更少密钥** = 更小的时间窗口 = 更难捕获race condition

### 调整刷新间隔

在`main.go`中修改：

```go
RefreshInterval: 10 * time.Millisecond,  // 改为你想要的间隔
```

### 调整检测延迟

在`vulnerable_version.go`中修改：

```go
time.Sleep(2 * time.Millisecond)  // 改为你想要的延迟
```

## 故障排查

### 问题: "go: inconsistent vendoring"

**解决方案**: 使用 `-mod=mod` 标志

```bash
go run -mod=mod vulnerable_version.go
```

### 问题: POC没有捕获到race condition

**原因**: 时间窗口太小

**解决方案**: 增加新密钥数量
```go
const n = 2000  // 增加到2000
```

### 问题: 找不到go命令

**解决方案**: 安装Go

```bash
# Ubuntu/Debian
sudo apt-get install golang

# macOS
brew install go
```

## 查看源代码

### 修复代码位置

```bash
# 查看修复后的代码
cat ../storage.go | sed -n '265,289p'
```

### 原始测试用例

```bash
# 查看原始test.diff
cat /ssebench/diffs/test.diff
```

## 输出说明

### 符号含义

- ✓ : 预期行为，测试通过
- ❌ : 异常行为，发现漏洞
- ⚠️  : 警告信息
- 🔥 : 严重问题
- ✅ : 修复验证通过
- 💡 : 提示信息

### 日志级别

```
[*] : 信息性消息
    ✓ : 成功/正常
    ❌ : 失败/异常
```

## 进阶使用

### 使用race detector

Go内置了race detector，可以检测race condition：

```bash
go run -race -mod=mod vulnerable_version.go
```

注意：这个POC的race condition是逻辑层面的，不是内存访问层面的，所以race detector可能不会报告。

### 增加日志详细度

在代码中添加更多打印语句来观察执行顺序：

```go
fmt.Printf("[DEBUG] Writing key: %s\n", kid)
fmt.Printf("[DEBUG] Deleting key: %s\n", kid)
```

### 使用debugger

```bash
dlv debug vulnerable_version.go
(dlv) break testVulnerable
(dlv) continue
```

## 相关资源

- **项目仓库**: https://github.com/MicahParks/jwkset
- **详细文档**: `README.md`
- **总结文档**: `../RACE_CONDITION_POC.md`
- **原始测试**: `/ssebench/diffs/test.diff`

## 联系与反馈

如果你有问题或发现新的问题，请查看项目的issue tracker。

---

**最后更新**: 2026-02-12
