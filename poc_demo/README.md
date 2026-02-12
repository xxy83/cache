# JWKSET Race Condition Vulnerability POC

## 漏洞描述

这是一个关于JWK Set密钥刷新过程中的race condition漏洞。当远程JWKS服务器撤销（删除）某个密钥并添加新密钥时，在密钥刷新期间会出现一个时间窗口，在这个窗口内被撤销的密钥仍然可以被访问。

## 漏洞影响

- **安全风险**: 已撤销/泄露的密钥在刷新期间仍可用于身份验证
- **密钥轮换失效**: 密钥轮换不能立即使旧密钥失效
- **时间窗口攻击**: 攻击者可利用这个并发时间窗口使用已撤销的密钥

## 漏洞根源

### 有漏洞的代码逻辑（修复前）

```go
// ❌ 错误的实现顺序
func refresh(ctx context.Context) error {
    // 1. 从远程获取新的JWKS
    jwks := fetchRemoteJWKS()
    
    // 2. 先写入新密钥
    for _, key := range jwks.Keys {
        store.KeyWrite(ctx, key)  // ⚠️ 新密钥已写入
    }
    
    // 3. 后删除旧密钥
    // ⚠️ 问题：在这个时间点，新密钥和旧密钥同时存在！
    for _, oldKey := range oldKeys {
        if !existsInNewKeys(oldKey) {
            store.KeyDelete(ctx, oldKey)  // 被撤销的密钥此时仍可读
        }
    }
}
```

### 修复后的代码逻辑（当前版本）

```go
// ✅ 正确的实现顺序 (storage.go:265-289)
func refresh(ctx context.Context) error {
    // 1. 从远程获取新的JWKS
    jwks := fetchRemoteJWKS()
    
    // 2. 先读取所有现有密钥
    existingKeys, err := store.KeyReadAll(options.Ctx)
    
    // 3. 删除所有旧密钥（完全清空）
    for _, existing := range existingKeys {
        store.KeyDelete(options.Ctx, existing.Marshal().KID)
    }
    
    // 4. 然后写入新密钥
    for _, marshal := range jwks.Keys {
        jwk := NewJWKFromMarshal(marshal, ...)
        store.KeyWrite(options.Ctx, jwk)
    }
    // ✅ 确保被撤销的密钥不会与新密钥共存
}
```

## POC测试场景

### 场景设置

1. **初始状态**: 服务器只有一个密钥 `"old"`
2. **密钥撤销**: 服务器切换到2000个新密钥（不包含`"old"`）
3. **自动刷新**: 客户端每10ms自动刷新JWKS
4. **并发测试**: 在新密钥出现后，检查旧密钥是否仍可访问

### 预期行为

✅ **正确**: 一旦新密钥`"new-0"`可读，旧密钥`"old"`应该立即不可读  
❌ **错误**: 新密钥出现后，旧密钥仍然可读（存在race condition）

## 运行POC

```bash
cd poc_demo
go run -mod=mod main.go
```

## POC输出解释

### 修复后的输出（当前版本）

```
[*] Step 8: CRITICAL TEST - Checking if revoked key 'old' is still accessible
    Expected: Key 'old' should NOT be readable (it was revoked)
    Actual:   Key 'old' is NOT readable ✓

✓ No vulnerability detected - revoked key properly removed
```

### 有漏洞版本的预期输出

```
[*] Step 8: CRITICAL TEST - Checking if revoked key 'old' is still accessible
    Expected: Key 'old' should NOT be readable (it was revoked)
    Actual:   Key 'old' is STILL READABLE! ❌

======================================================================
🔥 VULNERABILITY CONFIRMED 🔥
======================================================================

The revoked key 'old' is still accessible even after new keys appeared!
This is a RACE CONDITION vulnerability.
```

## 修复方案

核心修复策略：**原子性替换** - 确保密钥集合的替换是原子性的

1. **先清空后写入**: 删除所有旧密钥 → 写入所有新密钥
2. **避免部分状态**: 防止新旧密钥混合存在的中间状态
3. **使用锁保护**: 确保整个替换过程在锁的保护下完成

## 代码diff对比

查看修复的详细代码变更：

```bash
# 查看storage.go中的修复
git log --all --oneline --grep="revoked\|refresh\|race" -- storage.go
git diff <commit-hash> storage.go
```

## 时序图

### 有漏洞的时序

```
Time →
Server: [old] ────────→ [new-0, new-1, ..., new-1999]
                  ↓
Client:       fetch
              ↓
         write new keys first
              ↓
         [old, new-0, new-1, ...]  ← ⚠️ old + new 共存
              ↓
         delete old keys
              ↓
         [new-0, new-1, ...]
```

### 修复后的时序

```
Time →
Server: [old] ────────→ [new-0, new-1, ..., new-1999]
                  ↓
Client:       fetch
              ↓
         delete all existing keys
              ↓
         []  ← 清空状态
              ↓
         write new keys
              ↓
         [new-0, new-1, ...]  ← ✅ 只有新密钥
```

## 相关文件

- `main.go` - POC主程序
- `/src/jwkset/storage.go:265-289` - 修复代码位置
- `/ssebench/diffs/test.diff` - 原始测试用例

## 参考

- CVE编号: (待分配)
- 修复提交: (参考git log)
- 相关Issue: (如果有)
