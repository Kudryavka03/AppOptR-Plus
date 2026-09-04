# AppOptR

#### 介绍
Android 应用 CPU 亲和性管理工具

 **使用说明请参考** 

http://appopt.suto.top

### 模块说明

| 模块 | 功能 |
|------|------|
| `main.rs` | 程序入口，CLI 解析与双模式主循环编排 |
| `config.rs` | 配置解析、inotify 热加载与降级轮询 |
| `cpuset.rs` | CPU 拓扑检测与 cpuset 管理 |
| `rule_edit.rs` | 规则匹配、规则增删改与归一化 |
| `apply_affinity.rs` | 亲和性应用 |
| `cache.rs` | 统一缓存 |
| `ebpf_mode.rs` | eBPF 事件驱动 |
| `proc_mode.rs` | Proc 轮询模式 |
| `web.rs` | 轻量 HTTP 管理面板服务 |
| `appopt-ebpf` | eBPF 内核态 |

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c <file>` | 指定配置文件路径 | `./applist.conf` |
| `-s <seconds>` | 检查间隔（秒，≥1） | `2` |
| `-b <name>` | 指定 BASE_CPUSET 目录名（不可含 `/`） | `AppOpt` |
| `-v` | 显示版本信息 | — |
| `-h` | 显示帮助 | — |

### 请作者杯咖啡
![请作者喝咖啡](请作者杯咖啡.png)
