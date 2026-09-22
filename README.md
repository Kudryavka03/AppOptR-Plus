# AppOptR

#### 介绍

Android / KernelSU 环境下的应用调度管理工具。原有 CPU 亲和性规则继续保存在
applist.conf；从 v2.3 起，内存 cgroup、UCLAMP 和 nice 调优使用独立的
AppOpt.tuning.json，可在内置网页中编辑并即时生效。

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

### 新增：内存与线程调优

网页的“调优”页将配置原子写入 AppOpt.tuning.json。其模型分为两层：

1. **内存组**：定义一个已有 cgroup 的安全路径及其参数。路径可以是
   /dev/memcg 或 /sys/fs/cgroup 下的绝对路径，或相对于检测到的内存 cgroup
   根目录的路径。支持 {uid}、{pid}、{pkg} 占位符。
2. **应用调优**：把一个包名关联到内存组，并可添加多条线程规则。线程名支持
   glob，例如 Render*。

示例配置：

    {
      "version": 1,
      "memory_groups": [
        {
          "name": "game",
          "path": "mimd/uid_{uid}",
          "swappiness": 10,
          "memory_low": "512M",
          "memory_high": "1G",
          "memory_max": "2G"
        }
      ],
      "apps": [
        {
          "pkg": "com.example.game",
          "memory_group": "game",
          "threads": [
            {
              "pattern": "RenderThread",
              "uclamp_min": 512,
              "uclamp_max": 1024,
              "nice": -10
            }
          ]
        }
      ]
    }

运行时会探测 cgroup 接口：

- memory.swappiness 只在实际暴露该 v1 memcg 文件时写入；cgroup v2 不会
  退化为修改全局 vm.swappiness。
- 支持 memory.min、memory.low（v1 回退 memory.soft_limit_in_bytes）、
  memory.high、memory.max（v1 回退 memory.limit_in_bytes）和
  memory.oom.group。设备不支持的字段会显示在网页“运行提示”中。
- 应用迁移只写入命中进程的 cgroup.procs，或 v1 tasks 中该进程的线程；
  不会把同 UID 的其他应用一起迁走。
- UCLAMP 经 sched_getattr / sched_setattr 直接设置，nice 经 setpriority
  设置。UCLAMP 范围为 0..1024，nice 范围为 -20..19。为避免设备卡死或
  不可预期的抢占，未提供 SCHED_FIFO/RR 实时策略。

线程 comm 在常见 Android/Linux 内核中最多为 15 字节；网页会用当前运行
应用实际发现的线程名提供提示，并在保存时拒绝超过该上限的模式。

### KernelSU 打包与安装

仓库提供 arm64 KernelSU ZIP 打包脚本。它会构建 Android 用户态 ELF 与 eBPF
对象，再把两个同级文件、安装脚本和 Manager WebUI 跳转页放入 ZIP 根目录。

    .\scripts\package-ksu.ps1

输出为 out/AppOptR-Plus-v2.3.0-arm64.zip，可直接在 KernelSU Manager 中安装，
不能用于 Recovery。安装脚本会拒绝非 arm64 设备。

模块服务通过 APPOPT_STATE_DIR 将可变文件保存在
/data/adb/appoptr-plus，而非会在升级时替换的模块目录。因此 AppOpt.json、
AppOpt.tuning.json 与 applist.conf 会跨模块更新保留。卸载会停止已验证属于本
模块的守护进程，但保留该状态目录，方便重新安装恢复配置；如需彻底删除，可在
确认不再需要规则后手动删除该目录。

KernelSU Manager 的 WebUI 按钮会先尝试启动服务，再跳转到
http://127.0.0.1:8889/。首次启动较慢时可等待片刻或使用跳转页中的手动链接。

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
