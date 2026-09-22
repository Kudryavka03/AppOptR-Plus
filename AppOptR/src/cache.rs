use std::collections::HashMap;

use crate::apply_affinity::affinity_set;
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, CpuTopology};
use crate::rule_match::{comm_to_pkg, thread_affinity};
use crate::tuning;

pub struct TaskEntry {
    pub pid: i32,
    pub pkg: String,
    pub comm: String,
    /// None means this task is retained for memory/UCLAMP/nice tuning only;
    /// it must not have its affinity reset as a side effect.
    pub cpus: Option<CpuSet>,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// 双模式共用进程缓存，eBPF 事件驱动增量维护，proc 模式触发全量重建
pub struct ProcCache {
    pub tasks: HashMap<i32, TaskEntry>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.tasks.clear();
    }

    pub fn task_del(&mut self, tid: i32) {
        self.tasks.remove(&tid);
    }

    /// comm 匹配包名，线程名时回退主线程条目
    pub fn pkg_lookup_comm(&self, pid: i32, comm: &str, cfg: &AppConfig) -> Option<String> {
        comm_to_pkg(pid, comm, cfg).or_else(|| self.tasks.get(&pid).map(|e| e.pkg.clone()))
    }

    /// Apply scheduler/memory tuning independently from CPU affinity. A task
    /// with only a tuning rule is deliberately cached too, so later thread
    /// creation and periodic correction remain observable.
    pub fn task_apply<F>(
        &mut self,
        tid: i32,
        pid: i32,
        pkg: &str,
        comm: &str,
        cfg: &AppConfig,
        apply_fn: F,
    ) -> bool
    where
        F: FnOnce(i32, &CpuSet, &str) -> bool,
    {
        let thread_name = if cfg.has_thread_rules.contains(pkg) {
            comm
        } else {
            ""
        };
        let affinity = thread_affinity(pkg, thread_name, cfg);
        let tuning_matched = tuning::apply_task(tid, pid, pkg, thread_name);
        if affinity.is_none() && !tuning_matched {
            return false;
        }

        let (cpus, cpuset_dir, is_thread_rule) = if let Some(result) = affinity {
            if !result.is_thread_rule && self.tasks.get(&tid).is_some_and(|old| old.is_thread_rule)
            {
                // A package fallback must not overwrite an already matched
                // thread rule, but keep applying its independent tuning.
                let old = self.tasks.get(&tid).unwrap();
                (old.cpus, old.cpuset_dir.clone(), old.is_thread_rule)
            } else {
                let dead = apply_fn(tid, &result.cpus, &result.cpuset_dir);
                if dead {
                    self.tasks.remove(&tid);
                    return false;
                }
                (Some(result.cpus), result.cpuset_dir, result.is_thread_rule)
            }
        } else {
            (None, String::new(), false)
        };

        self.tasks.insert(
            tid,
            TaskEntry {
                pid,
                pkg: pkg.to_string(),
                comm: thread_name.to_string(),
                cpus,
                cpuset_dir,
                is_thread_rule,
            },
        );
        true
    }

    /// 遍历 tasks 应用亲和性，返回 dead_tids 供 eBPF 调用方清理 APPLIED_MAP
    pub fn affinity_sync(&mut self, topo: &CpuTopology) -> Vec<i32> {
        let dead_tids: Vec<i32> = self
            .tasks
            .iter()
            .filter_map(|(tid, e)| {
                tuning::reapply_thread(*tid, &e.pkg, &e.comm);
                match e.cpus {
                    Some(cpus) if affinity_set(*tid, &cpus, &e.cpuset_dir, topo) => Some(*tid),
                    Some(_) => None,
                    None => {
                        let alive = unsafe { libc::kill(*tid, 0) } == 0
                            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                        (!alive).then_some(*tid)
                    }
                }
            })
            .collect();
        for tid in &dead_tids {
            self.task_del(*tid);
        }
        dead_tids
    }
}
