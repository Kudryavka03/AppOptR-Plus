//! Per-application memory and scheduler tuning.
//!
//! CPU affinity deliberately remains in the legacy text configuration. These
//! knobs are structured because a line-oriented format cannot safely represent
//! an application, a reusable memory cgroup, and multiple thread rules.

use std::collections::HashSet;
use std::env;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, RwLock};

use serde_json::{Value, json};

use crate::apply_affinity::task_tids;
use crate::{MAX_PKG_LEN, MAX_THREAD_LEN};

/// Kept separate from AppOpt.json so existing settings and applist.conf remain
/// backwards compatible and manually editable.
pub const TUNING_FILE_NAME: &str = "AppOpt.tuning.json";

/// Module launchers can set APPOPT_STATE_DIR to keep mutable configuration
/// outside an updatable module directory. Standalone use keeps the historical
/// relative-file behavior.
pub fn state_file(name: &str) -> String {
    let state_dir = env::var("APPOPT_STATE_DIR")
        .ok()
        .filter(|dir| !dir.is_empty() && !dir.bytes().any(|byte| byte == 0 || byte < 0x20));
    state_dir.map_or_else(
        || format!("./{}", name),
        |dir| PathBuf::from(dir).join(name).to_string_lossy().into_owned(),
    )
}

pub fn tuning_file() -> String {
    state_file(TUNING_FILE_NAME)
}

#[derive(Clone, Default)]
pub struct MemoryGroup {
    pub name: String,
    /// An existing cgroup path, either absolute or relative to a detected
    /// memory cgroup root. The {uid}, {pid}, and {pkg} tokens are expanded at
    /// run time, so one definition can safely map each app to its own uid group.
    pub path: String,
    pub swappiness: Option<u8>,
    pub memory_min: Option<String>,
    pub memory_low: Option<String>,
    pub memory_high: Option<String>,
    pub memory_max: Option<String>,
    pub oom_group: Option<bool>,
}

#[derive(Clone, Default)]
pub struct ThreadTuneRule {
    /// POSIX fnmatch pattern. A plain thread comm is an exact match.
    pub pattern: String,
    pub uclamp_min: Option<u16>,
    pub uclamp_max: Option<u16>,
    /// Linux nice value, not a realtime priority.
    pub nice: Option<i8>,
}

#[derive(Clone, Default)]
pub struct AppTuneRule {
    pub pkg: String,
    pub memory_group: Option<String>,
    pub threads: Vec<ThreadTuneRule>,
}

#[derive(Clone, Default)]
pub struct TuningConfig {
    pub memory_groups: Vec<MemoryGroup>,
    pub apps: Vec<AppTuneRule>,
}

#[derive(Default)]
struct EffectiveThreadTune {
    uclamp_min: Option<u16>,
    uclamp_max: Option<u16>,
    nice: Option<i8>,
}

static TUNING_CONFIG: LazyLock<RwLock<Arc<TuningConfig>>> =
    LazyLock::new(|| RwLock::new(Arc::new(TuningConfig::default())));
static WARNING_KEYS: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));
static WARNINGS: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static TUNING_SAVE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn config_snapshot() -> Arc<TuningConfig> {
    TUNING_CONFIG
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn replace_config(config: TuningConfig) {
    *TUNING_CONFIG.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(config);
    WARNING_KEYS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    WARNINGS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

fn warn_once(key: impl Into<String>, message: impl Into<String>) {
    let key = key.into();
    let message = message.into();
    let mut seen = WARNING_KEYS.lock().unwrap_or_else(|e| e.into_inner());
    if !seen.insert(key) {
        return;
    }
    drop(seen);
    eprintln!("调优: {}", message);
    let mut warnings = WARNINGS.lock().unwrap_or_else(|e| e.into_inner());
    warnings.push(message);
    if warnings.len() > 20 {
        warnings.remove(0);
    }
}

pub fn app_package_names() -> HashSet<String> {
    config_snapshot()
        .apps
        .iter()
        .map(|app| app.pkg.clone())
        .collect()
}

pub fn thread_rule_packages() -> HashSet<String> {
    config_snapshot()
        .apps
        .iter()
        .filter(|app| !app.threads.is_empty())
        .map(|app| app.pkg.clone())
        .collect()
}

pub fn app_count() -> usize {
    config_snapshot().apps.len()
}

pub fn thread_rule_count() -> usize {
    config_snapshot()
        .apps
        .iter()
        .map(|app| app.threads.len())
        .sum()
}

fn plain_token_ok(value: &str, max_len: usize) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() < max_len
        && !value.bytes().any(|b| b < 0x20 || b == 0x7f)
        && !value.contains('#')
        && !value.contains("//")
}

pub fn package_name_ok(value: &str) -> bool {
    plain_token_ok(value, MAX_PKG_LEN)
        && !value.chars().any(|ch| matches!(ch, '{' | '}' | '\\'))
        && !value.contains('/')
}

fn group_name_ok(value: &str) -> bool {
    plain_token_ok(value, 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn thread_pattern_ok(value: &str) -> bool {
    // task comm is normally 15 bytes. A wildcard can still be useful, but a
    // longer literal cannot possibly match, so reject it at save time.
    value.len() <= 15 && plain_token_ok(value, MAX_THREAD_LEN) && !value.contains('\0')
}

fn cgroup_template_ok(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.len() >= 256
        || value.bytes().any(|b| b < 0x20 || b == 0x7f)
        || value.contains('\\')
    {
        return false;
    }

    let expanded_markers = value
        .replace("{uid}", "x")
        .replace("{pid}", "x")
        .replace("{pkg}", "x");
    if expanded_markers.contains('{') || expanded_markers.contains('}') {
        return false;
    }

    let absolute = value.starts_with('/');
    if absolute
        && !["/dev/memcg", "/sys/fs/cgroup"]
            .iter()
            .any(|root| value.starts_with(&format!("{}/", root)))
    {
        return false;
    }
    if !absolute && value.starts_with('/') {
        return false;
    }

    value
        .split('/')
        .filter(|part| !part.is_empty())
        .all(|part| part != "." && part != "..")
}

fn optional_string(value: &Value, field: &str, max_len: usize) -> Result<Option<String>, String> {
    let Some(value) = value.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(value) = value.as_str() else {
        return Err(format!("{} 必须是字符串", field));
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() >= max_len || value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("{} 格式无效", field));
    }
    Ok(Some(value.to_string()))
}

fn optional_u64(value: &Value, field: &str, max: u64) -> Result<Option<u64>, String> {
    let Some(value) = value.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(value) = value.as_u64() else {
        return Err(format!("{} 必须是整数", field));
    };
    if value > max {
        return Err(format!("{} 超出范围", field));
    }
    Ok(Some(value))
}

fn optional_i64(value: &Value, field: &str, min: i64, max: i64) -> Result<Option<i64>, String> {
    let Some(value) = value.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(value) = value.as_i64() else {
        return Err(format!("{} 必须是整数", field));
    };
    if !(min..=max).contains(&value) {
        return Err(format!("{} 超出范围", field));
    }
    Ok(Some(value))
}

/// Normalize a human-friendly byte value before it is written to a cgroup
/// control. The kernel receives plain bytes, or max for memory.max.
fn memory_limit(value: &Value, field: &str, allow_max: bool) -> Result<Option<String>, String> {
    let Some(raw) = optional_string(value, field, 64)? else {
        return Ok(None);
    };
    let raw = raw.to_ascii_lowercase();
    if raw == "max" {
        return allow_max
            .then_some(Some("max".to_string()))
            .ok_or_else(|| format!("{} 不支持 max", field));
    }

    let suffixes: [(&str, u64); 12] = [
        ("tib", 1_u64 << 40),
        ("tb", 1_u64 << 40),
        ("t", 1_u64 << 40),
        ("gib", 1_u64 << 30),
        ("gb", 1_u64 << 30),
        ("g", 1_u64 << 30),
        ("mib", 1_u64 << 20),
        ("mb", 1_u64 << 20),
        ("m", 1_u64 << 20),
        ("kib", 1_u64 << 10),
        ("kb", 1_u64 << 10),
        ("k", 1_u64 << 10),
    ];
    let (digits, multiplier) = suffixes
        .iter()
        .find_map(|(suffix, multiplier)| {
            raw.strip_suffix(suffix).map(|digits| (digits, *multiplier))
        })
        .unwrap_or((raw.as_str(), 1));
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{} 应为字节数或 512M / 1G 形式", field));
    }
    let bytes = digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .ok_or_else(|| format!("{} 数值过大", field))?;
    Ok(Some(bytes.to_string()))
}

fn memory_group_from_value(value: &Value) -> Result<MemoryGroup, String> {
    let Some(object) = value.as_object() else {
        return Err("内存组必须是对象".to_string());
    };
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| group_name_ok(name))
        .ok_or_else(|| "内存组 name 无效".to_string())?
        .to_string();
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|path| cgroup_template_ok(path))
        .ok_or_else(|| format!("内存组 {} 的 path 无效", name))?
        .to_string();

    let swappiness = optional_u64(value, "swappiness", 200)?.map(|value| value as u8);
    let memory_min = memory_limit(value, "memory_min", false)?;
    let memory_low = memory_limit(value, "memory_low", false)?;
    let memory_high = memory_limit(value, "memory_high", false)?;
    let memory_max = memory_limit(value, "memory_max", true)?;
    let oom_group = match object.get("oom_group") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(value)) => Some(*value),
        Some(_) => return Err(format!("内存组 {} 的 oom_group 必须是布尔值", name)),
    };

    Ok(MemoryGroup {
        name,
        path,
        swappiness,
        memory_min,
        memory_low,
        memory_high,
        memory_max,
        oom_group,
    })
}

fn thread_rule_from_value(value: &Value) -> Result<ThreadTuneRule, String> {
    let Some(object) = value.as_object() else {
        return Err("线程规则必须是对象".to_string());
    };
    let pattern = object
        .get("pattern")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|pattern| thread_pattern_ok(pattern))
        .ok_or_else(|| "线程 pattern 无效（task comm 最长通常为 15 字节）".to_string())?
        .to_string();
    let uclamp_min = optional_u64(value, "uclamp_min", 1024)?.map(|value| value as u16);
    let uclamp_max = optional_u64(value, "uclamp_max", 1024)?.map(|value| value as u16);
    let nice = optional_i64(value, "nice", -20, 19)?.map(|value| value as i8);
    if uclamp_min.is_none() && uclamp_max.is_none() && nice.is_none() {
        return Err(format!("线程 {} 没有设置任何调优参数", pattern));
    }
    if let (Some(min), Some(max)) = (uclamp_min, uclamp_max)
        && min > max
    {
        return Err(format!("线程 {} 的 UCLAMP min 不能大于 max", pattern));
    }
    Ok(ThreadTuneRule {
        pattern,
        uclamp_min,
        uclamp_max,
        nice,
    })
}

fn app_from_value(value: &Value) -> Result<AppTuneRule, String> {
    let Some(object) = value.as_object() else {
        return Err("应用调优必须是对象".to_string());
    };
    let pkg = object
        .get("pkg")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|pkg| package_name_ok(pkg))
        .ok_or_else(|| "应用 pkg 无效".to_string())?
        .to_string();
    let memory_group = match object.get("memory_group") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if value.trim().is_empty() => None,
        Some(Value::String(value)) if group_name_ok(value.trim()) => Some(value.trim().to_string()),
        Some(_) => return Err(format!("应用 {} 的 memory_group 无效", pkg)),
    };
    let threads = match object.get("threads") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(thread_rule_from_value)
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(format!("应用 {} 的 threads 必须是数组", pkg)),
    };
    if memory_group.is_none() && threads.is_empty() {
        return Err(format!("应用 {} 至少要关联内存组或添加一条线程规则", pkg));
    }
    Ok(AppTuneRule {
        pkg,
        memory_group,
        threads,
    })
}

pub fn config_from_value(value: &Value) -> Result<TuningConfig, String> {
    let Some(object) = value.as_object() else {
        return Err("调优配置必须是 JSON 对象".to_string());
    };
    let memory_groups = match object.get("memory_groups") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(groups)) => groups
            .iter()
            .map(memory_group_from_value)
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err("memory_groups 必须是数组".to_string()),
    };
    let mut group_names = HashSet::new();
    for group in &memory_groups {
        if !group_names.insert(group.name.clone()) {
            return Err(format!("内存组 {} 重复", group.name));
        }
    }

    let apps = match object.get("apps") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(apps)) => apps
            .iter()
            .map(app_from_value)
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err("apps 必须是数组".to_string()),
    };
    let mut packages = HashSet::new();
    for app in &apps {
        if !packages.insert(app.pkg.clone()) {
            return Err(format!("应用 {} 重复", app.pkg));
        }
        if let Some(group) = &app.memory_group
            && !group_names.contains(group)
        {
            return Err(format!("应用 {} 引用了不存在的内存组 {}", app.pkg, group));
        }
    }
    Ok(TuningConfig {
        memory_groups,
        apps,
    })
}

fn opt_value(value: Option<&String>) -> Value {
    value.map_or(Value::Null, |value| Value::String(value.clone()))
}

fn memory_group_value(group: &MemoryGroup) -> Value {
    json!({
        "name": group.name,
        "path": group.path,
        "swappiness": group.swappiness,
        "memory_min": opt_value(group.memory_min.as_ref()),
        "memory_low": opt_value(group.memory_low.as_ref()),
        "memory_high": opt_value(group.memory_high.as_ref()),
        "memory_max": opt_value(group.memory_max.as_ref()),
        "oom_group": group.oom_group,
    })
}

fn thread_rule_value(rule: &ThreadTuneRule) -> Value {
    json!({
        "pattern": rule.pattern,
        "uclamp_min": rule.uclamp_min,
        "uclamp_max": rule.uclamp_max,
        "nice": rule.nice,
    })
}

fn app_value(app: &AppTuneRule) -> Value {
    json!({
        "pkg": app.pkg,
        "memory_group": app.memory_group,
        "threads": app.threads.iter().map(thread_rule_value).collect::<Vec<_>>(),
    })
}

pub fn config_value(config: &TuningConfig) -> Value {
    json!({
        "version": 1,
        "memory_groups": config.memory_groups.iter().map(memory_group_value).collect::<Vec<_>>(),
        "apps": config.apps.iter().map(app_value).collect::<Vec<_>>(),
    })
}

fn write_config(path: &str, config: &TuningConfig) -> Result<(), String> {
    let text = serde_json::to_string_pretty(&config_value(config))
        .map_err(|error| format!("JSON 序列化失败: {}", error))?;
    let tmp = format!("{}.tmp", path);
    fs::File::create(&tmp)
        .and_then(|mut file| {
            file.write_all(format!("{}\n", text).as_bytes())?;
            file.sync_all()
        })
        .and_then(|_| fs::rename(&tmp, path))
        .map_err(|error| format!("写入 {} 失败: {}", path, error))
}

pub fn load_file(path: &str) {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text)
            .map_err(|error| format!("JSON 格式错误: {}", error))
            .and_then(|value| config_from_value(&value))
        {
            Ok(config) => {
                println!(
                    "调优配置已加载：{} 个内存组，{} 个应用",
                    config.memory_groups.len(),
                    config.apps.len()
                );
                replace_config(config);
            }
            Err(error) => {
                replace_config(TuningConfig::default());
                warn_once(
                    "tuning-config-invalid",
                    format!("{} 无效，已忽略：{}", path, error),
                );
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let config = TuningConfig::default();
            let created = write_config(path, &config);
            replace_config(config);
            match created {
                Ok(()) => println!("调优配置不存在，已创建: {}", path),
                Err(error) => warn_once("tuning-config-create", error),
            }
        }
        Err(error) => {
            replace_config(TuningConfig::default());
            warn_once(
                "tuning-config-read",
                format!("读取 {} 失败，已忽略调优规则：{}", path, error),
            );
        }
    }
}

pub fn replace_and_save(path: &str, config: TuningConfig) -> Result<(), String> {
    let _save_guard = TUNING_SAVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    write_config(path, &config)?;
    replace_config(config);
    Ok(())
}

fn cgroup_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for root in ["/dev/memcg", "/sys/fs/cgroup/memory", "/sys/fs/cgroup"] {
        let root = PathBuf::from(root);
        if root.is_dir() && !roots.contains(&root) {
            roots.push(root);
        }
    }
    roots
}

fn cgroup_capabilities() -> Value {
    let roots = cgroup_roots();
    let root_names: Vec<String> = roots
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    let v2 = roots
        .iter()
        .any(|root| root.join("cgroup.controllers").exists());
    let v1_swappiness = roots
        .iter()
        .any(|root| root.join("memory.swappiness").exists());
    json!({
        "memory_roots": root_names,
        "cgroup_v2": v2,
        "v1_swappiness": v1_swappiness,
        "uclamp": cfg!(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "riscv64"
        )),
    })
}

pub fn web_value() -> Value {
    let config = config_snapshot();
    let warnings = WARNINGS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut value = config_value(&config);
    value["ok"] = Value::Bool(true);
    value["capabilities"] = cgroup_capabilities();
    value["warnings"] = json!(warnings);
    value
}

fn process_uid(pid: i32) -> Option<u32> {
    let text = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse().ok())
}

fn expand_group_path(path: &str, pid: i32, pkg: &str) -> Option<String> {
    let uid = if path.contains("{uid}") {
        match process_uid(pid) {
            Some(uid) => uid.to_string(),
            None => {
                warn_once(
                    format!("uid-{}", pid),
                    format!("无法读取 pid {} 的 UID，跳过内存组迁移", pid),
                );
                return None;
            }
        }
    } else {
        String::new()
    };
    Some(
        path.replace("{uid}", &uid)
            .replace("{pid}", &pid.to_string())
            .replace("{pkg}", pkg),
    )
}

fn canonical_cgroup_dir(path: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    let candidate = path.canonicalize().ok()?;
    if !candidate.is_dir() {
        return None;
    }
    roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .find_map(|root| {
            (candidate == root || candidate.starts_with(&root)).then_some(candidate.clone())
        })
}

fn resolve_group_path(group: &MemoryGroup, pid: i32, pkg: &str) -> Option<PathBuf> {
    let path = expand_group_path(&group.path, pid, pkg)?;
    if !cgroup_template_ok(&path) {
        warn_once(
            format!("group-template-{}", group.name),
            format!("内存组 {} 展开后的路径无效", group.name),
        );
        return None;
    }
    let roots = cgroup_roots();
    if roots.is_empty() {
        warn_once(
            "no-memory-cgroup",
            "未发现可用的 memory cgroup 根目录，内存组调优已跳过",
        );
        return None;
    }

    let configured = PathBuf::from(&path);
    let candidates: Vec<PathBuf> = if configured.is_absolute() {
        vec![configured]
    } else {
        roots.iter().map(|root| root.join(&configured)).collect()
    };
    for candidate in candidates {
        if let Some(path) = canonical_cgroup_dir(&candidate, &roots) {
            return Some(path);
        }
    }
    warn_once(
        format!("group-missing-{}-{}", group.name, path),
        format!(
            "内存组 {} 不存在或不在允许的 cgroup 根目录内: {}",
            group.name, path
        ),
    );
    None
}

fn write_control(path: &Path, file_name: &str, value: &str) -> Result<(), String> {
    let path = path.join(file_name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(|error| format!("打开 {} 失败: {}", path.display(), error))?;
    file.write_all(value.as_bytes())
        .map_err(|error| format!("写入 {} 失败: {}", path.display(), error))
}

fn write_first_available(path: &Path, group: &str, names: &[&str], value: &str) {
    let Some(name) = names.iter().copied().find(|name| path.join(name).exists()) else {
        warn_once(
            format!("unsupported-{}-{}", group, names.join("|")),
            format!(
                "内存组 {} 不支持 {}（可能是 cgroup 版本不匹配）",
                group,
                names.join(" / ")
            ),
        );
        return;
    };
    if let Err(error) = write_control(path, name, value) {
        warn_once(
            format!("write-{}-{}-{}", group, name, error),
            format!("内存组 {} 的 {} 设置失败：{}", group, name, error),
        );
    }
}

fn move_process_to_group(pid: i32, path: &Path, group: &str) {
    if path.join("cgroup.procs").exists() {
        if let Err(error) = write_control(path, "cgroup.procs", &pid.to_string()) {
            warn_once(
                format!("move-procs-{}-{}", group, error),
                format!("迁移 pid {} 到内存组 {} 失败：{}", pid, group, error),
            );
        }
        return;
    }
    if !path.join("tasks").exists() {
        warn_once(
            format!("move-no-control-{}", group),
            format!(
                "内存组 {} 不提供 cgroup.procs 或 tasks，无法迁移应用",
                group
            ),
        );
        return;
    }
    for tid in task_tids(pid).unwrap_or_default() {
        if let Err(error) = write_control(path, "tasks", &tid.to_string()) {
            warn_once(
                format!("move-task-{}-{}", group, error),
                format!("迁移 tid {} 到内存组 {} 失败：{}", tid, group, error),
            );
        }
    }
}

fn apply_memory_group(pid: i32, pkg: &str, group: &MemoryGroup) {
    let Some(path) = resolve_group_path(group, pid, pkg) else {
        return;
    };
    if let Some(value) = group.swappiness {
        write_first_available(
            &path,
            &group.name,
            &["memory.swappiness"],
            &value.to_string(),
        );
    }
    if let Some(value) = &group.memory_min {
        write_first_available(&path, &group.name, &["memory.min"], value);
    }
    if let Some(value) = &group.memory_low {
        write_first_available(
            &path,
            &group.name,
            &["memory.low", "memory.soft_limit_in_bytes"],
            value,
        );
    }
    if let Some(value) = &group.memory_high {
        write_first_available(&path, &group.name, &["memory.high"], value);
    }
    if let Some(value) = &group.memory_max {
        write_first_available(
            &path,
            &group.name,
            &["memory.max", "memory.limit_in_bytes"],
            value,
        );
    }
    if let Some(value) = group.oom_group {
        write_first_available(
            &path,
            &group.name,
            &["memory.oom.group"],
            if value { "1" } else { "0" },
        );
    }
    // Move only the matched process. In particular, do not migrate every
    // process sharing its Android UID, unlike the reference shell module.
    move_process_to_group(pid, &path, &group.name);
}

fn pattern_matches(pattern: &str, comm: &str) -> bool {
    if comm.is_empty() || comm.len() >= MAX_THREAD_LEN {
        return false;
    }
    let Ok(pattern) = CString::new(pattern) else {
        return false;
    };
    let Ok(comm) = CString::new(comm) else {
        return false;
    };
    unsafe { libc::fnmatch(pattern.as_ptr(), comm.as_ptr(), libc::FNM_NOESCAPE) == 0 }
}

fn effective_thread_tune(app: &AppTuneRule, comm: &str) -> Option<EffectiveThreadTune> {
    let mut result = EffectiveThreadTune::default();
    let mut matched = false;
    for rule in &app.threads {
        if !pattern_matches(&rule.pattern, comm) {
            continue;
        }
        // Rules are intentionally ordered: a later, more specific rule can
        // override one field of an earlier wildcard rule.
        if rule.uclamp_min.is_some() {
            result.uclamp_min = rule.uclamp_min;
        }
        if rule.uclamp_max.is_some() {
            result.uclamp_max = rule.uclamp_max;
        }
        if rule.nice.is_some() {
            result.nice = rule.nice;
        }
        matched = true;
    }
    matched.then_some(result)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SchedAttr {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
    sched_util_min: u32,
    sched_util_max: u32,
}

const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 0x40;

#[cfg(target_arch = "aarch64")]
const SYS_SCHED_SETATTR: libc::c_long = 274;
#[cfg(target_arch = "aarch64")]
const SYS_SCHED_GETATTR: libc::c_long = 275;
#[cfg(target_arch = "arm")]
const SYS_SCHED_SETATTR: libc::c_long = 380;
#[cfg(target_arch = "arm")]
const SYS_SCHED_GETATTR: libc::c_long = 381;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_SETATTR: libc::c_long = 314;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_GETATTR: libc::c_long = 315;
#[cfg(target_arch = "x86")]
const SYS_SCHED_SETATTR: libc::c_long = 351;
#[cfg(target_arch = "x86")]
const SYS_SCHED_GETATTR: libc::c_long = 352;
#[cfg(target_arch = "riscv64")]
const SYS_SCHED_SETATTR: libc::c_long = 274;
#[cfg(target_arch = "riscv64")]
const SYS_SCHED_GETATTR: libc::c_long = 275;

#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "riscv64"
))]
fn set_uclamp(tid: i32, min: Option<u16>, max: Option<u16>) -> Result<(), String> {
    let mut attr = SchedAttr {
        size: std::mem::size_of::<SchedAttr>() as u32,
        ..Default::default()
    };
    let got = unsafe {
        libc::syscall(
            SYS_SCHED_GETATTR,
            tid as libc::pid_t,
            &mut attr as *mut SchedAttr,
            std::mem::size_of::<SchedAttr>(),
            0_u32,
        )
    };
    if got != 0 {
        return Err(format!(
            "sched_getattr: {}",
            std::io::Error::last_os_error()
        ));
    }
    attr.size = std::mem::size_of::<SchedAttr>() as u32;
    if let Some(min) = min {
        attr.sched_flags |= SCHED_FLAG_UTIL_CLAMP_MIN;
        attr.sched_util_min = min as u32;
    }
    if let Some(max) = max {
        attr.sched_flags |= SCHED_FLAG_UTIL_CLAMP_MAX;
        attr.sched_util_max = max as u32;
    }
    let set = unsafe {
        libc::syscall(
            SYS_SCHED_SETATTR,
            tid as libc::pid_t,
            &attr as *const SchedAttr,
            0_u32,
        )
    };
    if set != 0 {
        return Err(format!(
            "sched_setattr: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "riscv64"
)))]
fn set_uclamp(_tid: i32, _min: Option<u16>, _max: Option<u16>) -> Result<(), String> {
    Err("当前 CPU 架构未定义 sched_setattr 系统调用号".to_string())
}

fn apply_thread_tune(tid: i32, pkg: &str, comm: &str, tune: &EffectiveThreadTune) {
    if let (Some(min), Some(max)) = (tune.uclamp_min, tune.uclamp_max)
        && min > max
    {
        warn_once(
            format!("uclamp-order-{}-{}", pkg, comm),
            format!(
                "{} / {} 的合并 UCLAMP min 大于 max，已跳过 UCLAMP",
                pkg, comm
            ),
        );
    } else if (tune.uclamp_min.is_some() || tune.uclamp_max.is_some())
        && let Err(error) = set_uclamp(tid, tune.uclamp_min, tune.uclamp_max)
    {
        warn_once(
            format!("uclamp-{}-{}", pkg, error),
            format!("{} / {} 设置 UCLAMP 失败：{}", pkg, comm, error),
        );
    }
    if let Some(nice) = tune.nice {
        let result =
            unsafe { libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, nice as i32) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            warn_once(
                format!("nice-{}-{}", pkg, error),
                format!("{} / {} 设置 nice={} 失败：{}", pkg, comm, nice, error),
            );
        }
    }
}

/// Apply one newly observed task. Returns whether the app has any tuning rule,
/// allowing the shared process cache to retain pure tuning targets even when
/// they have no CPU-affinity rule.
pub fn apply_task(tid: i32, pid: i32, pkg: &str, comm: &str) -> bool {
    let config = config_snapshot();
    let Some(app) = config.apps.iter().find(|app| app.pkg == pkg) else {
        return false;
    };
    if tid == pid
        && let Some(group_name) = &app.memory_group
    {
        if let Some(group) = config
            .memory_groups
            .iter()
            .find(|group| &group.name == group_name)
        {
            apply_memory_group(pid, pkg, group);
        } else {
            // This should be impossible after validation, but stale data
            // must never panic in a root daemon.
            warn_once(
                format!("missing-group-{}", group_name),
                format!("应用 {} 引用了不存在的内存组 {}", pkg, group_name),
            );
        }
    }
    if let Some(tune) = effective_thread_tune(app, comm) {
        apply_thread_tune(tid, pkg, comm, &tune);
    }
    true
}

/// Reapply only scheduler knobs during the normal cache correction pass.
/// Memory cgroup migration is done when a process is discovered or after a
/// configuration reload, rather than continuously writing cgroup files.
pub fn reapply_thread(tid: i32, pkg: &str, comm: &str) {
    let config = config_snapshot();
    let Some(app) = config.apps.iter().find(|app| app.pkg == pkg) else {
        return;
    };
    if let Some(tune) = effective_thread_tune(app, comm) {
        apply_thread_tune(tid, pkg, comm, &tune);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_structured_tuning_and_normalizes_memory_units() {
        let value = json!({
            "memory_groups": [{
                "name": "game",
                "path": "mimd/uid_{uid}",
                "swappiness": 10,
                "memory_low": "512M",
                "memory_max": "2G"
            }],
            "apps": [{
                "pkg": "com.example.game",
                "memory_group": "game",
                "threads": [{
                    "pattern": "RenderThread",
                    "uclamp_min": 512,
                    "uclamp_max": 1024,
                    "nice": -10
                }]
            }]
        });
        let config = config_from_value(&value).unwrap();
        assert_eq!(
            config.memory_groups[0].memory_low.as_deref(),
            Some("536870912")
        );
        assert_eq!(
            config.memory_groups[0].memory_max.as_deref(),
            Some("2147483648")
        );
        assert_eq!(config.apps.len(), 1);
    }

    #[test]
    fn rejects_unsafe_cgroup_and_invalid_uclamp() {
        assert!(!cgroup_template_ok("../../data/local/tmp"));
        assert!(!cgroup_template_ok("/data/local/tmp/group"));
        let value = json!({
            "apps": [{
                "pkg": "com.example.game",
                "threads": [{"pattern": "RenderThread", "uclamp_min": 900, "uclamp_max": 100}]
            }]
        });
        assert!(config_from_value(&value).is_err());
    }
}
