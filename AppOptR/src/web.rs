use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use crate::apply_affinity::{read_cmdline, task_tids};
use crate::cache::ProcCache;
use crate::config::{
    CHECK_INTERVAL, CONFIG_FILE, CURRENT_CONFIG, FORCE_RELOAD, PARSE_FAILS, config_reload_now,
    spec_like,
};
use crate::cpuset::{
    CpuSet, CpuTopology, DEFAULT_CPUSET_NAME, base_cpuset, create_cpuset_dir, parse_cpu_spec,
};
use crate::ebpf_mode::ebpf_probe;
use crate::rule_edit::{
    RuleEdit, rule_clone, rule_clone_check, rule_delete, rule_delete_pkg, rule_rename, rule_upsert,
};
use crate::tuning::{self};
use crate::{EBPF_GAVE_UP, MAX_PKG_LEN, MAX_THREAD_LEN, lock_ignore_poison};

pub const WEB_PORT: u16 = 8889;
const INDEX_HTML: &str = include_str!("../web/index.html");

pub static MODE_FORCE: AtomicU8 = AtomicU8::new(0);
pub static WEB_ENABLED: AtomicBool = AtomicBool::new(false);

pub static WEB_STATS: Mutex<Option<WebStats>> = Mutex::new(None);
/// Serialize web mutations that span the legacy CPU file and structured
/// tuning JSON, preventing concurrent browser requests from interleaving.
static WEB_MUTATION_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
pub struct WebStats {
    pub rules: usize,
    pub pkgs: usize,
    pub hit_pkgs: usize,
    pub threads: usize,
    pub ebpf: bool,
    pub uptime: u64,
}

/// 缓存统计
pub fn cache_stats(cache: &ProcCache) -> (usize, usize) {
    let pkgs: HashSet<&str> = cache.tasks.values().map(|e| e.pkg.as_str()).collect();
    (cache.tasks.len(), pkgs.len())
}

/// 启动 web 前端
pub fn web_start() {
    let listener = match TcpListener::bind(("127.0.0.1", WEB_PORT)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Web: 监听 127.0.0.1:{} 失败 ({})", WEB_PORT, e);
            return;
        }
    };
    WEB_ENABLED.store(true, Ordering::Release);
    println!("Web: 前端已启用 http://127.0.0.1:{}/", WEB_PORT);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || conn_handle(stream));
        }
    });
}

struct Request {
    method: String,
    path: String,
    host: String,
    origin: String,
    fetch_site: String,
    content_type: String,
    body: Vec<u8>,
    keep_alive: bool,
}

fn conn_handle(stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_nodelay(true);
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    while let Some(req) = request_read(&mut reader) {
        dispatch(&mut writer, &req);
        if !req.keep_alive {
            return;
        }
    }
}

fn request_read(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut head = Vec::with_capacity(512);
    let mut line = Vec::with_capacity(128);
    loop {
        line.clear();
        reader.read_until(b'\n', &mut line).ok()?;
        if line.is_empty() {
            return None;
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        head.extend_from_slice(&line);
        if head.len() > 8192 {
            return None;
        }
    }

    let head_str = String::from_utf8_lossy(&head);
    let mut lines = head_str.lines();
    let mut parts = lines.next()?.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.split('?').next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let (mut host, mut origin, mut site, mut ctype, mut len) = (
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        0usize,
    );
    let mut conn = String::new();
    for h in lines {
        let Some((k, v)) = h.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "host" => host = v.to_ascii_lowercase(),
            "origin" => origin = v.to_ascii_lowercase(),
            "sec-fetch-site" => site = v.to_ascii_lowercase(),
            "content-type" => ctype = v.to_ascii_lowercase(),
            "content-length" => len = v.parse().unwrap_or(usize::MAX),
            "connection" => conn = v.to_ascii_lowercase(),
            "transfer-encoding" => return None, // 拒绝 chunked
            _ => {}
        }
    }
    if len > 16384 {
        return None;
    }

    let mut body = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    let keep_alive = if version == "HTTP/1.0" {
        conn.contains("keep-alive")
    } else {
        !conn.contains("close")
    };
    Some(Request {
        method,
        path,
        host,
        origin,
        fetch_site: site,
        content_type: ctype,
        body,
        keep_alive,
    })
}

fn resp_send(out: &mut TcpStream, status: u16, ctype: &str, body: &[u8], close: bool) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: {}\r\n\r\n",
        status,
        reason,
        ctype,
        body.len(),
        if close { "close" } else { "keep-alive" }
    );
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(body);
    let _ = out.flush();
}

fn dispatch(out: &mut TcpStream, req: &Request) {
    let port_str = format!(":{}", WEB_PORT);
    let host = req
        .host
        .strip_suffix(&port_str)
        .unwrap_or(req.host.as_str());
    let origin_ok = matches!(host, "127.0.0.1" | "localhost")
        && (req.origin.is_empty()
            || req.origin == "null"
            || matches!(req.fetch_site.as_str(), "" | "none" | "same-origin"))
        && (req.method != "POST" || req.content_type.starts_with("application/json"));
    if !origin_ok {
        resp_send(
            out,
            403,
            "application/json",
            b"{\"ok\":false,\"err\":\"forbidden\"}",
            true,
        );
        return;
    }

    if req.method == "GET" && matches!(req.path.as_str(), "/" | "/index.html") {
        resp_send(
            out,
            200,
            "text/html; charset=utf-8",
            INDEX_HTML.as_bytes(),
            !req.keep_alive,
        );
        return;
    }

    let (status, body) = match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/status") => (200, status_json()),
        ("GET", "/api/rules") => (200, rules_json()),
        ("GET", "/api/config") => (200, config_json()),
        ("GET", "/api/tuning") => (200, tuning_json()),
        ("POST", "/api/rule") => rule_api(req),
        ("POST", "/api/rule/del") => rule_del_api(req),
        ("POST", "/api/rule/rename") => rule_rename_api(req),
        ("POST", "/api/rule/clone") => rule_clone_api(req),
        ("POST", "/api/config") => config_set_api(req),
        ("POST", "/api/tuning") => tuning_set_api(req),
        ("POST", "/api/suggest") => suggest_api(req),
        _ => err_json(404, "not found"),
    };
    resp_send(
        out,
        status,
        "application/json",
        body.as_bytes(),
        !req.keep_alive,
    );
}

fn err_json(code: u16, msg: &str) -> (u16, String) {
    (code, json!({ "ok": false, "err": msg }).to_string())
}

fn current_cfg() -> Option<std::sync::Arc<crate::config::AppConfig>> {
    lock_ignore_poison(&CURRENT_CONFIG).clone()
}

fn sys_procs() -> u16 {
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } == 0 {
        info.procs
    } else {
        0
    }
}

/// CPU 集合转语义名
fn spec_name(cpus: &CpuSet, topo: &CpuTopology) -> String {
    if cpus.count() > 0 {
        if *cpus == topo.e_core {
            return "e-core".into();
        }
        if *cpus == topo.p_core {
            return "p-core".into();
        }
        if *cpus == topo.hp_core {
            return "hp-core".into();
        }
        if *cpus == topo.present_cpus {
            return "all-core".into();
        }
    }
    cpus.to_range_string()
}

fn status_json() -> String {
    let stats = lock_ignore_poison(&WEB_STATS).clone();
    let cfg = current_cfg();
    let topo = cfg.as_ref().map(|c| &c.topo);
    let s = stats.unwrap_or(WebStats {
        rules: 0,
        pkgs: 0,
        hit_pkgs: 0,
        threads: 0,
        ebpf: false,
        uptime: 0,
    });
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if s.ebpf { "ebpf" } else { "proc" },
        "uptime": s.uptime,
        "rules": s.rules,
        "pkgs": s.pkgs,
        "parse_fail": PARSE_FAILS.load(Ordering::Relaxed),
        "hit_pkgs": s.hit_pkgs,
        "threads": s.threads,
        "total_procs": sys_procs(),
        "interval": CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        "e_core": topo.map(|t| t.e_core.to_range_string()).unwrap_or_default(),
        "p_core": topo.map(|t| t.p_core.to_range_string()).unwrap_or_default(),
        "hp_core": topo.map(|t| t.hp_core.to_range_string()).unwrap_or_default(),
        "all_core": topo.map(|t| t.present_str.clone()).unwrap_or_default(),
        "cores": topo.map(|t| t.present_cpus.count()).unwrap_or(0),
        "cpuset_enabled": topo.is_some_and(|t| t.cpuset_enabled),
        "tuning_apps": tuning::app_count(),
        "tuning_threads": tuning::thread_rule_count(),
    })
    .to_string()
}

fn tuning_json() -> String {
    tuning::web_value().to_string()
}

/// Structured tuning is saved atomically as one document. This avoids a
/// partially-updated App profile when a browser is interrupted between a
/// memory-group edit and one of its thread-rule edits.
fn tuning_set_api(req: &Request) -> (u16, String) {
    let _mutation_guard = lock_ignore_poison(&WEB_MUTATION_LOCK);
    let Ok(value) = serde_json::from_slice::<Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let config = match tuning::config_from_value(&value) {
        Ok(config) => config,
        Err(error) => return err_json(400, &error),
    };
    match tuning::replace_and_save(&tuning::tuning_file(), config) {
        Ok(()) => {
            // AppConfig owns the package whitelist used by both discovery
            // modes; force a reload even though applist.conf itself is intact.
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        Err(error) => err_json(500, &error),
    }
}

fn rules_json() -> String {
    let Some(cfg) = current_cfg() else {
        return json!({ "rules": [] }).to_string();
    };
    let mut groups: Vec<serde_json::Value> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for r in &cfg.rules {
        let gi = *index.entry(r.pkg.as_str()).or_insert_with(|| {
            groups.push(json!({ "pkg": r.pkg, "items": [] }));
            groups.len() - 1
        });
        groups[gi]["items"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "thread": r.thread, "spec": spec_name(&r.cpus, &cfg.topo) }));
    }
    json!({ "rules": groups }).to_string()
}

/// 名称校验
fn token_ok(s: &str, max: usize) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.len() < max
        && !t.bytes().any(|b| b < 0x20 || b == 0x7f)
        && !t.contains('#')
        && !t.contains("//")
}

fn pkg_shape_ok(pkg: &str) -> bool {
    !(pkg.contains('{') && pkg.ends_with('}'))
}

fn rule_api(req: &Request) -> (u16, String) {
    let _mutation_guard = lock_ignore_poison(&WEB_MUTATION_LOCK);
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(pkg), Some(cpus)) = (
        v["pkg"].as_str().map(str::trim),
        v["cpus"].as_str().map(str::trim),
    ) else {
        return err_json(400, "缺少 pkg 或 cpus 字段");
    };
    let thread = v["thread"].as_str().map(str::trim).unwrap_or("");
    let Some(cfg) = current_cfg() else {
        return err_json(500, "配置未就绪");
    };
    if !token_ok(pkg, MAX_PKG_LEN) || (!thread.is_empty() && !token_ok(thread, MAX_THREAD_LEN)) {
        return err_json(400, "名称含有非法字符");
    }
    if thread.is_empty() && !pkg_shape_ok(pkg) {
        return err_json(400, "包名含 { 且以 } 结尾时不支持包级规则，可改用线程规则");
    }
    if cpus.is_empty()
        || cpus.len() >= 64
        || !spec_like(cpus)
        || parse_cpu_spec(cpus, &cfg.topo).count() == 0
    {
        return err_json(400, "无效的 CPU 规格");
    }

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rule_upsert(&file, pkg, thread, cpus) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        _ => err_json(500, "配置文件写入失败"),
    }
}

fn rule_del_api(req: &Request) -> (u16, String) {
    let _mutation_guard = lock_ignore_poison(&WEB_MUTATION_LOCK);
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let Some(pkg) = v["pkg"].as_str().map(str::trim) else {
        return err_json(400, "缺少 pkg 字段");
    };
    let thread = v["thread"].as_str().map(str::trim).unwrap_or("");

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    let result = if v["all"].as_bool().unwrap_or(false) {
        rule_delete_pkg(&file, pkg)
    } else {
        rule_delete(&file, pkg, thread)
    };
    match result {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::NotFound => err_json(404, "规则不存在"),
        RuleEdit::Conflict => err_json(409, "状态冲突"),
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        RuleEdit::IoErr => err_json(500, "配置文件写入失败"),
    }
}

fn rule_rename_api(req: &Request) -> (u16, String) {
    let _mutation_guard = lock_ignore_poison(&WEB_MUTATION_LOCK);
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(old), Some(new)) = (
        v["old"].as_str().map(str::trim),
        v["new"].as_str().map(str::trim),
    ) else {
        return err_json(400, "缺少 old 或 new 字段");
    };
    if !token_ok(old, MAX_PKG_LEN) || !token_ok(new, MAX_PKG_LEN) {
        return err_json(400, "名称含有非法字符");
    }
    if !pkg_shape_ok(new) {
        return err_json(400, "包名含 { 且以 } 结尾时不可作为重命名目标");
    }
    if old == new {
        return (200, json!({ "ok": true }).to_string());
    }

    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    match rule_rename(&file, old, new) {
        RuleEdit::Ok => {
            config_reload_now();
            (200, json!({ "ok": true }).to_string())
        }
        RuleEdit::NotFound => err_json(404, "原包名不存在"),
        RuleEdit::Conflict => err_json(409, "目标包名已存在规则"),
        RuleEdit::Malformed => err_json(409, "配置文件存在未闭合块，请修复后重试"),
        RuleEdit::IoErr => err_json(500, "配置文件写入失败"),
    }
}

/// Clone selected CPU and structured-tuning categories in one web request.
/// Each backing file is atomically replaced by its own editor; validation of
/// both sides happens before either file is written.
fn rule_clone_api(req: &Request) -> (u16, String) {
    let _mutation_guard = lock_ignore_poison(&WEB_MUTATION_LOCK);
    let Ok(value) = serde_json::from_slice::<Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let (Some(source), Some(target)) = (
        value["source"].as_str().map(str::trim),
        value["target"].as_str().map(str::trim),
    ) else {
        return err_json(400, "缺少 source 或 target 包名");
    };
    let copy_cpu_package = value["cpu_package"].as_bool().unwrap_or(false);
    let copy_cpu_threads = value["cpu_threads"].as_bool().unwrap_or(false);
    let copy_tuning_memory = value["tuning_memory"].as_bool().unwrap_or(false);
    let copy_tuning_threads = value["tuning_threads"].as_bool().unwrap_or(false);
    if !copy_cpu_package && !copy_cpu_threads && !copy_tuning_memory && !copy_tuning_threads {
        return err_json(400, "请至少选择一类要克隆的规则");
    }
    if source == target {
        return err_json(400, "源包名与目标包名不能相同");
    }
    if !token_ok(source, MAX_PKG_LEN) || !tuning::package_name_ok(target) {
        return err_json(400, "包名含有非法字符");
    }

    let copy_cpu = copy_cpu_package || copy_cpu_threads;
    let copy_tuning = copy_tuning_memory || copy_tuning_threads;
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    if copy_cpu {
        match rule_clone_check(&file, source, target, copy_cpu_package, copy_cpu_threads) {
            RuleEdit::Ok => {}
            RuleEdit::NotFound => return err_json(404, "来源应用没有所选 CPU 规则"),
            RuleEdit::Conflict => return err_json(409, "目标应用已有 CPU 规则，不能覆盖克隆"),
            RuleEdit::Malformed => {
                return err_json(409, "配置文件存在未闭合块，请修复后重试");
            }
            RuleEdit::IoErr => return err_json(500, "读取 CPU 规则文件失败"),
        }
    }
    if copy_tuning
        && let Err(error) =
            tuning::clone_app_check(source, target, copy_tuning_memory, copy_tuning_threads)
    {
        let code = if error.contains("目标应用") {
            409
        } else {
            404
        };
        return err_json(code, &error);
    }

    if copy_cpu {
        match rule_clone(&file, source, target, copy_cpu_package, copy_cpu_threads) {
            RuleEdit::Ok => {}
            RuleEdit::Malformed => {
                return err_json(409, "配置文件存在未闭合块，请修复后重试");
            }
            RuleEdit::Conflict => return err_json(409, "目标应用已有 CPU 规则，不能覆盖克隆"),
            RuleEdit::NotFound => return err_json(404, "来源应用没有所选 CPU 规则"),
            RuleEdit::IoErr => return err_json(500, "写入 CPU 规则文件失败"),
        }
    }
    if copy_tuning
        && let Err(error) =
            tuning::clone_app(source, target, copy_tuning_memory, copy_tuning_threads)
    {
        eprintln!("克隆: 调优写入失败，CPU 部分可能已完成: {}", error);
        return err_json(500, &format!("写入调优规则失败: {}", error));
    }

    config_reload_now();
    (200, json!({ "ok": true }).to_string())
}

/// 输入建议
fn suggest_api(req: &Request) -> (u16, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let q = v["q"].as_str().map(str::trim).unwrap_or("");
    if q.len() > 64 {
        return err_json(400, "q 过长");
    }
    let list: Vec<String> = match v["pkg"].as_str().map(str::trim).filter(|p| !p.is_empty()) {
        None => suggest_pkgs(q).into_iter().map(|(n, _)| n).collect(),
        Some(pkg) => {
            if !token_ok(pkg, MAX_PKG_LEN) {
                return err_json(400, "名称含有非法字符");
            }
            suggest_threads(pkg, q)
                .into_iter()
                .map(|(n, _)| n)
                .collect()
        }
    };
    (200, json!({ "ok": true, "list": list }).to_string())
}

/// 枚举包名
fn installed_pkgs() -> Vec<String> {
    fs::read_dir("/data/data")
        .map(|dirs| {
            dirs.flatten()
                .map(|d| d.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains('.') && !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default()
}

fn for_each_pid(mut f: impl FnMut(i32)) {
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                f(pid);
            }
        }
    }
}

/// 排序键
fn rank_top(counts: BTreeMap<String, usize>, lq: &str) -> Vec<(String, usize)> {
    let mut ranked: Vec<(u8, Reverse<usize>, String)> = counts
        .into_iter()
        .filter_map(|(n, c)| {
            let ln = n.to_ascii_lowercase();
            let r = if ln.starts_with(lq) {
                0
            } else if ln.contains(lq) {
                1
            } else {
                2
            };
            (r < 2).then_some((r, Reverse(c), n))
        })
        .collect();
    ranked.sort_unstable();
    ranked.truncate(20);
    ranked
        .into_iter()
        .map(|(_, Reverse(c), n)| (n, c))
        .collect()
}

fn suggest_pkgs(q: &str) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> =
        installed_pkgs().into_iter().map(|p| (p, 0)).collect();
    // Put configured packages first so the add dialogs can reuse an existing
    // CPU-rule or tuning-rule package even when it is not installed/running.
    // AppConfig already combines both configuration sources.
    const CONFIGURED_PRIORITY: usize = 1_000_000;
    if let Some(cfg) = current_cfg() {
        for pkg in &cfg.pkgs {
            counts.insert(pkg.clone(), CONFIGURED_PRIORITY);
        }
    }
    // The structured snapshot is read separately as a fresh fallback while a
    // config reload is in flight.
    for pkg in tuning::app_package_names() {
        counts.insert(pkg, CONFIGURED_PRIORITY);
    }
    for_each_pid(|pid| {
        if let Some(name) = read_cmdline(pid).filter(|n| n.contains('.')) {
            let count = counts.entry(name).or_insert(0);
            *count = count.saturating_add(1);
        }
    });
    rank_top(counts, &q.to_ascii_lowercase())
}

fn thread_comm(pid: i32, tid: i32) -> Option<String> {
    let s = fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, tid)).ok()?;
    let name = s.trim_end_matches(['\0', '\n']).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn suggest_threads(pkg: &str, q: &str) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for_each_pid(|pid| {
        if read_cmdline(pid).as_deref() == Some(pkg) {
            for tid in task_tids(pid).unwrap_or_default() {
                if let Some(comm) = thread_comm(pid, tid) {
                    *counts.entry(comm).or_insert(0) += 1;
                }
            }
        }
    });
    rank_top(counts, &q.to_ascii_lowercase())
}

fn config_json() -> String {
    let stats = lock_ignore_poison(&WEB_STATS).clone();
    let cfg = current_cfg();
    json!({
        "mode": MODE_FORCE.load(Ordering::Relaxed),
        "mode_active": if stats.is_some_and(|s| s.ebpf) { "ebpf" } else { "proc" },
        "ebpf_available": ebpf_probe(),
        "interval": CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        "cpuset_name": base_cpuset().rsplit('/').next().unwrap_or_default(),
        "config_file": lock_ignore_poison(&CONFIG_FILE).clone(),
        "cpuset_enabled": cfg.is_some_and(|c| c.topo.cpuset_enabled),
    })
    .to_string()
}

fn config_set_api(req: &Request) -> (u16, String) {
    let _mutation_guard = lock_ignore_poison(&WEB_MUTATION_LOCK);
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return err_json(400, "请求体不是合法 JSON");
    };
    let mode = v["mode"].as_u64();
    let interval = v["interval"].as_u64();
    let name = v["cpuset_name"].as_str();
    let path = v["config_file"].as_str();

    if mode.is_some_and(|m| m > 2) {
        return err_json(400, "无效的工作模式");
    }
    if interval.is_some_and(|n| !(1..=3600).contains(&n)) {
        return err_json(400, "间隔需在 1-3600 秒之间");
    }
    if name.is_some_and(|n| !valid_name(n)) {
        return err_json(400, "无效的 cpuset 目录名");
    }
    if path.is_some_and(|p| !valid_path(p)) {
        return err_json(400, "无效的配置文件路径");
    }

    if let Some(m) = mode {
        MODE_FORCE.store(m as u8, Ordering::Relaxed);
        // 用户主动切回 eBPF 方向时清除放弃标记允许重试
        if m != 2 {
            EBPF_GAVE_UP.store(false, Ordering::Relaxed);
        }
    }
    if let Some(n) = interval {
        CHECK_INTERVAL.store(n, Ordering::Relaxed);
    }
    if let Some(n) = name {
        crate::cpuset::set_base_cpuset(n);
        if let Some(cfg) = current_cfg()
            && cfg.topo.cpuset_enabled
        {
            create_cpuset_dir(&base_cpuset(), &cfg.topo.present_str, &cfg.topo.mems_str);
        }
        FORCE_RELOAD.store(true, Ordering::Release);
    }
    if let Some(p) = path {
        if std::fs::metadata(p).is_err() {
            let _ = std::fs::write(p, "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n");
        }
        *lock_ignore_poison(&CONFIG_FILE) = p.to_string();
        FORCE_RELOAD.store(true, Ordering::Release);
    }

    settings_save();
    (200, json!({ "ok": true }).to_string())
}

pub fn settings_file() -> String {
    tuning::state_file("AppOpt.json")
}

static SAVE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
pub struct Settings {
    pub web_enable: bool,
    pub mode: u8,
    pub check_interval: u64,
    pub cpuset_name: String,
    pub config_file: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            web_enable: false,
            mode: 0,
            check_interval: 2,
            cpuset_name: DEFAULT_CPUSET_NAME.to_string(),
            config_file: tuning::state_file("applist.conf"),
        }
    }
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() < 64 && !s.contains('/') && !s.bytes().any(|b| b <= b' ')
}

fn valid_path(s: &str) -> bool {
    !s.is_empty() && s.len() < 256 && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

impl Settings {
    fn from_json(v: &Value) -> Self {
        let d = Settings::default();
        Self {
            web_enable: v["web_enable"].as_bool().unwrap_or(d.web_enable),
            mode: v["mode"].as_u64().unwrap_or(d.mode as u64).min(2) as u8,
            check_interval: v["check_interval"]
                .as_u64()
                .unwrap_or(d.check_interval)
                .clamp(1, 3600),
            cpuset_name: v["cpuset_name"]
                .as_str()
                .filter(|s| valid_name(s))
                .unwrap_or(&d.cpuset_name)
                .to_string(),
            config_file: v["config_file"]
                .as_str()
                .filter(|s| valid_path(s))
                .unwrap_or(&d.config_file)
                .to_string(),
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "web_enable": self.web_enable,
            "mode": self.mode,
            "check_interval": self.check_interval,
            "cpuset_name": self.cpuset_name,
            "config_file": self.config_file,
        })
    }

    fn save(&self, path: &str) {
        let _guard = lock_ignore_poison(&SAVE_LOCK);
        let json = serde_json::to_string_pretty(&self.to_value()).unwrap_or_default();
        let tmp = format!("{}.tmp", path);
        let res = fs::File::create(&tmp)
            .and_then(|mut f| {
                f.write_all(format!("{}\n", json).as_bytes())?;
                f.sync_all()
            })
            .and_then(|_| fs::rename(&tmp, path));
        if let Err(e) = res {
            eprintln!("警告: 设置写入 {} 失败: {}", path, e);
        }
    }
}

pub fn settings_load(path: &str) -> Settings {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => Settings::from_json(&v),
            Err(e) => {
                eprintln!("警告: {} 已损坏({})，使用默认设置", path, e);
                Settings::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let d = Settings::default();
            d.save(path);
            println!("设置文件不存在，已写入默认设置: {}", path);
            d
        }
        Err(e) => {
            eprintln!("警告: 读取 {} 失败({})，使用默认设置", path, e);
            Settings::default()
        }
    }
}

pub fn settings_save() {
    Settings {
        web_enable: WEB_ENABLED.load(Ordering::Relaxed),
        mode: MODE_FORCE.load(Ordering::Relaxed),
        check_interval: CHECK_INTERVAL.load(Ordering::Relaxed).max(1),
        cpuset_name: base_cpuset()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string(),
        config_file: lock_ignore_poison(&CONFIG_FILE).clone(),
    }
    .save(&settings_file());
}
