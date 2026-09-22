use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::sync::Mutex;

use crate::config::{
    OuterLine, close_like, comment_at, parse_outer, split_rule_line, split_single_line,
    strip_comment,
};

pub enum RuleEdit {
    Ok,
    NotFound,
    Conflict,
    Malformed,
    IoErr,
}

static WRITE_LOCK: Mutex<()> = Mutex::new(());

enum PkgLine {
    Standalone(usize),
    OpenInline(usize),
    BareOpen(usize),
    BarePending(usize),
}

#[derive(Clone, Copy)]
struct ThreadLoc {
    idx: usize,
    single: bool,
    closed: bool,
    open: bool,
}

struct Target {
    pkg_line: Option<PkgLine>,
    block_open: Option<usize>,
    block_close: Option<usize>,
    threads: HashMap<String, Vec<ThreadLoc>>,
    unterminated: bool,
}

fn target_scan(lines: &[String], pkg: &str) -> Target {
    let mut t = Target {
        pkg_line: None,
        block_open: None,
        block_close: None,
        threads: HashMap::new(),
        unterminated: false,
    };
    let mut pending: Option<usize> = None;
    let mut in_block = false;
    let mut target_block = false;

    let block_close = |t: &mut Target, target_block: &mut bool, i: usize| {
        if *target_block && t.block_close.is_none() {
            t.block_close = Some(i);
        }
        *target_block = false;
    };
    let block_open = |t: &mut Target, i: usize| {
        if t.block_close.is_none() {
            t.block_open = Some(i);
        }
    };

    for (i, raw) in lines.iter().enumerate() {
        let p = raw.trim();
        if p.is_empty() || p.starts_with('#') || p.starts_with("//") {
            continue;
        }

        if in_block {
            if close_like(p) {
                in_block = false;
                block_close(&mut t, &mut target_block, i);
                continue;
            }
            match split_rule_line(p) {
                Some((name, _, closed)) => {
                    if target_block && !name.is_empty() {
                        t.threads
                            .entry(name.to_string())
                            .or_default()
                            .push(ThreadLoc {
                                idx: i,
                                single: false,
                                closed,
                                open: false,
                            });
                    }
                    if closed {
                        in_block = false;
                        block_close(&mut t, &mut target_block, i);
                    }
                }
                None => {
                    if p.contains('}') {
                        in_block = false;
                        block_close(&mut t, &mut target_block, i);
                    }
                }
            }
            continue;
        }

        match parse_outer(p) {
            OuterLine::Single {
                pkg: pg,
                thread: th,
                open,
                ..
            } => {
                pending = None;
                if pg == pkg && !th.is_empty() {
                    t.threads
                        .entry(th.to_string())
                        .or_default()
                        .push(ThreadLoc {
                            idx: i,
                            single: true,
                            closed: false,
                            open,
                        });
                }
                if open {
                    in_block = true;
                    if pg == pkg {
                        target_block = true;
                        block_open(&mut t, i);
                    }
                }
            }
            OuterLine::Rule { pkg: pg, open, .. } => {
                if open {
                    in_block = true;
                    pending = None;
                    if pg == pkg {
                        target_block = true;
                        block_open(&mut t, i);
                        if t.pkg_line.is_none() {
                            t.pkg_line = Some(PkgLine::OpenInline(i));
                        }
                    }
                } else {
                    pending = None;
                    if pg == pkg && t.pkg_line.is_none() {
                        t.pkg_line = Some(PkgLine::Standalone(i));
                    }
                }
            }
            OuterLine::BareOpen { pkg: owner } => {
                if !owner.is_empty() {
                    pending = None;
                    in_block = true;
                    if owner == pkg {
                        target_block = true;
                        block_open(&mut t, i);
                        if t.pkg_line.is_none() {
                            t.pkg_line = Some(PkgLine::BareOpen(i));
                        }
                    }
                } else if let Some(pi) = pending.take() {
                    in_block = true;
                    if let OuterLine::Pending { pkg: pp } = parse_outer(lines[pi].trim())
                        && pp == pkg
                    {
                        target_block = true;
                        block_open(&mut t, i);
                        if t.pkg_line.is_none() {
                            t.pkg_line = Some(PkgLine::BarePending(pi));
                        }
                    }
                }
            }
            OuterLine::Pending { .. } => {
                pending = Some(i);
            }
            OuterLine::Junk => {
                pending = None;
            }
        }
    }

    t.unterminated = in_block;
    t
}

impl Target {
    fn singles(&self) -> impl Iterator<Item = &ThreadLoc> {
        self.threads.values().flatten().filter(|l| l.single)
    }
    fn any_line(&self) -> bool {
        self.pkg_line.is_some() || self.singles().next().is_some()
    }
}

fn normalize_singles(lines: &mut Vec<String>, pkg: &str) {
    let t = target_scan(lines, pkg);
    let mut items: Vec<(ThreadLoc, String)> = Vec::new();
    for loc in t.singles() {
        let raw_line = lines[loc.idx].trim();
        let raw = strip_comment(raw_line);
        let body = raw.strip_suffix('{').map(str::trim_end).unwrap_or(raw);
        if let Some((_, th, cp)) = split_single_line(body) {
            let line = with_comment(&format!("\t{}={}", th, cp), raw_line);
            items.push((*loc, line));
        }
    }
    if items.is_empty() {
        return;
    }
    items.sort_unstable_by_key(|(l, _)| l.idx);
    if t.block_close.is_none()
        && (items.iter().any(|(l, _)| l.open)
            || !matches!(t.pkg_line, None | Some(PkgLine::Standalone(_))))
    {
        return;
    }

    let at = items[0].0.idx;
    for (loc, _) in items.iter().rev() {
        line_remove(lines, pkg, loc);
    }
    let items: Vec<String> = items.into_iter().map(|(_, line)| line).collect();

    let t2 = target_scan(lines, pkg);
    if let Some(close) = t2.block_close {
        for (off, line) in items.into_iter().enumerate() {
            lines.insert(close + off, line);
        }
    } else if let Some(PkgLine::Standalone(i)) = t2.pkg_line {
        lines[i] = format!("{} {{", lines[i].trim_end());
        let chunk: Vec<String> = items
            .into_iter()
            .chain(std::iter::once("}".to_string()))
            .collect();
        lines.splice(i + 1..i + 1, chunk);
    } else {
        let chunk: Vec<String> = std::iter::once(bare_open_line(pkg))
            .chain(items)
            .chain(std::iter::once("}".to_string()))
            .collect();
        let at = at.min(lines.len());
        lines.splice(at..at, chunk);
    }
}

fn bare_open_line(pkg: &str) -> String {
    if pkg.contains('=') {
        format!("{pkg}= {{")
    } else {
        format!("{pkg} {{")
    }
}

fn with_comment(new_line: &str, old: &str) -> String {
    match comment_at(old) {
        Some(at) => format!("{}{}", new_line, &old[at..]),
        None => new_line.to_string(),
    }
}

fn spec_swap(raw: &str, cpus: &str) -> String {
    let cut = comment_at(raw).unwrap_or(raw.len());
    let Some(eq) = raw[..cut].rfind('=') else {
        return raw.into();
    };
    let rhs = &raw[eq + 1..cut];
    let val = rhs.trim_start();
    let lead = rhs.len() - val.len();
    let v_end = val
        .find(|c: char| c.is_whitespace() || c == '{' || c == '}')
        .unwrap_or(val.len());
    let tail: String = val[v_end..]
        .chars()
        .filter(|c| c.is_whitespace() || *c == '{' || *c == '}')
        .collect();
    format!("{}{}{}{}", &raw[..eq + 1 + lead], cpus, tail, &raw[cut..])
}

fn line_remove(lines: &mut Vec<String>, pkg: &str, loc: &ThreadLoc) {
    if loc.open {
        lines[loc.idx] = with_comment(&bare_open_line(pkg), &lines[loc.idx]);
    } else if loc.closed {
        lines[loc.idx] = with_comment("}", &lines[loc.idx]);
    } else {
        lines.remove(loc.idx);
    }
}

fn file_write(path: &str, lines: &[String]) -> RuleEdit {
    let mut out = lines.join("\n");
    out.push('\n');
    let tmp = format!("{}.tmp", path);
    let res = fs::File::create(&tmp)
        .and_then(|mut f| {
            f.write_all(out.as_bytes())?;
            f.sync_all()
        })
        .and_then(|_| fs::rename(&tmp, path));
    if res.is_ok() {
        RuleEdit::Ok
    } else {
        RuleEdit::IoErr
    }
}

struct CloneRules {
    package_cpus: Option<String>,
    threads: Vec<(String, String)>,
}

fn clone_package_spec(lines: &[String], target: &Target) -> Option<String> {
    let idx = match target.pkg_line {
        Some(PkgLine::Standalone(idx) | PkgLine::OpenInline(idx)) => idx,
        _ => return None,
    };
    match parse_outer(lines[idx].trim()) {
        OuterLine::Rule { cpus, .. } => Some(cpus.to_string()),
        _ => None,
    }
}

fn clone_thread_spec(lines: &[String], loc: &ThreadLoc) -> Option<String> {
    let line = lines.get(loc.idx)?.trim();
    if loc.single {
        let raw = strip_comment(line);
        let body = raw.strip_suffix('{').map(str::trim_end).unwrap_or(raw);
        split_single_line(body).map(|(_, _, cpus)| cpus.to_string())
    } else {
        split_rule_line(line).map(|(_, cpus, _)| cpus.to_string())
    }
}

fn clone_prepare(
    lines: &mut Vec<String>,
    source: &str,
    target: &str,
    copy_package: bool,
    copy_threads: bool,
) -> Result<CloneRules, RuleEdit> {
    normalize_singles(lines, source);
    normalize_singles(lines, target);
    let source_rules = target_scan(lines, source);
    let target_rules = target_scan(lines, target);
    if source_rules.unterminated || target_rules.unterminated {
        return Err(RuleEdit::Malformed);
    }
    if target_rules.any_line() {
        return Err(RuleEdit::Conflict);
    }

    let package_cpus = clone_package_spec(lines, &source_rules);
    if copy_package && package_cpus.is_none() {
        return Err(RuleEdit::NotFound);
    }

    let mut thread_entries: Vec<(usize, String, String)> = source_rules
        .threads
        .iter()
        .flat_map(|(thread, locs)| {
            locs.iter().filter_map(|loc| {
                clone_thread_spec(lines, loc).map(|cpus| (loc.idx, thread.clone(), cpus))
            })
        })
        .collect();
    thread_entries.sort_unstable_by_key(|(idx, _, _)| *idx);
    if copy_threads && thread_entries.is_empty() {
        return Err(RuleEdit::NotFound);
    }

    Ok(CloneRules {
        package_cpus: copy_package.then_some(package_cpus).flatten(),
        threads: if copy_threads {
            thread_entries
                .into_iter()
                .map(|(_, thread, cpus)| (thread, cpus))
                .collect()
        } else {
            Vec::new()
        },
    })
}

fn clone_append(lines: &mut Vec<String>, target: &str, rules: CloneRules) {
    if !lines.is_empty() && !lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.push(String::new());
    }
    if rules.threads.is_empty() {
        if let Some(cpus) = rules.package_cpus {
            lines.push(format!("{}={}", target, cpus));
        }
        return;
    }

    if let Some(cpus) = rules.package_cpus {
        lines.push(format!("{}={} {{", target, cpus));
    } else {
        lines.push(bare_open_line(target));
    }
    for (thread, cpus) in rules.threads {
        lines.push(format!("\t{}={}", thread, cpus));
    }
    lines.push("}".to_string());
}

pub fn rule_clone_check(
    path: &str,
    source: &str,
    target: &str,
    copy_package: bool,
    copy_threads: bool,
) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
    match clone_prepare(&mut lines, source, target, copy_package, copy_threads) {
        Ok(_) => RuleEdit::Ok,
        Err(error) => error,
    }
}

/// Clone selected CPU-affinity categories into a package that has no existing
/// CPU rule. The cloned form is normalized into a single package block.
pub fn rule_clone(
    path: &str,
    source: &str,
    target: &str,
    copy_package: bool,
    copy_threads: bool,
) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
    let rules = match clone_prepare(&mut lines, source, target, copy_package, copy_threads) {
        Ok(rules) => rules,
        Err(error) => return error,
    };
    clone_append(&mut lines, target, rules);
    file_write(path, &lines)
}

pub fn rule_upsert(path: &str, pkg: &str, thread: &str, cpus: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
    normalize_singles(&mut lines, pkg);
    let t = target_scan(&lines, pkg);

    if thread.is_empty() {
        match t.pkg_line {
            Some(PkgLine::Standalone(i)) => {
                lines[i] = spec_swap(&lines[i], cpus);
            }
            Some(PkgLine::BarePending(i)) => {
                lines[i] = with_comment(&format!("{}={} {{", pkg, cpus), &lines[i]);
                if let Some(open) = t.block_open
                    && matches!(
                        parse_outer(lines[open].trim()),
                        OuterLine::BareOpen { pkg: "" }
                    )
                {
                    lines.remove(open);
                }
            }
            Some(PkgLine::OpenInline(i)) => {
                lines[i] = spec_swap(&lines[i], cpus);
            }
            Some(PkgLine::BareOpen(i)) => {
                lines[i] = with_comment(&format!("{}={} {{", pkg, cpus), &lines[i]);
            }
            None if t.unterminated => return RuleEdit::Malformed,
            None => lines.push(format!("{}={}", pkg, cpus)),
        }
    } else if let Some(locs) = t.threads.get(thread) {
        let last = locs.last().copied().unwrap();
        lines[last.idx] = spec_swap(&lines[last.idx], cpus);
        for loc in locs[..locs.len() - 1].iter().rev() {
            line_remove(&mut lines, pkg, loc);
        }
    } else if let Some(close) = t.block_close {
        lines.insert(close, format!("\t{}={}", thread, cpus));
    } else if let Some(PkgLine::Standalone(i)) = t.pkg_line {
        lines[i] = format!("{} {{", lines[i].trim_end());
        lines.splice(
            i + 1..i + 1,
            [format!("\t{}={}", thread, cpus), "}".to_string()],
        );
    } else if t.unterminated {
        return RuleEdit::Malformed;
    } else {
        lines.push(bare_open_line(pkg));
        lines.push(format!("\t{}={}", thread, cpus));
        lines.push("}".to_string());
    }

    file_write(path, &lines)
}

pub fn rule_delete(path: &str, pkg: &str, thread: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
    normalize_singles(&mut lines, pkg);
    let t = target_scan(&lines, pkg);

    if thread.is_empty() {
        match t.pkg_line {
            Some(PkgLine::Standalone(i)) => {
                lines.remove(i);
            }
            Some(PkgLine::OpenInline(i)) => {
                lines[i] = bare_open_line(pkg);
            }
            _ => return RuleEdit::NotFound,
        }
    } else if let Some(locs) = t.threads.get(thread) {
        for loc in locs.iter().rev() {
            line_remove(&mut lines, pkg, loc);
        }
    } else {
        return RuleEdit::NotFound;
    }

    file_write(path, &lines)
}

pub fn rule_delete_pkg(path: &str, pkg: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
    normalize_singles(&mut lines, pkg);

    let mut removed = false;
    loop {
        let t = target_scan(&lines, pkg);
        let mut del: Vec<usize> = Vec::new();
        match t.pkg_line {
            Some(PkgLine::Standalone(i))
            | Some(PkgLine::OpenInline(i))
            | Some(PkgLine::BareOpen(i))
            | Some(PkgLine::BarePending(i)) => del.push(i),
            None => {
                if !t.any_line() {
                    break;
                }
            }
        }
        if let Some(open) = t.block_open {
            let end = t
                .block_close
                .or_else(|| {
                    t.threads
                        .values()
                        .flatten()
                        .filter(|l| !l.single)
                        .map(|l| l.idx)
                        .max()
                })
                .unwrap_or(open);
            del.extend(open..=end);
        }
        del.extend(t.singles().map(|l| l.idx));

        del.sort_unstable();
        del.dedup();
        for i in del.into_iter().rev() {
            lines.remove(i);
        }
        removed = true;
    }

    if !removed {
        return RuleEdit::NotFound;
    }
    file_write(path, &lines)
}

pub fn rule_rename(path: &str, old: &str, new: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
    normalize_singles(&mut lines, old);
    if !target_scan(&lines, old).any_line() {
        return RuleEdit::NotFound;
    }
    if target_scan(&lines, new).any_line() {
        return RuleEdit::Conflict;
    }

    loop {
        let t = target_scan(&lines, old);
        let mut idxs: Vec<usize> = t.singles().map(|l| l.idx).collect();
        if let Some(
            PkgLine::Standalone(i)
            | PkgLine::OpenInline(i)
            | PkgLine::BareOpen(i)
            | PkgLine::BarePending(i),
        ) = t.pkg_line
        {
            idxs.push(i);
        }
        if idxs.is_empty() {
            break;
        }
        for i in idxs {
            if let Some(rest) = lines[i].trim().strip_prefix(old) {
                let tail = match (new.contains('='), rest.trim()) {
                    (true, "" | "=") => "=",
                    (true, "{") => "= {",
                    _ => rest,
                };
                lines[i] = format!("{}{}", new, tail);
            }
        }
    }
    file_write(path, &lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_selected_cpu_categories_into_one_normalized_block() {
        let path = std::env::temp_dir().join(format!(
            "appoptr-rule-clone-{}-{}.conf",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(
            &path,
            "com.example.source=0-3\ncom.example.source {\n\tRenderThread=4-5\n\tWorker=0-1\n}\n",
        )
        .unwrap();

        assert!(matches!(
            rule_clone(
                path.to_str().unwrap(),
                "com.example.source",
                "com.example.target",
                true,
                true
            ),
            RuleEdit::Ok
        ));
        let cloned = fs::read_to_string(&path).unwrap();
        assert!(cloned.contains("com.example.target=0-3 {"));
        assert!(cloned.contains("\tRenderThread=4-5"));
        assert!(cloned.contains("\tWorker=0-1"));
        assert!(matches!(
            rule_clone_check(
                path.to_str().unwrap(),
                "com.example.source",
                "com.example.target",
                true,
                false
            ),
            RuleEdit::Conflict
        ));
        let _ = fs::remove_file(path);
    }
}
