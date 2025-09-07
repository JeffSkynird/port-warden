use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

// Public defaults so bin and tests share them
pub static DEFAULT_PORTS: &[u16] = &[3000, 8000];

// ===== Profiles (.portkill.json) =====
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileCfg {
    pub ports: Vec<u16>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub stop: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileCfg {
    #[serde(default)]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileCfg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub refresh_secs: u64,
    pub active_profile: String,
    pub project_root: PathBuf,
    pub file_cfg: FileCfg,
    pub cpu_threshold: f32,   // %
    pub mem_threshold_mb: u64,
    pub alerts_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        let refresh_secs = std::env::var("PORTKILL_REFRESH").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
        let (root, file_cfg) = load_profiles_from_fs().unwrap_or_else(|| (std::env::current_dir().unwrap(), FileCfg::default()));
        let active_profile = file_cfg.default_profile.clone().unwrap_or_else(|| "default".to_string());
        let cpu_threshold = std::env::var("PORTKILL_CPU").ok().and_then(|v| v.parse().ok()).unwrap_or(90.0);
        let mem_threshold_mb = std::env::var("PORTKILL_MEM_MB").ok().and_then(|v| v.parse().ok()).unwrap_or(1024);
        Self { refresh_secs, active_profile, project_root: root, file_cfg, cpu_threshold, mem_threshold_mb, alerts_enabled: false }
    }
}

pub fn load_profiles_from_fs() -> Option<(PathBuf, FileCfg)> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".portkill.json");
        if candidate.exists() {
            let txt = fs::read_to_string(&candidate).ok()?;
            let cfg: FileCfg = serde_json::from_str(&txt).ok()?;
            return Some((dir, cfg));
        }
        if !dir.pop() { break; }
    }
    None
}

pub fn active_profile(cfg: &Config) -> ProfileCfg {
    cfg.file_cfg
        .profiles
        .get(&cfg.active_profile)
        .cloned()
        .unwrap_or_else(|| ProfileCfg { ports: env_ports_default(), cwd: Some(cfg.project_root.clone()), start: None, stop: None })
}

pub fn env_ports_default() -> Vec<u16> {
    std::env::var("PORTKILL_PORTS").ok().and_then(|s| {
        let mut out = Vec::new();
        for p in s.split(',') { if let Ok(v) = p.trim().parse::<u16>() { out.push(v); } }
        if out.is_empty() { None } else { Some(out) }
    }).unwrap_or_else(|| DEFAULT_PORTS.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DockerInfo { pub id: String, pub name: String, pub image: String }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcInfo {
    pub pid: u32,               // 0 if not applies (e.g. container)
    pub name: String,
    #[serde(default)]
    pub docker: Option<DockerInfo>,
}

// ===== Abstractions for system ops (scanning + killing) =====
pub trait SystemOps {
    fn scan(&self, targets: &[u16]) -> Result<HashMap<u16, Vec<ProcInfo>>>;
    fn kill_pid(&self, pid: u32) -> bool;
}

// ===== CLI core (testable) =====
pub fn run_cli_with<I, W, S>(args: I, out: &mut W, sys: &S) -> Result<()>
where
    I: IntoIterator<Item = String>,
    W: Write,
    S: SystemOps,
{
    let cfg = Config::default();
    let profile = active_profile(&cfg);
    let mut it = args.into_iter();
    let _bin = it.next();
    let cmd = it.next().unwrap_or_else(|| "list".to_string());
    // Best-effort: if system scanning fails (e.g., sandbox), proceed with empty map
    let map = match sys.scan(&profile.ports) {
        Ok(m) => m,
        Err(_e) => HashMap::new(),
    };

    match cmd.as_str() {
        "list" => {
            writeln!(out, "Perfil: {} @ {:?}", cfg.active_profile, cfg.project_root)?;
            writeln!(out, "Puertos: {:?}", profile.ports)?;
            for port in &profile.ports {
                let v = map.get(port).cloned().unwrap_or_default();
                if v.is_empty() {
                    writeln!(out, "{}: libre", port)?;
                } else {
                    for p in v {
                        if let Some(d) = p.docker {
                            writeln!(out, "{}: container {} ({})", port, d.name, d.image)?;
                        } else {
                            writeln!(out, "{}: {} (pid {})", port, p.name, p.pid)?;
                        }
                    }
                }
            }
        }
        "kill-all" => {
            let mut total = 0;
            for port in &profile.ports {
                if let Some(list) = map.get(port) {
                    for p in list {
                        if p.pid != 0 && sys.kill_pid(p.pid) { total += 1; }
                    }
                }
            }
            writeln!(out, "Matados {total} procesos.")?;
        }
        other if other.starts_with("kill:") => {
            let port = u16::from_str(other.trim_start_matches("kill:")).context("Formato: kill:<puerto>")?;
            if let Some(list) = map.get(&port) {
                let mut n = 0;
                for p in list { if p.pid != 0 && sys.kill_pid(p.pid) { n += 1; } }
                writeln!(out, "Puerto {port}: {n} procesos terminados")?;
            } else {
                writeln!(out, "Puerto {port}: libre")?;
            }
        }
        _ => {
            writeln!(out, "Uso: port-kill [list|kill:<puerto>|kill-all]")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, sync::Mutex};
    use once_cell::sync::Lazy;

    // Serialize tests that mutate global process state (cwd/env)
    static TEST_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn guard_env() -> std::sync::MutexGuard<'static, ()> {
        TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn env_ports_default_reads_env() {
        let _g = guard_env();
        let prev = env::var("PORTKILL_PORTS").ok();
        unsafe { env::set_var("PORTKILL_PORTS", "3001, 3002 , 9999"); }
        let v = env_ports_default();
        if let Some(p) = prev { unsafe { env::set_var("PORTKILL_PORTS", p); } } else { unsafe { env::remove_var("PORTKILL_PORTS"); } }
        assert_eq!(v, vec![3001, 3002, 9999]);
    }

    #[test]
    fn env_ports_default_uses_defaults_when_missing() {
        let _g = guard_env();
        let prev = env::var("PORTKILL_PORTS").ok();
        unsafe { env::remove_var("PORTKILL_PORTS"); }
        let v = env_ports_default();
        if let Some(p) = prev { unsafe { env::set_var("PORTKILL_PORTS", p); } }
        assert_eq!(v, DEFAULT_PORTS);
    }

    #[derive(Default)]
    struct MockSys {
        pub map: HashMap<u16, Vec<ProcInfo>>,
        pub killed: std::sync::Mutex<Vec<u32>>,
    }

    impl SystemOps for MockSys {
        fn scan(&self, _targets: &[u16]) -> Result<HashMap<u16, Vec<ProcInfo>>> { Ok(self.map.clone()) }
        fn kill_pid(&self, pid: u32) -> bool { self.killed.lock().unwrap().push(pid); true }
    }

    fn with_clean_cwd<T>(f: impl FnOnce() -> T) -> T {
        let _g = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let old = std::env::current_dir().unwrap();
        let tmp = std::env::temp_dir().join(format!("pw-unit-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        std::env::set_current_dir(&tmp).unwrap();
        let res = f();
        std::env::set_current_dir(old).unwrap();
        res
    }

    #[test]
    fn cli_list_renders_process_and_container() {
        with_clean_cwd(|| {
            let prev = env::var("PORTKILL_PORTS").ok();
            unsafe { env::set_var("PORTKILL_PORTS", "4000"); }

            let mut sys = MockSys::default();
            sys.map.insert(4000, vec![
                ProcInfo { pid: 123, name: "node".into(), docker: None },
                ProcInfo { pid: 0, name: "container:web".into(), docker: Some(DockerInfo { id: "abc".into(), name: "web".into(), image: "nginx:alpine".into() }) },
            ]);

            let mut out: Vec<u8> = Vec::new();
            let args = vec!["bin".to_string(), "list".to_string()];
            run_cli_with(args, &mut out, &sys).unwrap();
            let s = String::from_utf8(out).unwrap();
            assert!(s.contains("Puertos: [4000]"), "stdout: {}", s);
            assert!(s.contains("4000: node (pid 123)"), "stdout: {}", s);
            assert!(s.contains("4000: container web (nginx:alpine)"), "stdout: {}", s);

            if let Some(p) = prev { unsafe { env::set_var("PORTKILL_PORTS", p); } } else { unsafe { env::remove_var("PORTKILL_PORTS"); } }
        });
    }

    #[test]
    fn cli_kill_all_counts_kills() {
        with_clean_cwd(|| {
            let prev = env::var("PORTKILL_PORTS").ok();
            unsafe { env::set_var("PORTKILL_PORTS", "1111,2222"); }

            let mut sys = MockSys::default();
            sys.map.insert(1111, vec![ProcInfo { pid: 1, name: "a".into(), docker: None }]);
            sys.map.insert(2222, vec![ProcInfo { pid: 2, name: "b".into(), docker: None }]);

            let mut out: Vec<u8> = Vec::new();
            let args = vec!["bin".to_string(), "kill-all".to_string()];
            run_cli_with(args, &mut out, &sys).unwrap();
            let s = String::from_utf8(out).unwrap();
            assert!(s.contains("Matados 2 procesos."), "stdout: {}", s);
            let killed = sys.killed.lock().unwrap().clone();
            assert_eq!(killed, vec![1, 2]);

            if let Some(p) = prev { unsafe { env::set_var("PORTKILL_PORTS", p); } } else { unsafe { env::remove_var("PORTKILL_PORTS"); } }
        });
    }

    #[test]
    fn cli_kill_specific_port() {
        with_clean_cwd(|| {
            let prev = env::var("PORTKILL_PORTS").ok();
            unsafe { env::set_var("PORTKILL_PORTS", "1111,2222"); }

            let mut sys = MockSys::default();
            sys.map.insert(1111, vec![ProcInfo { pid: 10, name: "x".into(), docker: None }]);
            sys.map.insert(2222, vec![ProcInfo { pid: 20, name: "y".into(), docker: None }, ProcInfo { pid: 21, name: "z".into(), docker: None }]);

            let mut out: Vec<u8> = Vec::new();
            let args = vec!["bin".to_string(), "kill:2222".to_string()];
            run_cli_with(args, &mut out, &sys).unwrap();
            let s = String::from_utf8(out).unwrap();
            assert!(s.contains("Puerto 2222: 2 procesos terminados"), "stdout: {}", s);
            let mut killed = sys.killed.lock().unwrap().clone();
            killed.sort();
            assert_eq!(killed, vec![20, 21]);

            if let Some(p) = prev { unsafe { env::set_var("PORTKILL_PORTS", p); } } else { unsafe { env::remove_var("PORTKILL_PORTS"); } }
        });
    }
}
