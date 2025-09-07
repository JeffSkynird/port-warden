use anyhow::Result;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet},
    thread,
    time::{Duration, Instant},
};
#[cfg(feature = "gui")]
use std::path::PathBuf;
#[cfg(feature = "gui")]
use std::net::SocketAddr;
#[cfg(feature = "gui")]
use std::path::Path;
#[cfg(feature = "gui")]
use std::process::Command;
use sysinfo::{Pid, System};
#[cfg(feature = "gui")]
use tao::event::{Event, StartCause};
#[cfg(feature = "gui")]
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder};
#[cfg(feature = "gui")]
use tray_icon::{TrayIcon, TrayIconBuilder};
#[cfg(feature = "gui")]
use tray_icon::menu::{Menu, MenuItemBuilder, PredefinedMenuItem, Submenu};

use port_warden::{active_profile, Config, DockerInfo, ProcInfo, SystemOps, run_cli_with};
#[cfg(feature = "gui")]
use port_warden::{load_profiles_from_fs, ProfileCfg};

// Max label length to avoid the tray menu stretching horizontally
#[cfg(feature = "gui")]
const MENU_CMD_LABEL_MAX: usize = 60;

static STATE: Lazy<RwLock<State>> = Lazy::new(|| RwLock::new(State::default()));
#[cfg(feature = "gui")]
static PROTECTED_PORTS: Lazy<HashSet<u16>> = Lazy::new(|| vec![5432, 6379, 3306, 27017].into_iter().collect());
#[cfg(feature = "gui")]
static FRIENDLY_PORTS: Lazy<HashMap<u16, &'static str>> = Lazy::new(|| vec![
    (9000, "MinIO"),
    (9001, "MinIO Console"),
    (15672, "RabbitMQ UI"),
    (7700, "Meilisearch"),
    (8080, "Nginx"),
].into_iter().collect());

// Shorten long labels to keep the tray width reasonable
#[cfg(feature = "gui")]
fn ellipsize(s: &str, max: usize) -> String {
    if max == 0 { return String::new(); }
    let mut out = String::new();
    let mut count = 0usize;
    for ch in s.chars() {
        if count + 1 >= max { out.push('…'); return out; }
        out.push(ch);
        count += 1;
    }
    out
}

#[derive(Debug, Default)]
struct State {
    cfg: Config,
    ports: HashMap<u16, Vec<ProcInfo>>, // actual status
    last_busy: HashMap<u16, bool>,      // previous busy
    #[cfg_attr(not(feature = "gui"), allow(dead_code))]
    hot_pids: HashMap<u32, u8>,         // overusage consecutive
    #[cfg_attr(not(feature = "gui"), allow(dead_code))]
    tasks: Vec<Task>,                   // tasks queue
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
enum Task { WhenFreeRestart { port: u16 }, WhenFreeRun { port: u16, cmd: String } }

// User events for the GUI event loop
#[cfg(feature = "gui")]
#[derive(Debug, Clone)]
enum UserEvent { RefreshMenu }

// Desktop notifications: Linux only for now. Other OS later.
#[cfg(all(target_os = "linux", feature = "gui"))]
fn notify(title: &str, body: &str) {
    let _ = notify_rust::Notification::new()
        .summary(title)
        .body(body)
        .show();
}
#[cfg(not(all(target_os = "linux", feature = "gui")))]
#[allow(dead_code)]
fn notify(_title: &str, _body: &str) { /* no-op on non-Linux or non-GUI */ }

// ===== Docker awareness (bollard) =====
#[cfg(not(target_os = "windows"))]
fn docker_port_map_blocking() -> HashMap<u16, Vec<DockerInfo>> {
    // Use independent Tokio runtime to avoid coupling to external runtimes
    tokio::runtime::Runtime::new().unwrap().block_on(async move {
        use bollard::container::ListContainersOptions; use bollard::Docker;
        let docker = match Docker::connect_with_local_defaults() { Ok(d) => d, Err(_) => return HashMap::new() };
        let opts = ListContainersOptions::<String> { all: true, ..Default::default() };
        let mut map: HashMap<u16, Vec<DockerInfo>> = HashMap::new();
        if let Ok(list) = docker.list_containers(Some(opts)).await {
            for c in list {
                let id = c.id.unwrap_or_default();
                let name = c.names.unwrap_or_default().get(0).cloned().unwrap_or_default().trim_start_matches('/').to_string();
                let image = c.image.unwrap_or_default();
                if let Some(ports) = c.ports {
                    for p in ports {
                        if let Some(public) = p.public_port {
                            let _private = p.private_port;
                            let info = DockerInfo { id: id.clone(), name: name.clone(), image: image.clone() };
                            map.entry(public as u16).or_default().push(info);
                        }
                    }
                }
            }
        }
        map
    })
}
#[cfg(target_os = "windows")]
fn docker_port_map_blocking() -> HashMap<u16, Vec<DockerInfo>> { HashMap::new() }

// ===== Sockets Scan + merge with Docker =====
fn scan_ports(targets: &[u16]) -> Result<HashMap<u16, Vec<ProcInfo>>> {
    use netstat2::{iterate_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let pf = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let set: HashSet<u16> = targets.iter().copied().collect();

    let mut sys = System::new_all();
    sys.refresh_all();

    let mut map: HashMap<u16, Vec<ProcInfo>> = HashMap::new();
    for port in targets { map.insert(*port, Vec::new()); }

    for socket in iterate_sockets_info(af, pf)? {
        let info = socket?;
        let port = match info.protocol_socket_info {
            ProtocolSocketInfo::Tcp(ref t) => t.local_port,
            ProtocolSocketInfo::Udp(ref u) => u.local_port,
        };
        if !set.contains(&port) { continue; }

        #[cfg(target_os = "linux")]
        {
            let pids: Vec<u32> = info.associated_pids.clone();
            if let Some(pid) = pids.into_iter().next() {
                let name = sys.process(Pid::from_u32(pid)).map(|p| p.name().to_string()).unwrap_or_else(|| "?".into());
                map.entry(port).or_default().push(ProcInfo { pid, name, docker: None });
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Best-effort: without per-OS fields, skip attaching process info.
        }
    }

    let dmap = docker_port_map_blocking();
    for (port, containers) in dmap { if !set.contains(&port) { continue; } let e = map.entry(port).or_default(); for c in containers { if !e.iter().any(|p| p.docker.as_ref().map(|d| d.id.as_str()) == Some(c.id.as_str())) { e.push(ProcInfo { pid: 0, name: format!("container:{}", c.name), docker: Some(c) }); } } }
    Ok(map)
}

// ===== Helpers =====
#[cfg(feature = "gui")]
fn copy_to_clipboard(s: &str) { let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(s.to_string())); }
#[cfg(feature = "gui")]
fn tail_logs_for_pid(pid: u32) -> String {
    #[cfg(target_os = "linux")]
    { let cmd = format!("(tail -n 200 /proc/{pid}/fd/1 2>/dev/null || tail -n 200 /proc/{pid}/fd/2 2>/dev/null || echo 'No stdout/stderr available for PID {pid}')"); String::from_utf8_lossy(&Command::new("sh").arg("-c").arg(cmd).output().map(|o| o.stdout).unwrap_or_default()).to_string() }
    #[cfg(target_os = "macos")]
    { let args = ["show", "--last", "5m", "--style", "syslog", "--predicate", &format!("processID == {}", pid)]; String::from_utf8_lossy(&Command::new("log").args(&args).output().map(|o| o.stdout).unwrap_or_default()).to_string() }
    #[cfg(target_os = "windows")]
    { "Tail logs no compatible en Windows".to_string() }
}

// ===== Kill inteligente =====
#[cfg(unix)] fn send_signal_unix(pid: i32, sig: nix::sys::signal::Signal) { let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), sig); }
fn wait_until_gone(pid: u32, timeout_ms: u64) -> bool { let end = Instant::now() + Duration::from_millis(timeout_ms); let mut sys = System::new_all(); while Instant::now() < end { sys.refresh_all(); if sys.process(Pid::from_u32(pid)).is_none() { return true; } thread::sleep(Duration::from_millis(100)); } false }
fn kill_pid_smart(pid: u32) -> Result<()> {
    #[cfg(unix)] { send_signal_unix(pid as i32, nix::sys::signal::Signal::SIGTERM); if wait_until_gone(pid, 400) {return Ok(());} send_signal_unix(pid as i32, nix::sys::signal::Signal::SIGINT); if wait_until_gone(pid, 400) {return Ok(());} send_signal_unix(pid as i32, nix::sys::signal::Signal::SIGKILL); let _=wait_until_gone(pid, 400); Ok(()) }
    #[cfg(windows)] { let mut sys = System::new_all(); sys.refresh_all(); if let Some(p) = sys.process(Pid::from_u32(pid)) { p.kill(); } Ok(()) }
}
#[cfg(feature = "gui")]
fn kill_by_port(port: u16) -> Result<usize> { let state = STATE.read(); let items = state.ports.get(&port).cloned().unwrap_or_default(); drop(state); let mut count = 0; for p in items { if p.pid != 0 && kill_pid_smart(p.pid).is_ok() { count += 1; } } Ok(count) }
#[cfg(feature = "gui")]
fn kill_all_ports() -> Result<usize> { let ports: Vec<u16> = active_profile(&STATE.read().cfg).ports.clone(); let mut total = 0; for port in ports { total += kill_by_port(port)?; } Ok(total) }

// ===== Docker actions =====
#[cfg(feature = "gui")]
fn docker_restart(id: &str) { let _ = tokio::runtime::Runtime::new().unwrap().block_on(async move { use bollard::Docker; let docker = Docker::connect_with_local_defaults().ok(); if let Some(d) = docker { let _ = d.restart_container(id, None).await; } }); }
#[cfg(feature = "gui")]
fn docker_delete(id: &str) { let _ = tokio::runtime::Runtime::new().unwrap().block_on(async move { use bollard::Docker; use bollard::container::RemoveContainerOptions; let docker = Docker::connect_with_local_defaults().ok(); if let Some(d) = docker { let opts = RemoveContainerOptions { force: true, v: true, link: false }; let _ = d.remove_container(id, Some(opts)).await; } }); }

// ===== Kill + Restart heurístico =====
#[cfg(feature = "gui")]
#[derive(Clone, Debug)] struct CommandSpec { program: String, args: Vec<String>, cwd: Option<PathBuf> }
#[cfg(feature = "gui")]
fn guess_restart_cmd(root: &Path, profile: &ProfileCfg) -> Option<CommandSpec> {
    let cwd = profile.cwd.clone().unwrap_or_else(|| root.to_path_buf());
    if cwd.join("docker-compose.yml").exists() || cwd.join("docker-compose.yaml").exists() { return Some(CommandSpec{ program:"docker".into(), args: vec!["compose".into(), "up".into(), "-d".into()], cwd: Some(cwd)}); }
    if cwd.join("package.json").exists() { let pm = if cwd.join("pnpm-lock.yaml").exists(){"pnpm"} else if cwd.join("yarn.lock").exists(){"yarn"} else {"npm"}; let args = match pm {"yarn"=>vec!["dev".into()],"pnpm"=>vec!["dev".into()],_=>vec!["run".into(),"dev".into()]}; return Some(CommandSpec{ program: pm.into(), args, cwd: Some(cwd)}); }
    if cwd.join("Cargo.toml").exists() { return Some(CommandSpec{ program: "cargo".into(), args: vec!["run".into()], cwd: Some(cwd)}); }
    None
}
#[cfg(feature = "gui")]
fn spawn_command(cmd: &CommandSpec) -> Result<()> { let mut c = Command::new(&cmd.program); c.args(&cmd.args); if let Some(ref d) = cmd.cwd { c.current_dir(d); } c.spawn()?; Ok(()) }

// ===== Collisions =====
#[cfg(feature = "gui")]
fn open_browser(port: u16) { let _ = webbrowser::open(&format!("http://localhost:{}", port)); }

// ===== local API =====
#[cfg(feature = "gui")]
use axum::{extract::{Path as AxPath, Query as AxQuery}, Json};
#[cfg(feature = "gui")]
async fn api_kill_port(AxQuery(q): AxQuery<HashMap<String, String>>) -> Json<serde_json::Value> { let port=q.get("port").and_then(|s| s.parse::<u16>().ok()); let confirm=q.get("confirm").map(|s| s=="1"||s=="true").unwrap_or(false); let mut killed=0usize; if let Some(p)=port { if PROTECTED_PORTS.contains(&p) && !confirm { return Json(serde_json::json!({"ok":false,"reason":"protected_port","hint":"add ?confirm=1"})); } if let Ok(n)=kill_by_port(p){killed=n;} } Json(serde_json::json!({"ok":true,"killed":killed})) }
#[cfg(feature = "gui")]
async fn api_kill_profile(AxPath(name): AxPath<String>) -> Json<serde_json::Value> { let cfg=STATE.read().cfg.clone(); let profile=cfg.file_cfg.profiles.get(&name).cloned(); if profile.is_none(){return Json(serde_json::json!({"ok":false,"reason":"unknown_profile"}));} let profile=profile.unwrap(); let mut total=0usize; for p in profile.ports { if PROTECTED_PORTS.contains(&p) { continue; } if let Ok(n)=kill_by_port(p){ total+=n; } } Json(serde_json::json!({"ok":true,"killed":total})) }
#[cfg(feature = "gui")]
async fn api_when_free(AxQuery(q): AxQuery<HashMap<String, String>>) -> Json<serde_json::Value> { let port=q.get("port").and_then(|s| s.parse::<u16>().ok()); if port.is_none(){return Json(serde_json::json!({"ok":false,"reason":"missing_port"}));} let port=port.unwrap(); if let Some(cmd)=q.get("cmd").cloned(){ STATE.write().tasks.push(Task::WhenFreeRun{port,cmd}); } else { STATE.write().tasks.push(Task::WhenFreeRestart{port}); } Json(serde_json::json!({"ok":true})) }
#[cfg(feature = "gui")]
fn start_api_server() {
    let port = std::env::var("PORTKILL_API_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(7077);
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async move {
            use axum::{routing::post, Router};
            let app = Router::new()
                .route("/kill", post(api_kill_port))
                .route("/profile/:name/kill", post(api_kill_profile))
                .route("/when_free", post(api_when_free));
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            let listener = tokio::net::TcpListener::bind(addr).await.expect("bind listener");
            let _ = axum::serve(listener, app).await;
        });
    });
}

// ===== Dinamic Menu =====
#[cfg(feature = "gui")]
fn friendly_label(port: &u16) -> String { FRIENDLY_PORTS.get(port).map(|n| format!("{} ({})", port, n)).unwrap_or_else(|| port.to_string()) }
#[cfg(feature = "gui")]
fn build_menu() -> Menu {
    let state = STATE.read();
    let profile = active_profile(&state.cfg);
    let menu = Menu::new();

    // Profiles submenu
    let prof_sub: Submenu = Submenu::new("Profiles", true);
    {
        let item = MenuItemBuilder::new()
            .text("Reload profiles")
            .id("profiles_reload".into())
            .enabled(true)
            .build();
        let _ = prof_sub.append(&item);
        let sep = PredefinedMenuItem::separator();
        let _ = prof_sub.append(&sep);
        for name in state.cfg.file_cfg.profiles.keys() {
            let label = if *name == state.cfg.active_profile { format!("● {}", name) } else { name.clone() };
            let item = MenuItemBuilder::new()
                .text(label)
                .id(format!("profile_use:{}", name).into())
                .enabled(true)
                .build();
            let _ = prof_sub.append(&item);
        }
    }
    let _ = menu.append(&prof_sub);

    // Refresh menu action (rebuilds the tray menu)
    let item = MenuItemBuilder::new()
        .text("Refresh Menu")
        .id("refresh_menu".into())
        .enabled(true)
        .build();
    let _ = menu.append(&item);

    if let Some(start) = profile.start.as_ref() {
        let run_label = format!("Run: {}", ellipsize(start, MENU_CMD_LABEL_MAX.saturating_sub(5))); // account for prefix
        let item = MenuItemBuilder::new()
            .text(run_label)
            .id("profile_start".into())
            .enabled(true)
            .build();
        let _ = menu.append(&item);
    }
    if let Some(stop) = profile.stop.as_ref() {
        let stop_label = format!("Stop: {}", ellipsize(stop, MENU_CMD_LABEL_MAX.saturating_sub(6)));
        let item = MenuItemBuilder::new()
            .text(stop_label)
            .id("profile_stop".into())
            .enabled(true)
            .build();
        let _ = menu.append(&item);
    }

    {
        let sep = PredefinedMenuItem::separator();
        let _ = menu.append(&sep);
        let item = MenuItemBuilder::new()
            .text("Kill All Processes")
            .id("kill_all".into())
            .enabled(true)
            .build();
        let _ = menu.append(&item);
        let sep = PredefinedMenuItem::separator();
        let _ = menu.append(&sep);
    }

    // Ports listed as submenus; avoid extra separator (we already added one above)
    // If there are no profiles loaded, skip showing free ports (useless noise).
    let skip_free_when_no_profiles = state.cfg.file_cfg.profiles.is_empty();
    for port in &profile.ports {
        let procs = state.ports.get(port).cloned().unwrap_or_default();
        if procs.is_empty() && skip_free_when_no_profiles {
            // Do not show free ports when no profiles are loaded
            continue;
        }
        let title = if procs.is_empty() {
            format!("Port {}: (free)", friendly_label(port))
        } else {
            format!("Port {}: ({} proc)", friendly_label(port), procs.len())
        };
        let port_sub: Submenu = Submenu::new(&title, true);

        // Common quick actions
        {
            let item = MenuItemBuilder::new()
                .text(format!("Open http://localhost:{}", port))
                .id(format!("open:{}", port).into())
                .enabled(true)
                .build();
            let _ = port_sub.append(&item);
            let item = MenuItemBuilder::new()
                .text(format!("Copy lsof :{}", port))
                .id(format!("copy_lsof:{}", port).into())
                .enabled(true)
                .build();
            let _ = port_sub.append(&item);
            let sep = PredefinedMenuItem::separator();
            let _ = port_sub.append(&sep);
        }

        if !procs.is_empty() {
            let all_label = if PROTECTED_PORTS.contains(port) { format!("Kill: Port {} (protected)", friendly_label(port)) } else { format!("Kill: Port {} (all)", friendly_label(port)) };
            let item = MenuItemBuilder::new()
                .text(all_label)
                .id(format!("kill_port:{}", port).into())
                .enabled(true)
                .build();
            let _ = port_sub.append(&item);
            // Removed: "Kill & Restart" action
            // Removed: "Move to next free port (rewrite .env)"

            let sep = PredefinedMenuItem::separator();
            let _ = port_sub.append(&sep);
            for p in procs {
                if let Some(d) = p.docker.clone() {
                    let is_core = FRIENDLY_PORTS.contains_key(port) || PROTECTED_PORTS.contains(port);
                    let restart_lbl = if is_core { format!("Restart core container {}", d.name) } else { format!("Restart container {}", d.name) };
                    let item = MenuItemBuilder::new()
                        .text(restart_lbl)
                        .id(format!("docker_restart:{}", d.id).into())
                        .enabled(true)
                        .build();
                    let _ = port_sub.append(&item);
                    // Removed: "Stop container" action
                    let item = MenuItemBuilder::new()
                        .text(format!("Delete container {} (force)", d.name))
                        .id(format!("docker_delete:{}", d.id).into())
                        .enabled(true)
                        .build();
                    let _ = port_sub.append(&item);
                } else {
                    let item = MenuItemBuilder::new()
                        .text(format!("Tail logs (pid {})", p.pid))
                        .id(format!("tail_pid:{}", p.pid).into())
                        .enabled(true)
                        .build();
                    let _ = port_sub.append(&item);
                    let item = MenuItemBuilder::new()
                        .text(format!("Copy kill {}", p.pid))
                        .id(format!("copy_kill:{}", p.pid).into())
                        .enabled(true)
                        .build();
                    let _ = port_sub.append(&item);
                    let label = format!("Kill: Port {} · {} (pid {})", port, p.name, p.pid);
                    let item = MenuItemBuilder::new()
                        .text(label)
                        .id(format!("kill_pid:{}:{}", port, p.pid).into())
                        .enabled(true)
                        .build();
                    let _ = port_sub.append(&item);
                }
            }
        }

        let _ = menu.append(&port_sub);
    }

    let item = MenuItemBuilder::new().text("Quit").id("quit".into()).enabled(true).build();
    let _ = menu.append(&item);
    menu
}

// ===== simple CLI =====
struct RealSystemOps;
impl SystemOps for RealSystemOps {
    fn scan(&self, targets: &[u16]) -> Result<HashMap<u16, Vec<ProcInfo>>> { scan_ports(targets) }
    fn kill_pid(&self, pid: u32) -> bool { kill_pid_smart(pid).is_ok() }
}

// ===== Main + monitoring =====
#[cfg(feature = "gui")]
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if std::env::var("PORTKILL_MODE").as_deref() == Ok("cli") || args.iter().any(|a| a == "--cli") {
        let mut out = std::io::stdout();
        return run_cli_with(args, &mut out, &RealSystemOps);
    }
    // Opt-in HTTP API flag (disabled by default)
    let enable_api = args.iter().any(|a| a == "--api");

    {
        let mut st = STATE.write();
        st.cfg = Config::default();
        // Enable alerts only when flag is present
        st.cfg.alerts_enabled = args.iter().any(|a| a == "--alerts");
        let profile = active_profile(&st.cfg);
        st.ports = scan_ports(&profile.ports).unwrap_or_default();
        st.last_busy = profile.ports.iter().map(|p| (*p, st.ports.get(p).map(|v| !v.is_empty()).unwrap_or(false))).collect();
    }

    // Refresh Thread + alerts + tasks
    thread::spawn(|| {
        let mut sys_alert = System::new_all();
        loop {
            let refresh = STATE.read().cfg.refresh_secs;
            let cfg = STATE.read().cfg.clone();
            let profile = active_profile(&cfg);

            // Scan
            let new_map = scan_ports(&profile.ports).unwrap_or_default();
            {
                let mut st = STATE.write();
                // Track status changes (busy/free) without notifications
                for port in &profile.ports {
                    let was_busy = *st.last_busy.get(port).unwrap_or(&false);
                    let now_busy = new_map.get(port).map(|v| !v.is_empty()).unwrap_or(false);
                    if now_busy != was_busy { st.last_busy.insert(*port, now_busy); }
                }
                st.ports = new_map.clone();

                // Tasks WhenFree
                let tasks = std::mem::take(&mut st.tasks);
                let ports_snapshot = st.ports.clone();
                let cfg_snapshot = st.cfg.clone();
                drop(st); // release borrow before reading snapshots and re-borrowing

                let mut keep = Vec::new();
                for t in tasks {
                    match &t {
                        Task::WhenFreeRestart { port } => {
                            let busy = ports_snapshot.get(port).map(|v| !v.is_empty()).unwrap_or(false);
                            if !busy {
                                if let Some(spec) = guess_restart_cmd(&cfg_snapshot.project_root, &active_profile(&cfg_snapshot)) { let _ = spawn_command(&spec); }
                            } else {
                                keep.push(t);
                            }
                        }
                        Task::WhenFreeRun { port, cmd } => {
                            let busy = ports_snapshot.get(port).map(|v| !v.is_empty()).unwrap_or(false);
                            if !busy {
                                let parts: Vec<_> = cmd.split_whitespace().map(|s| s.to_string()).collect();
                                if !parts.is_empty() { let spec = CommandSpec { program: parts[0].clone(), args: parts[1..].to_vec(), cwd: Some(cfg_snapshot.project_root.clone()) }; let _ = spawn_command(&spec); }
                            } else {
                                keep.push(t);
                            }
                        }
                    }
                }
                let mut st = STATE.write();
                st.tasks = keep;
            }

            // CPU/Mem Monitoring (only if alerts are enabled)
            let alerts_on = STATE.read().cfg.alerts_enabled;
            if alerts_on {
                sys_alert.refresh_all();
                let (cpu_thr, mem_thr) = { let c = &STATE.read().cfg; (c.cpu_threshold, c.mem_threshold_mb) };
                {
                // Snapshot pids to avoid borrowing conflicts
                let pids: Vec<u32> = {
                    let st = STATE.read();
                    st.ports
                        .values()
                        .flat_map(|v| v.iter().map(|p| p.pid))
                        .filter(|pid| *pid != 0)
                        .collect()
                };
                let mut st = STATE.write();
                for pid in pids {
                    if let Some(proc_) = sys_alert.process(Pid::from_u32(pid)) {
                        let cpu = proc_.cpu_usage();
                        let mem_mb = proc_.memory() / 1024 / 1024;
                        let over = cpu >= cpu_thr || mem_mb >= mem_thr;
                        let cnt = st.hot_pids.entry(pid).or_insert(0);
                        if over {
                            *cnt = cnt.saturating_add(1);
                            if *cnt >= 3 {
                                notify("High usage", &format!("pid {}: {:.0}% CPU, {} MB", pid, cpu, mem_mb));
                                *cnt = 0;
                            }
                        } else {
                            *cnt = 0;
                        }
                    }
                }
                }
            }

            // Rebuild the tray menu on demand elsewhere if needed.
            thread::sleep(Duration::from_secs(refresh));
        }
    });

    // Local API HTTP (only if --api flag is present)
    if enable_api { start_api_server(); }

    // Create tray and event loop
    // Event loop with user events to request menu rebuilds
    let event_loop: EventLoop<UserEvent> = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let menu = build_menu();
    let tray: TrayIcon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Port Kill")
        .build()
        .expect("tray icon");

    tray_icon::menu::MenuEvent::set_event_handler(Some(move |event: tray_icon::menu::MenuEvent| {
        let id_str = event.id.as_ref();
        match id_str {
                "quit" => std::process::exit(0),
                "kill_all" => { let _ = kill_all_ports(); let proxy2 = proxy.clone(); thread::spawn(move || { std::thread::sleep(Duration::from_millis(250)); let _ = proxy2.send_event(UserEvent::RefreshMenu); }); },
                "refresh_menu" => {
                    let _ = proxy.send_event(UserEvent::RefreshMenu);
                },
                "profiles_reload" => {
                    if let Some((root, file_cfg)) = load_profiles_from_fs() {
                        let mut s = STATE.write();
                        s.cfg.project_root = root;
                        s.cfg.file_cfg = file_cfg;
                    }
                    let _ = proxy.send_event(UserEvent::RefreshMenu);
                },
                "profile_start" => { let s = STATE.read(); let prof = active_profile(&s.cfg); if let Some(cmdline) = prof.start { let parts: Vec<_> = cmdline.split_whitespace().map(|s| s.to_string()).collect(); if !parts.is_empty() { let spec = CommandSpec { program: parts[0].clone(), args: parts[1..].to_vec(), cwd: prof.cwd.or(Some(s.cfg.project_root.clone())) }; let _ = spawn_command(&spec); let _ = proxy.send_event(UserEvent::RefreshMenu); } } },
                "profile_stop" => { let s = STATE.read(); let prof = active_profile(&s.cfg); if let Some(cmdline) = prof.stop { let parts: Vec<_> = cmdline.split_whitespace().map(|s| s.to_string()).collect(); if !parts.is_empty() { let spec = CommandSpec { program: parts[0].clone(), args: parts[1..].to_vec(), cwd: prof.cwd.or(Some(s.cfg.project_root.clone())) }; let _ = spawn_command(&spec); let _ = proxy.send_event(UserEvent::RefreshMenu); } } },
                _ => {
                    if let Some(rest) = id_str.strip_prefix("profile_use:") { STATE.write().cfg.active_profile = rest.to_string(); let _ = proxy.send_event(UserEvent::RefreshMenu); }
                    else if let Some(rest) = id_str.strip_prefix("open:") { if let Ok(port) = rest.parse::<u16>() { open_browser(port); } }
                    else if let Some(rest) = id_str.strip_prefix("copy_lsof:") { if let Ok(port) = rest.parse::<u16>() { copy_to_clipboard(&format!("lsof -i :{} -nP", port)); } }
                    // Removed handler: kill_restart:*
                    else if let Some(rest) = id_str.strip_prefix("copy_kill:") { if let Ok(pid) = rest.parse::<u32>() { #[cfg(unix)] { copy_to_clipboard(&format!("kill -TERM {}", pid)); } #[cfg(windows)] { copy_to_clipboard(&format!("taskkill /PID {} /T /F", pid)); } } }
                    else if let Some(rest) = id_str.strip_prefix("tail_pid:") {
                        if let Ok(pid) = rest.parse::<u32>() {
                            let logs = tail_logs_for_pid(pid);
                            let mut dlg = rfd::MessageDialog::new();
                            dlg = dlg.set_title("Tail logs");
                            dlg = dlg.set_description(&logs);
                            dlg = dlg.set_buttons(rfd::MessageButtons::Ok);
                            let _ = dlg.show();
                        }
                    }
                    // Removed handler: resolve_port:*
                    else if let Some(rest) = id_str.strip_prefix("kill_port:") { if let Ok(port) = rest.parse::<u16>() { let _ = kill_by_port(port); let proxy2 = proxy.clone(); thread::spawn(move || { std::thread::sleep(Duration::from_millis(250)); let _ = proxy2.send_event(UserEvent::RefreshMenu); }); } }
                    else if let Some(rest) = id_str.strip_prefix("kill_pid:") { if let Some((_, pid_s)) = rest.split_once(':') { if let Ok(pid) = pid_s.parse::<u32>() { let _ = kill_pid_smart(pid); let proxy2 = proxy.clone(); thread::spawn(move || { std::thread::sleep(Duration::from_millis(250)); let _ = proxy2.send_event(UserEvent::RefreshMenu); }); } } }
                    else if let Some(id) = id_str.strip_prefix("docker_restart:") { docker_restart(id); let proxy2 = proxy.clone(); thread::spawn(move || { std::thread::sleep(Duration::from_millis(350)); let _ = proxy2.send_event(UserEvent::RefreshMenu); }); }
                    else if let Some(id) = id_str.strip_prefix("docker_delete:") { docker_delete(id); let proxy2 = proxy.clone(); thread::spawn(move || { std::thread::sleep(Duration::from_millis(350)); let _ = proxy2.send_event(UserEvent::RefreshMenu); }); }
                }
        }
    }));

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {}
            Event::UserEvent(UserEvent::RefreshMenu) => {
                // Rebuild tray menu on demand
                let _ = tray.set_menu(Some(Box::new(build_menu())));
            }
            Event::LoopDestroyed => {}
            _ => {}
        }
    });
}

#[cfg(not(feature = "gui"))]
fn main() -> Result<()> {
    // CLI-only mode: populate initial state and run CLI
    {
        let mut st = STATE.write();
        st.cfg = Config::default();
        let profile = active_profile(&st.cfg);
        st.ports = scan_ports(&profile.ports).unwrap_or_default();
        st.last_busy = profile.ports.iter().map(|p| (*p, st.ports.get(p).map(|v| !v.is_empty()).unwrap_or(false))).collect();
    }
    let args: Vec<String> = std::env::args().collect();
    let mut out = std::io::stdout();
    run_cli_with(args, &mut out, &RealSystemOps)
}
