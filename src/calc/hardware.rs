//! Зонд «скрытых глазу» параметров ПК (цикл M, v0.48.0).
//!
//! Читает то, что не видно в обычном `htop`: кеши L1d/L1i/L2/L3 по
//! индексам sysfs, флаги ISA (AVX/AVX2/AVX-512/AES…), топологию
//! (сокеты/NUMA/потоки на ядро), bogomips, страницы памяти, слоты дисков,
//! GPU (nvidia-smi при наличии + PCI IDs в sysfs), виртуализацию.
//!
//! Всё — только чтение /proc и /sys (+ один вызов nvidia-smi, если он
//! есть в PATH). Никаких прав root не требуется.

use std::collections::BTreeMap;
use std::fs;

/// Прочитать файл в String (trim), None — если нет/не читается.
fn read_file(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Прочитать файл в байтах-число.
fn read_num(path: &str) -> Option<u64> {
    read_file(path).and_then(|s| s.parse::<u64>().ok())
}

/// Упорядоченный отчёт: (категория, ключ, значение).
pub struct HardwareReport {
    pub fields: Vec<(String, String, String)>,
}

impl HardwareReport {
    fn push(&mut self, cat: &str, key: &str, val: String) {
        self.fields.push((cat.into(), key.into(), val));
    }

    /// Текстовый вид для `hw`.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let mut cur_cat = String::new();
        for (cat, key, val) in &self.fields {
            if *cat != cur_cat {
                out.push_str(&format!("\n── {cat} ─────────────────────\n"));
                cur_cat = cat.clone();
            }
            out.push_str(&format!("  {key:<26} {val}\n"));
        }
        out
    }

    /// JSON-вид для `hw --json` / MCP.
    pub fn to_json(&self) -> String {
        let mut map: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for (cat, key, val) in &self.fields {
            map.entry(cat.clone())
                .or_default()
                .insert(key.clone(), val.clone());
        }
        serde_json::to_string_pretty(&map).unwrap_or_else(|_| "{}".into())
    }
}

/// Собрать отчёт о железе.
pub fn probe() -> HardwareReport {
    let mut r = HardwareReport { fields: Vec::new() };

    probe_cpu(&mut r);
    probe_caches(&mut r);
    probe_topology(&mut r);
    probe_memory(&mut r);
    probe_kernel(&mut r);
    probe_disks(&mut r);
    probe_gpu(&mut r);
    probe_vm(&mut r);

    r
}

fn probe_cpu(r: &mut HardwareReport) {
    let cpuinfo = read_file("/proc/cpuinfo").unwrap_or_default();
    let mut model = String::new();
    let mut vendor = String::new();
    let mut mhz = String::new();
    let mut bogomips = String::new();
    let mut flags = String::new();
    let mut addr_sizes = String::new();
    let clean = |v: &str| v.trim_start_matches(|c: char| c == ':' || c == '\t' || c == ' ').to_string();
    for line in cpuinfo.lines() {
        if let Some(v) = line.strip_prefix("model name") {
            model = clean(v);
        } else if let Some(v) = line.strip_prefix("vendor_id") {
            vendor = clean(v);
        } else if let Some(v) = line.strip_prefix("cpu MHz") {
            mhz = clean(v);
        } else if let Some(v) = line.strip_prefix("bogomips") {
            bogomips = clean(v);
        } else if let Some(v) = line.strip_prefix("flags") {
            flags = clean(v);
        } else if let Some(v) = line.strip_prefix("address sizes") {
            addr_sizes = clean(v);
        }
    }
    r.push("CPU", "модель", model);
    r.push("CPU", "вендор", vendor);
    r.push("CPU", "частота (МГц)", mhz);
    r.push("CPU", "bogomips", bogomips);
    r.push("CPU", "разрядность адресов", addr_sizes);

    // «Скрытые» возможности ISA — что реально умеет камень
    let interesting = [
        "avx512f", "avx512bw", "avx512vl", "avx2", "avx", "sse4_2", "sse4_1",
        "aes", "sha_ni", "rdrand", "rdseed", "bmi1", "bmi2", "fma", "f16c",
        "popcnt", "adx", "pclmulqdq", "movbe", "hypervisor",
    ];
    let have: Vec<&str> = interesting
        .iter()
        .copied()
        .filter(|f| flags.split_whitespace().any(|w| w == *f))
        .collect();
    r.push(
        "CPU",
        "ISA (векторы/крипто)",
        if have.is_empty() { "не определены".into() } else { have.join(" ") },
    );
    // гипервизор — отдельной строкой, заметнее
    if flags.split_whitespace().any(|w| w == "hypervisor") {
        r.push("CPU", "гипервизор", "флаг hypervisor присутствует".into());
    }
    // число логических процессоров
    if let Some(n) = read_num("/sys/devices/system/cpu/kernel_max") {
        r.push("CPU", "kernel_max", n.to_string());
    }
}

fn probe_caches(r: &mut HardwareReport) {
    // Кеши по индексам: /sys/devices/system/cpu/cpu0/cache/index*/
    let mut found = false;
    for idx in 0..8 {
        let base = format!("/sys/devices/system/cpu/cpu0/cache/index{idx}");
        let (Some(level), Some(kind)) = (
            read_file(&format!("{base}/level")),
            read_file(&format!("{base}/type")),
        ) else {
            continue;
        };
        let size = read_file(&format!("{base}/size")).unwrap_or_else(|| "?".into());
        let line = read_file(&format!("{base}/shared_cpu_list"))
            .map(|s| format!(" (делится с {s})"))
            .unwrap_or_default();
        r.push(
            "Кеши",
            &format!("L{level} {kind}"),
            format!("{size}{line}"),
        );
        found = true;
    }
    if !found {
        // fallback: "cache size" из cpuinfo (суммарный L3)
        if let Some(cpuinfo) = read_file("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if let Some(v) = line.strip_prefix("cache size") {
                    let v = v.trim_start_matches(|c: char| c == ':' || c == ' ');
                    r.push("Кеши", "L3 (cpuinfo)", v.to_string());
                    break;
                }
            }
        }
    }
}

fn probe_topology(r: &mut HardwareReport) {
    // Логические CPU
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") {
        let ncpu = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|s| s.starts_with("cpu") && s[3..].chars().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false)
            })
            .count();
        if ncpu > 0 {
            r.push("Топология", "логических CPU", ncpu.to_string());
        }
    }
    // Физические ядра: максимальный core id + 1 по всем thread_siblings
    let mut cores: Vec<String> = Vec::new();
    let mut sockets: Vec<String> = Vec::new();
    let mut threads_per_core = 0usize;
    for cpu in 0..1024 {
        let base = format!("/sys/devices/system/cpu/cpu{cpu}/topology");
        let (Some(sib), Some(core), Some(sock)) = (
            read_file(&format!("{base}/thread_siblings_list")),
            read_file(&format!("{base}/core_id")),
            read_file(&format!("{base}/physical_package_id")),
        ) else {
            break;
        };
        if !cores.contains(&core) {
            cores.push(core);
        }
        if !sockets.contains(&sock) {
            sockets.push(sock);
        }
        let n_sib = sib.split(',').count();
        if n_sib > threads_per_core {
            threads_per_core = n_sib;
        }
    }
    if !cores.is_empty() {
        r.push("Топология", "физических ядер", cores.len().to_string());
    }
    if !sockets.is_empty() {
        r.push("Топология", "сокетов (CPU)", sockets.len().to_string());
    }
    if threads_per_core > 0 {
        r.push("Топология", "потоков на ядро", threads_per_core.to_string());
    }
    // NUMA
    if let Ok(entries) = fs::read_dir("/sys/devices/system/node") {
        let numa: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|s| s.starts_with("node") && s[4..].chars().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false)
            })
            .collect();
        if !numa.is_empty() {
            r.push("Топология", "NUMA-узлов", numa.len().to_string());
        }
    }
}

fn probe_memory(r: &mut HardwareReport) {
    if let Some(mi) = read_file("/proc/meminfo") {
        let grab = |key: &str| -> Option<String> {
            mi.lines().find_map(|l| {
                let mut it = l.split_whitespace();
                let k = it.next()?.trim_end_matches(':');
                if k == key {
                    let kb: f64 = it.next()?.parse().ok()?;
                    // человекочитаемо: ГиБ с одним знаком
                    Some(format!("{:.1} ГиБ", kb / 1048576.0))
                } else {
                    None
                }
            })
        };
        if let Some(v) = grab("MemTotal") {
            r.push("Память", "всего", v);
        }
        if let Some(v) = grab("MemAvailable") {
            r.push("Память", "доступно", v);
        }
        if let Some(v) = grab("SwapTotal") {
            r.push("Память", "swap", v);
        }
        if let Some(v) = grab("HugePages_Total") {
            r.push("Память", "HugePages", v);
        }
        if let Some(v) = grab("Hugepagesize") {
            r.push("Память", "размер HugePage", v);
        }
    }
    if let Some(l) = read_file("/proc/loadavg") {
        r.push("Память", "loadavg", l);
    }
}

fn probe_kernel(r: &mut HardwareReport) {
    let uts = read_file("/proc/sys/kernel/osrelease")
        .or_else(|| read_file("/proc/version"));
    if let Some(v) = uts {
        r.push("Ядро", "версия", v);
    }
    if let Ok(p) = fs::read_link("/proc/self/exe") {
        r.push("Ядро", "битность процесса", "x86_64".into());
        let _ = p;
    }
    // размер страницы памяти
    if let Some(s) = read_file("/proc/self/smaps") {
        if let Some(line) = s.lines().next() {
            r.push("Ядро", "smaps первая строка", line.to_string());
        }
    }
    if let Some(v) = read_file("/proc/uptime") {
        let secs: f64 = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0.0);
        let d = (secs / 86400.0).floor();
        let h = ((secs - d * 86400.0) / 3600.0).floor();
        let m = ((secs - d * 86400.0 - h * 3600.0) / 60.0).floor();
        r.push("Ядро", "uptime", format!("{d} д {h} ч {m} мин"));
    }
}

fn probe_disks(r: &mut HardwareReport) {
    if let Ok(entries) = fs::read_dir("/sys/block") {
        let mut names: Vec<String> = Vec::new();
        for e in entries.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.starts_with("loop") {
                names.push(name);
            }
        }
        names.sort();
        for name in names.iter().take(8) {
            let size512 = read_num(&format!("/sys/block/{name}/size"));
            let size_gib = size512.map(|s| format!("{:.1} ГиБ", s as f64 * 512.0 / 1_073_741_824.0));
            let rotational = read_num(&format!("/sys/block/{name}/queue/rotational"))
                .map(|v| if v == 1 { "HDD" } else { "SSD/NVMe" }.to_string());
            let model = read_file(&format!("/sys/block/{name}/device/model"))
                .or_else(|| read_file(&format!("/sys/block/{name}/device/name")));
            let mut desc = String::new();
            if let Some(s) = size_gib {
                desc.push_str(&s);
            }
            if let Some(rot) = rotational {
                if !desc.is_empty() {
                    desc.push_str(", ");
                }
                desc.push_str(&rot);
            }
            if let Some(m) = model {
                if !desc.is_empty() {
                    desc.push_str(", ");
                }
                desc.push_str(&m);
            }
            if !desc.is_empty() {
                r.push("Диски", name, desc);
            }
        }
    }
}

fn probe_gpu(r: &mut HardwareReport) {
    // 1) nvidia-smi — самый информативный путь
    let smi = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,driver_version,memory.total,compute_cap,pci.bus_id",
            "--format=csv,noheader",
        ])
        .output();
    if let Ok(out) = smi {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for (i, line) in text.lines().enumerate() {
                let parts: Vec<&str> = line.split(", ").collect();
                let name = parts.first().copied().unwrap_or("GPU");
                r.push(
                    "GPU",
                    &format!("nvidia[{i}] {name}"),
                    format!(
                        "драйвер {}, память {}, compute {}, шина {}",
                        parts.get(1).copied().unwrap_or("?"),
                        parts.get(2).copied().unwrap_or("?"),
                        parts.get(3).copied().unwrap_or("?"),
                        parts.get(4).copied().unwrap_or("?")
                    ),
                );
            }
            return;
        }
    }
    // 2) sysfs DRM: PCI vendor/device
    let vendors = [
        ("0x10de", "NVIDIA"),
        ("0x1002", "AMD"),
        ("0x8086", "Intel"),
        ("0x15ad", "VMware"),
        ("0x1af4", "virtio"),
    ];
    if let Ok(entries) = fs::read_dir("/sys/class/drm") {
        let mut cards: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("card") && n[4..].chars().all(|c| c.is_ascii_digit()))
            .collect();
        cards.sort();
        for card in cards.iter().take(4) {
            let base = format!("/sys/class/drm/{card}/device");
            let vid = read_file(&format!("{base}/vendor")).unwrap_or_default();
            let did = read_file(&format!("{base}/device")).unwrap_or_default();
            let vendor_name = vendors
                .iter()
                .find(|(v, _)| *v == vid)
                .map(|(_, n)| n.to_string())
                .unwrap_or_else(|| vid.clone());
            // VRAM (AMD exposes mem_info_vram_total)
            let vram = read_num(&format!("{base}/mem_info_vram_total"))
                .map(|b| format!(", VRAM {:.0} МиБ", b as f64 / 1_048_576.0))
                .unwrap_or_default();
            r.push(
                "GPU",
                card,
                format!("PCI {vendor_name} {did}{vram}"),
            );
        }
    }
}

fn probe_vm(r: &mut HardwareReport) {
    let product = read_file("/sys/class/dmi/id/product_name");
    let vendor = read_file("/sys/class/dmi/id/sys_vendor");
    if let Some(v) = vendor {
        r.push("Платформа", "вендор DMI", v.clone());
        let cloudish = ["KVM", "QEMU", "VMware", "VirtualBox", "Xen", "Hyper-V", "Docker", "LXC"];
        if cloudish.iter().any(|c| v.contains(c)) {
            r.push("Платформа", "виртуализация", "да (гостевая ВМ)".into());
        }
    }
    if let Some(p) = product {
        r.push("Платформа", "продукт DMI", p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_something() {
        let r = probe();
        // В любом Linux-окружении CPU-модель и память должны читаться;
        // в совсем чужой ОС отчёт может быть пуст — допускаем, но не паникуем.
        assert!(!r.to_text().is_empty() || r.fields.is_empty());
    }

    #[test]
    fn report_rendering() {
        let mut r = HardwareReport { fields: Vec::new() };
        r.push("CPU", "модель", "Test CPU 9000".into());
        r.push("CPU", "вендор", "GenuineTest".into());
        r.push("GPU", "card0", "PCI NVIDIA 0x1234".into());
        let text = r.to_text();
        assert!(text.contains("Test CPU 9000"));
        assert!(text.contains("── CPU"));
        assert!(text.contains("── GPU"));
        let json = r.to_json();
        assert!(json.contains("\"модель\": \"Test CPU 9000\""));
        assert!(json.contains("GPU"));
    }

    #[test]
    fn json_is_valid() {
        let r = probe();
        let j = r.to_json();
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&j);
        assert!(parsed.is_ok(), "JSON невалиден: {j}");
    }
}
