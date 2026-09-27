//! FileCache — резидентный RAM-кэш содержимого файлов (M6).
//!
//! Назначение: интерактивные grep-запросы резидентного MCP-сервера не
//! должны перечитывать корпус с диска на каждый вызов. Кэш держит
//! содержимое плоских файлов в RAM с инвалидацией по `mtime + len`
//! (стат дешевле чтения на порядки) и LRU-вытеснением по бюджету байт.
//!
//! ## Контракт честности
//!
//! - Хит возможен ТОЛЬКО при совпадении `mtime` и длины с текущим
//!   `stat` файла: правка файла (даже с сохранением длины) меняет
//!   mtime → кэш перечитывает. Это компромисс «stat против полного
//!   хеша» — для интерактивного слоя достаточно (злонамеренная
//!   подмена с откатом mtime — вне модели угроз локального инструмента).
//! - Бюджет — жёсткий верхний предел RAM под кэш (по умолчанию задаёт
//!   `--mcp-ram-budget`, МиБ). Архивные записи (`архив::запись`) в v1
//!   не кэшируются — у них другая семантика чтения.
//! - Потокобезопасен: `&FileCache` шарится между лучами rayon.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Запись кэша: содержимое + валидационная подпись.
struct Entry {
    mtime: SystemTime,
    len: u64,
    data: Arc<Vec<u8>>,
}

struct Inner {
    map: HashMap<PathBuf, Entry>,
    /// Порядок касания (голова — свежее): LRU-вытеснение из хвоста.
    order: VecDeque<PathBuf>,
    bytes: usize,
}

/// Статистика кэша (для --mcp-bench и диагностики).
#[derive(Clone, Copy, Debug, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    /// Перечитано из-за изменения файла (инвалидация).
    pub invalidated: u64,
    pub evictions: u64,
    pub files: usize,
    pub bytes: usize,
}

/// Резидентный кэш файлов. `Clone` = ручка на общее состояние
/// (Arc внутри), копия дешёвая.
#[derive(Clone)]
pub struct FileCache {
    inner: Arc<Mutex<Inner>>,
    cap_bytes: usize,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    invalidated: Arc<AtomicU64>,
    evictions: Arc<AtomicU64>,
}

impl FileCache {
    /// Кэш с бюджетом `cap_bytes` байт (0 → безлимитный, для тестов).
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
            })),
            cap_bytes,
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            invalidated: Arc::new(AtomicU64::new(0)),
            evictions: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Бюджет кэша (байт).
    pub fn cap_bytes(&self) -> usize {
        self.cap_bytes
    }

    /// Получить содержимое файла: из RAM при валидной подписи,
    /// иначе прочитать с диска и закэшировать. `Err` — файл не
    /// читается (пропускается вызывающим grep-слоем как ошибка файла).
    pub fn get_or_read(&self, path: &Path) -> std::io::Result<Arc<Vec<u8>>> {
        let meta = std::fs::metadata(path)?;
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let len = meta.len();

        // Быстрый путь: валидная запись в RAM.
        {
            let mut inner = self.inner.lock().expect("filecache: отравленный лок");
            if let Some(entry) = inner.map.get(path) {
                if entry.mtime == mtime && entry.len == len {
                    let data = entry.data.clone();
                    // Касание LRU: переставить в голову.
                    if let Some(pos) = inner.order.iter().position(|p| p == path) {
                        inner.order.remove(pos);
                    }
                    inner.order.push_back(path.to_path_buf());
                    drop(inner);
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(data);
                }
                // Подпись не совпала: файл изменился — убрать устаревшую.
                let old = inner.map.remove(path).expect("только что была");
                inner.bytes = inner.bytes.saturating_sub(old.data.len());
                if let Some(pos) = inner.order.iter().position(|p| p == path) {
                    inner.order.remove(pos);
                }
                drop(inner);
                self.invalidated.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Медленный путь: чтение с диска.
        let data = Arc::new(std::fs::read(path)?);
        self.misses.fetch_add(1, Ordering::Relaxed);

        let mut inner = self.inner.lock().expect("filecache: отравленный лок");
        inner.map.insert(
            path.to_path_buf(),
            Entry { mtime, len, data: data.clone() },
        );
        inner.bytes += data.len();
        inner.order.push_back(path.to_path_buf());
        // LRU-вытеснение из головы очереди (самые старые касания).
        while self.cap_bytes > 0 && inner.bytes > self.cap_bytes {
            let victim = match inner.order.pop_front() {
                Some(v) => v,
                None => break,
            };
            if let Some(old) = inner.map.remove(&victim) {
                inner.bytes = inner.bytes.saturating_sub(old.data.len());
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(data)
    }

    /// Снимок статистики.
    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.lock().expect("filecache: отравленный лок");
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            invalidated: self.invalidated.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            files: inner.map.len(),
            bytes: inner.bytes,
        }
    }

    /// Полный сброс (смена корня сканирования, тесты).
    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("filecache: отравленный лок");
        inner.map.clear();
        inner.order.clear();
        inner.bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("poler-fc-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Хит после первого чтения + честная инвалидация по mtime.
    #[test]
    fn hit_and_mtime_invalidation() {
        let dir = tmpdir("mtime");
        let f = dir.join("doc.md");
        std::fs::write(&f, "version-1: резонанс").unwrap();

        let cache = FileCache::new(0);
        let d1 = cache.get_or_read(&f).unwrap();
        assert_eq!(&d1[..], "version-1: резонанс".as_bytes());
        assert_eq!(cache.stats().misses, 1);

        let d2 = cache.get_or_read(&f).unwrap();
        assert_eq!(cache.stats().hits, 1, "второе чтение — из RAM");
        assert!(Arc::ptr_eq(&d1, &d2), "хит возвращает ту же Arc-альлокацию");

        // Правка файла: mtime обязан отличиться. Гарантируем явной
        // установкой времени модификации (не полагаемся на гранулярность ФС).
        std::fs::write(&f, "version-2: диссипация").unwrap();
        let fh = std::fs::File::options().write(true).open(&f).unwrap();
        fh.set_modified(SystemTime::now() + std::time::Duration::from_secs(3600))
            .unwrap();
        drop(fh);

        let d3 = cache.get_or_read(&f).unwrap();
        assert_eq!(&d3[..], "version-2: диссипация".as_bytes(), "изменившийся файл перечитан");
        assert_eq!(cache.stats().invalidated, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// LRU-вытеснение по бюджету: суммарно не больше cap.
    #[test]
    fn lru_eviction_respects_budget() {
        let dir = tmpdir("lru");
        let cache = FileCache::new(1000);
        for i in 0..5 {
            let f = dir.join(format!("f{i}.bin"));
            std::fs::write(&f, vec![b'x'; 400]).unwrap();
            cache.get_or_read(&f).unwrap();
        }
        let s = cache.stats();
        assert!(s.bytes <= 1000, "бюджет превышен: {s:?}");
        assert!(s.evictions >= 1, "вытеснение обязано было сработать: {s:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Несуществующий файл — Err, кэш не отравлен.
    #[test]
    fn missing_file_is_error() {
        let cache = FileCache::new(0);
        let r = cache.get_or_read(Path::new("/definitely/not/here/poler.md"));
        assert!(r.is_err());
        assert_eq!(cache.stats().files, 0);
    }
}
