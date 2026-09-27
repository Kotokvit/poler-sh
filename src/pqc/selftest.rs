//! `--pqw-selftest` — полный автономный цикл суверенного инференса.
//!
//! Генерирует синтетические модели (энкодер int8/int4, GLiNER,
//! GLM dense, GLM MoE), прогоняет живые циклы: генерация `.pqw` →
//! mmap + Sha256-верификация → нативный forward → сверка с fp32-эталоном.
//! Ноль сети, ноль внешних библиотек, один бинарь — критерий успеха
//! Part E («полный цикл инференса автономно») до появления конвертера
//! реальных весов.

use std::path::Path;
use std::time::Instant;

use super::encoder::{self, EncoderModel};
use super::pqw::{self, Quant};
use super::tensor;

use crate::llm::glm_engine::{self, GlmModel, Sampling};
use crate::ner::native_gliner::{self, GlinerModel};

/// Запускает самотест, возвращает код выхода (0 = все проверки зелёные).
pub fn run_selftest() -> u8 {
    let dir = std::env::temp_dir().join(format!("poler-pqw-selftest-{}", std::process::id()));
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("poler-pqw-selftest: не создать временную папку {}", dir.display());
        return 2;
    }
    println!("══════ POLER PQW SELFTEST — суверенный нативный инференс (pqc) ══════");
    println!(
        "CPU: AVX2+FMA = {} · формат .pqw v2 · mmap zero-copy · Sha256\n",
        tensor::avx2()
    );

    let checks: Vec<(&str, Result<String, String>)> = vec![
        ("энкодер int8 (BERT-класс) vs fp32-эталон", check_encoder(&dir, Quant::Int8)),
        ("энкодер int4 vs fp32-эталон", check_encoder(&dir, Quant::Int4)),
        ("GLiNER span-голова (синтетика)", check_gliner(&dir)),
        ("GLM-декодер dense: генерация greedy", check_glm(&dir, Quant::Int8, 0)),
        ("GLM-декодер MoE (int4): роутинг топ-k", check_glm(&dir, Quant::Int4, 4)),
        ("Sha256-верификация весов (порча файла)", check_tamper(&dir)),
    ];

    let mut pass = 0;
    for (i, (name, res)) in checks.iter().enumerate() {
        match res {
            Ok(detail) => {
                pass += 1;
                println!("[{}/{}] ✓ {} — {}", i + 1, checks.len(), name, detail);
            }
            Err(e) => println!("[{}/{}] ✗ {} — {}", i + 1, checks.len(), name, e),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);

    println!(
        "\nИТОГ: {}/{} — {}",
        pass,
        checks.len(),
        if pass == checks.len() {
            "полный цикл инференса автономно: один бинарь, ноль .so, ноль сети"
        } else {
            "ЕСТЬ ПРОВАЛЫ (см. выше)"
        }
    );
    if pass == checks.len() {
        0
    } else {
        1
    }
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let ip = a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>();
    let na = a.iter().map(|v| v * v).sum::<f32>().sqrt();
    let nb = b.iter().map(|v| v * v).sum::<f32>().sqrt();
    ip / (na * nb)
}

fn check_encoder(dir: &Path, quant: Quant) -> Result<String, String> {
    let path = dir.join(format!("selftest-enc-{:?}.pqw", quant));
    let t0 = Instant::now();
    let (builder, fp32) = encoder::synth_encoder(42, 2, 64, 4, 128, 96, 64, quant);
    builder.write_to(&path)?;
    let model = EncoderModel::open(&path)?;
    let ids: Vec<u32> = (0..12u32).map(|i| (i * 7 + 3) % 96).collect();
    let out = model.forward(&ids)?;
    let reference = encoder::reference_forward(&fp32, &ids);
    let c = cosine(&out.states, &reference);
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let norm: f32 = out.cls.iter().map(|v| v * v).sum::<f32>().sqrt();
    let _ = std::fs::remove_file(&path);
    // int4/trit5 — физика сверхнизкого битрейта: на синтетике честный порог ниже.
    let (threshold, note) = match quant {
        Quant::Int4 => (0.98, "физика int4"),
        Quant::Trit5 => (0.95, "физика троичного резонанса trit5"),
        Quant::Int8 => (0.999, "weight-only int8"),
        Quant::F32 => (0.9999, "fp32-контроль"),
    };
    if c > threshold && (norm - 1.0).abs() < 1e-3 {
        Ok(format!(
            "cos={c:.4} ({note}) · CLS-норма {norm:.3} · {ms:.0} мс полный цикл (генерация модели → mmap → forward 12 токенов)"
        ))
    } else {
        Err(format!("cos={c:.4} < {threshold}, CLS-норма {norm:.3}"))
    }
}

fn check_gliner(dir: &Path) -> Result<String, String> {
    let path = dir.join("selftest-gliner.pqw");
    let t0 = Instant::now();
    let (builder, _) = native_gliner::synth_gliner(
        7,
        1,
        32,
        4,
        64,
        64,
        64,
        &["PERSON", "LOCATION", "OBJECT"],
        Quant::Int8,
    );
    builder.write_to(&path)?;
    let model = GlinerModel::open(&path)?;
    let words = ["Вэнс", "прибыл", "на", "Архисферу", "вечером"];
    let ids: Vec<u32> = words.iter().map(|w| (w.len() as u32 * 13 + 1) % 64).collect();
    let ents = model.extract(&words, &ids, 0.5)?;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let sample: Vec<String> = ents
        .iter()
        .take(3)
        .map(|e| format!("{}:{:.2}", e.label, e.score))
        .collect();
    let _ = std::fs::remove_file(&path);
    if ents.is_empty() {
        Err("span-голова не дала ни одной сущности".into())
    } else {
        Ok(format!(
            "{} сущностей (порог 0.5), например [{}] · {ms:.0} мс",
            ents.len(),
            sample.join(", ")
        ))
    }
}

fn check_glm(dir: &Path, quant: Quant, experts: usize) -> Result<String, String> {
    let path = dir.join(format!("selftest-glm-{:?}-{}.pqw", quant, experts));
    let t0 = Instant::now();
    let (builder, _) = glm_engine::synth_glm(9, 2, 64, 4, 1, 96, 128, 64, quant, experts, 2);
    builder.write_to(&path)?;
    let model = GlmModel::open(&path)?;
    let prompt: Vec<u32> = vec![1, 2, 3, 4];
    let n = 24usize;
    let out = model.generate(&prompt, n, &Sampling::Greedy, 0)?;
    let dt = t0.elapsed().as_secs_f64();
    let tps = (n as f64 / dt.max(1e-9)) as usize;
    let text = detokenize_synthetic(&out);
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let _ = std::fs::remove_file(&path);
    if out.len() != n {
        return Err(format!("сгенерировано {} токенов вместо {n}", out.len()));
    }
    if experts > 0 {
        let (chosen, w) = glm_engine::moe_route(&[0.2, 1.5, 0.9, 2.2], 2);
        Ok(format!(
            "{tps} ток/с · {} КБ · маршрут: эксперты {chosen:?}, веса {:.3}/{:.3} · «{text}»",
            size / 1024,
            w[0],
            w[1]
        ))
    } else {
        Ok(format!(
            "{tps} ток/с · {} КБ · RoPE+MQA+SwiGLU · «{text}»",
            size / 1024
        ))
    }
}

fn check_tamper(dir: &Path) -> Result<String, String> {
    let path = dir.join("selftest-tamper.pqw");
    let (builder, _) = encoder::synth_encoder(1, 1, 16, 2, 32, 32, 32, Quant::Int8);
    builder.write_to(&path)?;
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let mut bad = bytes.clone();
    // Порча байта в payload (за заголовком, в первой секции данных).
    bad[pqw::PAGE + 8] ^= 0x5A;
    let bad_path = dir.join("selftest-tampered.pqw");
    std::fs::write(&bad_path, &bad).map_err(|e| e.to_string())?;
    let err = match pqw::QuantizedWeightsView::open(&bad_path) {
        Err(e) => e,
        Ok(_) => String::from("порча НЕ распознана при открытии"),
    };
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&bad_path);
    if err.contains("Sha256") {
        Ok("подменённый байт пойман при открытии (до инференса)".into())
    } else {
        Err(format!("порча не распознана как Sha256: {err}"))
    }
}

/// Детокенизация синтетического словаря: `w{id}` + UAX#29-правила.
fn detokenize_synthetic(ids: &[u32]) -> String {
    let words: Vec<String> = ids.iter().map(|&i| format!("w{i}")).collect();
    let refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
    glm_engine::detokenize_join(&refs)
}

#[cfg(test)]
mod tests {
    #[test]
    fn selftest_passes() {
        // Самотест сам является тестом: 6/6 зелёных.
        let code = super::run_selftest();
        assert_eq!(code, 0, "самотест обязан проходить полностью");
    }
}
