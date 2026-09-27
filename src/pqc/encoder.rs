//! Нативный Transformer-энкодер BERT/XLM-R-класса (Part E, задача 3.1).
//!
//! Это спина **BGE-M3** (эмбеддинги) и **GLiNER** (NER — голова в
//! `crate::ner::native_gliner`): post-norm BERT-блок
//! `x = LN(x + Attn(x)); x = LN(x + FFN(x))`, GELU-erf, XLM-R-позиции
//! (сдвиг на padding_idx + 1). Веса читаются из `.pqw` zero-copy,
//! Linear-слои матвекторятся кернелами `pqc::tensor` (weight-only
//! int8/int4) — ни ONNX, ни FFI, ни Python.
//!
//! Именование тензоров (конвенция конвертера):
//!
//! ```text
//! word_embeddings        [vocab, hidden]        int8/int4
//! position_embeddings    [max_pos, hidden]      int8/int4
//! token_type_embeddings  [2, hidden]            int8/int4 (опционально)
//! embeddings_ln_gamma    [hidden]               f32
//! embeddings_ln_beta     [hidden]               f32 (опционально, нули)
//! layers.{i}.attn_{q,k,v,o}_w  [out, in]       int8/int4
//! layers.{i}.attn_{q,k,v,o}_b  [out]           f32 (опционально)
//! layers.{i}.attn_ln_gamma|beta [hidden]       f32
//! layers.{i}.ffn_up_w    [intermediate, hidden] int8/int4
//! layers.{i}.ffn_down_w  [hidden, intermediate] int8/int4
//! layers.{i}.ffn_{up,down}_b                   f32 (опционально)
//! layers.{i}.ffn_ln_gamma|beta [hidden]        f32
//! final_ln_gamma|beta    [hidden]               f32 (опционально)
//! ```

use std::path::Path;

use super::pqw::{ModelType, PqwBuilder, Quant, QuantizedWeightsView};
use super::tensor;

/// XLM-R-style позиция токена `t` (padding_idx = 1 → сдвиг +2).
#[inline]
pub fn xlmr_pos_id(t: usize) -> usize {
    t + 2
}

// ---------------------------------------------------------------------------
// Модель
// ---------------------------------------------------------------------------

/// Энкодер поверх mmap-весов `.pqw`.
pub struct EncoderModel {
    view: QuantizedWeightsView,
    hidden: usize,
    heads: usize,
    head_dim: usize,
    layers: usize,
    max_pos: usize,
    xlmr: bool,
}

/// Результат прямого прохода: все скрытые состояния + CLS-пулинг.
pub struct EncoderOut {
    /// Скрытые состояния `[seq × hidden]` (после финальной нормы).
    pub states: Vec<f32>,
    /// CLS-токен, L2-нормализованный (dense-эмбеддинг BGE-M3).
    pub cls: Vec<f32>,
}

impl EncoderModel {
    /// Открывает модель (с Sha256-верификацией весов).
    pub fn open(path: &Path) -> Result<Self, String> {
        let view = QuantizedWeightsView::open(path)?;
        let h = view.header();
        if !matches!(h.model_type, ModelType::Encoder | ModelType::SpanNer) {
            return Err(format!(
                "модель не энкодерного класса (model_type={:?})",
                h.model_type
            ));
        }
        if h.hidden == 0 || h.heads == 0 || h.hidden % h.heads != 0 {
            return Err(format!(
                "архитектура невалидна: hidden={} heads={}",
                h.hidden, h.heads
            ));
        }
        Ok(Self {
            hidden: h.hidden,
            heads: h.heads,
            head_dim: h.hidden / h.heads,
            layers: h.layers,
            max_pos: h.max_pos,
            xlmr: h.xlmr_positions(),
            view,
        })
    }

    /// Размерность эмбеддинга.
    pub fn hidden(&self) -> usize {
        self.hidden
    }

    /// Число слоёв.
    pub fn layers(&self) -> usize {
        self.layers
    }

    /// Доступ к весам (для голов вроде GLiNER span-классификатора).
    pub fn view(&self) -> &QuantizedWeightsView {
        &self.view
    }

    /// Прямой проход по токен-идентификаторам.
    pub fn forward(&self, ids: &[u32]) -> Result<EncoderOut, String> {
        let seq = ids.len();
        if seq == 0 {
            return Err("энкодер: пустая последовательность токенов".into());
        }
        if seq > self.max_pos.saturating_sub(if self.xlmr { 2 } else { 0 }) {
            return Err(format!(
                "последовательность {seq} длиннее max_pos={}",
                self.max_pos
            ));
        }
        let h = self.hidden;

        // --- Эмбеддинги ---
        let word = self.view.require("word_embeddings")?;
        let pos = self.view.require("position_embeddings")?;
        let tok_type = self.view.tensor("token_type_embeddings");
        let (emb_g, emb_b) = self.ln_params("embeddings_ln_gamma", "embeddings_ln_beta")?;
        let mut x = vec![0f32; seq * h];
        let mut row = vec![0f32; h];
        for (t, &id) in ids.iter().enumerate() {
            let id = id as usize;
            if id >= word.rows() {
                return Err(format!("токен {id} вне словаря ({})", word.rows()));
            }
            word.gather_row(id, &mut row)?;
            for (o, v) in x[t * h..(t + 1) * h].iter_mut().zip(&row) {
                *o = *v;
            }
            let p = if self.xlmr { xlmr_pos_id(t) } else { t };
            pos.gather_row(p, &mut row)?;
            for (o, v) in x[t * h..(t + 1) * h].iter_mut().zip(&row) {
                *o += *v;
            }
            if let Some(tt) = &tok_type {
                tt.gather_row(0, &mut row)?;
                for (o, v) in x[t * h..(t + 1) * h].iter_mut().zip(&row) {
                    *o += *v;
                }
            }
            tensor::layer_norm(&mut x[t * h..(t + 1) * h], &emb_g, &emb_b, 1e-5);
        }

        // --- Слои ---
        let intermediate = self.view.header().intermediate;
        let mut q = vec![0f32; seq * h];
        let mut k = vec![0f32; seq * h];
        let mut v = vec![0f32; seq * h];
        let mut ctx = vec![0f32; seq * h];
        let mut attn_out = vec![0f32; h];
        let mut ffn_in = vec![0f32; h];
        let mut inter = vec![0f32; intermediate];
        let mut scores = vec![0f32; seq];
        let scale = 1.0 / (self.head_dim as f32).sqrt();

        for layer in 0..self.layers {
            let p = |suffix: &str| format!("layers.{layer}.{suffix}");
            let wq = self.view.require(&p("attn_q_w"))?;
            let wk = self.view.require(&p("attn_k_w"))?;
            let wv = self.view.require(&p("attn_v_w"))?;
            let wo = self.view.require(&p("attn_o_w"))?;
            let bq = self.view.tensor(&p("attn_q_b"));
            let bk = self.view.tensor(&p("attn_k_b"));
            let bv = self.view.tensor(&p("attn_v_b"));
            let bo = self.view.tensor(&p("attn_o_b"));

            for t in 0..seq {
                let xt = &x[t * h..(t + 1) * h];
                wq.matvec(xt, &mut q[t * h..(t + 1) * h])?;
                wk.matvec(xt, &mut k[t * h..(t + 1) * h])?;
                wv.matvec(xt, &mut v[t * h..(t + 1) * h])?;
                add_bias(&mut q[t * h..(t + 1) * h], bq.as_ref())?;
                add_bias(&mut k[t * h..(t + 1) * h], bk.as_ref())?;
                add_bias(&mut v[t * h..(t + 1) * h], bv.as_ref())?;
            }

            // Многоголовое внимание (bidirectional, как BERT).
            for head in 0..self.heads {
                let off = head * self.head_dim;
                for s in 0..seq {
                    let qs = &q[s * h + off..s * h + off + self.head_dim];
                    for t in 0..seq {
                        let kt = &k[t * h + off..t * h + off + self.head_dim];
                        scores[t] = tensor::dot_f32(qs, kt) * scale;
                    }
                    tensor::softmax_inplace(&mut scores);
                    let cs = &mut ctx[s * h + off..s * h + off + self.head_dim];
                    cs.fill(0.0);
                    for (t, &w) in scores.iter().enumerate() {
                        let vt = &v[t * h + off..t * h + off + self.head_dim];
                        for (o, &vv) in cs.iter_mut().zip(vt) {
                            *o += w * vv;
                        }
                    }
                }
            }

            // Проекция + residual + post-norm.
            let (attn_g, attn_b) = self.ln_params(&p("attn_ln_gamma"), &p("attn_ln_beta"))?;
            for t in 0..seq {
                wo.matvec(&ctx[t * h..(t + 1) * h], &mut attn_out)?;
                add_bias(&mut attn_out, bo.as_ref())?;
                for i in 0..h {
                    x[t * h + i] += attn_out[i];
                }
                tensor::layer_norm(&mut x[t * h..(t + 1) * h], &attn_g, &attn_b, 1e-5);
            }

            // FFN: GELU-erf между двумя матвекторами.
            let up = self.view.require(&p("ffn_up_w"))?;
            let down = self.view.require(&p("ffn_down_w"))?;
            let bu = self.view.tensor(&p("ffn_up_b"));
            let bd = self.view.tensor(&p("ffn_down_b"));
            let (ffn_g, ffn_b) = self.ln_params(&p("ffn_ln_gamma"), &p("ffn_ln_beta"))?;
            for t in 0..seq {
                ffn_in.copy_from_slice(&x[t * h..(t + 1) * h]);
                up.matvec(&ffn_in, &mut inter)?;
                add_bias(&mut inter, bu.as_ref())?;
                tensor::gelu_inplace(&mut inter);
                down.matvec(&inter, &mut attn_out)?;
                add_bias(&mut attn_out, bd.as_ref())?;
                for i in 0..h {
                    x[t * h + i] += attn_out[i];
                }
                tensor::layer_norm(&mut x[t * h..(t + 1) * h], &ffn_g, &ffn_b, 1e-5);
            }
        }

        // Финальная норма (если есть).
        if self.view.tensor("final_ln_gamma").is_some() {
            let (fg, fb) = self.ln_params("final_ln_gamma", "final_ln_beta")?;
            for t in 0..seq {
                tensor::layer_norm(&mut x[t * h..(t + 1) * h], &fg, &fb, 1e-5);
            }
        }

        let mut cls = x[..h].to_vec();
        tensor::l2_normalize(&mut cls);
        Ok(EncoderOut { states: x, cls })
    }

    /// Dense-эмбеддинг последовательности токенов (CLS, L2).
    pub fn embed(&self, ids: &[u32]) -> Result<Vec<f32>, String> {
        Ok(self.forward(ids)?.cls)
    }

    /// Пара (гамма, бета) LayerNorm-параметров; бета опциональна —
    /// нулевая при отсутствии тензора.
    fn ln_params(&self, gamma: &str, beta: &str) -> Result<(Vec<f32>, Vec<f32>), String> {
        let g = self.view.require(gamma)?.f32s()?.to_vec();
        let b = match self.view.tensor(beta) {
            Some(t) => t.f32s()?.to_vec(),
            None => vec![0f32; g.len()],
        };
        Ok((g, b))
    }
}

fn add_bias(out: &mut [f32], bias: Option<&super::pqw::TensorView<'_>>) -> Result<(), String> {
    if let Some(b) = bias {
        let b = b.f32s()?;
        if b.len() != out.len() {
            return Err(format!("bias длины {} вместо {}", b.len(), out.len()));
        }
        for (o, &v) in out.iter_mut().zip(b) {
            *o += v;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Синтетическая модель + fp32-эталон (дифференциальные тесты)
// ---------------------------------------------------------------------------

/// Детерминированный ГПСЧ (SplitMix64 → uniform).
pub struct SynthRng(pub u64);

impl SynthRng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// uniform(a, b).
    pub fn uniform(&mut self, a: f32, b: f32) -> f32 {
        let u = (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32;
        a + (b - a) * u
    }
    pub fn fill(&mut self, v: &mut [f32], a: f32, b: f32) {
        for x in v.iter_mut() {
            *x = self.uniform(a, b);
        }
    }
}

/// fp32-копия синтетической модели (эталон дифференциальных тестов).
pub struct Fp32Encoder {
    pub word: Vec<f32>,
    pub pos: Vec<f32>,
    pub tok_type: Vec<f32>,
    pub emb_ln_g: Vec<f32>,
    pub emb_ln_b: Vec<f32>,
    pub layers: Vec<Fp32Layer>,
    pub final_ln_g: Vec<f32>,
    pub final_ln_b: Vec<f32>,
    pub hidden: usize,
    pub heads: usize,
}

/// Один fp32-слой эталона.
pub struct Fp32Layer {
    pub q_w: Vec<f32>,
    pub k_w: Vec<f32>,
    pub v_w: Vec<f32>,
    pub o_w: Vec<f32>,
    pub q_b: Vec<f32>,
    pub k_b: Vec<f32>,
    pub v_b: Vec<f32>,
    pub o_b: Vec<f32>,
    pub attn_ln_g: Vec<f32>,
    pub attn_ln_b: Vec<f32>,
    pub up_w: Vec<f32>,
    pub up_b: Vec<f32>,
    pub down_w: Vec<f32>,
    pub down_b: Vec<f32>,
    pub ffn_ln_g: Vec<f32>,
    pub ffn_ln_b: Vec<f32>,
}

/// Генерирует синтетический энкодер: квантованный `.pqw`-билдер и
/// fp32-эталон одними и теми же весами (SplitMix64 — битовая
/// воспроизводимость). Синтетика нужна конвейерным тестам и
/// `--pqw-selftest` до появления конвертера реальных весов.
#[allow(clippy::too_many_arguments)]
pub fn synth_encoder(
    seed: u64,
    layers: usize,
    hidden: usize,
    heads: usize,
    intermediate: usize,
    vocab: usize,
    max_pos: usize,
    quant: Quant,
) -> (PqwBuilder, Fp32Encoder) {
    let mut rng = SynthRng(seed);
    let mut b = PqwBuilder::new(
        ModelType::Encoder,
        quant,
        layers,
        hidden,
        heads,
        intermediate,
        vocab,
        max_pos,
    );

    // Мат-тензор с сохранением fp32-копии (квантование — по режиму).
    let mat = |name: &str,
                   rows: usize,
                   cols: usize,
                   b: &mut PqwBuilder,
                   rng: &mut SynthRng|
     -> Vec<f32> {
        let mut w = vec![0f32; rows * cols];
        rng.fill(&mut w, -0.2, 0.2);
        match quant {
            Quant::Int8 => {
                let (q, s) = tensor::quant_i8_per_row(&w, rows, cols);
                b.add_i8(name, vec![rows, cols], &q, &s);
            }
            Quant::Int4 => {
                let (q, s) = tensor::quant_i4_per_row(&w, rows, cols);
                b.add_i4(name, vec![rows, cols], &q, &s);
            }
            Quant::Trit5 => {
                let (q, s) = tensor::quant_trit5_per_row(&w, rows, cols);
                b.add_trit5(name, vec![rows, cols], &q, &s);
            }
            Quant::F32 => {
                b.add_f32(name, vec![rows, cols], &w);
            }
        }
        w
    };

    let vecf = |name: &str,
                    n: usize,
                    b: &mut PqwBuilder,
                    rng: &mut SynthRng,
                    a: f32,
                    c: f32|
     -> Vec<f32> {
        let mut v = vec![0f32; n];
        rng.fill(&mut v, a, c);
        b.add_f32(name, vec![n], &v);
        v
    };

    let word = mat("word_embeddings", vocab, hidden, &mut b, &mut rng);
    let pos = mat("position_embeddings", max_pos, hidden, &mut b, &mut rng);
    let tok_type = mat("token_type_embeddings", 2, hidden, &mut b, &mut rng);
    let emb_ln_g = vecf("embeddings_ln_gamma", hidden, &mut b, &mut rng, 0.9, 1.1);
    let emb_ln_b = vecf("embeddings_ln_beta", hidden, &mut b, &mut rng, -0.05, 0.05);

    let mut fp32_layers = Vec::new();
    for i in 0..layers {
        let p = |s: &str| format!("layers.{i}.{s}");
        let q_w = mat(&p("attn_q_w"), hidden, hidden, &mut b, &mut rng);
        let k_w = mat(&p("attn_k_w"), hidden, hidden, &mut b, &mut rng);
        let v_w = mat(&p("attn_v_w"), hidden, hidden, &mut b, &mut rng);
        let o_w = mat(&p("attn_o_w"), hidden, hidden, &mut b, &mut rng);
        let q_b = vecf(&p("attn_q_b"), hidden, &mut b, &mut rng, -0.05, 0.05);
        let k_b = vecf(&p("attn_k_b"), hidden, &mut b, &mut rng, -0.05, 0.05);
        let v_b = vecf(&p("attn_v_b"), hidden, &mut b, &mut rng, -0.05, 0.05);
        let o_b = vecf(&p("attn_o_b"), hidden, &mut b, &mut rng, -0.05, 0.05);
        let attn_ln_g = vecf(&p("attn_ln_gamma"), hidden, &mut b, &mut rng, 0.9, 1.1);
        let attn_ln_b = vecf(&p("attn_ln_beta"), hidden, &mut b, &mut rng, -0.05, 0.05);
        let up_w = mat(&p("ffn_up_w"), intermediate, hidden, &mut b, &mut rng);
        let up_b = vecf(&p("ffn_up_b"), intermediate, &mut b, &mut rng, -0.05, 0.05);
        let down_w = mat(&p("ffn_down_w"), hidden, intermediate, &mut b, &mut rng);
        let down_b = vecf(&p("ffn_down_b"), hidden, &mut b, &mut rng, -0.05, 0.05);
        let ffn_ln_g = vecf(&p("ffn_ln_gamma"), hidden, &mut b, &mut rng, 0.9, 1.1);
        let ffn_ln_b = vecf(&p("ffn_ln_beta"), hidden, &mut b, &mut rng, -0.05, 0.05);
        fp32_layers.push(Fp32Layer {
            q_w,
            k_w,
            v_w,
            o_w,
            q_b,
            k_b,
            v_b,
            o_b,
            attn_ln_g,
            attn_ln_b,
            up_w,
            up_b,
            down_w,
            down_b,
            ffn_ln_g,
            ffn_ln_b,
        });
    }
    let final_ln_g = vecf("final_ln_gamma", hidden, &mut b, &mut rng, 0.9, 1.1);
    let final_ln_b = vecf("final_ln_beta", hidden, &mut b, &mut rng, -0.05, 0.05);

    let fp32 = Fp32Encoder {
        word,
        pos,
        tok_type,
        emb_ln_g,
        emb_ln_b,
        layers: fp32_layers,
        final_ln_g,
        final_ln_b,
        hidden,
        heads,
    };
    (b, fp32)
}

/// Наивный fp32-эталон прямого прохода (никакого SIMD, никакого
/// квантования — независимая реализация для дифференциальных тестов).
pub fn reference_forward(w: &Fp32Encoder, ids: &[u32]) -> Vec<f32> {
    let h = w.hidden;
    let heads = w.heads;
    let hd = h / heads;
    let seq = ids.len();
    let mut x = vec![0f32; seq * h];
    for (t, &id) in ids.iter().enumerate() {
        for i in 0..h {
            x[t * h + i] = w.word[id as usize * h + i]
                + w.pos[xlmr_pos_id(t) * h + i]
                + w.tok_type[i];
        }
    }
    for t in 0..seq {
        let mut row = x[t * h..(t + 1) * h].to_vec();
        tensor::layer_norm(&mut row, &w.emb_ln_g, &w.emb_ln_b, 1e-5);
        x[t * h..(t + 1) * h].copy_from_slice(&row);
    }
    let scale = 1.0 / (hd as f32).sqrt();
    for layer in &w.layers {
        let mut qkv = vec![vec![0f32; 3 * h]; seq];
        for t in 0..seq {
            let xt = &x[t * h..(t + 1) * h];
            for i in 0..h {
                qkv[t][i] = dot_naive(&layer.q_w[i * h..(i + 1) * h], xt) + layer.q_b[i];
                qkv[t][h + i] = dot_naive(&layer.k_w[i * h..(i + 1) * h], xt) + layer.k_b[i];
                qkv[t][2 * h + i] = dot_naive(&layer.v_w[i * h..(i + 1) * h], xt) + layer.v_b[i];
            }
        }
        let mut ctx = vec![0f32; seq * h];
        for head in 0..heads {
            let off = head * hd;
            for s in 0..seq {
                let mut scores = vec![0f32; seq];
                for t in 0..seq {
                    let mut d = 0f32;
                    for d_i in 0..hd {
                        d += qkv[s][off + d_i] * qkv[t][h + off + d_i];
                    }
                    scores[t] = d * scale;
                }
                tensor::softmax_inplace(&mut scores);
                for d_i in 0..hd {
                    let mut acc = 0f32;
                    for t in 0..seq {
                        acc += scores[t] * qkv[t][2 * h + off + d_i];
                    }
                    ctx[s * h + off + d_i] = acc;
                }
            }
        }
        for t in 0..seq {
            let mut a = vec![0f32; h];
            for i in 0..h {
                a[i] = dot_naive(&layer.o_w[i * h..(i + 1) * h], &ctx[t * h..(t + 1) * h])
                    + layer.o_b[i];
            }
            for i in 0..h {
                x[t * h + i] += a[i];
            }
            let mut row = x[t * h..(t + 1) * h].to_vec();
            tensor::layer_norm(&mut row, &layer.attn_ln_g, &layer.attn_ln_b, 1e-5);
            x[t * h..(t + 1) * h].copy_from_slice(&row);
        }
        for t in 0..seq {
            let xt = &x[t * h..(t + 1) * h];
            let intermediate = layer.up_w.len() / h;
            let mut inter = vec![0f32; intermediate];
            for i in 0..inter.len() {
                inter[i] = dot_naive(&layer.up_w[i * h..(i + 1) * h], xt) + layer.up_b[i];
            }
            for v in inter.iter_mut() {
                *v = tensor::gelu(*v);
            }
            let mut d = vec![0f32; h];
            for i in 0..h {
                // down_w — [hidden, intermediate]: строка длины intermediate,
                // НЕ h (бага эталона, вскрытая дифференциалом debug_steps).
                d[i] = dot_naive(
                    &layer.down_w[i * intermediate..(i + 1) * intermediate],
                    &inter,
                ) + layer.down_b[i];
            }
            for i in 0..h {
                x[t * h + i] += d[i];
            }
            let mut row = x[t * h..(t + 1) * h].to_vec();
            tensor::layer_norm(&mut row, &layer.ffn_ln_g, &layer.ffn_ln_b, 1e-5);
            x[t * h..(t + 1) * h].copy_from_slice(&row);
        }
    }
    for t in 0..seq {
        let mut row = x[t * h..(t + 1) * h].to_vec();
        tensor::layer_norm(&mut row, &w.final_ln_g, &w.final_ln_b, 1e-5);
        x[t * h..(t + 1) * h].copy_from_slice(&row);
    }
    x
}

fn dot_naive(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cos(a: &[f32], b: &[f32]) -> f32 {
        let ip = a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>();
        let na = a.iter().map(|v| v * v).sum::<f32>().sqrt();
        let nb = b.iter().map(|v| v * v).sum::<f32>().sqrt();
        ip / (na * nb)
    }

    fn run_diff(quant: Quant) -> f32 {
        let path = std::env::temp_dir().join(format!(
            "poler-enc-{:?}-{}.pqw",
            quant,
            std::process::id()
        ));
        let (builder, fp32) = synth_encoder(42, 2, 32, 4, 64, 64, 48, quant);
        builder.write_to(&path).unwrap();
        let model = EncoderModel::open(&path).unwrap();
        let ids: Vec<u32> = vec![3, 17, 5, 42, 9, 21, 8, 30];
        let native = model.forward(&ids).unwrap();
        let reference = reference_forward(&fp32, &ids);
        let c = cos(&native.states, &reference);
        let _ = std::fs::remove_file(&path);
        c
    }

    #[test]
    fn native_matches_reference_int8() {
        let c = run_diff(Quant::Int8);
        assert!(c > 0.999, "косинус int8-энкодера vs эталона = {c}");
    }

    #[test]
    fn native_matches_reference_int4() {
        let c = run_diff(Quant::Int4);
        assert!(c > 0.98, "косинус int4-энкодера vs эталона = {c}");
    }

    #[test]
    fn native_matches_reference_f32() {
        let c = run_diff(Quant::F32);
        assert!(c > 0.9999, "косинус fp32-энкодера vs эталона = {c}");
    }

    #[test]
    fn deterministic_across_runs() {
        let path = std::env::temp_dir().join(format!("poler-enc-det-{}.pqw", std::process::id()));
        let (builder, _) = synth_encoder(7, 2, 32, 4, 64, 64, 48, Quant::Int8);
        builder.write_to(&path).unwrap();
        let model = EncoderModel::open(&path).unwrap();
        let ids: Vec<u32> = vec![1, 2, 3, 4, 5];
        let a = model.embed(&ids).unwrap();
        let b = model.embed(&ids).unwrap();
        assert_eq!(a, b, "инференс должен быть побитово детерминирован");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cls_is_unit_norm() {
        let path = std::env::temp_dir().join(format!("poler-enc-norm-{}.pqw", std::process::id()));
        let (builder, _) = synth_encoder(11, 1, 16, 2, 32, 32, 32, Quant::Int8);
        builder.write_to(&path).unwrap();
        let model = EncoderModel::open(&path).unwrap();
        let cls = model.embed(&[1, 5, 9]).unwrap();
        let n = cls.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((n - 1.0).abs() < 1e-5, "норма CLS = {n}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_and_oversize_rejected() {
        let path = std::env::temp_dir().join(format!("poler-enc-err-{}.pqw", std::process::id()));
        let (builder, _) = synth_encoder(1, 1, 16, 2, 32, 32, 16, Quant::Int8);
        builder.write_to(&path).unwrap();
        let model = EncoderModel::open(&path).unwrap();
        assert!(model.forward(&[]).is_err());
        // xlmr: полезный диапазон позиций = max_pos − 2.
        let too_long: Vec<u32> = (0..15u32).collect();
        assert!(model.forward(&too_long).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn xlmr_position_offset() {
        // padding_idx = 1 → позиции начинаются с 2.
        assert_eq!(xlmr_pos_id(0), 2);
        assert_eq!(xlmr_pos_id(5), 7);
    }
}
