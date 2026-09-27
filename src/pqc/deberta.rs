//! DeBERTa-v2/v3-энкодер — спина GLiNER реальных чекпойнтов (Part E, 7.1).
//!
//! Disentangled attention: скор пары (q,k) = контент + два позиционных
//! члена через ОДНУ таблицу log-бакетов относительных позиций:
//!
//! ```text
//! bucket(i−j): |r| ≤ 128 → r (линейно);  иначе ceil(log(|r|/128)/log(511/128)·127)+128, ·sign
//! idx(i,j)  = clamp(bucket(i−j)+256, 0, 511)          — индекс строки rel_emb
//! c2p[i,j]  = Q_i · PK[idx]   (PK = key_proj(rel_emb_ln))
//! p2c[i,j]  = K_j · PQ[idx]   (PQ = query_proj(rel_emb_ln)) — ТЕ ЖЕ индексы!
//! score     = (Q_i·K_j + c2p + p2c) / √(d_head·3)
//! ```
//!
//! share_att_key: позиционные проекции — те же query/key_proj, что и для
//! контента (отдельных pos_key_proj/pos_query_proj в чекпойнте нет).
//! Нормализации: post-norm BERT-схема, eps 1e-7; rel_emb прогоняется через
//! LayerNorm (norm_rel_ebd="layer_norm") один раз за проход.
//! Абсолютных позиционных эмбеддингов нет (position_biased_input=false).
//!
//! Именование секций (конвенция конвертера `convert_gliner_to_pqw.py`):
//!
//! ```text
//! word_embeddings        [vocab, hidden]        int8/int4
//! embeddings_ln_gamma    [hidden]               f32
//! embeddings_ln_beta     [hidden]               f32
//! rel_embeddings         [512, hidden]          int8/int4
//! rel_ln_gamma           [hidden]               f32
//! rel_ln_beta            [hidden]               f32
//! layers.{i}.attn_{q,k,v,o}_w  [out, in]       int8/int4
//! layers.{i}.attn_{q,k,v,o}_b  [out]           f32
//! layers.{i}.attn_ln_gamma|beta [hidden]       f32
//! layers.{i}.ffn_up_w    [intermediate, hidden] int8/int4
//! layers.{i}.ffn_up_b    [intermediate]         f32
//! layers.{i}.ffn_down_w  [hidden, intermediate] int8/int4
//! layers.{i}.ffn_down_b  [hidden]              f32
//! layers.{i}.ffn_ln_gamma|beta [hidden]        f32
//! ```

use std::path::Path;

use super::pqw::{ModelType, QuantizedWeightsView};
use super::tensor;

/// Число строк rel-таблицы (position_buckets=256, ×2 направления).
const REL_ROWS: usize = 512;
/// Граница линейной зоны бакетов (bucket_size/2).
const MID: usize = 128;
/// Позиционный максимум для log-шкалы (max_position_embeddings).
const MAX_POS: usize = 512;
/// eps LayerNorm (DeBERTa-v2/v3).
const EPS: f32 = 1e-7;

/// Log-бакет относительной позиции (точный порт make_log_bucket_position).
///
/// Возвращает bucket ∈ [−255, 255]; индекс строки = bucket+256.
#[inline]
pub fn rel_bucket(rel: i32) -> i32 {
    let sign: i32 = match rel {
        r if r > 0 => 1,
        r if r < 0 => -1,
        _ => 0,
    };
    // numpy: abs_pos = where((rel<mid)&(rel>-mid), mid-1, |rel|)
    let abs_pos: i32 = if rel < MID as i32 && rel > -(MID as i32) {
        MID as i32 - 1
    } else {
        rel.abs()
    };
    if abs_pos <= MID as i32 {
        return rel;
    }
    // ceil(ln(abs/mid)/ln((max-1)/mid)·(mid-1)) + mid  (f64 — как эталон)
    let log_pos = ((abs_pos as f64 / MID as f64).ln()
        / (((MAX_POS - 1) as f64) / MID as f64).ln()
        * ((MID - 1) as f64))
        .ceil()
        + MID as f64;
    (log_pos * sign as f64) as i32
}

/// Таблица индексов c2p/p2c для последовательности длины L: `idx[i·L+j]`.
///
/// clamp(bucket(i−j)+256, 0, 511) — одна таблица на оба члена.
pub fn rel_index_table(len: usize) -> Vec<u16> {
    let mut t = Vec::with_capacity(len * len);
    for i in 0..len as i32 {
        for j in 0..len as i32 {
            let b = rel_bucket(i - j) + REL_ROWS as i32 / 2;
            t.push(b.clamp(0, REL_ROWS as i32 - 1) as u16);
        }
    }
    t
}

// ---------------------------------------------------------------------------
// Модель
// ---------------------------------------------------------------------------

/// DeBERTa-энкодер поверх mmap-весов `.pqw` (model_type=Gliner, флаг deberta).
pub struct DebertaEncoder {
    view: QuantizedWeightsView,
    hidden: usize,
    heads: usize,
    head_dim: usize,
    layers: usize,
}

impl DebertaEncoder {
    /// Открывает модель (с Sha256-верификацией).
    pub fn open(path: &Path) -> Result<Self, String> {
        let view = QuantizedWeightsView::open(path)?;
        Self::from_view(view)
    }

    /// Строит энкодер из уже открытого view (голова GLiNER делит его секции).
    pub fn from_view(view: QuantizedWeightsView) -> Result<Self, String> {
        let h = view.header();
        if h.model_type != ModelType::Gliner {
            return Err(format!(
                "модель не Gliner-класса (model_type={:?})",
                h.model_type
            ));
        }
        if !h.is_deberta() {
            return Err("флаг deberta не установлен — спина не DeBERTa".into());
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

    /// Доступ к весам (голова GLiNER читает свои секции).
    pub fn view(&self) -> &QuantizedWeightsView {
        &self.view
    }

    /// Прямой проход: ids [seq] → скрытые состояния [seq × hidden] (f32).
    pub fn forward(&self, ids: &[u32]) -> Result<Vec<f32>, String> {
        let (states, _) = self.forward_staged(ids, false)?;
        Ok(states)
    }

    /// Прямой проход со снимками стадий (дифференциальные тесты):
    /// `emb_ln` после эмбеддинг-LN, `rel_ln` после LN rel-таблицы,
    /// снимок после каждого слоя (если `per_layer`).
    pub fn forward_staged(&self, ids: &[u32], per_layer: bool) -> Result<(Vec<f32>, Vec<Vec<f32>>), String> {
        let seq = ids.len();
        if seq == 0 {
            return Err("deberta: пустая последовательность токенов".into());
        }
        let h = self.hidden;
        let hd = self.head_dim;
        let heads = self.heads;
        let scale = 1.0 / ((hd as f32) * 3.0).sqrt();

        // --- Эмбеддинги: word → LN (позиций нет) ---
        let word = self.view.require("word_embeddings")?;
        let (emb_g, emb_b) = self.ln_params("embeddings_ln_gamma", "embeddings_ln_beta")?;
        let mut x = vec![0f32; seq * h];
        let mut row = vec![0f32; h];
        let mut stages: Vec<Vec<f32>> = Vec::new();
        for (t, &id) in ids.iter().enumerate() {
            let id = id as usize;
            if id >= word.rows() {
                return Err(format!("токен {id} вне словаря ({})", word.rows()));
            }
            word.gather_row(id, &mut row)?;
            x[t * h..(t + 1) * h].copy_from_slice(&row);
            tensor::layer_norm(&mut x[t * h..(t + 1) * h], &emb_g, &emb_b, EPS);
        }
        stages.push(x.clone()); // стадия 0: emb_ln

        // --- rel-таблица: 512 строк → LN → [512 × h] ---
        let rel = self.view.require("rel_embeddings")?;
        if rel.rows() != REL_ROWS {
            return Err(format!(
                "rel_embeddings: {} строк (ожидалось {REL_ROWS})",
                rel.rows()
            ));
        }
        let (rel_g, rel_b) = self.ln_params("rel_ln_gamma", "rel_ln_beta")?;
        let mut rel_ln = vec![0f32; REL_ROWS * h];
        for m in 0..REL_ROWS {
            rel.gather_row(m, &mut row)?;
            rel_ln[m * h..(m + 1) * h].copy_from_slice(&row);
            tensor::layer_norm(&mut rel_ln[m * h..(m + 1) * h], &rel_g, &rel_b, EPS);
        }
        stages.push(rel_ln.clone()); // стадия 1: rel_ln

        // --- таблица бакетов ---
        let idx = rel_index_table(seq);

        // --- Слои ---
        let intermediate = self.view.header().intermediate;
        let mut q = vec![0f32; seq * h];
        let mut k = vec![0f32; seq * h];
        let mut v = vec![0f32; seq * h];
        let mut ctx = vec![0f32; seq * h];
        let mut attn_out = vec![0f32; h];
        let mut ffn_in = vec![0f32; h];
        let mut inter = vec![0f32; intermediate];
        // M-матрицы: [L × 512] на голову (контент×поз-векторы)
        let mut m_c2p = vec![0f32; seq * REL_ROWS];
        let mut m_p2c = vec![0f32; seq * REL_ROWS];
        let mut scores = vec![0f32; seq];
        // поз-проекции: [512 × h] (те же query/key_proj, что у контента)
        let mut pos_key = vec![0f32; REL_ROWS * h];
        let mut pos_query = vec![0f32; REL_ROWS * h];

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

            // поз-проекции rel-строк (share_att_key: те же веса q/k).
            for m in 0..REL_ROWS {
                let rm = &rel_ln[m * h..(m + 1) * h];
                wk.matvec(rm, &mut pos_key[m * h..(m + 1) * h])?;
                wq.matvec(rm, &mut pos_query[m * h..(m + 1) * h])?;
            }
            if let Some(bk) = bk {
                for m in 0..REL_ROWS {
                    for (o, &b) in pos_key[m * h..(m + 1) * h].iter_mut().zip(bk.f32s()?) {
                        *o += b;
                    }
                }
            }
            if let Some(bq) = bq {
                for m in 0..REL_ROWS {
                    for (o, &b) in pos_query[m * h..(m + 1) * h].iter_mut().zip(bq.f32s()?) {
                        *o += b;
                    }
                }
            }

            // Многоголовое disentangled-внимание.
            for head in 0..heads {
                let off = head * hd;
                // M-матрицы: контент×поз для этой головы
                for s in 0..seq {
                    let qs = &q[s * h + off..s * h + off + hd];
                    let ks = &k[s * h + off..s * h + off + hd];
                    for m in 0..REL_ROWS {
                        let pm = m * h + off;
                        m_c2p[s * REL_ROWS + m] = tensor::dot_f32(qs, &pos_key[pm..pm + hd]);
                        m_p2c[s * REL_ROWS + m] = tensor::dot_f32(ks, &pos_query[pm..pm + hd]);
                    }
                }
                for s in 0..seq {
                    let qs = &q[s * h + off..s * h + off + hd];
                    // скоры: контент + c2p + p2c (индексы ОДНИ)
                    for t in 0..seq {
                        let kt = &k[t * h + off..t * h + off + hd];
                        let ix = idx[s * seq + t] as usize;
                        scores[t] = (tensor::dot_f32(qs, kt)
                            + m_c2p[s * REL_ROWS + ix]
                            + m_p2c[t * REL_ROWS + ix])
                            * scale;
                    }
                    tensor::softmax_inplace(&mut scores);
                    let cs = &mut ctx[s * h + off..s * h + off + hd];
                    cs.fill(0.0);
                    for (t, &w) in scores.iter().enumerate() {
                        let vt = &v[t * h + off..t * h + off + hd];
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
                tensor::layer_norm(&mut x[t * h..(t + 1) * h], &attn_g, &attn_b, EPS);
            }

            // FFN: GELU-erf.
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
                tensor::layer_norm(&mut x[t * h..(t + 1) * h], &ffn_g, &ffn_b, EPS);
            }
            if per_layer {
                stages.push(x.clone()); // стадия 2 + i: слой i
            }
        }
        Ok((x, stages))
    }

    /// Пара (гамма, бета) LayerNorm (бета опциональна — нулевая).
    fn ln_params(&self, gamma: &str, beta: &str) -> Result<(Vec<f32>, Vec<f32>), String> {
        let g = self.view.require(gamma)?.f32s()?.to_vec();
        let b = match self.view.tensor(beta) {
            Some(t) => t.f32s()?.to_vec(),
            None => vec![0f32; g.len()],
        };
        Ok((g, b))
    }
}

/// Прибавляет bias (если есть) к вектору.
fn add_bias(vec: &mut [f32], bias: Option<&super::pqw::TensorView>) -> Result<(), String> {
    if let Some(b) = bias {
        let bs = b.f32s()?;
        if bs.len() != vec.len() {
            return Err(format!(
                "bias {} != выход {}",
                bs.len(),
                vec.len()
            ));
        }
        for (o, &b) in vec.iter_mut().zip(bs) {
            *o += b;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Бакеты: линейная зона ±128, лог-зона выше, симметрия, границы.
    #[test]
    fn rel_bucket_linear_and_log() {
        // линейная зона остаётся собой
        for r in [-127, -1, 0, 1, 64, 127, 128] {
            assert_eq!(rel_bucket(r), r, "r={r}");
        }
        // лог-зона: монотонный рост, ограничение 255
        let b129 = rel_bucket(129);
        let b200 = rel_bucket(200);
        let b511 = rel_bucket(511);
        assert!(b129 >= 128 && b129 <= 130);
        assert!(b200 > b129);
        assert_eq!(b511, 255);
        // симметрия знака
        assert_eq!(rel_bucket(-200), -rel_bucket(200));
        assert_eq!(rel_bucket(-511), -255);
    }

    /// Индексная таблица: диагональ = 256, симметрия зеркальная.
    #[test]
    fn rel_index_table_shape() {
        let l = 300usize; // > 128 — попадаем в лог-зону
        let t = rel_index_table(l);
        assert_eq!(t.len(), l * l);
        // диагональ: bucket(0)=0 → idx 256
        for i in 0..l {
            assert_eq!(t[i * l + i], 256);
        }
        // сосед слева/справа
        let i = 200usize;
        assert_eq!(t[i * l + (i - 1)], 257); // bucket(+1)=1
        assert_eq!(t[i * l + (i + 1)], 255); // bucket(-1)=-1
        // дальний сосед: bucket(199) — лог-зона
        let far = t[i * l + (i - 199)] as i32;
        assert!(far > 256 && far < 512);
        // clamp-границы не нарушены
        assert!(t.iter().all(|&v| v < 512));
    }
}
