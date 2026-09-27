//! POLER-SH — Суверенная командная оболочка и терминальный шлюз (Terminal Gateway).
//!
//! Полный перенос ядра «Калькулятора Всего» (`src/calc/`), аппаратного
//! аудита (`src/calc/hardware.rs`), среды агента (`src/shell/agentenv.rs`)
//! и слоя трансляции команд (`src/shell/wincompat.rs`).

pub mod calc;
pub mod shell {
    pub mod agentenv;
    pub mod wincompat;
}

pub use calc::{CalcState, Value};
