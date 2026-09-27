//! Semantic Bridge — кросс-языковый сенсор запроса (v0.21, Задача 3).
//!
//! Боль из аудита §8.1: русский запрос к английскому корпусу давал
//! НОЛЬ результатов — «блокировка мьютекса» не находила «mutex lock»,
//! потому что терм «блокировк» отсутствует в индексе физически.
//!
//! Конвейер (архитектурный консенсус «Retrieval Substrate + Evidence-first»):
//!
//! ```text
//! Запрос ──► локальный оффлайн-сенсор (Query Expansion) ──► POLER-ядро
//!            LexiconSensor: ru→en / en→ru                BM25 + WebRank
//!            кандидаты + confidence + provenance         (+ EntityGraph,
//!                                                          см. Задачу 1)
//! ```
//!
//! Принципы:
//! * **сенсор — не решатель**: нейросеть/словарь — ВНЕШНИЙ датчик близости;
//!   он только предлагает кандидатов с уровнем уверенности;
//! * **ранжирование остаётся детерминированным**: кандидаты подмешиваются
//!   в BM25 с весом [`BRIDGE_TERM_WEIGHT`]·confidence (≤ 0.85), финальный
//!   скор — тот же WebRank 0.55·BM25 + 0.15·PageRank + 0.20·title +
//!   0.10·ε-плотность;
//! * **объяснимость (WHY?) обязательна**: каждое расширение несёт
//!   provenance («lexicon:ru→en»), попадает в ответ и в лог — агент
//!   видит, ПОЧЕМУ документ найден, и может не доверять сенсору;
//! * **ноль новых зависимостей**: офлайн-словарь в бинарнике, внешний
//!   ИИ-сенсор подключается трейтом [`SemanticSensor`], когда появится.
//!
//! Стем-пространство: сенсор работает в термах `tokenize_stem`
//! (кириллица — основа, латиница — как есть), т.е. в ТОЙ же системе
//! координат, что и инвертированный индекс (урок бага «слайд-шоу»:
//! разные токенизаторы → ноль хитов).

use std::collections::HashMap;

use serde::Serialize;

use crate::web::stem::stem_cyr;

/// Вес кандидата сенсора в BM25-аккумуляторе: родные термы запроса — 1.0,
/// сенсорные — `BRIDGE_TERM_WEIGHT · confidence` (максимум 0.85):
/// доказанный терм всегда весит больше, чем предположение сенсора.
pub const BRIDGE_TERM_WEIGHT: f64 = 0.85;

/// Уверенность первичного кандидата словаря.
const CONF_PRIMARY: f64 = 0.90;
/// Уверенность вторичных кандидатов (строка → string, line, row).
const CONF_SECONDARY: f64 = 0.70;
/// Обратное направление (en→ru) шумнее прямого.
const CONF_REVERSE_SCALE: f64 = 0.85;

/// Кандидат сенсора: терм + уверенность + происхождение.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SemanticCandidate {
    /// Терм в стем-пространстве индекса (латиница не стеммингуется).
    pub term: String,
    /// Уверенность сенсора, 0..1.
    pub confidence: f64,
    /// Происхождение: «lexicon:ru→en», «lexicon:en→ru», позже —
    /// «sensor:onnx-minilm» и т.п. — WHY-цепочка для агента.
    pub provenance: String,
}

/// Внешний датчик близости термов. Реализации: офлайн-словарь (сейчас),
/// локальная нейросеть-энкодер (потом, тот же трейт — без переделки ядра).
pub trait SemanticSensor: Send + Sync {
    /// Имя сенсора для WHY-вывода.
    fn name(&self) -> &'static str;
    /// Кандидаты для одного терма запроса (стем-форма на входе).
    fn candidates(&self, term: &str) -> Vec<SemanticCandidate>;
}

/// Офлайн-словарь ru↔en IT-терминологии: ~120 курируемых пар.
///
/// Ключи — стем-формы (собираются через [`stem_cyr`] при инициализации,
/// естественная форма в исходнике читаемее). Кандидаты упорядочены по
/// приоритету: первый — первичный (confidence 0.90), остальные —
/// вторичные (0.70). Обратное направление (en→ru) строится разворотом
/// карты с масштабом уверенности ×0.85.
static LEXICON_RU_EN: &[(&str, &[&str])] = &[
    // ---- память и данные ----
    ("буфер", &["buffer"]),
    ("кэш", &["cache"]),
    ("кеш", &["cache"]),
    ("память", &["memory"]),
    ("файл", &["file"]),
    ("каталог", &["directory"]),
    ("директория", &["directory"]),
    ("папка", &["folder"]),
    ("путь", &["path"]),
    ("строка", &["string", "line", "row"]),
    ("символ", &["symbol", "char"]),
    ("байт", &["byte"]),
    ("число", &["number"]),
    ("массив", &["array"]),
    ("список", &["list"]),
    ("словарь", &["dict", "map"]),
    ("дерево", &["tree"]),
    ("граф", &["graph"]),
    ("узел", &["node"]),
    ("ребро", &["edge"]),
    ("корень", &["root"]),
    ("стек", &["stack"]),
    ("очередь", &["queue"]),
    ("значение", &["value"]),
    ("ключ", &["key"]),
    ("индекс", &["index"]),
    ("данные", &["data", "payload"]),
    ("текст", &["text"]),
    ("вектор", &["vector"]),
    // ---- конкурентность ----
    ("поток", &["thread", "stream"]),
    ("процесс", &["process"]),
    ("задача", &["task", "issue"]),
    ("блокировка", &["lock", "blocking"]),
    ("мьютекс", &["mutex"]),
    ("гонка", &["race"]),
    ("тупик", &["deadlock"]),
    ("ожидание", &["wait"]),
    ("асинхронность", &["async"]),
    ("параллельность", &["parallelism"]),
    ("конкурентность", &["concurrency"]),
    ("событие", &["event"]),
    ("обработчик", &["handler", "callback"]),
    // ---- язык и типы ----
    ("функция", &["function", "fn"]),
    ("метод", &["method"]),
    ("класс", &["class"]),
    ("объект", &["object"]),
    ("экземпляр", &["instance"]),
    ("наследование", &["inheritance"]),
    ("интерфейс", &["interface"]),
    ("реализация", &["implementation"]),
    ("конструктор", &["constructor"]),
    ("исключение", &["exception"]),
    ("ошибка", &["error", "bug"]),
    ("предупреждение", &["warning"]),
    ("переменная", &["variable"]),
    ("константа", &["constant"]),
    ("параметр", &["parameter", "param"]),
    ("аргумент", &["argument"]),
    ("владение", &["ownership"]),
    ("заимствование", &["borrow"]),
    ("модель", &["model"]),
    ("обучение", &["training", "learning"]),
    // ---- поиск и ранжирование ----
    ("поиск", &["search", "retrieval"]),
    ("запрос", &["query", "request"]),
    ("ответ", &["response", "answer"]),
    ("фильтр", &["filter"]),
    ("сортировка", &["sort"]),
    ("ранжирование", &["ranking"]),
    ("релевантность", &["relevance"]),
    ("вес", &["weight"]),
    ("порог", &["threshold"]),
    ("чанк", &["chunk"]),
    ("фрагмент", &["chunk", "fragment", "passage"]),
    ("документ", &["document"]),
    ("сниппет", &["snippet"]),
    // ---- сеть ----
    ("соединение", &["connection"]),
    ("сокет", &["socket"]),
    ("сеть", &["network"]),
    ("сервер", &["server"]),
    ("клиент", &["client"]),
    ("прокси", &["proxy"]),
    ("порт", &["port"]),
    ("протокол", &["protocol"]),
    ("заголовок", &["header"]),
    ("браузер", &["browser"]),
    ("страница", &["page"]),
    ("ссылка", &["link", "url"]),
    ("домен", &["domain"]),
    ("транзакция", &["transaction"]),
    // ---- хранилище ----
    ("база", &["database", "base"]),
    ("таблица", &["table"]),
    ("столбец", &["column", "field"]),
    ("запись", &["record", "write"]),
    ("чтение", &["read"]),
    ("удаление", &["delete", "removal"]),
    ("создание", &["create", "creation"]),
    ("обновление", &["update", "refresh"]),
    // ---- безопасность ----
    ("шифрование", &["encryption", "crypto"]),
    ("пароль", &["password"]),
    ("токен", &["token"]),
    ("авторизация", &["authorization"]),
    ("аутентификация", &["authentication"]),
    ("безопасность", &["security"]),
    ("уязвимость", &["vulnerability"]),
    ("пользователь", &["user"]),
    ("сессия", &["session"]),
    ("куки", &["cookie"]),
    ("хэш", &["hash"]),
    ("хеш", &["hash"]),
    ("подпись", &["signature"]),
    ("сертификат", &["certificate"]),
    // ---- инструментарий ----
    ("компилятор", &["compiler"]),
    ("сборка", &["build", "assembly"]),
    ("зависимость", &["dependency"]),
    ("пакет", &["package", "packet"]),
    ("библиотека", &["library"]),
    ("модуль", &["module"]),
    ("отладка", &["debug"]),
    ("тест", &["test"]),
    ("покрытие", &["coverage"]),
    ("движок", &["engine"]),
    ("ядро", &["core", "kernel"]),
    ("плагин", &["plugin"]),
    ("расширение", &["extension"]),
    ("конфигурация", &["config", "configuration"]),
    ("настройка", &["setting", "option"]),
    ("флаг", &["flag"]),
    ("команда", &["command"]),
    ("скрипт", &["script"]),
    ("терминал", &["terminal"]),
    ("окружение", &["environment"]),
    ("версия", &["version"]),
    ("релиз", &["release"]),
    ("ветка", &["branch"]),
    ("коммит", &["commit"]),
    ("репозиторий", &["repository"]),
    ("слияние", &["merge"]),
    ("патч", &["patch"]),
    ("изменение", &["change", "modification"]),
    ("производительность", &["performance"]),
    ("оптимизация", &["optimization"]),
    ("скорость", &["speed"]),
    ("задержка", &["latency", "delay"]),
    ("формат", &["format"]),
    ("кодировка", &["encoding"]),
    ("код", &["code"]),
];

/// Офлайн-словарный сенсор: без сети, без модели, вшит в бинарник.
pub struct LexiconSensor {
    ru_en: HashMap<String, Vec<(&'static str, f64)>>,
    en_ru: HashMap<String, Vec<(String, f64)>>,
}

impl LexiconSensor {
    pub fn new() -> Self {
        let mut ru_en: HashMap<String, Vec<(&'static str, f64)>> = HashMap::new();
        let mut en_ru: HashMap<String, Vec<(String, f64)>> = HashMap::new();
        for (ru, ens) in LEXICON_RU_EN {
            let key = stem_cyr(ru);
            let mut cands: Vec<(&'static str, f64)> = Vec::with_capacity(ens.len());
            for (i, en) in ens.iter().enumerate() {
                let conf = if i == 0 { CONF_PRIMARY } else { CONF_SECONDARY };
                cands.push((en, conf));
                // обратное направление: en → ru-основа (система координат
                // индекса, где кириллица хранится стем-формой)
                en_ru
                    .entry(en.to_string())
                    .or_default()
                    .push((key.clone(), conf * CONF_REVERSE_SCALE));
            }
            ru_en.insert(key, cands);
        }
        Self { ru_en, en_ru }
    }
}

impl Default for LexiconSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticSensor for LexiconSensor {
    fn name(&self) -> &'static str {
        "lexicon-ru-en-offline"
    }

    fn candidates(&self, term: &str) -> Vec<SemanticCandidate> {
        let mut out = Vec::new();
        // прямое направление: кириллическая основа → английские термы
        if let Some(cands) = self.ru_en.get(term) {
            for (en, conf) in cands {
                out.push(SemanticCandidate {
                    term: en.to_string(),
                    confidence: *conf,
                    provenance: "lexicon:ru→en".to_string(),
                });
            }
        }
        // обратное: латинский терм → кириллические основы
        if let Some(cands) = self.en_ru.get(term) {
            for (ru, conf) in cands {
                out.push(SemanticCandidate {
                    term: ru.clone(),
                    confidence: *conf,
                    provenance: "lexicon:en→ru".to_string(),
                });
            }
        }
        out
    }
}

/// Одно расширение запроса: исходный терм → кандидат сенсора.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TermExpansion {
    /// Исходный терм запроса (стем-форма).
    pub source_term: String,
    /// Кандидат сенсора.
    pub candidate: SemanticCandidate,
    /// Итоговой вес в BM25: BRIDGE_TERM_WEIGHT · confidence.
    pub bm25_weight: f64,
}

/// Результат расширения запроса: все кандидаты всех сенсоров + WHY-блок.
#[derive(Debug, Clone, Default, Serialize)]
pub struct QueryExpansion {
    /// Имена сработавших сенсоров.
    pub sensors: Vec<String>,
    /// Расширения по термам (порядок: термы запроса, затем приоритет сенсора).
    pub expansions: Vec<TermExpansion>,
}

impl QueryExpansion {
    pub fn is_empty(&self) -> bool {
        self.expansions.is_empty()
    }

    /// Уникальные термы-кандидаты (без исходных термов запроса).
    pub fn extra_terms(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for e in &self.expansions {
            if !out.contains(&e.candidate.term) {
                out.push(e.candidate.term.clone());
            }
        }
        out
    }

    /// WHY-строки: происхождение каждого расширения (объяснимость).
    pub fn why_lines(&self) -> Vec<String> {
        self.expansions
            .iter()
            .map(|e| {
                format!(
                    "«{}» → {} [{}, conf {:.2}, вес BM25 {:.2}]",
                    e.source_term, e.candidate.term, e.candidate.provenance,
                    e.candidate.confidence, e.bm25_weight
                )
            })
            .collect()
    }

    /// WHY-блок одной строкой (для CLI/логов).
    pub fn why(&self) -> String {
        if self.is_empty() {
            return "Semantic Bridge: расширений нет (сенсор промолчал)".to_string();
        }
        let mut s = format!(
            "Semantic Bridge WHY (сенсоры: {}): ранжирование детерминированное WebRank, \
             кандидаты подмешаны с весом ≤ {:.2}",
            self.sensors.join(", "),
            BRIDGE_TERM_WEIGHT
        );
        for line in self.why_lines() {
            s.push_str("\n  ");
            s.push_str(&line);
        }
        s
    }
}

/// Мост «запрос → сенсоры → кандидаты». Сенсоры сменные, ядро — одно.
pub struct SemanticBridge {
    sensors: Vec<Box<dyn SemanticSensor>>,
}

impl SemanticBridge {
    /// Офлайн-мост: единственный сенсор — словарь ru↔en (v0.21 прототип).
    pub fn offline() -> Self {
        Self {
            sensors: vec![Box::new(LexiconSensor::new())],
        }
    }

    /// Мост с явным набором сенсоров (для тестов и будущих датчиков).
    pub fn with_sensors(sensors: Vec<Box<dyn SemanticSensor>>) -> Self {
        Self { sensors }
    }

    /// Расширяет термы запроса (уже в стем-пространстве индекса).
    ///
    /// Гарантии:
    /// * кандидат не дублирует исходные термы (сенсор не «открывает» то,
    ///   что уже известно);
    /// * один кандидат-терм вносится один раз (первый по приоритету);
    /// * порядок детерминирован: терм запроса → порядок сенсора.
    pub fn expand(&self, terms: &[String]) -> QueryExpansion {
        let mut out = QueryExpansion::default();
        let mut taken: Vec<String> = terms.to_vec();
        for term in terms {
            for sensor in &self.sensors {
                for cand in sensor.candidates(term) {
                    if taken.contains(&cand.term) {
                        continue;
                    }
                    taken.push(cand.term.clone());
                    let name = sensor.name().to_string();
                    if !out.sensors.contains(&name) {
                        out.sensors.push(name);
                    }
                    out.expansions.push(TermExpansion {
                        source_term: term.clone(),
                        bm25_weight: BRIDGE_TERM_WEIGHT * cand.confidence,
                        candidate: cand,
                    });
                }
            }
        }
        out
    }
}

impl Default for SemanticBridge {
    fn default() -> Self {
        Self::offline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::stem::tokenize_stem;

    fn terms_of(q: &str) -> Vec<String> {
        tokenize_stem(q)
    }

    #[test]
    fn ru_terms_expand_to_english() {
        // боль §8.1: «блокировка мьютекса» ↔ корпус «mutex lock»
        let bridge = SemanticBridge::offline();
        let exp = bridge.expand(&terms_of("блокировка мьютекса"));
        let got: Vec<&str> = exp.expansions.iter().map(|e| e.candidate.term.as_str()).collect();
        assert!(got.contains(&"mutex"), "{got:?}");
        assert!(got.contains(&"lock"), "{got:?}");
        assert!(got.contains(&"blocking"), "{got:?}");
    }

    #[test]
    fn morphology_collapses_to_same_stem() {
        // словарь хранит стем-ключи: падежи запроса находят запись
        let bridge = SemanticBridge::offline();
        let a = bridge.expand(&terms_of("блокировка"));
        let b = bridge.expand(&terms_of("блокировки"));
        let c = bridge.expand(&terms_of("блокировку"));
        assert_eq!(a.extra_terms(), b.extra_terms());
        assert_eq!(a.extra_terms(), c.extra_terms());
    }

    #[test]
    fn multi_candidate_terms_ordered_by_confidence() {
        let bridge = SemanticBridge::offline();
        let exp = bridge.expand(&terms_of("строка"));
        let cands: Vec<(String, f64)> = exp
            .expansions
            .iter()
            .map(|e| (e.candidate.term.clone(), e.candidate.confidence))
            .collect();
        assert_eq!(cands[0], ("string".into(), CONF_PRIMARY));
        assert!(cands.iter().any(|(t, c)| t == "line" && *c == CONF_SECONDARY));
        assert!(cands.iter().any(|(t, c)| t == "row" && *c == CONF_SECONDARY));
    }

    #[test]
    fn reverse_direction_en_to_ru() {
        let bridge = SemanticBridge::offline();
        let exp = bridge.expand(&["mutex".to_string(), "lock".to_string()]);
        let got = exp.extra_terms();
        // mutex → мьютекс; lock → блокировк
        assert!(got.contains(&"мьютекс".to_string()), "{got:?}");
        assert!(got.contains(&"блокировк".to_string()), "{got:?}");
        // обратное направление тише прямого
        let rev = exp
            .expansions
            .iter()
            .find(|e| e.candidate.term == "мьютекс")
            .unwrap();
        assert!(rev.candidate.confidence < CONF_PRIMARY);
        assert_eq!(rev.candidate.provenance, "lexicon:en→ru");
    }

    #[test]
    fn expansion_never_duplicates_source_terms() {
        let bridge = SemanticBridge::offline();
        // «строка buffer» — buffer уже есть в запросе, дублировать нельзя
        let exp = bridge.expand(&terms_of("строка buffer"));
        for e in &exp.expansions {
            assert!(
                !terms_of("строка buffer").contains(&e.candidate.term),
                "кандидат {} дублирует исходный терм",
                e.candidate.term
            );
        }
    }

    #[test]
    fn bm25_weight_bounded_by_bridge_constant() {
        let bridge = SemanticBridge::offline();
        let exp = bridge.expand(&terms_of("блокировка"));
        for e in &exp.expansions {
            assert!(e.bm25_weight > 0.0 && e.bm25_weight <= BRIDGE_TERM_WEIGHT);
            assert!((e.bm25_weight - BRIDGE_TERM_WEIGHT * e.candidate.confidence).abs() < 1e-12);
        }
    }

    #[test]
    fn unknown_terms_produce_no_expansion() {
        let bridge = SemanticBridge::offline();
        let exp = bridge.expand(&terms_of("здравствуй незнакомое слово"));
        assert!(exp.is_empty());
        assert!(exp.why().contains("расширений нет"));
    }

    #[test]
    fn why_lines_carry_provenance_and_weight() {
        let bridge = SemanticBridge::offline();
        let exp = bridge.expand(&terms_of("блокировка мьютекса"));
        let why = exp.why();
        assert!(why.contains("lexicon:ru→en"), "{why}");
        assert!(why.contains("детерминированное"), "{why}");
        assert!(why.contains("«блокировк» → lock"), "{why}");
        assert!(exp.why_lines().len() >= 3, "{:?}", exp.why_lines());
    }

    #[test]
    fn sensors_reported_once() {
        let bridge = SemanticBridge::offline();
        let exp = bridge.expand(&terms_of("блокировка мьютекс поиск"));
        assert_eq!(exp.sensors, vec!["lexicon-ru-en-offline".to_string()]);
    }

    // ---------- интеграция с ядром: §8.1 замкнут end-to-end ----------

    #[test]
    fn russian_query_finds_english_corpus_with_bridge() {
        use crate::web::index::{content_hash, WebDoc, WebIndex};
        let mut ix = WebIndex::open_memory().unwrap();
        ix.upsert_page(&WebDoc {
            url: "https://docs.io/mutex".into(),
            title: "Mutex lock and concurrency".into(),
            lang: "en".into(),
            meta_description: String::new(),
            text: "A mutex lock guards shared state in concurrent code. \
                   The lock is acquired before access and released after."
                .into(),
            links: vec![],
            content_hash: content_hash("mutex lock text"),
        })
        .unwrap();
        ix.upsert_page(&WebDoc {
            url: "https://docs.io/arrays".into(),
            title: "Array indexing".into(),
            lang: "en".into(),
            meta_description: String::new(),
            text: "Arrays are indexed collections of values with fast access.".into(),
            links: vec![],
            content_hash: content_hash("array text"),
        })
        .unwrap();

        let query = "блокировка мьютекса";
        // БЕЗ моста: русский запрос по английскому корпусу — ноль хитов
        let plain = ix.search(query, 10).unwrap();
        assert!(plain.is_empty(), "без моста должно быть пусто: {plain:?}");

        // С мостом: найден mutex-документ, WHY объясняет почему
        let bridge = SemanticBridge::offline();
        let (hits, exp) = ix.search_with_bridge(query, 10, &bridge).unwrap();
        assert!(!hits.is_empty(), "мост обязан найти mutex-страницу");
        assert_eq!(hits[0].url, "https://docs.io/mutex");
        assert!(exp.extra_terms().contains(&"mutex".to_string()));
        assert!(exp.why().contains("«мьютекс» → mutex"), "{}", exp.why());
    }

    #[test]
    fn bridge_does_not_break_plain_english_queries() {
        use crate::web::index::{content_hash, WebDoc, WebIndex};
        let mut ix = WebIndex::open_memory().unwrap();
        ix.upsert_page(&WebDoc {
            url: "https://a.io/lock".into(),
            title: "Lock".into(),
            lang: "en".into(),
            meta_description: String::new(),
            text: "lock mutex concurrency".into(),
            links: vec![],
            content_hash: content_hash("lock"),
        })
        .unwrap();
        // английский запрос по английскому корпусу: мост расширяет в ru,
        // но исходные термы весят 1.0 — порядок выдачи не страдает
        let (hits, exp) = ix
            .search_with_bridge("mutex lock", 10, &SemanticBridge::offline())
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].url, "https://a.io/lock");
        assert!(!exp.is_empty(), "обратное направление тоже работает");
    }

    #[test]
    fn custom_sensor_plug_in_without_touching_core() {
        // трейт-контракт: сторонний сенсор (мок внешней нейросети)
        // подключается без изменений ядра — архитектурная проверка
        struct MockNnSensor;
        impl SemanticSensor for MockNnSensor {
            fn name(&self) -> &'static str {
                "sensor:mock-nn"
            }
            fn candidates(&self, term: &str) -> Vec<SemanticCandidate> {
                if term == "памят" {
                    vec![SemanticCandidate {
                        term: "allocator".into(),
                        confidence: 0.6,
                        provenance: "sensor:mock-nn".into(),
                    }]
                } else {
                    vec![]
                }
            }
        }
        let bridge = SemanticBridge::with_sensors(vec![Box::new(MockNnSensor)]);
        let exp = bridge.expand(&terms_of("память"));
        assert_eq!(exp.sensors, vec!["sensor:mock-nn".to_string()]);
        assert_eq!(exp.extra_terms(), vec!["allocator".to_string()]);
        let e = &exp.expansions[0];
        assert_eq!(e.candidate.provenance, "sensor:mock-nn");
        assert!((e.bm25_weight - 0.85 * 0.6).abs() < 1e-12);
    }
}
