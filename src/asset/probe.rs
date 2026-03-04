use crate::common::config::WebRequestConfig;
use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// 单个 URL 的探测结果。
#[derive(Debug, Clone, Default)]
pub struct ProbeInfo {
    pub status_code: String,
    pub title: String,
    pub content_type: String,
    pub body_preview: String,
    pub body_hash: String,
}

/// 对 URL 列表逐个探测，返回 `url -> ProbeInfo` 映射。
pub fn probe_urls(urls: &[String], cfg: &WebRequestConfig) -> HashMap<String, ProbeInfo> {
    let mut out = HashMap::new();
    if urls.is_empty() {
        return out;
    }

    let client = match Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            // client 创建失败时，所有 URL 统一标记为 ERR。
            let info = ProbeInfo {
                status_code: "ERR".to_string(),
                title: truncate(&format!("client_build_failed: {err}"), cfg.max_title_len),
                content_type: String::new(),
                body_preview: String::new(),
                body_hash: String::new(),
            };
            for url in urls {
                out.insert(url.clone(), info.clone());
            }
            return out;
        }
    };

    let worker_count = cfg.concurrency.max(1).min(urls.len());
    let tasks = Arc::new(Mutex::new(urls.to_vec()));
    let results = Arc::new(Mutex::new(HashMap::with_capacity(urls.len())));
    let cfg_arc = Arc::new(cfg.clone());

    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let tasks_ref = Arc::clone(&tasks);
        let results_ref = Arc::clone(&results);
        let cfg_ref = Arc::clone(&cfg_arc);
        let client_ref = client.clone();

        handles.push(thread::spawn(move || loop {
            let maybe_url = {
                let mut guard = tasks_ref.lock().expect("lock tasks");
                guard.pop()
            };
            let Some(url) = maybe_url else { break };
            let info = probe_one(&client_ref, &url, &cfg_ref);
            let mut guard = results_ref.lock().expect("lock results");
            guard.insert(url, info);
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    match Arc::try_unwrap(results) {
        Ok(mutex) => mutex.into_inner().unwrap_or_default(),
        Err(shared) => shared.lock().map(|m| m.clone()).unwrap_or_default(),
    }
}

/// 探测单个 URL：GET 请求 + 提取 HTML `<title>`。
fn probe_one(client: &Client, url: &str, cfg: &WebRequestConfig) -> ProbeInfo {
    let ua = pick_user_agent(url, &cfg.user_agents);
    let response = match client.get(url).header(USER_AGENT, ua).send() {
        Ok(resp) => resp,
        Err(err) => {
            return ProbeInfo {
                status_code: "ERR".to_string(),
                title: truncate(&format!("request_failed: {err}"), cfg.max_title_len),
                content_type: String::new(),
                body_preview: String::new(),
                body_hash: String::new(),
            };
        }
    };

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let status_code = response.status().as_u16().to_string();

    // 仅读取有限大小的响应体，避免内存被超大页面占用。
    let mut bytes = Vec::new();
    let mut limited = response.take(cfg.max_body_bytes as u64);
    let (title, body_preview, body_hash) = match limited.read_to_end(&mut bytes) {
        Ok(_) => {
            let body = String::from_utf8_lossy(&bytes);
            let extracted_title = extract_title(&body)
                .map(|text| truncate(&text, cfg.max_title_len))
                .unwrap_or_default();
            let preview = truncate(&body, cfg.body_preview_chars);
            let hash = hash_normalized_body(&body);
            (extracted_title, preview, hash)
        }
        Err(_) => (String::new(), String::new(), String::new()),
    };
    ProbeInfo {
        status_code,
        title,
        content_type,
        body_preview,
        body_hash,
    }
}

fn pick_user_agent(url: &str, user_agents: &[String]) -> String {
    if user_agents.is_empty() {
        return "trace/0.1".to_string();
    }
    if user_agents.len() == 1 {
        return user_agents[0].clone();
    }

    static UA_COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = UA_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    url.hash(&mut hasher);
    seq.hash(&mut hasher);
    let idx = (hasher.finish() as usize) % user_agents.len();
    user_agents[idx].clone()
}

fn hash_normalized_body(body: &str) -> String {
    let normalized = normalize_body_for_hash(body);
    if normalized.is_empty() {
        return String::new();
    }
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn normalize_body_for_hash(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut prev_ws = false;
    for ch in body.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch);
            prev_ws = false;
        }
    }
    out.trim().to_string()
}

/// 从 HTML 中提取 `<title>...</title>`（大小写不敏感）。
fn extract_title(html: &str) -> Option<String> {
    if html.is_empty() {
        return None;
    }

    let lower = html.to_ascii_lowercase();
    let start_tag = lower.find("<title")?;
    let open_end = lower[start_tag..].find('>')? + start_tag + 1;
    let close_start = lower[open_end..].find("</title>")? + open_end;
    if close_start <= open_end {
        return None;
    }

    let raw = &html[open_end..close_start];
    let clean = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

/// 安全截断字符串（按字符数）。
fn truncate(text: &str, max_len: usize) -> String {
    if text.chars().count() <= max_len {
        return text.to_string();
    }
    text.chars().take(max_len).collect()
}
