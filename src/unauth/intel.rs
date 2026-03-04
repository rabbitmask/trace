use crate::asset::probe::ProbeInfo;
use crate::common::config::UnauthIntelConfig;
use regex::{Regex, RegexBuilder};

/// 未授权测试目标的智能标记结果。
#[derive(Debug, Clone, Default)]
pub struct IntelResult {
    pub risk_level: String,
    pub score: i32,
    pub reasons: String,
}

#[derive(Debug, Clone, Default)]
struct CompiledRegexes {
    sensitive: Vec<Regex>,
    business: Vec<Regex>,
    noise: Vec<Regex>,
    login: Vec<Regex>,
}

#[derive(Debug, Clone)]
pub struct IntelEngine {
    cfg: UnauthIntelConfig,
    compiled: CompiledRegexes,
}

impl IntelEngine {
    pub fn new(cfg: &UnauthIntelConfig) -> Self {
        Self {
            cfg: cfg.clone(),
            compiled: CompiledRegexes {
                sensitive: compile_patterns(&cfg.sensitive_regexes),
                business: compile_patterns(&cfg.business_regexes),
                noise: compile_patterns(&cfg.noise_regexes),
                login: compile_patterns(&cfg.login_regexes),
            },
        }
    }

    /// 对单个 URL 做“是否可能有价值”的规则评估。
    /// 这里不用机器学习，先用可配置规则打分，方便后续逐步迭代。
    pub fn evaluate(&self, url: &str, path: &str, probe: &ProbeInfo) -> IntelResult {
        if !self.cfg.enabled {
            return IntelResult::default();
        }

        let mut score: i32 = 0;
        let mut reasons: Vec<String> = Vec::new();

        let status_num = probe.status_code.parse::<u16>().ok();
        match status_num {
            Some(200) => {
                score += self.cfg.score_http_200;
                reasons.push("状态码200，可访问".to_string());
            }
            Some(401 | 403) => {
                score += self.cfg.score_auth_required;
                reasons.push("状态码为鉴权类，疑似已拦截".to_string());
            }
            Some(code) if code >= 500 => {
                score += self.cfg.score_server_error;
                reasons.push("状态码5xx，响应不稳定".to_string());
            }
            Some(_) | None => {}
        }

        let title = probe.title.to_ascii_lowercase();
        let body = probe.body_preview.to_ascii_lowercase();
        let content_type = probe.content_type.to_ascii_lowercase();
        let url_lower = url.to_ascii_lowercase();
        let path_lower = path.to_ascii_lowercase();

        if is_likely_json(&body, &content_type) {
            score += self.cfg.score_json_response;
            reasons.push("响应疑似结构化JSON".to_string());
        }

        if is_likely_html_shell(&body, &content_type) {
            score += self.cfg.score_html_shell;
            reasons.push("响应疑似通用HTML壳页".to_string());
        }

        let login_regex_hit = any_regex_match(&title, &self.compiled.login)
            || any_regex_match(&body, &self.compiled.login)
            || any_regex_match(&url_lower, &self.compiled.login);
        if contains_any(&title, &self.cfg.login_keywords)
            || contains_any(&body, &self.cfg.login_keywords)
            || contains_any(&url_lower, &self.cfg.login_keywords)
            || login_regex_hit
        {
            score += self.cfg.score_login_page;
            reasons.push("命中登录/认证特征".to_string());
        }

        let sensitive_hits = count_keyword_hits(
            &body,
            &self.cfg.sensitive_keywords,
            self.cfg.max_keyword_hits_per_class,
        );
        if sensitive_hits > 0 {
            score += self.cfg.score_sensitive_keyword * sensitive_hits as i32;
            reasons.push(format!("命中敏感关键词 {} 个", sensitive_hits));
        }
        let sensitive_regex_hits = count_regex_hits(
            &body,
            &self.compiled.sensitive,
            self.cfg.max_regex_hits_per_class,
        );
        if sensitive_regex_hits > 0 {
            score += self.cfg.score_sensitive_regex * sensitive_regex_hits as i32;
            reasons.push(format!("命中敏感正则 {} 个", sensitive_regex_hits));
        }

        let business_hits = count_keyword_hits(
            &body,
            &self.cfg.business_keywords,
            self.cfg.max_keyword_hits_per_class,
        );
        if business_hits > 0 {
            score += self.cfg.score_business_keyword * business_hits as i32;
            reasons.push(format!("命中业务关键词 {} 个", business_hits));
        }
        let business_regex_hits = count_regex_hits(
            &body,
            &self.compiled.business,
            self.cfg.max_regex_hits_per_class,
        );
        if business_regex_hits > 0 {
            score += self.cfg.score_business_regex * business_regex_hits as i32;
            reasons.push(format!("命中业务正则 {} 个", business_regex_hits));
        }

        let noise_hits = count_keyword_hits(&body, &self.cfg.noise_keywords, self.cfg.max_keyword_hits_per_class)
            + count_keyword_hits(
                &title,
                &self.cfg.noise_keywords,
                self.cfg.max_keyword_hits_per_class,
            );
        let noise_hits = noise_hits.min(self.cfg.max_keyword_hits_per_class);
        if noise_hits > 0 {
            score += self.cfg.score_noise_keyword * noise_hits as i32;
            reasons.push(format!("命中低价值关键词 {} 个", noise_hits));
        }
        let noise_regex_hits = count_regex_hits(
            &body,
            &self.compiled.noise,
            self.cfg.max_regex_hits_per_class,
        );
        if noise_regex_hits > 0 {
            score += self.cfg.score_noise_regex * noise_regex_hits as i32;
            reasons.push(format!("命中低价值正则 {} 个", noise_regex_hits));
        }

        if contains_any(&url_lower, &self.cfg.api_path_keywords)
            || contains_any(&path_lower, &self.cfg.api_path_keywords)
        {
            score += self.cfg.score_api_path;
            reasons.push("路径命中API/管理特征".to_string());
        }

        let risk_level = if score >= self.cfg.high_risk_score {
            "HIGH".to_string()
        } else if score >= self.cfg.medium_risk_score {
            "MEDIUM".to_string()
        } else {
            "LOW".to_string()
        };

        if reasons.len() > self.cfg.max_reason_count {
            reasons.truncate(self.cfg.max_reason_count);
        }

        IntelResult {
            risk_level,
            score,
            reasons: reasons.join(" | "),
        }
    }
}

fn contains_any(text: &str, keywords: &[String]) -> bool {
    keywords.iter().any(|keyword| {
        let k = keyword.trim().to_ascii_lowercase();
        !k.is_empty() && text.contains(&k)
    })
}

fn count_keyword_hits(text: &str, keywords: &[String], limit: usize) -> usize {
    if limit == 0 {
        return 0;
    }
    let mut hit = 0usize;
    for keyword in keywords {
        let k = keyword.trim().to_ascii_lowercase();
        if k.is_empty() {
            continue;
        }
        if text.contains(&k) {
            hit += 1;
            if hit >= limit {
                break;
            }
        }
    }
    hit
}

fn compile_patterns(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|pattern| {
            let p = pattern.trim();
            if p.is_empty() {
                return None;
            }
            RegexBuilder::new(p).case_insensitive(true).build().ok()
        })
        .collect()
}

fn any_regex_match(text: &str, patterns: &[Regex]) -> bool {
    if text.is_empty() {
        return false;
    }
    patterns.iter().any(|regex| regex.is_match(text))
}

fn count_regex_hits(text: &str, patterns: &[Regex], limit: usize) -> usize {
    if text.is_empty() || limit == 0 {
        return 0;
    }
    let mut hit = 0usize;
    for regex in patterns {
        if regex.is_match(text) {
            hit += 1;
            if hit >= limit {
                break;
            }
        }
    }
    hit
}

fn is_likely_json(body: &str, content_type: &str) -> bool {
    if content_type.contains("application/json") {
        return true;
    }
    let trimmed = body.trim_start();
    (trimmed.starts_with('{') || trimmed.starts_with('[')) && trimmed.contains(':')
}

fn is_likely_html_shell(body: &str, content_type: &str) -> bool {
    if content_type.contains("text/html") {
        return true;
    }
    let lower = body.trim_start();
    lower.starts_with("<!doctype html") || lower.starts_with("<html")
}
