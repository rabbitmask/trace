use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub filter: FilterConfig,
    pub asset: AssetConfig,
    pub asset_path: AssetPathConfig,
    pub asset_probe: AssetProbeConfig,
    pub unauth_probe: UnauthProbeConfig,
    pub unauth_intel: UnauthIntelConfig,
    pub web_request: WebRequestConfig,
    pub output: OutputConfig,
    pub path_normalization: PathNormalizationConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            filter: FilterConfig::default(),
            asset: AssetConfig::default(),
            asset_path: AssetPathConfig::default(),
            asset_probe: AssetProbeConfig::default(),
            unauth_probe: UnauthProbeConfig::default(),
            unauth_intel: UnauthIntelConfig::default(),
            web_request: WebRequestConfig::default(),
            output: OutputConfig::default(),
            path_normalization: PathNormalizationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FilterConfig {
    pub status_filter_enabled: bool,
    pub allow_status_ranges: Vec<String>,
    pub ignore_path_suffixes: Vec<String>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            status_filter_enabled: true,
            allow_status_ranges: vec!["200-399".to_string()],
            ignore_path_suffixes: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AssetConfig {
    pub elide_ports: Vec<u16>,
}

impl Default for AssetConfig {
    fn default() -> Self {
        Self { elide_ports: vec![443] }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AssetPathConfig {
    pub keep_dir_trailing_slash: bool,
    pub skip_single_file_like: bool,
}

impl Default for AssetPathConfig {
    fn default() -> Self {
        Self {
            keep_dir_trailing_slash: true,
            skip_single_file_like: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AssetProbeConfig {
    pub enabled: bool,
}

impl Default for AssetProbeConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UnauthProbeConfig {
    pub enabled: bool,
    pub export_candidates: bool,
    pub allow_status_ranges: Vec<String>,
    pub redact_query_values: bool,
    pub redact_query_key_keywords: Vec<String>,
    pub max_uris_per_path: usize,
    pub candidates_csv_file: String,
}

impl Default for UnauthProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            export_candidates: true,
            allow_status_ranges: vec!["200-200".to_string()],
            redact_query_values: false,
            redact_query_key_keywords: vec![],
            max_uris_per_path: 1,
            candidates_csv_file: "unauth_targets.csv".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebRequestConfig {
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub max_body_bytes: usize,
    pub body_preview_chars: usize,
    pub max_title_len: usize,
    pub user_agents: Vec<String>,
}

impl Default for WebRequestConfig {
    fn default() -> Self {
        Self {
            concurrency: 30,
            timeout_secs: 5,
            max_body_bytes: 262_144,
            body_preview_chars: 2_000,
            max_title_len: 200,
            user_agents: vec![
                "trace/0.1".to_string(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36".to_string(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15".to_string(),
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36".to_string(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UnauthIntelConfig {
    pub enabled: bool,
    pub high_risk_score: i32,
    pub medium_risk_score: i32,
    pub max_reason_count: usize,
    pub max_keyword_hits_per_class: usize,
    pub max_regex_hits_per_class: usize,
    pub score_http_200: i32,
    pub score_auth_required: i32,
    pub score_server_error: i32,
    pub score_json_response: i32,
    pub score_html_shell: i32,
    pub score_login_page: i32,
    pub score_sensitive_keyword: i32,
    pub score_sensitive_regex: i32,
    pub score_business_keyword: i32,
    pub score_business_regex: i32,
    pub score_noise_keyword: i32,
    pub score_noise_regex: i32,
    pub score_api_path: i32,
    pub sensitive_keywords: Vec<String>,
    pub sensitive_regexes: Vec<String>,
    pub business_keywords: Vec<String>,
    pub business_regexes: Vec<String>,
    pub noise_keywords: Vec<String>,
    pub noise_regexes: Vec<String>,
    pub login_keywords: Vec<String>,
    pub login_regexes: Vec<String>,
    pub api_path_keywords: Vec<String>,
}

impl Default for UnauthIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            high_risk_score: 70,
            medium_risk_score: 40,
            max_reason_count: 8,
            max_keyword_hits_per_class: 3,
            max_regex_hits_per_class: 3,
            score_http_200: 10,
            score_auth_required: -20,
            score_server_error: -15,
            score_json_response: 18,
            score_html_shell: -12,
            score_login_page: -35,
            score_sensitive_keyword: 20,
            score_sensitive_regex: 25,
            score_business_keyword: 10,
            score_business_regex: 12,
            score_noise_keyword: -8,
            score_noise_regex: -10,
            score_api_path: 8,
            sensitive_keywords: vec![
                "token".to_string(),
                "access_key".to_string(),
                "secret".to_string(),
                "password".to_string(),
                "手机号".to_string(),
                "身份证".to_string(),
                "银行卡".to_string(),
                "身份证号".to_string(),
                "ak".to_string(),
                "sk".to_string(),
            ],
            sensitive_regexes: vec![
                r"(?i)\b(access[_-]?key|api[_-]?key|token|secret|passwd|password)\b\s*[:=]\s*[A-Za-z0-9_\-]{8,}".to_string(),
                r"\b1[3-9]\d{9}\b".to_string(),
                r"\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b".to_string(),
                r"(?i)\bAKIA[0-9A-Z]{16}\b".to_string(),
                r"(?i)\bASIA[0-9A-Z]{16}\b".to_string(),
                r"(?i)\bLTAI[a-z0-9]{12,}\b".to_string(),
            ],
            business_keywords: vec![
                "user".to_string(),
                "username".to_string(),
                "mobile".to_string(),
                "phone".to_string(),
                "order".to_string(),
                "customer".to_string(),
                "amount".to_string(),
                "balance".to_string(),
            ],
            business_regexes: vec![
                r#"(?i)"(user(id|name)?|mobile|phone|order(_?id|_?no)?|customer(_?id)?|amount|balance)"\s*:"#.to_string(),
                r#"(?i)\b(order_no|order_id|customer_id|user_id)\b\s*[:=]\s*["']?[A-Za-z0-9\-_]{4,}"#.to_string(),
            ],
            noise_keywords: vec![
                "登录".to_string(),
                "登录页".to_string(),
                "请登录".to_string(),
                "sso".to_string(),
                "验证码".to_string(),
                "copyright".to_string(),
                "javascript".to_string(),
            ],
            noise_regexes: vec![
                r"(?i)<form[^>]*>.*(login|signin|password).*?</form>".to_string(),
                r"(?i)<script[^>]*src=".to_string(),
            ],
            login_keywords: vec![
                "login".to_string(),
                "signin".to_string(),
                "sso".to_string(),
                "oauth".to_string(),
                "passport".to_string(),
                "认证".to_string(),
                "登录".to_string(),
            ],
            login_regexes: vec![
                r"(?i)\b(login|signin|sso|oauth|passport|cas)\b".to_string(),
                r"(?i)(用户名|账号).*(密码)|(密码).*(验证码)".to_string(),
            ],
            api_path_keywords: vec![
                "/api".to_string(),
                "/admin".to_string(),
                "/internal".to_string(),
                "/open".to_string(),
                "/v1".to_string(),
                "/v2".to_string(),
                "/v3".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub out_dir: PathBuf,
    pub format: OutputFormat,
    pub csv_file: String,
    pub json_file: String,
    pub console_top: usize,
    pub color: ColorMode,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("out"),
            format: OutputFormat::Csv,
            csv_file: "assets.csv".to_string(),
            json_file: "assets.json".to_string(),
            console_top: 20,
            color: ColorMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Csv,
    Json,
    Both,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PathNormalizationConfig {
    pub enabled: bool,
    pub replace_int_segment: bool,
    pub replace_uuid_segment: bool,
    pub replace_hex_segment: bool,
    pub min_hex_len: usize,
}

impl Default for PathNormalizationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            replace_int_segment: true,
            replace_uuid_segment: true,
            replace_hex_segment: true,
            min_hex_len: 8,
        }
    }
}

pub fn load_config(config_path: &Path) -> anyhow::Result<AppConfig> {
    if !config_path.exists() {
        anyhow::bail!(
            "配置文件缺失: {}。请先创建配置文件后再运行。",
            config_path.display()
        );
    }
    let raw = std::fs::read_to_string(config_path)?;
    let cfg: AppConfig = toml::from_str(&raw)?;
    Ok(cfg)
}

