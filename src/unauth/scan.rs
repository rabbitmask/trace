use crate::asset::analyzer::AnalyzeResult;
use crate::common::config::{AppConfig, AssetPathConfig, PathNormalizationConfig, UnauthProbeConfig};
use crate::common::source::{RowSource, WafRowRef};
use anyhow::anyhow;
use std::collections::HashMap;

/// 未授权测试目标唯一键：
/// 同一个 `request_uri` 视为一个目标。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnauthCandidateKey {
    pub scheme: String,
    pub host: String,
    pub dst_port: u16,
    pub request_path: String,
    pub request_uri: String,
    pub url: String,
}

/// 用于“同一路径下只保留 TopN URI”的分组键。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UnauthPathGroupKey {
    scheme: String,
    host: String,
    dst_port: u16,
    request_path: String,
}

#[derive(Debug, Clone)]
pub struct UnauthCandidatesResult {
    pub unique: usize,
    pub counts: HashMap<UnauthCandidateKey, u64>,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub assets: AnalyzeResult,
    pub unauth_candidates: Option<UnauthCandidatesResult>,
}

/// 扫描入口：
/// 1) 统计资产（当前按 `/XX/` 聚合）
/// 2) 产出未授权测试目标（按配置启用）
pub fn scan(source: &mut dyn RowSource, cfg: &AppConfig) -> anyhow::Result<ScanResult> {
    let unauth = if cfg.unauth_probe.export_candidates {
        Some(UnauthCandidateCollector::new(
            &cfg.unauth_probe,
            &cfg.asset.elide_ports,
        )?)
    } else {
        None
    };

    let status_ranges = crate::asset::analyzer::parse_status_ranges(&cfg.filter)?;
    let unauth_status_ranges = if let Some(u) = &unauth {
        Some(crate::asset::analyzer::parse_status_ranges_from_strings(
            &u.cfg.allow_status_ranges,
            (200, 200),
        )?)
    } else {
        None
    };

    let mut total_rows: u64 = 0;
    let mut matched_rows: u64 = 0;
    let mut groups: HashMap<crate::asset::analyzer::GroupKey, HashMap<crate::asset::analyzer::AssetKey, u64>> =
        HashMap::new();
    let mut collector = unauth;

    source.visit_rows(&mut |row: WafRowRef<'_>| -> anyhow::Result<()> {
        total_rows += 1;

        // 解析基础字段
        let scheme = crate::asset::analyzer::scheme_from_https(row.https.as_ref());
        let host = row.host.as_ref().trim();
        if host.is_empty() {
            return Ok(());
        }
        let dst_port = crate::asset::analyzer::parse_u16(row.dst_port.as_ref())
            .ok_or_else(|| anyhow!("dst_port parse failed: {:?}", row.dst_port.as_ref()))?;
        let path = crate::asset::analyzer::normalize_path(row.request_path.as_ref());

        // 路径后缀黑名单过滤（assets 与 unauth 都生效）
        if is_blacklisted_path(&path, &cfg.filter.ignore_path_suffixes) {
            return Ok(());
        }

        // 全局状态码质量过滤
        let status = crate::asset::analyzer::parse_u16(row.status.as_ref());
        if cfg.filter.status_filter_enabled
            && !crate::asset::analyzer::status_allowed(status, &status_ranges)
        {
            return Ok(());
        }

        // 资产聚合：按一级路径归一化；可配置跳过单段文件型路径。
        let Some(suspicious_path) = normalize_one_level_path(&path, &cfg.asset_path) else {
            return Ok(());
        };
        let url = crate::asset::analyzer::build_url(
            &scheme,
            host,
            dst_port,
            &suspicious_path,
            &cfg.asset.elide_ports,
        );

        let gk = crate::asset::analyzer::GroupKey {
            host: host.to_string(),
            dst_port,
        };
        let ak = crate::asset::analyzer::AssetKey {
            scheme: scheme.clone(),
            host: host.to_string(),
            dst_port,
            path: suspicious_path,
            url,
        };
        *groups.entry(gk).or_default().entry(ak).or_insert(0) += 1;
        matched_rows += 1;

        // 未授权测试目标收集（只导出，不在线探测）
        if let (Some(c), Some(ranges)) = (&mut collector, &unauth_status_ranges) {
            c.maybe_collect(
                &row,
                &scheme,
                host,
                dst_port,
                &path,
                &cfg.path_normalization,
                status,
                ranges,
            )?;
        }

        Ok(())
    })?;

    let unique_keys = groups.values().map(|m| m.len()).sum();
    let assets = AnalyzeResult {
        total_rows,
        matched_rows,
        unique_keys,
        counts: groups,
    };

    let unauth_candidates = collector.map(|c| c.finish());
    Ok(ScanResult {
        assets,
        unauth_candidates,
    })
}

/// 未授权测试目标收集器。
struct UnauthCandidateCollector {
    cfg: UnauthProbeConfig,
    elide_ports: Vec<u16>,
    counts: HashMap<UnauthCandidateKey, u64>,
}

impl UnauthCandidateCollector {
    fn new(cfg: &UnauthProbeConfig, elide_ports: &[u16]) -> anyhow::Result<Self> {
        Ok(Self {
            cfg: cfg.clone(),
            elide_ports: elide_ports.to_vec(),
            counts: HashMap::new(),
        })
    }

    /// 仅收集满足条件的未授权测试目标：
    /// - method = GET
    /// - 状态码命中 allow_ranges
    fn maybe_collect(
        &mut self,
        row: &WafRowRef<'_>,
        scheme: &str,
        host: &str,
        dst_port: u16,
        request_path: &str,
        path_norm_cfg: &PathNormalizationConfig,
        status: Option<u16>,
        allow_ranges: &[(u16, u16)],
    ) -> anyhow::Result<()> {
        let method = row.request_method.as_ref().trim();
        if !method.eq_ignore_ascii_case("GET") {
            return Ok(());
        }
        if !crate::asset::analyzer::status_allowed(status, allow_ranges) {
            return Ok(());
        }

        let uri = normalize_uri(
            row.request_uri.as_ref(),
            request_path,
            self.cfg.redact_query_values,
            &self.cfg.redact_query_key_keywords,
        );
        let normalized_path = normalize_path_template(request_path, path_norm_cfg);
        let url = build_url_from_uri(scheme, host, dst_port, &uri, &self.elide_ports);

        let key = UnauthCandidateKey {
            scheme: scheme.to_string(),
            host: host.to_string(),
            dst_port,
            request_path: normalized_path,
            request_uri: uri,
            url,
        };
        *self.counts.entry(key).or_insert(0) += 1;
        Ok(())
    }

    fn finish(self) -> UnauthCandidatesResult {
        let counts = truncate_candidates_by_path(self.counts, self.cfg.max_uris_per_path);
        let unique = counts.len();
        UnauthCandidatesResult { unique, counts }
    }
}

/// 规范化 request_uri：
/// - 空或 `-`：回退到 request_path
/// - 保证以 `/` 开头
/// - query 脱敏策略：
///   - `redact_query_values=true`：全量脱敏参数值
///   - 否则仅脱敏命中关键字的参数值
fn normalize_uri(
    uri: &str,
    request_path: &str,
    redact_query_values: bool,
    redact_query_key_keywords: &[String],
) -> String {
    let t = uri.trim();
    let base = if t.is_empty() || t == "-" { request_path } else { t };
    let base = if base.starts_with('/') {
        base.to_string()
    } else {
        format!("/{base}")
    };

    let Some((path, q)) = base.split_once('?') else {
        return base;
    };
    if q.is_empty() {
        return format!("{path}?");
    }

    let mut out = String::with_capacity(base.len());
    out.push_str(path);
    out.push('?');
    for (index, part) in q.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }

        let (key, value_opt) = match part.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (part, None),
        };

        out.push_str(key);
        out.push('=');

        if !redact_query_values && !should_redact_query_key(key, redact_query_key_keywords) {
            if let Some(value) = value_opt {
                out.push_str(value);
            }
        }
    }
    out
}

/// 参数名命中关键字即视为敏感参数（不区分大小写，包含匹配）。
fn should_redact_query_key(key: &str, keywords: &[String]) -> bool {
    let lower_key = key.to_ascii_lowercase();
    keywords.iter().any(|keyword| {
        let k = keyword.trim().to_ascii_lowercase();
        !k.is_empty() && lower_key.contains(&k)
    })
}

/// 对同一 `(scheme,host,dst_port,request_path)` 仅保留前 N 个 request_uri。
fn truncate_candidates_by_path(
    counts: HashMap<UnauthCandidateKey, u64>,
    max_uris_per_path: usize,
) -> HashMap<UnauthCandidateKey, u64> {
    if max_uris_per_path == 0 {
        return counts;
    }

    let mut grouped: HashMap<UnauthPathGroupKey, Vec<(UnauthCandidateKey, u64)>> = HashMap::new();
    for (key, count) in counts {
        let group = UnauthPathGroupKey {
            scheme: key.scheme.clone(),
            host: key.host.clone(),
            dst_port: key.dst_port,
            request_path: key.request_path.clone(),
        };
        grouped.entry(group).or_default().push((key, count));
    }

    let mut out = HashMap::new();
    for (_, mut items) in grouped {
        let group_total: u64 = items.iter().map(|(_, count)| *count).sum();
        // 优先按频次降序，再按 URL 字典序稳定排序
        items.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.url.cmp(&right.0.url)));
        for (key, _) in items.into_iter().take(max_uris_per_path) {
            out.insert(key, group_total);
        }
    }
    out
}

/// 路径后缀黑名单匹配（大小写不敏感）。
fn is_blacklisted_path(path: &str, suffixes: &[String]) -> bool {
    let lower_path = path.to_ascii_lowercase();
    suffixes.iter().any(|raw_suffix| {
        let normalized = raw_suffix.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return false;
        }
        if lower_path.ends_with(&normalized) {
            return true;
        }
        if normalized.starts_with('.') {
            return false;
        }
        lower_path.ends_with(&format!(".{normalized}"))
    })
}

/// 可疑资产路径归一化规则：
/// - `/a/b/c` -> `/a/`（目录型，默认保留尾斜杠）
/// - `/a`     -> `/a`
/// - `/a.jsp` -> 若启用 `skip_single_file_like` 则跳过
fn normalize_one_level_path(path: &str, cfg: &AssetPathConfig) -> Option<String> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return Some("/".to_string());
    }

    let first = segments[0];
    let has_more = segments.len() > 1;
    if !has_more && cfg.skip_single_file_like && first.contains('.') {
        return None;
    }

    let keep_trailing = cfg.keep_dir_trailing_slash && (has_more || path.ends_with('/'));
    if keep_trailing {
        Some(format!("/{first}/"))
    } else {
        Some(format!("/{first}"))
    }
}

/// 将路径归一化为模板，降低“同一接口不同ID”的噪声。
/// 例如：
/// `/a/detail/50917` -> `/a/detail/{int}`
/// `/a/order/550e8400-e29b-41d4-a716-446655440000` -> `/a/order/{uuid}`
fn normalize_path_template(path: &str, cfg: &PathNormalizationConfig) -> String {
    if !cfg.enabled {
        return path.to_string();
    }

    let mut out = String::new();
    let starts_with_slash = path.starts_with('/');
    if starts_with_slash {
        out.push('/');
    }

    let mut first = true;
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        if !first {
            out.push('/');
        }
        first = false;
        out.push_str(&normalize_segment(segment, cfg));
    }

    if out.is_empty() {
        "/".to_string()
    } else {
        out
    }
}

fn normalize_segment(segment: &str, cfg: &PathNormalizationConfig) -> String {
    if cfg.replace_int_segment && is_all_digits(segment) {
        return "{int}".to_string();
    }
    if cfg.replace_uuid_segment && is_uuid_like(segment) {
        return "{uuid}".to_string();
    }
    if cfg.replace_hex_segment && is_hex_like(segment, cfg.min_hex_len) {
        return "{hex}".to_string();
    }
    segment.to_string()
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

fn is_uuid_like(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    for (idx, ch) in s.chars().enumerate() {
        let dash = idx == 8 || idx == 13 || idx == 18 || idx == 23;
        if dash {
            if ch != '-' {
                return false;
            }
        } else if !ch.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn is_hex_like(s: &str, min_len: usize) -> bool {
    s.len() >= min_len && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// 用 request_uri 拼接完整 URL（用于未授权测试目标的 url2）。
fn build_url_from_uri(
    scheme: &str,
    host: &str,
    dst_port: u16,
    request_uri: &str,
    elide_ports: &[u16],
) -> String {
    if elide_ports.iter().any(|p| *p == dst_port) {
        format!("{scheme}://{host}{request_uri}")
    } else {
        format!("{scheme}://{host}:{dst_port}{request_uri}")
    }
}
