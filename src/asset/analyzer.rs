use crate::common::config::FilterConfig;
use anyhow::{anyhow, Context};
use std::collections::HashMap;

/// 资产分组键：同一 host + dst_port 一组。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupKey {
    pub host: String,
    pub dst_port: u16,
}

/// 资产条目键：同一 URL 视作一个资产项。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetKey {
    pub scheme: String,
    pub host: String,
    pub dst_port: u16,
    pub path: String,
    pub url: String,
}

/// 扫描结果总结构（供输出层使用）。
#[derive(Debug, Clone)]
pub struct AnalyzeResult {
    pub total_rows: u64,
    pub matched_rows: u64,
    pub unique_keys: usize,
    pub counts: HashMap<GroupKey, HashMap<AssetKey, u64>>,
}

/// 解析全局状态码区间配置。
pub(crate) fn parse_status_ranges(filter: &FilterConfig) -> anyhow::Result<Vec<(u16, u16)>> {
    if !filter.status_filter_enabled {
        return Ok(vec![]);
    }
    if filter.allow_status_ranges.is_empty() {
        return Ok(vec![(200, 399)]);
    }
    parse_status_ranges_from_strings(&filter.allow_status_ranges, (200, 399))
}

/// 将区间字符串（如 `200-399`）解析为数值区间。
pub(crate) fn parse_status_ranges_from_strings(
    ranges: &[String],
    default_range: (u16, u16),
) -> anyhow::Result<Vec<(u16, u16)>> {
    if ranges.is_empty() {
        return Ok(vec![default_range]);
    }

    let mut out = Vec::with_capacity(ranges.len());
    for text in ranges {
        let parts: Vec<&str> = text.split('-').collect();
        if parts.len() != 2 {
            return Err(anyhow!("状态码区间格式错误: {text}（应为 200-399）"));
        }

        let start = parts[0]
            .trim()
            .parse::<u16>()
            .with_context(|| format!("状态码区间起始解析失败: {text}"))?;
        let end = parts[1]
            .trim()
            .parse::<u16>()
            .with_context(|| format!("状态码区间结束解析失败: {text}"))?;

        out.push((start.min(end), start.max(end)));
    }
    Ok(out)
}

/// 判断状态码是否命中任一区间。
pub(crate) fn status_allowed(status: Option<u16>, ranges: &[(u16, u16)]) -> bool {
    let Some(code) = status else {
        return false;
    };
    if ranges.is_empty() {
        return true;
    }
    ranges.iter().any(|(start, end)| code >= *start && code <= *end)
}

/// 解析 `u16`，空值或 `-` 返回 None。
pub(crate) fn parse_u16(s: &str) -> Option<u16> {
    let t = s.trim();
    if t.is_empty() || t == "-" {
        return None;
    }
    t.parse::<u16>().ok()
}

/// `https` 字段到协议名转换。
pub(crate) fn scheme_from_https(https: &str) -> String {
    let t = https.trim();
    if t.eq_ignore_ascii_case("on") || t.eq_ignore_ascii_case("true") || t == "1" {
        "https".to_string()
    } else {
        "http".to_string()
    }
}

/// 路径规范化：
/// - 空值/`-` -> `/`
/// - 无前导 `/` 时自动补齐
pub(crate) fn normalize_path(path: &str) -> String {
    let t = path.trim();
    if t.is_empty() || t == "-" {
        return "/".to_string();
    }
    if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    }
}

/// 拼接 URL。
pub(crate) fn build_url(
    scheme: &str,
    host: &str,
    dst_port: u16,
    path: &str,
    elide_ports: &[u16],
) -> String {
    let port_part = if elide_ports.iter().any(|p| *p == dst_port) {
        String::new()
    } else {
        format!(":{dst_port}")
    };
    format!("{scheme}://{host}{port_part}{path}")
}
