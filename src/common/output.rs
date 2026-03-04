use crate::asset::analyzer::{AnalyzeResult, AssetKey, GroupKey};
use crate::asset::probe::{probe_urls, ProbeInfo};
use crate::common::config::{AppConfig, ColorMode, OutputFormat};
use crate::unauth::scan::{UnauthCandidateKey, UnauthCandidatesResult};
use crate::unauth::intel as unauth_intel;
use anyhow::Context;
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::io::IsTerminal;
use std::path::PathBuf;

const COL_IDX: usize = 4;
const COL_HOST_PORT: usize = 34;
const COL_COUNT: usize = 10;
const COL_PATH: usize = 34;
const COL_URL_ASSET: usize = 70;
const COL_URL_UNAUTH: usize = 60;

#[derive(Clone, Copy)]
enum Align {
    Left,
    Center,
}

#[derive(Clone, Copy)]
enum Style {
    Border,
    Title,
    Header,
}

struct Painter {
    enabled: bool,
}

impl Painter {
    fn new(mode: ColorMode) -> Self {
        let enabled = match mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        };
        Self { enabled }
    }

    fn paint(&self, text: &str, style: Style) -> String {
        if !self.enabled {
            return text.to_string();
        }
        let code = match style {
            Style::Border => "36",
            Style::Title => "1;36",
            Style::Header => "1;37",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

pub fn write_outputs(
    result: &AnalyzeResult,
    cfg: &AppConfig,
) -> anyhow::Result<(Option<PathBuf>, Option<PathBuf>)> {
    std::fs::create_dir_all(&cfg.output.out_dir)
        .with_context(|| format!("创建输出目录失败: {}", cfg.output.out_dir.display()))?;

    let mut csv_path = None;
    let mut json_path = None;
    match cfg.output.format {
        OutputFormat::Csv => csv_path = Some(write_csv(result, cfg)?),
        OutputFormat::Json => json_path = Some(write_json(result, cfg)?),
        OutputFormat::Both => {
            csv_path = Some(write_csv(result, cfg)?);
            json_path = Some(write_json(result, cfg)?);
        }
    }
    Ok((csv_path, json_path))
}

pub fn print_console_summary(result: &AnalyzeResult, cfg: &AppConfig) {
    let painter = Painter::new(cfg.output.color);
    let cols = [COL_IDX, COL_HOST_PORT, COL_URL_ASSET, COL_COUNT];
    let width = table_total_width(&cols);

    let mut all: Vec<(&GroupKey, &AssetKey, u64)> = Vec::new();
    for (group_key, item_map) in &result.counts {
        for (asset_key, count) in item_map {
            all.push((group_key, asset_key, *count));
        }
    }
    all.sort_by_key(|(_, asset_key, count)| (Reverse(*count), asset_key.url.as_str()));
    let top = cfg.output.console_top.min(all.len());

    print_banner(width, &painter);

    println!();
    println!("{}", painter.paint(&single_border(width, '='), Style::Border));
    println!(
        "{}",
        painter.paint(&make_single_row(width, "资产统计摘要", Align::Center), Style::Title)
    );
    println!(
        "{}",
        make_single_row(
            width,
            &format!(
                "总行数 {} | 命中行数 {} | 唯一资产 {}",
                result.total_rows, result.matched_rows, result.unique_keys
            ),
            Align::Center
        )
    );
    println!("{}", painter.paint(&single_border(width, '='), Style::Border));

    println!("{}", painter.paint(&table_border(&cols, '-'), Style::Border));
    println!(
        "{}",
        table_row(
            &["NO", "HOST:PORT", "URL", "COUNT"],
            &cols,
            &[Align::Left, Align::Left, Align::Left, Align::Left],
            Some((&painter, Style::Header))
        )
    );
    println!("{}", painter.paint(&table_border(&cols, '-'), Style::Border));

    if top == 0 {
        println!(
            "{}",
            table_row(
                &["-", "-", "无可展示数据", "-"],
                &cols,
                &[Align::Left, Align::Left, Align::Left, Align::Left],
                None
            )
        );
    } else {
        for (idx, (group_key, asset_key, count)) in all.into_iter().take(top).enumerate() {
            let idx_text = (idx + 1).to_string();
            let host_port = format!("{}:{}", group_key.host, group_key.dst_port);
            let count_text = count.to_string();
            let url_text = truncate_for_console(&asset_key.url, COL_URL_ASSET);
            println!(
                "{}",
                table_row(
                    &[&idx_text, &host_port, &url_text, &count_text],
                    &cols,
                    &[Align::Left, Align::Left, Align::Left, Align::Left],
                    None
                )
            );
        }
    }
    println!("{}", painter.paint(&table_border(&cols, '-'), Style::Border));
}

pub fn print_startup_banner(color: ColorMode) {
    let painter = Painter::new(color);
    let cols = [COL_IDX, COL_HOST_PORT, COL_URL_ASSET, COL_COUNT];
    let width = table_total_width(&cols);
    print_banner(width, &painter);
}

fn print_banner(width: usize, painter: &Painter) {
    let left_dog = [
        "      /\\__",
        "      (    @\\___",
        "      /         O",
        "      /   (_____/",
        "      /_____/   U",
    ];
    let right_text = [
        "",
        "",
        "TRACR WAF日志分析工具(资产收集与未授权漏洞测试)",
        "Powered by 基建运维中心",
        "",
    ];
    println!();
    println!("{}", painter.paint(&single_border(width, '='), Style::Border));
    let row_width = width.saturating_sub(4);
    let dog_col_width = left_dog
        .iter()
        .map(|s| display_width(s))
        .max()
        .unwrap_or(0)
        + 2;
    let right_col_width = row_width.saturating_sub(dog_col_width);
    for idx in 0..left_dog.len() {
        let left = pad_right_display(left_dog[idx], dog_col_width);
        let right = pad_center_display(right_text[idx], right_col_width);
        let line = format!("{left}{right}");
        let style = if idx == 2 || idx == 3 {
            Style::Title
        } else {
            Style::Border
        };
        println!("{}", painter.paint(&make_single_row(width, &line, Align::Left), style));
    }
    println!("{}", painter.paint(&single_border(width, '='), Style::Border));
}

pub fn print_unauth_candidates_summary(result: &UnauthCandidatesResult, cfg: &AppConfig) {
    let painter = Painter::new(cfg.output.color);
    let cols = [COL_IDX, COL_HOST_PORT, COL_PATH, COL_URL_UNAUTH, COL_COUNT];
    let width = table_total_width(&cols);

    let mut items: Vec<(&UnauthCandidateKey, u64)> =
        result.counts.iter().map(|(key, count)| (key, *count)).collect();
    items.sort_by_key(|(key, count)| {
        (
            key.host.as_str(),
            key.dst_port,
            key.request_path.as_str(),
            Reverse(*count),
            key.url.as_str(),
        )
    });
    let top = cfg.output.console_top.min(items.len());

    println!();
    println!("{}", painter.paint(&single_border(width, '='), Style::Border));
    println!(
        "{}",
        painter.paint(&make_single_row(width, "未授权测试目标摘要", Align::Center), Style::Title)
    );
    println!(
        "{}",
        make_single_row(width, &format!("目标唯一条目 {}", result.unique), Align::Left)
    );
    println!("{}", painter.paint(&single_border(width, '='), Style::Border));

    println!("{}", painter.paint(&table_border(&cols, '-'), Style::Border));
    println!(
        "{}",
        table_row(
            &["NO", "HOST:PORT", "PATH", "URL", "COUNT"],
            &cols,
            &[Align::Left, Align::Left, Align::Left, Align::Left, Align::Left],
            Some((&painter, Style::Header))
        )
    );
    println!("{}", painter.paint(&table_border(&cols, '-'), Style::Border));

    if top == 0 {
        println!(
            "{}",
            table_row(
                &["-", "-", "-", "无可展示数据", "-"],
                &cols,
                &[Align::Left, Align::Left, Align::Left, Align::Left, Align::Left],
                None
            )
        );
    } else {
        for (idx, (key, count)) in items.into_iter().take(top).enumerate() {
            let idx_text = (idx + 1).to_string();
            let host_port = format!("{}:{}", key.host, key.dst_port);
            let path_text = truncate_for_console(&key.request_path, COL_PATH);
            let url_text = truncate_for_console(&key.url, COL_URL_UNAUTH);
            let count_text = count.to_string();
            println!(
                "{}",
                table_row(
                    &[&idx_text, &host_port, &path_text, &url_text, &count_text],
                    &cols,
                    &[Align::Left, Align::Left, Align::Left, Align::Left, Align::Left],
                    None
                )
            );
        }
    }
    println!("{}", painter.paint(&table_border(&cols, '-'), Style::Border));
}

pub fn write_unauth_candidates_csv(
    result: &UnauthCandidatesResult,
    cfg: &AppConfig,
) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(&cfg.output.out_dir)
        .with_context(|| format!("创建输出目录失败: {}", cfg.output.out_dir.display()))?;

    let out_path = cfg.output.out_dir.join(&cfg.unauth_probe.candidates_csv_file);
    let mut writer = csv::WriterBuilder::new()
        .has_headers(true)
        .from_path(&out_path)
        .with_context(|| format!("创建CSV输出失败: {}", out_path.display()))?;
    writer.write_record([
        "HOST",
        "PORT",
        "PATH",
        "URL",
        "COUNT",
        "STATUS_CODE",
        "TITLE",
        "RISK_LEVEL",
        "SCORE",
        "REASONS",
    ])?;

    let urls = collect_unauth_urls(result);
    let probe_map = if cfg.unauth_probe.enabled {
        probe_urls(&urls, &cfg.web_request)
    } else {
        std::collections::HashMap::new()
    };

    let mut items: Vec<(&UnauthCandidateKey, u64)> =
        result.counts.iter().map(|(key, count)| (key, *count)).collect();
    items.sort_by_key(|(key, count)| {
        (
            key.host.as_str(),
            key.dst_port,
            key.request_path.as_str(),
            Reverse(*count),
            key.url.as_str(),
        )
    });
    let intel_engine = unauth_intel::IntelEngine::new(&cfg.unauth_intel);

    for (key, count) in items {
        let probe = probe_map
            .get(&key.url)
            .cloned()
            .unwrap_or_else(ProbeInfo::default);
        let intel = intel_engine.evaluate(&key.url, &key.request_path, &probe);
        writer.write_record([
            &key.host,
            &key.dst_port.to_string(),
            &key.request_path,
            &key.url,
            &count.to_string(),
            &probe.status_code,
            &probe.title,
            &intel.risk_level,
            &intel.score.to_string(),
            &intel.reasons,
        ])?;
    }
    writer.flush()?;
    Ok(out_path)
}

fn ordered_groups<'a>(
    result: &'a AnalyzeResult,
) -> BTreeMap<(String, u16), Vec<(&'a AssetKey, u64)>> {
    let mut ordered: BTreeMap<(String, u16), Vec<(&AssetKey, u64)>> = BTreeMap::new();
    for (group_key, item_map) in &result.counts {
        let mut items: Vec<(&AssetKey, u64)> = item_map.iter().map(|(k, v)| (k, *v)).collect();
        items.sort_by_key(|(asset_key, count)| (Reverse(*count), asset_key.url.as_str()));
        ordered.insert((group_key.host.clone(), group_key.dst_port), items);
    }
    ordered
}

fn write_csv(result: &AnalyzeResult, cfg: &AppConfig) -> anyhow::Result<PathBuf> {
    let out_path = cfg.output.out_dir.join(&cfg.output.csv_file);
    let mut writer = csv::WriterBuilder::new()
        .has_headers(true)
        .from_path(&out_path)
        .with_context(|| format!("创建CSV输出失败: {}", out_path.display()))?;
    writer.write_record(["HOST", "PORT", "URL", "COUNT", "STATUS_CODE", "TITLE"])?;

    let urls = collect_asset_urls(result);
    let probe_map = if cfg.asset_probe.enabled {
        probe_urls(&urls, &cfg.web_request)
    } else {
        std::collections::HashMap::new()
    };

    for ((host, dst_port), items) in ordered_groups(result) {
        let mut rows = Vec::with_capacity(items.len());
        for (asset_key, count) in items {
            let probe = probe_map.get(&asset_key.url).cloned().unwrap_or_default();
            rows.push(AssetCsvRow {
                asset_key: asset_key.clone(),
                count,
                probe,
            });
        }
        let rows = dedupe_asset_rows(rows);
        for row in rows {
            writer.write_record([
                &host,
                &dst_port.to_string(),
                &row.asset_key.url,
                &row.count.to_string(),
                &row.probe.status_code,
                &row.probe.title,
            ])?;
        }
    }
    writer.flush()?;
    Ok(out_path)
}

#[derive(Debug, Clone)]
struct AssetCsvRow {
    asset_key: AssetKey,
    count: u64,
    probe: ProbeInfo,
}

fn dedupe_asset_rows(rows: Vec<AssetCsvRow>) -> Vec<AssetCsvRow> {
    let mut grouped: HashMap<(String, String, String, String), Vec<AssetCsvRow>> = HashMap::new();
    let mut passthrough: Vec<AssetCsvRow> = Vec::new();

    for row in rows {
        if row.probe.status_code.is_empty() || row.probe.body_hash.is_empty() {
            passthrough.push(row);
            continue;
        }
        let key = (
            row.asset_key.scheme.clone(),
            row.probe.status_code.clone(),
            normalize_content_type(&row.probe.content_type),
            row.probe.body_hash.clone(),
        );
        grouped.entry(key).or_default().push(row);
    }

    let mut merged_rows: Vec<AssetCsvRow> = Vec::new();
    for (_, mut group_rows) in grouped {
        if group_rows.len() == 1 {
            merged_rows.push(group_rows.remove(0));
            continue;
        }

        group_rows.sort_by(|left, right| {
            let left_is_root = left.asset_key.path == "/";
            let right_is_root = right.asset_key.path == "/";
            right_is_root
                .cmp(&left_is_root)
                .then_with(|| left.asset_key.path.len().cmp(&right.asset_key.path.len()))
                .then_with(|| right.count.cmp(&left.count))
                .then_with(|| left.asset_key.url.cmp(&right.asset_key.url))
        });

        let total_count: u64 = group_rows.iter().map(|r| r.count).sum();
        let mut canonical = group_rows.remove(0);
        canonical.count = total_count;
        merged_rows.push(canonical);
    }

    let mut out = Vec::with_capacity(merged_rows.len() + passthrough.len());
    out.extend(merged_rows);
    out.extend(passthrough);
    out.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.asset_key.url.cmp(&right.asset_key.url))
    });
    out
}

fn normalize_content_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn collect_asset_urls(result: &AnalyzeResult) -> Vec<String> {
    let mut unique = std::collections::BTreeSet::new();
    for item_map in result.counts.values() {
        for key in item_map.keys() {
            unique.insert(key.url.clone());
        }
    }
    unique.into_iter().collect()
}

fn collect_unauth_urls(result: &UnauthCandidatesResult) -> Vec<String> {
    let mut unique = std::collections::BTreeSet::new();
    for key in result.counts.keys() {
        unique.insert(key.url.clone());
    }
    unique.into_iter().collect()
}

fn table_total_width(cols: &[usize]) -> usize {
    1 + cols.iter().map(|w| w + 3).sum::<usize>()
}

fn single_border(width: usize, fill: char) -> String {
    format!("+{}+", fill.to_string().repeat(width.saturating_sub(2)))
}

fn make_single_row(width: usize, text: &str, align: Align) -> String {
    let cell_w = width.saturating_sub(4);
    let content = match align {
        Align::Left => pad_right_display(text, cell_w),
        Align::Center => pad_center_display(text, cell_w),
    };
    format!("| {content} |")
}

fn table_border(cols: &[usize], fill: char) -> String {
    let mut out = String::from("+");
    for &w in cols {
        out.push_str(&fill.to_string().repeat(w + 2));
        out.push('+');
    }
    out
}

fn table_row(
    cells: &[&str],
    widths: &[usize],
    aligns: &[Align],
    paint: Option<(&Painter, Style)>,
) -> String {
    let mut out = String::from("|");
    for i in 0..widths.len() {
        let raw = if i < cells.len() { cells[i] } else { "" };
        let padded = match aligns.get(i).copied().unwrap_or(Align::Left) {
            Align::Left => pad_right_display(raw, widths[i]),
            Align::Center => pad_center_display(raw, widths[i]),
        };
        let cell = if let Some((painter, style)) = paint {
            painter.paint(&padded, style)
        } else {
            padded
        };
        out.push(' ');
        out.push_str(&cell);
        out.push(' ');
        out.push('|');
    }
    out
}

fn truncate_for_console(text: &str, max_len: usize) -> String {
    if display_width(text) <= max_len {
        return text.to_string();
    }
    if max_len <= 3 {
        return ".".repeat(max_len);
    }
    let mut width = 0usize;
    let mut out = String::new();
    let reserve = 3usize;
    for ch in text.chars() {
        let w = char_display_width(ch);
        if width + w + reserve > max_len {
            break;
        }
        out.push(ch);
        width += w;
    }
    out.push_str("...");
    out
}

fn char_display_width(ch: char) -> usize {
    if ch.is_ascii() { 1 } else { 2 }
}

fn display_width(text: &str) -> usize {
    text.chars().map(char_display_width).sum()
}

fn pad_right_display(text: &str, width: usize) -> String {
    let current = display_width(text);
    if current >= width {
        return text.to_string();
    }
    format!("{text}{}", " ".repeat(width - current))
}

fn pad_center_display(text: &str, width: usize) -> String {
    let current = display_width(text);
    if current >= width {
        return text.to_string();
    }
    let pad_total = width - current;
    let left = pad_total / 2;
    let right = pad_total - left;
    format!("{}{}{}", " ".repeat(left), text, " ".repeat(right))
}

#[derive(Debug, Serialize)]
struct JsonItem {
    scheme: String,
    host: String,
    dst_port: u16,
    request_path: String,
    url: String,
    count: u64,
}

#[derive(Debug, Serialize)]
struct JsonGroup {
    host: String,
    dst_port: u16,
    items: Vec<JsonItem>,
}

fn write_json(result: &AnalyzeResult, cfg: &AppConfig) -> anyhow::Result<PathBuf> {
    let out_path = cfg.output.out_dir.join(&cfg.output.json_file);
    let mut groups: Vec<JsonGroup> = Vec::new();

    for ((host, dst_port), items) in ordered_groups(result) {
        let json_items = items
            .into_iter()
            .map(|(asset_key, count)| JsonItem {
                scheme: asset_key.scheme.clone(),
                host: host.clone(),
                dst_port,
                request_path: asset_key.path.clone(),
                url: asset_key.url.clone(),
                count,
            })
            .collect();
        groups.push(JsonGroup {
            host,
            dst_port,
            items: json_items,
        });
    }

    let file = std::fs::File::create(&out_path)
        .with_context(|| format!("创建JSON输出失败: {}", out_path.display()))?;
    serde_json::to_writer_pretty(file, &groups)
        .with_context(|| format!("写入JSON输出失败: {}", out_path.display()))?;
    Ok(out_path)
}
