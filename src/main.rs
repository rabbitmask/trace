mod asset;
mod common;
mod unauth;

use anyhow::Context;
use clap::{ArgAction, CommandFactory, Parser};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "trace")]
#[command(disable_help_flag = true, disable_help_subcommand = true, long_about = None)]
struct Cli {
    /// 输入 CSV 日志路径。
    #[arg(value_name = "CSV")]
    input: Option<PathBuf>,

    /// 配置文件路径（不存在则使用默认配置）。
    #[arg(short = 'c', long, value_name = "TOML", default_value = "trace.toml")]
    config: PathBuf,

    /// 覆盖输出格式：csv | json | both。
    #[arg(short = 'f', long, value_name = "FORMAT")]
    format: Option<String>,

    /// 覆盖输出目录。
    #[arg(short = 'o', long, value_name = "DIR")]
    out_dir: Option<PathBuf>,

    /// 显示帮助信息。
    #[arg(short = 'h', long = "help", action = ArgAction::SetTrue)]
    help: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.help {
        common::output::print_startup_banner(common::config::ColorMode::Auto);
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        return Ok(());
    }
    let Some(input_path) = cli.input else {
        let mut cmd = Cli::command();
        common::output::print_startup_banner(common::config::ColorMode::Auto);
        println!("{}", cmd.render_usage());
        println!("Use -h or --help for details.");
        return Ok(());
    };

    // 1) 读取配置
    let mut cfg = common::config::load_config(&cli.config)
        .with_context(|| format!("加载配置失败: {}", cli.config.display()))?;

    // 2) 应用命令行参数覆盖配置
    if let Some(dir) = cli.out_dir {
        cfg.output.out_dir = dir;
    }
    if let Some(fmt) = cli.format {
        cfg.output.format = parse_format(&fmt)?;
    }

    // 3) 打开数据源并执行扫描聚合
    let mut source = common::source_csv::CsvFileSource::open(&input_path)
        .with_context(|| format!("打开输入失败: {}", input_path.display()))?;
    let result = unauth::scan::scan(&mut source, &cfg).with_context(|| "分析失败")?;

    // 4) 输出资产统计结果
    common::output::print_console_summary(&result.assets, &cfg);
    let (csv_path, json_path) = common::output::write_outputs(&result.assets, &cfg)?;
    if let Some(p) = csv_path {
        println!("csv_out={}", p.display());
    }
    if let Some(p) = json_path {
        println!("json_out={}", p.display());
    }

    // 5) 输出未授权测试目标结果（如果启用）
    if let Some(unauth) = &result.unauth_candidates {
        common::output::print_unauth_candidates_summary(unauth, &cfg);
        let p = common::output::write_unauth_candidates_csv(unauth, &cfg)?;
        println!("unauth_targets_csv_out={}", p.display());
    }

    Ok(())
}

fn parse_format(s: &str) -> anyhow::Result<common::config::OutputFormat> {
    match s.trim().to_ascii_lowercase().as_str() {
        "csv" => Ok(common::config::OutputFormat::Csv),
        "json" => Ok(common::config::OutputFormat::Json),
        "both" => Ok(common::config::OutputFormat::Both),
        other => anyhow::bail!("未知 format: {other}（应为 csv|json|both）"),
    }
}
