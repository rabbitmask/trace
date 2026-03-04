use crate::common::source::{RowSource, WafRowRef};
use anyhow::{anyhow, Context};
use csv::ByteRecord;
use std::fs::File;
use std::path::{Path, PathBuf};

/// CSV 列索引缓存，避免每行都按列名查找。
#[derive(Debug, Clone)]
struct ColIdx {
    https: usize,
    host: usize,
    dst_port: usize,
    request_path: usize,
    request_uri: Option<usize>,
    request_method: Option<usize>,
    status: usize,
}

/// 基于本地 CSV 文件的数据源。
pub struct CsvFileSource {
    path: PathBuf,
    rdr: csv::Reader<File>,
    idx: ColIdx,
}

impl CsvFileSource {
    /// 打开 CSV 文件并解析表头索引。
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let file =
            File::open(path).with_context(|| format!("无法打开CSV文件: {}", path.display()))?;
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(file);

        let headers = rdr.byte_headers().context("读取CSV表头失败")?.clone();
        let idx = build_indices_bytes(&headers)?;

        Ok(Self {
            path: path.to_path_buf(),
            rdr,
            idx,
        })
    }
}

impl RowSource for CsvFileSource {
    fn visit_rows(
        &mut self,
        visitor: &mut dyn for<'a> FnMut(WafRowRef<'a>) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        for row in self.rdr.byte_records() {
            let record =
                row.with_context(|| format!("读取CSV行失败: {}", self.path.display()))?;

            // 仅抽取本工具需要的字段，避免额外开销。
            let https = decode_field(record.get(self.idx.https).unwrap_or(b""));
            let host = decode_field(record.get(self.idx.host).unwrap_or(b""));
            let dst_port = decode_field(record.get(self.idx.dst_port).unwrap_or(b""));
            let request_path = decode_field(record.get(self.idx.request_path).unwrap_or(b""));
            let request_uri = self
                .idx
                .request_uri
                .and_then(|i| record.get(i))
                .map(decode_field)
                .unwrap_or_default();
            let request_method = self
                .idx
                .request_method
                .and_then(|i| record.get(i))
                .map(decode_field)
                .unwrap_or_default();
            let status = decode_field(record.get(self.idx.status).unwrap_or(b""));

            visitor(WafRowRef {
                https,
                host,
                dst_port,
                request_path,
                request_uri,
                request_method,
                status,
            })?;
        }
        Ok(())
    }
}

/// 构建列索引（必需列缺失会报错，可选列允许不存在）。
fn build_indices_bytes(headers: &ByteRecord) -> anyhow::Result<ColIdx> {
    let need = |name: &str| -> anyhow::Result<usize> {
        headers
            .iter()
            .position(|h| decode_field(h).as_ref() == name)
            .ok_or_else(|| anyhow!("CSV缺少必需列: {name}"))
    };

    let maybe = |name: &str| -> Option<usize> {
        headers
            .iter()
            .position(|h| decode_field(h).as_ref() == name)
    };

    Ok(ColIdx {
        https: need("https")?,
        host: need("host")?,
        dst_port: need("dst_port")?,
        request_path: need("request_path")?,
        request_uri: maybe("request_uri"),
        request_method: maybe("request_method"),
        status: need("status")?,
    })
}

/// 字节转字符串：容忍非 UTF-8（防止日志异常编码导致整体失败）。
fn decode_field(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}
