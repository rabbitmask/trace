use std::borrow::Cow;

/// 扫描器使用的统一日志行视图（只保留当前分析需要的字段）。
#[derive(Debug, Clone)]
pub struct WafRowRef<'a> {
    pub https: Cow<'a, str>,
    pub host: Cow<'a, str>,
    pub dst_port: Cow<'a, str>,
    pub request_path: Cow<'a, str>,
    pub request_uri: Cow<'a, str>,
    pub request_method: Cow<'a, str>,
    pub status: Cow<'a, str>,
}

/// 数据源抽象：后续可扩展为 OSS、SLS、API 拉取等实现。
pub trait RowSource {
    fn visit_rows(
        &mut self,
        visitor: &mut dyn for<'a> FnMut(WafRowRef<'a>) -> anyhow::Result<()>,
    ) -> anyhow::Result<()>;
}
