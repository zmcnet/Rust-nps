//! 内嵌静态资源：管理页面不需要 Node 构建，也不引用任何 CDN / 外部字体。

pub const INDEX_HTML: &str = include_str!("../static/index.html");
pub const APP_CSS: &str = include_str!("../static/app.css");
pub const APP_JS: &str = include_str!("../static/app.js");
pub const FAVICON_SVG: &str = include_str!("../static/favicon.svg");
