#[macro_export]
macro_rules! spanned {
    ($val:expr) => {{
        nu_protocol::Spanned {
            item: $val,
            span: $val.span(),
        }
    }};
    ($val:expr, $span:expr) => {{
        nu_protocol::Spanned {
            item: $val,
            span: $span,
        }
    }};
}
