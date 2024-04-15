use nu_plugin::{serve_plugin, MsgPackSerializer};
use nu_plugin_dns::Dns;

fn main() {
    serve_plugin(&Dns::new(), MsgPackSerializer)
}
