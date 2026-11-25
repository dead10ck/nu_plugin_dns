use nu_plugin::{MsgPackSerializer, serve_plugin};
use nu_plugin_dns::Dns;

fn main() {
    serve_plugin(&Dns::new(), MsgPackSerializer)
}
