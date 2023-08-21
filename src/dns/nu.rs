use nu_plugin::{EvaluatedCall, LabeledError, Plugin};
use nu_protocol::{Category, PluginExample, PluginSignature, SyntaxShape, Value};

use crate::dns::constants;

use super::Dns;

impl Plugin for Dns {
    fn signature(&self) -> Vec<PluginSignature> {
        // It is possible to declare multiple signature in a plugin
        // Each signature will be converted to a command declaration once the
        // plugin is registered to nushell
        vec![PluginSignature::build(constants::commands::QUERY)
            .usage("Perform a DNS query")
            .rest(
                constants::flags::NAME,
                SyntaxShape::OneOf(vec![
                    SyntaxShape::String,
                    SyntaxShape::List(Box::new(SyntaxShape::Binary)),
                ]),
                "DNS record name",
            )
            .named(
                constants::flags::SERVER,
                SyntaxShape::String,
                "Nameserver to query (defaults to system config or 8.8.8.8)",
                Some('s'),
            )
            .named(
                constants::flags::PROTOCOL,
                SyntaxShape::String,
                "Protocol to use to connect to the nameserver: UDP, TCP. (default: UDP)",
                Some('p'),
            )
            .named(constants::flags::TYPE, SyntaxShape::Any, "Query type", Some('t'))
            .named(constants::flags::CLASS, SyntaxShape::Any, "Query class", None)
            .switch(
                constants::flags::CODE,
                "Return code fields with both string and numeric representations",
                Some('c'),
            )
            .named(
                constants::flags::DNSSEC,
                SyntaxShape::String,
                r##"Perform DNSSEC validation on records. Choices are: "none", "strict" (error if record has no RRSIG or does not validate), "opportunistic" (validate if RRSIGs present, otherwise no validation; default)"##,
                Some('d'),
            )
            .named(
                constants::flags::DNS_NAME,
                SyntaxShape::String,
                "DNS name of the TLS certificate in use by the nameserver (for TLS and HTTPS only)",
                Some('n'),
            )
            .plugin_examples(vec![
                PluginExample {
                    example: format!("{} google.com", constants::commands::QUERY),
                    description: "simple query for A / AAAA records".into(),
                    result: None,
                },
                PluginExample {
                    example: format!("{} --type CNAME google.com", constants::commands::QUERY),
                    description: "specify query type".into(),
                    result: None,
                },
                PluginExample {
                    example: format!("{} --type [cname, mx] -c google.com", constants::commands::QUERY),
                    description: "specify multiple query types".into(),
                    result: None,
                },
                PluginExample {
                    example: format!("{} --type [5, 15] -c google.com", constants::commands::QUERY),
                    description: "specify query types by numeric ID, and get numeric IDs in output".into(),
                    result: None,
                },
                PluginExample {
                    example: format!("'google.com' | {}", constants::commands::QUERY),
                    description: "pipe name into command".into(),
                    result: None,
                },
                PluginExample {
                    example: format!("['google.com', 'amazon.com'] | {}", constants::commands::QUERY),
                    description: "pipe lists of names into command".into(),
                    result: None,
                },
                PluginExample {
                    example: format!("[{{name: 'google.com', type: 'A'}}, {{name: 'amazon.com', type: 'A'}}] | {}", constants::commands::QUERY),
                    description: "pipe table of queries into command (ignores --type flag)".into(),
                    result: None,
                },
            ])
            .category(Category::Network)]
    }

    fn run(
        &mut self,
        name: &str,
        call: &EvaluatedCall,
        input: &Value,
    ) -> Result<Value, LabeledError> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.run_impl(name, call, input))
    }
}
