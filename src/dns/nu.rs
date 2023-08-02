use nu_plugin::{EvaluatedCall, LabeledError, Plugin};
use nu_protocol::{Category, PluginSignature, SyntaxShape, Value};

use super::Dns;

impl Plugin for Dns {
    fn signature(&self) -> Vec<PluginSignature> {
        // It is possible to declare multiple signature in a plugin
        // Each signature will be converted to a command declaration once the
        // plugin is registered to nushell
        vec![PluginSignature::build("dns query")
            .usage("Perform a DNS query")
            .rest(
                "name",
                SyntaxShape::OneOf(vec![
                    SyntaxShape::String,
                    SyntaxShape::List(Box::new(SyntaxShape::Binary)),
                ]),
                "DNS record name",
            )
            .named(
                "server",
                SyntaxShape::String,
                "Nameserver to query (defaults to system config or 8.8.8.8)",
                Some('s'),
            )
            .named(
                "protocol",
                SyntaxShape::String,
                "Protocol to use to connect to the nameserver: UDP, TCP. (default: UDP)",
                Some('p'),
            )
            .named("type", SyntaxShape::Any, "Query type", Some('t'))
            .named("class", SyntaxShape::Any, "Query class", None)
            .switch(
                "code",
                "Return code fields with both string and numeric representations",
                Some('c'),
            )
            .named(
                "dnssec",
                SyntaxShape::String,
                r##"Perform DNSSEC validation on records. Choices are: "none", "strict" (error if record has no RRSIG or does not validate), "opportunistic" (validate if RRSIGs present, otherwise no validation; default)"##,
                Some('d'),
            )
            // .plugin_examples(vec![PluginExample {
            //     example: "nu-example-1 3 bb".into(),
            //     description: "running example with an int value and string value".into(),
            //     result: None,
            // }])
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
