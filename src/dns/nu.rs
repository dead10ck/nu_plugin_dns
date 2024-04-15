use nu_plugin::{EngineInterface, EvaluatedCall, Plugin, PluginCommand};
use nu_protocol::{Example, LabeledError, PipelineData, Signature, SyntaxShape, Type};

use crate::dns::constants;

use super::{Dns, DnsQuery};

impl Plugin for Dns {
    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin = Self>>> {
        vec![Box::new(DnsQuery)]
    }
}

impl PluginCommand for DnsQuery {
    type Plugin = Dns;

    fn run(
        &self,
        plugin: &Self::Plugin,
        engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        plugin
            .runtime
            .block_on(self.run_impl(plugin, engine, call, input))
    }

    fn name(&self) -> &str {
        constants::commands::QUERY
    }

    fn usage(&self) -> &str {
        "Perform a DNS query"
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build(self.name())
            .input_output_types(vec![
                (Type::String, Type::Any),
                (Type::List(Type::String.into()), Type::Any),
                (Type::List(
                    Type::Record(vec![
                        ("name".into(), Type::String),
                    ]).into()),
                    Type::Any
                ),
                (Type::List(
                    Type::Record(vec![
                        ("name".into(), Type::String),
                        ("type".into(), Type::String),
                    ]).into()),
                    Type::Any
                ),
                (Type::List(
                    Type::Record(vec![
                        ("name".into(), Type::String),
                        ("type".into(), Type::String),
                        ("class".into(), Type::String),
                    ]).into()),
                    Type::Any
                ),
            ])
            .rest(
                constants::flags::NAME,
                SyntaxShape::OneOf(vec![
                    SyntaxShape::String,
                    SyntaxShape::List(Box::new(SyntaxShape::OneOf(vec![
                        SyntaxShape::String,
                        SyntaxShape::Binary,
                        SyntaxShape::Int,
                        SyntaxShape::Boolean,
                    ]))),
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
                "Perform DNSSEC validation on records. Choices are: \"none\", \"strict\" (error if record has no RRSIG or does not validate), \"opportunistic\" (validate if RRSIGs present, otherwise no validation; default)",
                Some('d'),
            )
            .named(
                constants::flags::DNS_NAME,
                SyntaxShape::String,
                "DNS name of the TLS certificate in use by the nameserver (for TLS and HTTPS only)",
                Some('n'),
            )
    }

    fn examples(&self) -> Vec<nu_protocol::Example> {
        vec![
            Example {
                example: "dns query google.com",
                description: "simple query for A / AAAA records",
                result: None,
            },
            Example {
                example: "dns query --type CNAME google.com",
                description: "specify query type",
                result: None,
            },
            Example {
                example: "dns query --type [cname, mx] -c google.com",
                description: "specify multiple query types",
                result: None,
            },
            Example {
                example: "dns query --type [5, 15] -c google.com",
                description: "specify query types by numeric ID, and get numeric IDs in output"
                    ,
                result: None,
            },
            Example {
                example: "'google.com' | dns query",
                description: "pipe nameommand",
                result: None,
            },
            Example {
                example: "['google.com', 'amazon.com'] | dns query",
                description: "pipe lists of namesommand",
                result: None,
            },
            Example {
                example: "[{{name: 'google.com', type: 'A'}}, {{name: 'amazon.com', type: 'A'}}] | dns query",
                description: "pipe table of queriesommand (ignores --type flag)",
                result: None,
            },
        ]
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["dns", "network", "dig"]
    }
}
