use nu_plugin::{EvaluatedCall, LabeledError, Plugin};
use nu_protocol::{Category, PluginSignature, Span, SyntaxShape, Value};
use tokio::net::UdpSocket;
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_proto::{
    rr::{DNSClass, RecordType},
    udp::UdpClientStream,
};
use trust_dns_resolver::{
    config::{Protocol, ResolverConfig},
    proto::error::ProtoError,
    Name,
};

const LOOKUP_RESULT_COLS: &[&str] = &["question", "answer"];
mod serde;

pub struct Dns {}

impl Dns {
    /*
    fn print_values(
        &self,
        index: u32,
        call: &EvaluatedCall,
        input: &Value,
    ) -> Result<(), LabeledError> {
        // Note. When debugging your plugin, you may want to print something to the console
        // Use the eprintln macro to print your messages. Trying to print to stdout will
        // cause a decoding error for your message
        eprintln!("Calling test {index} signature");
        eprintln!("value received {input:?}");

        // To extract the arguments from the Call object you can use the functions req, has_flag,
        // opt, rest, and get_flag
        //
        // Note that plugin calls only accept simple arguments, this means that you can
        // pass to the plug in Int and String. This should be improved when the plugin has
        // the ability to call back to NuShell to extract more information
        // Keep this in mind when designing your plugin signatures
        let a: i64 = call.req(0)?;
        let b: String = call.req(1)?;
        let flag = call.has_flag("flag");
        let opt: Option<i64> = call.opt(2)?;
        let named: Option<String> = call.get_flag("named")?;
        let rest: Vec<String> = call.rest(3)?;

        eprintln!("Required values");
        eprintln!("a: {a:}");
        eprintln!("b: {b:}");
        eprintln!("flag: {flag:}");
        eprintln!("rest: {rest:?}");

        if let Some(v) = opt {
            eprintln!("Found optional value opt: {v:}")
        } else {
            eprintln!("No optional value found")
        }

        if let Some(v) = named {
            eprintln!("Named value: {v:?}")
        } else {
            eprintln!("No named value found")
        }

        Ok(())
    }
    */
    async fn run_impl(
        &mut self,
        name: &str,
        call: &EvaluatedCall,
        input: &Value,
    ) -> Result<Value, LabeledError> {
        match name {
            "dns query" => self.query(call, input).await,
            _ => Err(LabeledError {
                label: "No such command".into(),
                msg: "No such command".into(),
                span: Some(call.head),
            }),
        }
    }

    async fn query(&self, call: &EvaluatedCall, _input: &Value) -> Result<Value, LabeledError> {
        let (name, name_span) = match call.req(0)? {
            Value::String { val, span } => (Name::from_utf8(val), span),
            Value::List { vals, span } => (
                Name::from_labels(vals.into_iter().map(|val| {
                    if let Value::Binary { val: bin_val, .. } = val {
                        bin_val
                    } else {
                        unreachable!("Invalid input type");
                    }
                })),
                span,
            ),
            _ => unreachable!("Invalid input type"),
        };

        let name = name.map_err(|err| parse_name_err(err, name_span))?;
        let (config, _) = trust_dns_resolver::system_conf::read_system_conf().unwrap_or_default();
        let (addr, protocol) = match config.name_servers() {
            [ns, ..] => (ns.socket_addr, ns.protocol),
            [] => {
                let config = ResolverConfig::default();
                let ns = config.name_servers().first().unwrap();
                (ns.socket_addr, ns.protocol)
            }
        };

        let (mut client, bg) = match protocol {
            Protocol::Udp => {
                let conn = UdpClientStream::<UdpSocket>::new(addr);
                AsyncClient::connect(conn)
                    .await
                    .map_err(|err| LabeledError {
                        label: "UdpConnectError".into(),
                        msg: format!("Error creating UDP client connection: {}", err),
                        span: None,
                    })?
            }
            Protocol::Tcp => todo!(),
            _ => todo!(),
        };

        let _bg_handle = tokio::spawn(bg);

        let resp = client
            .query(name, DNSClass::IN, RecordType::A)
            .await
            .map_err(|err| LabeledError {
                label: "DNSResponseError".into(),
                msg: format!("Error in DNS response: {}", err),
                span: None,
            })?
            .into_inner();

        let question = resp.query().map_or_else(
            || Value::record(Vec::default(), Vec::default(), Span::unknown()),
            |q| Value::from(serde::Query(q)),
        );
        let answer = resp
            .answers()
            .iter()
            .map(|record| Value::from(serde::Record(record)))
            .collect();

        Ok(Value::record(
            Vec::from_iter(LOOKUP_RESULT_COLS.iter().map(|s| (*s).into())),
            vec![question, Value::list(answer, Span::unknown())],
            Span::unknown(),
        ))
    }
}

fn parse_name_err(err: ProtoError, span: Span) -> LabeledError {
    LabeledError {
        label: "DnsNameParseError".into(),
        msg: format!("Error parsing as DNS name: {}", err),
        span: Some(span),
    }
}

impl Plugin for Dns {
    fn signature(&self) -> Vec<PluginSignature> {
        // It is possible to declare multiple signature in a plugin
        // Each signature will be converted to a command declaration once the
        // plugin is registered to nushell
        vec![
            // TODO
            // PluginSignature::build("dns")
            //     .usage("DNS utilities")
            //     .category(Category::Network),
            PluginSignature::build("dns query")
                .usage("Perform a DNS query")
                .required(
                    "name",
                    SyntaxShape::OneOf(vec![
                        SyntaxShape::String,
                        SyntaxShape::List(Box::new(SyntaxShape::Binary)),
                    ]),
                    "DNS record name",
                )
                // .optional("type", SyntaxShape::String, "Query type")
                // .plugin_examples(vec![PluginExample {
                //     example: "nu-example-1 3 bb".into(),
                //     description: "running example with an int value and string value".into(),
                //     result: None,
                // }])
                .category(Category::Network),
        ]
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
