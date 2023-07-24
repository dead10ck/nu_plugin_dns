use nu_plugin::{EvaluatedCall, LabeledError, Plugin};
use nu_protocol::{Category, PluginSignature, Span, SyntaxShape, Value};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    error::ResolveErrorKind,
    proto::error::ProtoError,
    Name, TokioAsyncResolver,
};

const RECORD_COLS: &[&str] = &["name", "type", "class", "ttl", "rdata"];

pub struct Record<'r>(&'r trust_dns_proto::rr::resource::Record);

impl<'r> From<Record<'r>> for Value {
    fn from(record: Record) -> Self {
        let Record(record) = record;

        let name = Value::string(record.name().to_utf8(), Span::unknown());
        let rtype = Value::string(record.rr_type().to_string(), Span::unknown());
        let class = Value::string(record.dns_class().to_string(), Span::unknown());
        let ttl = Value::int(record.ttl() as i64, Span::unknown());
        let rdata = match record.data() {
            Some(data) => Value::string(data.to_string(), Span::unknown()),
            None => Value::nothing(Span::unknown()),
        };

        Value::record(
            Vec::from_iter(RECORD_COLS.iter().map(|s| (*s).into())),
            vec![name, rtype, class, ttl, rdata],
            Span::unknown(),
        )
    }
}

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

    async fn query(&self, call: &EvaluatedCall, input: &Value) -> Result<Value, LabeledError> {
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

        let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(res) => res,
            Err(err) => {
                eprintln!("Warning: falling back to default DNS config: {}", err);
                TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
                    .map_err(|err| system_conf_err(err, call.head))?
            }
        };

        let resp = resolver
            .lookup(name, trust_dns_resolver::proto::rr::RecordType::A)
            .await;

        let records = match resp {
            Err(err) => {
                if matches!(err.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                    vec![]
                } else {
                    return Err(LabeledError {
                        label: "DnsResolveError".into(),
                        msg: format!("Failed to resolve: {}", err),
                        span: Some(call.head),
                    });
                }
            }
            Ok(lookup) => lookup
                .records()
                .iter()
                .map(|record| Value::from(Record(record)))
                .collect(),
        };

        Ok(Value::list(records, call.head))
    }
}

fn system_conf_err(err: trust_dns_resolver::error::ResolveError, span: Span) -> LabeledError {
    LabeledError {
        label: "SystemDnsConfigError".into(),
        msg: format!("Failed to get system DNS config: {}", err),
        span: Some(span),
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
