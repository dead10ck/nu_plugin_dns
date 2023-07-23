use nu_plugin::{EvaluatedCall, LabeledError, Plugin};
use nu_protocol::{Category, PluginSignature, Span, SyntaxShape, Value};

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

    fn query(&self, call: &EvaluatedCall, input: &Value) -> Result<Value, LabeledError> {
        eprintln!("call: {:?}", call);
        eprintln!("input: {:?}", input);

        let name: Value = call.req(0)?;
        eprintln!("name: {:?}", name);

        Ok(Value::Nothing { span: call.head })
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
        // You can use the name to identify what plugin signature was called
        match name {
            "dns query" => self.query(call, input),
            _ => Err(LabeledError {
                label: "No such command".into(),
                msg: "No such command".into(),
                span: Some(call.head),
            }),
        }
    }
}
