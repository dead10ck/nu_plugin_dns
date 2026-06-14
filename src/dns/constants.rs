pub mod commands {
    pub const QUERY: &str = "dns query";
}

pub mod params {
    use std::sync::LazyLock;

    use nu_protocol::{Flag, Parameter, PositionalArg, SyntaxShape};

    pub static NAME: LazyLock<Parameter> = LazyLock::new(|| {
        Parameter::Rest(PositionalArg {
            name: "name".to_string(),
            desc: "DNS record name".to_string(),

            // [NOTE] this does not work
            // SyntaxShape::OneOf(vec![
            //     SyntaxShape::String,
            //     SyntaxShape::List(Box::new(SyntaxShape::OneOf(vec![
            //         SyntaxShape::String,
            //         SyntaxShape::Binary,
            //         SyntaxShape::Int,
            //         SyntaxShape::Boolean,
            //     ]))),
            // ]),
            shape: SyntaxShape::Any,
            completion: None,
            var_id: None,
            default_value: None,
        })
    });

    pub static CONFIG: LazyLock<Parameter> = LazyLock::new(|| {
        Parameter::Flag(Flag {
            long: "config".to_string(),
            short: None,
            arg: Some(SyntaxShape::Any),
            required: false,
            desc: "DNS resolver config".to_string(),
            completion: None,
            var_id: None,
            default_value: None,
        })
    });

    pub static TYPE: LazyLock<Parameter> = LazyLock::new(|| {
        Parameter::Flag(Flag {
            long: "type".to_string(),
            short: Some('t'),
            // Any because it can be a number too
            arg: Some(SyntaxShape::Any),
            required: false,
            desc: "Query type".to_string(),
            completion: None,
            var_id: None,
            default_value: None,
        })
    });

    pub static CLASS: LazyLock<Parameter> = LazyLock::new(|| {
        Parameter::Flag(Flag {
            long: "class".to_string(),
            short: None,
            // Any because it can be a number too
            arg: Some(SyntaxShape::Any),
            required: false,
            desc: "Query class".to_string(),
            completion: None,
            var_id: None,
            default_value: None,
        })
    });

    pub static TASKS: LazyLock<Parameter> = LazyLock::new(|| {
        Parameter::Flag(Flag {
            long: "tasks".to_string(),
            short: Some('j'),
            arg: Some(SyntaxShape::Int),
            required: false,
            desc: format!(
                "Number of concurrent tasks to execute queries. Please be mindful not to overwhelm your nameserver! Default: {}",
                super::config::default::TASKS
            ),
            completion: None,
            var_id: None,
            default_value: None,
        })
    });

    pub static TIMEOUT: LazyLock<Parameter> = LazyLock::new(|| {
        Parameter::Flag(Flag {
            long: "timeout".to_string(),
            short: None,
            arg: Some(SyntaxShape::Duration),
            required: false,
            desc: format!(
                "How long a request can take before timing out. Be aware the concurrency level can affect this. Default: {}sec",
                super::config::default::TIMEOUT.as_secs()
            ),
            completion: None,
            var_id: None,
            default_value: None,
        })
    });

    pub static CODE: LazyLock<Parameter> = LazyLock::new(|| {
        Parameter::Flag(Flag {
            long: "code".to_string(),
            short: Some('c'),
            arg: None,
            required: false,
            desc: "Return code fields with both string and numeric representations".to_string(),
            completion: None,
            var_id: None,
            default_value: None,
        })
    });

    pub static ALL: &[&LazyLock<Parameter>] =
        &[&NAME, &CONFIG, &TYPE, &CLASS, &TASKS, &TIMEOUT, &CODE];
}

pub mod config {
    use hickory_net::xfer::Protocol;

    pub mod default {
        use std::time::Duration;

        pub const TASKS: usize = 8;
        pub const TIMEOUT: Duration = Duration::from_secs(30);
    }

    pub fn default_port(protocol: Protocol) -> u16 {
        match protocol {
            Protocol::Udp | Protocol::Tcp => 53,
            Protocol::Tls | Protocol::Quic => 853,
            Protocol::Https => 443,
            _ => 53,
        }
    }
}

pub mod columns {
    pub mod message {
        pub const HEADER: &str = "header";
        pub const QUESTION: &str = "question";
        pub const ANSWER: &str = "answer";
        pub const AUTHORITY: &str = "authority";
        pub const ADDITIONAL: &str = "additional";
        pub const EDNS: &str = "edns";

        pub const COLS: &[&str] = &[HEADER, QUESTION, ANSWER, AUTHORITY, ADDITIONAL, EDNS];

        pub mod header {
            pub const ID: &str = "id";
            pub const MESSAGE_TYPE: &str = "message_type";
            pub const OP_CODE: &str = "op_code";
            pub const AUTHORITATIVE: &str = "authoritative";
            pub const TRUNCATED: &str = "truncated";
            pub const RECURSION_DESIRED: &str = "recursion_desired";
            pub const RECURSION_AVAILABLE: &str = "recursion_available";
            pub const AUTHENTIC_DATA: &str = "authentic_data";
            pub const RESPONSE_CODE: &str = "response_code";

            pub const COLS: &[&str] = &[
                ID,
                MESSAGE_TYPE,
                OP_CODE,
                AUTHORITATIVE,
                TRUNCATED,
                RECURSION_DESIRED,
                RECURSION_AVAILABLE,
                AUTHENTIC_DATA,
                RESPONSE_CODE,
            ];
        }

        pub mod query {
            pub const COLS: &[&str] = &[
                super::super::rr::NAME,
                super::super::rr::TYPE,
                super::super::rr::CLASS,
            ];
        }
    }

    pub mod rr {
        pub const NAME: &str = "name";
        pub const TYPE: &str = "type";
        pub const CLASS: &str = "class";
        pub const TTL: &str = "ttl";
        pub const RDATA: &str = "rdata";
        pub const PROOF: &str = "proof";

        pub const COLS: &[&str] = &[NAME, TYPE, CLASS, TTL, RDATA, PROOF];

        pub mod code {
            pub const CODE: &str = "code";

            pub const COLS: &[&str] = &[super::NAME, CODE];
        }
    }
}
