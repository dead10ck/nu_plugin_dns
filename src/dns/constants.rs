pub mod commands {
    pub const QUERY: &str = "dns query";
}

pub mod flags {
    pub const DNS_NAME: &str = "dns-name";
    pub const NAME: &str = "name";
    pub const SERVER: &str = "server";
    pub const PROTOCOL: &str = "protocol";
    pub const TYPE: &str = "type";
    pub const CLASS: &str = "class";
    pub const DNSSEC: &str = "dnssec";
    pub const CODE: &str = "code";
    pub const TASKS: &str = "tasks";
    pub const TIMEOUT: &str = "timeout";
}

pub mod config {
    use hickory_resolver::config::Protocol;

    pub mod default {
        use std::time::Duration;

        pub const TASKS: usize = 8;
        pub const TIMEOUT: Duration = Duration::from_secs(5);
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
    pub const NAME: &str = "name";
    pub const TYPE: &str = "type";
    pub const CLASS: &str = "class";

    pub const MESSAGE_COLS: &[&str] = &[
        "header",
        "question",
        "answer",
        "authority",
        "additional",
        "edns",
        "size",
    ];

    pub const HEADER_COLS: &[&str] = &[
        "id",
        "message_type",
        "op_code",
        "authoritative",
        "truncated",
        "recursion_desired",
        "recursion_available",
        "authentic_data",
        "response_code",
        "query_count",
        "answer_count",
        "name_server_count",
        "additional_count",
    ];
    pub const QUERY_COLS: &[&str] = &["name", "type", "class"];
    pub const RECORD_COLS: &[&str] = &["name", "type", "class", "ttl", "rdata"];
    pub const CODE_COLS: &[&str] = &["name", "code"];
}
