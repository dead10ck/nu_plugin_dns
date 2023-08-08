pub mod flags {
    pub const NAME: &str = "name";
    pub const SERVER: &str = "server";
    pub const PROTOCOL: &str = "protocol";
    pub const TYPE: &str = "type";
    pub const CLASS: &str = "class";
    pub const DNSSEC: &str = "dnssec";
    pub const CODE: &str = "code";
}

pub mod config {
    pub const SERVER_PORT: u16 = 53;
}

pub mod columns {
    pub const NAME: &str = "name";
    pub const TYPE: &str = "type";
    pub const CLASS: &str = "class";

    pub const NAMESERVER: &str = "nameserver";
    pub const MESSAGES: &str = "messages";
    pub const ADDRESS: &str = "address";
    pub const PROTOCOL: &str = "protocol";

    pub const MESSAGE_COLS: &[&str] = &["header", "question", "answer", "authority", "additional"];
    pub const HEADER_COLS: &[&str] = &[
        "id",
        "message_type",
        "op_code",
        "authoritative",
        "truncated",
        "recusion_desired",
        "recusion_available",
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
