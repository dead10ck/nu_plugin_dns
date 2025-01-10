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
    use hickory_proto::xfer::Protocol;

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
    pub mod message {
        pub const HEADER: &str = "header";
        pub const QUESTION: &str = "question";
        pub const ANSWER: &str = "answer";
        pub const AUTHORITY: &str = "authority";
        pub const ADDITIONAL: &str = "additional";
        pub const EDNS: &str = "edns";
        pub const SIZE: &str = "size";

        pub const COLS: &[&str] = &[HEADER, QUESTION, ANSWER, AUTHORITY, ADDITIONAL, EDNS, SIZE];

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
            pub const QUERY_COUNT: &str = "query_count";
            pub const ANSWER_COUNT: &str = "answer_count";
            pub const NAME_SERVER_COUNT: &str = "name_server_count";
            pub const ADDITIONAL_COUNT: &str = "additional_count";

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
                QUERY_COUNT,
                ANSWER_COUNT,
                NAME_SERVER_COUNT,
                ADDITIONAL_COUNT,
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
