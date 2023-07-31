use std::fmt::Display;
use std::str::FromStr;

use nu_plugin::EvaluatedCall;
use nu_plugin::LabeledError;
use nu_protocol::Span;
use nu_protocol::Value;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::rr::RecordType;

const MESSAGE_COLS: &[&str] = &["header", "question", "answer", "authority", "additional"];
pub(crate) const HEADER_COLS: &[&str] = &[
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
pub(crate) const QUERY_COLS: &[&str] = &["name", "type", "class"];
pub(crate) const RECORD_COLS: &[&str] = &["name", "type", "class", "ttl", "rdata"];

fn code_to_record_u16<C>(code: C, call: &EvaluatedCall) -> Value
where
    C: Display + Into<u16>,
{
    let code_string = Value::string(code.to_string(), Span::unknown());

    if call.has_flag("code") {
        Value::record(
            vec!["name".into(), "code".into()],
            vec![
                code_string,
                Value::int(Into::<u16>::into(code) as i64, Span::unknown()),
            ],
            Span::unknown(),
        )
    } else {
        code_string
    }
}

fn code_to_record_u8<C>(code: C, call: &EvaluatedCall) -> Value
where
    C: Display + Into<u8>,
{
    let code_string = Value::string(code.to_string(), Span::unknown());

    if call.has_flag("code") {
        Value::record(
            vec!["name".into(), "code".into()],
            vec![
                code_string,
                Value::int(Into::<u8>::into(code) as i64, Span::unknown()),
            ],
            Span::unknown(),
        )
    } else {
        code_string
    }
}

pub struct Message<'r>(pub(crate) &'r trust_dns_proto::op::Message);

impl<'r> Message<'r> {
    pub fn into_value(self, call: &EvaluatedCall) -> Value {
        let Message(message) = self;
        let header = Header(message.header()).into_value(call);

        let question = message.query().map_or_else(
            || Value::record(Vec::default(), Vec::default(), Span::unknown()),
            |q| Query(q).into_value(call),
        );

        let parse_records = |records: &[trust_dns_client::rr::Record]| {
            records
                .iter()
                .map(|record| Record(record).into_value(call))
                .collect()
        };

        let answer = parse_records(message.answers());
        let authority = parse_records(message.name_servers());
        let additional = parse_records(message.additionals());

        Value::record(
            Vec::from_iter(MESSAGE_COLS.iter().map(|s| (*s).into())),
            vec![
                header,
                question,
                Value::list(answer, Span::unknown()),
                Value::list(authority, Span::unknown()),
                Value::list(additional, Span::unknown()),
            ],
            Span::unknown(),
        )
    }
}

pub struct Header<'r>(pub(crate) &'r trust_dns_proto::op::Header);

impl<'r> Header<'r> {
    pub fn into_value(self, call: &EvaluatedCall) -> Value {
        let Header(header) = self;

        let id = Value::int(header.id().into(), Span::unknown());

        let message_type_string = Value::string(header.message_type().to_string(), Span::unknown());
        let message_type = if call.has_flag("code") {
            Value::record(
                vec!["name".into(), "code".into()],
                vec![
                    message_type_string,
                    Value::int(header.message_type() as i64, Span::unknown()),
                ],
                Span::unknown(),
            )
        } else {
            message_type_string
        };

        let op_code = code_to_record_u8(header.op_code(), call);
        let authoritative = Value::bool(header.authoritative(), Span::unknown());
        let truncated = Value::bool(header.truncated(), Span::unknown());
        let recursion_desired = Value::bool(header.recursion_desired(), Span::unknown());
        let recursion_available = Value::bool(header.recursion_available(), Span::unknown());
        let authentic_data = Value::bool(header.authentic_data(), Span::unknown());
        let response_code = code_to_record_u16(header.response_code(), call);
        let query_count = Value::int(header.query_count().into(), Span::unknown());
        let answer_count = Value::int(header.answer_count().into(), Span::unknown());
        let name_server_count = Value::int(header.name_server_count().into(), Span::unknown());
        let additional_count = Value::int(header.additional_count().into(), Span::unknown());

        Value::record(
            Vec::from_iter(HEADER_COLS.iter().map(|s| (*s).into())),
            vec![
                id,
                message_type,
                op_code,
                authoritative,
                truncated,
                recursion_desired,
                recursion_available,
                authentic_data,
                response_code,
                query_count,
                answer_count,
                name_server_count,
                additional_count,
            ],
            Span::unknown(),
        )
    }
}

pub struct Query<'r>(pub(crate) &'r trust_dns_proto::op::query::Query);

impl<'r> Query<'r> {
    pub fn into_value(self, call: &EvaluatedCall) -> Value {
        let Query(query) = self;

        let name = Value::string(query.name().to_utf8(), Span::unknown());
        let qtype = code_to_record_u16(query.query_type(), call);
        let class = code_to_record_u16(query.query_class(), call);

        Value::record(
            Vec::from_iter(QUERY_COLS.iter().map(|s| (*s).into())),
            vec![name, qtype, class],
            Span::unknown(),
        )
    }
}

pub struct Record<'r>(pub(crate) &'r trust_dns_proto::rr::resource::Record);

impl<'r> Record<'r> {
    pub fn into_value(self, call: &EvaluatedCall) -> Value {
        let Record(record) = self;

        let name = Value::string(record.name().to_utf8(), Span::unknown());
        let rtype = code_to_record_u16(record.rr_type(), call);
        let class = code_to_record_u16(record.dns_class(), call);
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

pub struct RType(pub(crate) trust_dns_proto::rr::RecordType);

impl TryFrom<Value> for RType {
    type Error = LabeledError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let qtype_err = |err: ProtoError, span: Span| LabeledError {
            label: "InvalidRecordType".into(),
            msg: format!("Error parsing record type: {}", err),
            span: Some(span),
        };

        match value {
            Value::String { val, span } => Ok(RType(
                RecordType::from_str(&val.to_uppercase()).map_err(|err| qtype_err(err, span))?,
            )),
            Value::Int { val, span } => {
                let rtype = RecordType::from(val as u16);

                if let RecordType::Unknown(r) = rtype {
                    return Err(LabeledError {
                        label: "InvalidRecordType".into(),
                        msg: format!("Error parsing record type: unknown code: {}", r),
                        span: Some(span),
                    });
                }

                Ok(RType(rtype))
            }
            value => Err(LabeledError {
                label: "InvalidRecordType".into(),
                msg: "Invalid type for record type argument. Must be either string or int.".into(),
                span: Some(value.span()?),
            }),
        }
    }
}

pub struct DNSClass(pub(crate) trust_dns_proto::rr::DNSClass);

impl TryFrom<Value> for DNSClass {
    type Error = LabeledError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let class_err = |err: ProtoError, span: Span| LabeledError {
            label: "InvalidDNSClass".into(),
            msg: format!("Error parsing DNS class: {}", err),
            span: Some(span),
        };

        let dns_class: DNSClass = match value {
            Value::String { val, span } => DNSClass(
                trust_dns_proto::rr::DNSClass::from_str(&val.to_uppercase())
                    .map_err(|err| class_err(err, span))?,
            ),
            Value::Int { val, span } => DNSClass(
                trust_dns_proto::rr::DNSClass::from_u16(val as u16)
                    .map_err(|err| class_err(err, span))?,
            ),
            value => {
                return Err(LabeledError {
                    label: "InvalidClassType".into(),
                    msg: "Invalid type for class type argument. Must be either string or int."
                        .into(),
                    span: Some(value.span()?),
                });
            }
        };

        Ok(dns_class)
    }
}

pub struct Protocol(pub(crate) trust_dns_resolver::config::Protocol);

impl TryFrom<Value> for Protocol {
    type Error = LabeledError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let result = match value {
            Value::String { val, span } => match val.to_uppercase().as_str() {
                "UDP" => Protocol(trust_dns_resolver::config::Protocol::Udp),
                "TCP" => Protocol(trust_dns_resolver::config::Protocol::Tcp),
                proto => {
                    return Err(LabeledError {
                        label: "InvalidProtocol".into(),
                        msg: format!("Invalid or unsupported protocol: {proto}"),
                        span: Some(span),
                    })
                }
            },
            _ => {
                return Err(LabeledError {
                    label: "InvalidInput".into(),
                    msg: "Input must be a string".into(),
                    span: Some(value.span()?),
                })
            }
        };

        Ok(result)
    }
}

#[derive(Default, PartialEq)]
pub enum DnssecMode {
    None,
    Strict,

    #[default]
    Opportunistic,
}

impl TryFrom<Value> for DnssecMode {
    type Error = LabeledError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::String { val, span } => Ok(match val.to_uppercase().as_str() {
                "NONE" => DnssecMode::None,
                "STRICT" => DnssecMode::Strict,
                "OPPORTUNISTIC" => DnssecMode::Opportunistic,
                _ => {
                    return Err(LabeledError {
                        label: "InvalidDnssecModeError".into(),
                        msg: "Invalid DNSSEC mode. Must be one of: none, strict, opportunistic"
                            .into(),
                        span: Some(span),
                    });
                }
            }),
            _ => Err(LabeledError {
                label: "InvalidInputError".into(),
                msg: "Input must be a string".into(),
                span: Some(value.span()?),
            }),
        }
    }
}
