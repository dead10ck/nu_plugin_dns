use nu_protocol::Span;
use nu_protocol::Value;

const MESSAGE_COLS: &[&str] = &["header", "question", "answer"];
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

pub struct Message<'r>(pub(crate) &'r trust_dns_proto::op::Message);

impl<'r> From<Message<'r>> for Value {
    fn from(message: Message<'r>) -> Self {
        let Message(message) = message;

        let header = Value::from(Header(message.header()));

        let question = message.query().map_or_else(
            || Value::record(Vec::default(), Vec::default(), Span::unknown()),
            |q| Value::from(Query(q)),
        );

        let answer = message
            .answers()
            .iter()
            .map(|record| Value::from(Record(record)))
            .collect();

        Value::record(
            Vec::from_iter(MESSAGE_COLS.iter().map(|s| (*s).into())),
            vec![header, question, Value::list(answer, Span::unknown())],
            Span::unknown(),
        )
    }
}

pub struct Header<'r>(pub(crate) &'r trust_dns_proto::op::Header);

impl<'r> From<Header<'r>> for Value {
    fn from(header: Header<'r>) -> Self {
        let Header(header) = header;

        let id = Value::int(header.id().into(), Span::unknown());
        let message_type = Value::string(header.message_type().to_string(), Span::unknown());
        let op_code = Value::string(header.op_code().to_string(), Span::unknown());
        let authoritative = Value::bool(header.authoritative(), Span::unknown());
        let truncated = Value::bool(header.truncated(), Span::unknown());
        let recursion_desired = Value::bool(header.recursion_desired(), Span::unknown());
        let recursion_available = Value::bool(header.recursion_available(), Span::unknown());
        let authentic_data = Value::bool(header.authentic_data(), Span::unknown());
        let response_code = Value::string(header.response_code().to_string(), Span::unknown());
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

impl<'r> From<Query<'r>> for Value {
    fn from(query: Query) -> Self {
        let Query(query) = query;

        let name = Value::string(query.name().to_utf8(), Span::unknown());
        let qtype = Value::string(query.query_type().to_string(), Span::unknown());
        let class = Value::string(query.query_class().to_string(), Span::unknown());

        Value::record(
            Vec::from_iter(QUERY_COLS.iter().map(|s| (*s).into())),
            vec![name, qtype, class],
            Span::unknown(),
        )
    }
}

pub struct Record<'r>(pub(crate) &'r trust_dns_proto::rr::resource::Record);

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
