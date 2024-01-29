use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;

use hickory_client::rr::rdata::key;
use hickory_client::rr::rdata::DNSSECRData;
use hickory_proto::error::ProtoError;
use hickory_proto::rr::dnssec;
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::sshfp;
use hickory_proto::rr::rdata::svcb::EchConfig;
use hickory_proto::rr::rdata::svcb::IpHint;
use hickory_proto::rr::rdata::svcb::SvcParamValue;
use hickory_proto::rr::rdata::svcb::Unknown;
use hickory_proto::rr::rdata::tlsa;
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::BinEncodable;
use hickory_resolver::Name;
use nu_plugin::EvaluatedCall;
use nu_plugin::LabeledError;
use nu_protocol::record;
use nu_protocol::FromValue;
use nu_protocol::Span;
use nu_protocol::Value;

use super::constants;

fn code_to_record_u16<C>(code: C, call: &EvaluatedCall) -> Value
where
    C: Display + Into<u16>,
{
    let code_string = Value::string(code.to_string(), Span::unknown());

    if call.has_flag(constants::flags::CODE) {
        Value::record(
            nu_protocol::Record::from_iter(std::iter::zip(
                Vec::from_iter(
                    constants::columns::CODE_COLS
                        .iter()
                        .map(|s| String::from(*s)),
                ),
                vec![
                    code_string,
                    Value::int(Into::<u16>::into(code) as i64, Span::unknown()),
                ],
            )),
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

    if call.has_flag(constants::flags::CODE) {
        Value::record(
            nu_protocol::Record::from_iter(std::iter::zip(
                Vec::from_iter(
                    constants::columns::CODE_COLS
                        .iter()
                        .map(|s| String::from(*s)),
                ),
                vec![
                    code_string,
                    Value::int(Into::<u8>::into(code) as i64, Span::unknown()),
                ],
            )),
            Span::unknown(),
        )
    } else {
        code_string
    }
}

pub struct Message {
    msg: hickory_proto::op::Message,
    bytes: Vec<u8>,
}

impl Message {
    pub fn new(msg: hickory_proto::op::Message) -> Self {
        let bytes = msg.to_bytes().expect("unencodable message");
        Self { msg, bytes }
    }

    pub fn into_inner(self) -> hickory_proto::op::Message {
        self.msg
    }

    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    pub fn into_value(self, call: &EvaluatedCall) -> Result<Value, LabeledError> {
        let size = Value::filesize(self.size() as i64, Span::unknown());
        let message = self.into_inner();
        let header = Header(message.header()).into_value(call);
        let mut parts = message.into_parts();

        let question = parts.queries.pop().map_or_else(
            || Value::record(record!(), Span::unknown()),
            |q| Query(q).into_value(call),
        );

        let parse_records =
            |records: Vec<hickory_client::rr::Record>| -> Result<Value, LabeledError> {
                Ok(Value::list(
                    records
                        .into_iter()
                        .map(|record| Record(record).into_value(call))
                        .collect::<Result<_, _>>()?,
                    Span::unknown(),
                ))
            };

        let answer = parse_records(parts.answers)?;
        let authority = parse_records(parts.name_servers)?;
        let additional = parse_records(parts.additionals)?;
        let edns = parts
            .edns
            .map(|edns| Edns(edns).into_value(call))
            .unwrap_or(Value::nothing(Span::unknown()));

        Ok(Value::record(
            nu_protocol::Record::from_iter(std::iter::zip(
                Vec::from_iter(constants::columns::MESSAGE_COLS.iter().map(|s| (*s).into())),
                vec![header, question, answer, authority, additional, edns, size],
            )),
            Span::unknown(),
        ))
    }
}

pub struct Header<'r>(pub(crate) &'r hickory_proto::op::Header);

impl<'r> Header<'r> {
    pub fn into_value(self, call: &EvaluatedCall) -> Value {
        let Header(header) = self;

        let id = Value::int(header.id().into(), Span::unknown());

        let message_type_string = Value::string(header.message_type().to_string(), Span::unknown());
        let message_type = if call.has_flag(constants::flags::CODE) {
            Value::record(
                nu_protocol::Record::from_iter(std::iter::zip(
                    Vec::from_iter(
                        constants::columns::CODE_COLS
                            .iter()
                            .map(|s| String::from(*s)),
                    ),
                    vec![
                        message_type_string,
                        Value::int(header.message_type() as i64, Span::unknown()),
                    ],
                )),
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
            nu_protocol::Record::from_iter(std::iter::zip(
                Vec::from_iter(constants::columns::HEADER_COLS.iter().map(|s| (*s).into())),
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
            )),
            Span::unknown(),
        )
    }
}

pub struct Query(pub(crate) hickory_proto::op::query::Query);

impl Query {
    pub fn into_value(self, call: &EvaluatedCall) -> Value {
        let Query(query) = self;

        let name = Value::string(query.name().to_utf8(), Span::unknown());
        let qtype = code_to_record_u16(query.query_type(), call);
        let class = code_to_record_u16(query.query_class(), call);

        Value::record(
            nu_protocol::Record::from_iter(std::iter::zip(
                Vec::from_iter(constants::columns::QUERY_COLS.iter().map(|s| (*s).into())),
                vec![name, qtype, class],
            )),
            Span::unknown(),
        )
    }
}

impl Query {
    pub fn try_from_value(value: &Value, call: &EvaluatedCall) -> Result<Vec<Self>, LabeledError> {
        let qtypes: Vec<RecordType> = match call.get_flag_value(constants::flags::TYPE) {
            Some(Value::List { vals, .. }) => vals
                .into_iter()
                .map(RType::try_from)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|RType(rtype)| rtype)
                .collect(),
            Some(val) => vec![RType::try_from(val)?.0],
            None => vec![RecordType::AAAA, RecordType::A],
        };

        let dns_class: hickory_proto::rr::DNSClass =
            match call.get_flag_value(constants::flags::CLASS) {
                Some(val) => DNSClass::try_from(val)?.0,
                None => hickory_proto::rr::DNSClass::IN,
            };

        match value {
            // If a record is given, it must have at least a name and qtype and
            // will be used as is, overriding any command line arguments.
            rec @ Value::Record { .. } => {
                let span = rec.span();

                let must_have_col_err = |col| LabeledError {
                    label: "InvalidInputError".into(),
                    msg: format!("Record must have a column named '{}'", col),
                    span: Some(span),
                };

                let name = Name::from_utf8(
                    String::from_value(
                        rec.get_data_by_key(constants::columns::NAME)
                            .ok_or_else(|| must_have_col_err(constants::columns::NAME))?,
                    )
                    .map_err(|err| LabeledError {
                        label: "InvalidValueError".into(),
                        msg: format!("Could not convert value to String: {}", err),
                        span: Some(span),
                    })?,
                )
                .map_err(|err| LabeledError {
                    label: "InvalidNameError".into(),
                    msg: format!("Could not convert string to name: {}", err),
                    span: Some(span),
                })?;

                let qtype = RType::try_from(
                    rec.get_data_by_key(constants::columns::TYPE)
                        .ok_or_else(|| must_have_col_err(constants::columns::TYPE))?,
                )?;

                let class = rec
                    .get_data_by_key(constants::columns::CLASS)
                    .map(DNSClass::try_from)
                    .unwrap_or(Ok(DNSClass(hickory_proto::rr::DNSClass::IN)))?
                    .0;

                let mut query = hickory_proto::op::Query::query(name, qtype.0);
                query.set_query_class(class);

                Ok(vec![Query(query)])
            }

            // If any other input type is given, the CLI flags fill in the type
            // and class.
            str_val @ Value::String { val, .. } => {
                let span = str_val.span();

                let name = Name::from_utf8(val).map_err(|err| LabeledError {
                    label: "InvalidNameError".into(),
                    msg: format!("Error parsing name: {}", err),
                    span: Some(span),
                })?;

                let queries = qtypes
                    .into_iter()
                    .map(|qtype| {
                        let mut query = hickory_proto::op::Query::query(name.clone(), qtype);
                        query.set_query_class(dns_class);
                        Query(query)
                    })
                    .collect();

                Ok(queries)
            }
            list @ Value::List { vals, .. } => {
                let span = list.span();

                let name = Name::from_labels(
                    vals.iter()
                        .map(|val| match val {
                            Value::Binary { val: bin_val, .. } => Ok(bin_val.clone()),
                            _ => Err(LabeledError {
                                label: "InvalidNameError".into(),
                                msg: "Invalid input type for name".into(),
                                span: Some(val.span()),
                            }),
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                )
                .map_err(|err| LabeledError {
                    label: "NameParseError".into(),
                    msg: format!("Error parsing into name: {}", err),
                    span: Some(span),
                })?;

                let queries = qtypes
                    .into_iter()
                    .map(|qtype| {
                        let mut query = hickory_proto::op::Query::query(name.clone(), qtype);
                        query.set_query_class(dns_class);
                        Query(query)
                    })
                    .collect();

                Ok(queries)
            }
            val => Err(LabeledError {
                label: "InvalidInputTypeError".into(),
                msg: "Invalid input type".into(),
                span: Some(val.span()),
            }),
        }
    }
}

pub struct Record(pub(crate) hickory_proto::rr::resource::Record);

impl Record {
    pub fn into_value(self, call: &EvaluatedCall) -> Result<Value, LabeledError> {
        let Record(record) = self;
        let parts = record.into_parts();

        let name = Value::string(parts.name_labels.to_utf8(), Span::unknown());
        let rtype = code_to_record_u16(parts.rr_type, call);
        let class = code_to_record_u16(parts.dns_class, call);
        let ttl = util::sec_to_duration(parts.ttl);
        let rdata = match parts.rdata {
            Some(data) => RData(data).into_value(call)?,
            None => Value::nothing(Span::unknown()),
        };

        Ok(Value::record(
            nu_protocol::Record::from_iter(std::iter::zip(
                Vec::from_iter(constants::columns::RECORD_COLS.iter().map(|s| (*s).into())),
                vec![name, rtype, class, ttl, rdata],
            )),
            Span::unknown(),
        ))
    }
}

pub struct RData(pub(crate) hickory_proto::rr::RData);

impl RData {
    pub fn into_value(self, call: &EvaluatedCall) -> Result<Value, LabeledError> {
        let val = match self.0 {
            hickory_proto::rr::RData::CAA(caa) => {
                let issuer_ctitical = Value::bool(caa.issuer_critical(), Span::unknown());
                let tag = Value::string(caa.tag().as_str(), Span::unknown());
                let value = match caa.value() {
                    hickory_proto::rr::rdata::caa::Value::Issuer(issuer_name, key_values) => {
                        let issuer_name = issuer_name
                            .as_ref()
                            .map(|name| Value::string(name.to_string(), Span::unknown()))
                            .unwrap_or(Value::nothing(Span::unknown()));

                        let parameters: HashMap<String, Value> = key_values
                            .iter()
                            .map(|key_val| {
                                (
                                    key_val.key().into(),
                                    Value::string(key_val.value(), Span::unknown()),
                                )
                            })
                            .collect();

                        Value::record(
                            nu_protocol::Record::from_iter(std::iter::zip(
                                vec!["issuer_name".into(), "parameters".into()],
                                vec![
                                    issuer_name,
                                    Value::record(
                                        nu_protocol::Record::from_iter(parameters),
                                        Span::unknown(),
                                    ),
                                ],
                            )),
                            Span::unknown(),
                        )
                    }
                    hickory_proto::rr::rdata::caa::Value::Url(url) => {
                        Value::string(url.to_string(), Span::unknown())
                    }
                    hickory_proto::rr::rdata::caa::Value::Unknown(data) => {
                        Value::binary(data.clone(), Span::unknown())
                    }
                };

                Value::record(
                    record![
                        "issuer_critical" => issuer_ctitical,
                        "tag"             => tag,
                        "value"           => value,
                    ],
                    Span::unknown(),
                )
            }
            // CSYNC seems to be missing some accessors in the trust-dns lib,
            // which oddly enough actually are serialized in the `Display` impl,
            // so just use that
            // hickory_proto::rr::RData::CSYNC(_) => todo!(),
            hickory_proto::rr::RData::HINFO(hinfo) => {
                let cpu = util::string_or_binary(hinfo.cpu());
                let os = util::string_or_binary(hinfo.os());

                Value::record(
                    record!(
                        "cpu" => cpu,
                        "os"  => os,
                    ),
                    Span::unknown(),
                )
            }

            hickory_proto::rr::RData::HTTPS(hickory_proto::rr::rdata::HTTPS(svcb))
            | hickory_proto::rr::RData::SVCB(svcb) => {
                let svc_priority = Value::int(svcb.svc_priority() as i64, Span::unknown());
                let target_name = Value::string(svcb.target_name().to_string(), Span::unknown());
                let svc_params = svcb.svc_params().iter().map(|(key, value)| {
                    let value = match value {
                        SvcParamValue::Mandatory(param_keys) => Value::list(
                            param_keys
                                .0
                                .iter()
                                .map(|key| Value::string(key.to_string(), Span::unknown()))
                                .collect(),
                            Span::unknown(),
                        ),
                        SvcParamValue::Alpn(alpn) => Value::list(
                            alpn.0
                                .iter()
                                .map(|alpn| Value::string(alpn, Span::unknown()))
                                .collect(),
                            Span::unknown(),
                        ),
                        nda @ SvcParamValue::NoDefaultAlpn => {
                            Value::string(nda.to_string(), Span::unknown())
                        }
                        SvcParamValue::Port(port) => Value::int(*port as i64, Span::unknown()),
                        SvcParamValue::Ipv4Hint(IpHint(ipv4s)) => Value::list(
                            ipv4s
                                .iter()
                                .map(|ip| Value::string(ip.to_string(), Span::unknown()))
                                .collect(),
                            Span::unknown(),
                        ),
                        SvcParamValue::EchConfig(EchConfig(config)) => {
                            Value::binary(config.clone(), Span::unknown())
                        }
                        SvcParamValue::Ipv6Hint(IpHint(ipv6s)) => Value::list(
                            ipv6s
                                .iter()
                                .map(|ip| Value::string(ip.to_string(), Span::unknown()))
                                .collect(),
                            Span::unknown(),
                        ),
                        SvcParamValue::Unknown(Unknown(bytes)) => {
                            Value::binary(bytes.clone(), Span::unknown())
                        }
                    };

                    (key.to_string(), value)
                });

                let svc_params =
                    Value::record(nu_protocol::Record::from_iter(svc_params), Span::unknown());

                Value::record(
                    record!(
                        "svc_priority" => svc_priority,
                        "target_name"  => target_name,
                        "svc_params"   => svc_params,
                    ),
                    Span::unknown(),
                )
            }

            hickory_proto::rr::RData::MX(mx) => {
                let preference = Value::int(mx.preference() as i64, Span::unknown());
                let exchange = Value::string(mx.exchange().to_string(), Span::unknown());

                Value::record(
                    record![
                        "preference" => preference,
                        "exchange"   => exchange
                    ],
                    Span::unknown(),
                )
            }

            hickory_proto::rr::RData::NAPTR(naptr) => {
                let order = Value::int(naptr.order() as i64, Span::unknown());
                let preference = Value::int(naptr.preference() as i64, Span::unknown());
                let flags = util::string_or_binary(naptr.flags());
                let services = util::string_or_binary(naptr.services());
                let regexp = util::string_or_binary(naptr.regexp());
                let replacement = Value::string(naptr.replacement().to_string(), Span::unknown());

                Value::record(
                    record![
                        "order"       => order,
                        "preference"  => preference,
                        "flags"       => flags,
                        "services"    => services,
                        "regexp"      => regexp,
                        "replacement" => replacement,
                    ],
                    Span::unknown(),
                )
            }

            hickory_proto::rr::RData::NULL(null) => util::string_or_binary(null.anything()),
            hickory_proto::rr::RData::NS(ns) => Value::string(ns.to_string(), Span::unknown()),
            hickory_proto::rr::RData::OPENPGPKEY(key) => {
                Value::binary(key.public_key(), Span::unknown())
            }
            hickory_proto::rr::RData::OPT(opt) => Opt(&opt).into_value(call),
            hickory_proto::rr::RData::PTR(name) => Value::string(name.to_string(), Span::unknown()),

            hickory_proto::rr::RData::SOA(soa) => {
                let mname = Value::string(soa.mname().to_string(), Span::unknown());
                let rname = Value::string(soa.rname().to_string(), Span::unknown());
                let serial = Value::int(soa.serial() as i64, Span::unknown());
                let refresh = util::sec_to_duration(soa.refresh() as u64);
                let retry = util::sec_to_duration(soa.retry() as u64);
                let expire = util::sec_to_duration(soa.expire() as u64);
                let minimum = util::sec_to_duration(soa.minimum() as u64);

                Value::record(
                    record![
                        "mname"   => mname,
                        "rname"   => rname,
                        "serial"  => serial,
                        "refresh" => refresh,
                        "retry"   => retry,
                        "expire"  => expire,
                        "minimum" => minimum,
                    ],
                    Span::unknown(),
                )
            }

            hickory_proto::rr::RData::SRV(srv) => {
                let priority = Value::int(srv.priority() as i64, Span::unknown());
                let weight = Value::int(srv.weight() as i64, Span::unknown());
                let port = Value::int(srv.port() as i64, Span::unknown());
                let target = Value::string(srv.target().to_string(), Span::unknown());

                Value::record(
                    record![
                        "priority" => priority,
                        "weight"   => weight,
                        "port"     => port,
                        "target"   => target
                    ],
                    Span::unknown(),
                )
            }

            hickory_proto::rr::RData::SSHFP(sshfp) => {
                let algorithm = match sshfp.algorithm() {
                    sshfp::Algorithm::Reserved => Value::string("reserved", Span::unknown()),
                    sshfp::Algorithm::RSA => Value::string("RSA", Span::unknown()),
                    sshfp::Algorithm::DSA => Value::string("DSA", Span::unknown()),
                    sshfp::Algorithm::ECDSA => Value::string("ECDSA", Span::unknown()),
                    sshfp::Algorithm::Ed25519 => Value::string("Ed25519", Span::unknown()),
                    sshfp::Algorithm::Ed448 => Value::string("Ed448", Span::unknown()),
                    sshfp::Algorithm::Unassigned(code) => Value::int(code as i64, Span::unknown()),
                };

                let fingerprint_type = match sshfp.fingerprint_type() {
                    sshfp::FingerprintType::Reserved => Value::string("reserved", Span::unknown()),
                    sshfp::FingerprintType::SHA1 => Value::string("SHA-1", Span::unknown()),
                    sshfp::FingerprintType::SHA256 => Value::string("SHA-256", Span::unknown()),
                    sshfp::FingerprintType::Unassigned(code) => {
                        Value::int(code as i64, Span::unknown())
                    }
                };

                let fingerprint = Value::binary(sshfp.fingerprint(), Span::unknown());

                Value::record(
                    record![
                        "algorithm"        => algorithm,
                        "fingerprint_type" => fingerprint_type,
                        "fingerprint"      => fingerprint,
                    ],
                    Span::unknown(),
                )
            }
            hickory_proto::rr::RData::TLSA(tlsa) => {
                let cert_usage = match tlsa.cert_usage() {
                    tlsa::CertUsage::CA => Value::string("CA", Span::unknown()),
                    tlsa::CertUsage::Service => Value::string("service", Span::unknown()),
                    tlsa::CertUsage::TrustAnchor => Value::string("trust anchor", Span::unknown()),
                    tlsa::CertUsage::DomainIssued => {
                        Value::string("domain issued", Span::unknown())
                    }
                    tlsa::CertUsage::Private => Value::string("private", Span::unknown()),
                    tlsa::CertUsage::Unassigned(code) => Value::int(code as i64, Span::unknown()),
                };

                let selector = match tlsa.selector() {
                    tlsa::Selector::Full => Value::string("full", Span::unknown()),
                    tlsa::Selector::Spki => Value::string("spki", Span::unknown()),
                    tlsa::Selector::Private => Value::string("private", Span::unknown()),
                    tlsa::Selector::Unassigned(code) => Value::int(code as i64, Span::unknown()),
                };

                let matching = match tlsa.matching() {
                    tlsa::Matching::Raw => Value::string("raw", Span::unknown()),
                    tlsa::Matching::Sha256 => Value::string("SHA-256", Span::unknown()),
                    tlsa::Matching::Sha512 => Value::string("SHA-512", Span::unknown()),
                    tlsa::Matching::Private => Value::string("private", Span::unknown()),
                    tlsa::Matching::Unassigned(code) => Value::int(code as i64, Span::unknown()),
                };

                let cert_data = Value::binary(tlsa.cert_data(), Span::unknown());

                Value::record(
                    record![
                        "cert_usage" => cert_usage,
                        "selector"   => selector,
                        "matching"   => matching,
                        "cert_data"  => cert_data,
                    ],
                    Span::unknown(),
                )
            }
            hickory_proto::rr::RData::TXT(data) => Value::list(
                data.iter()
                    .map(|txt_data| util::string_or_binary(Vec::from(txt_data.clone())))
                    .collect(),
                Span::unknown(),
            ),
            hickory_proto::rr::RData::DNSSEC(dnssec) => match dnssec {
                DNSSECRData::DNSKEY(dnskey) => parse_dnskey(&dnskey),
                DNSSECRData::CDNSKEY(cdnskey) => parse_dnskey(cdnskey),
                DNSSECRData::DS(ds) => parse_ds(&ds),
                DNSSECRData::CDS(cds) => parse_ds(cds),
                DNSSECRData::KEY(key) => {
                    let (key_authentication_prohibited, key_confidentiality_prohibited) =
                        match key.key_trust() {
                            key::KeyTrust::NotAuth => (
                                Value::bool(true, Span::unknown()),
                                Value::bool(false, Span::unknown()),
                            ),
                            key::KeyTrust::NotPrivate => (
                                Value::bool(false, Span::unknown()),
                                Value::bool(true, Span::unknown()),
                            ),
                            key::KeyTrust::AuthOrPrivate => (
                                Value::bool(false, Span::unknown()),
                                Value::bool(false, Span::unknown()),
                            ),
                            key::KeyTrust::DoNotTrust => (
                                Value::bool(true, Span::unknown()),
                                Value::bool(true, Span::unknown()),
                            ),
                        };

                    let key_type = Value::record(
                        record![
                            "authentication_prohibited" => key_authentication_prohibited,
                            "confidentiality_prohibited" => key_confidentiality_prohibited,
                        ],
                        Span::unknown(),
                    );

                    let key_name_type = Value::string(
                        Into::<String>::into(match key.key_usage() {
                            key::KeyUsage::Host => "host",
                            #[allow(deprecated)]
                            key::KeyUsage::Zone => "zone",
                            key::KeyUsage::Entity => "entity",
                            key::KeyUsage::Reserved => "reserved",
                        }),
                        Span::unknown(),
                    );

                    let key_signatory = key.signatory();

                    #[allow(deprecated)]
                    let signatory = Value::record(
                        record![
                            "zone"    => Value::bool(key_signatory.zone, Span::unknown()),
                            "strong"  => Value::bool(key_signatory.strong, Span::unknown()),
                            "unique"  => Value::bool(key_signatory.unique, Span::unknown()),
                            "general" => Value::bool(key_signatory.general, Span::unknown()),
                        ],
                        Span::unknown(),
                    );

                    #[allow(deprecated)]
                    let protocol = match key.protocol() {
                        key::Protocol::Reserved => Value::string("RESERVED", Span::unknown()),
                        key::Protocol::TLS => Value::string("TLS", Span::unknown()),
                        key::Protocol::Email => Value::string("EMAIL", Span::unknown()),
                        key::Protocol::DNSSEC => Value::string("DNSSEC", Span::unknown()),
                        key::Protocol::IPSec => Value::string("IPSEC", Span::unknown()),
                        key::Protocol::Other(code) => Value::int(code as i64, Span::unknown()),
                        key::Protocol::All => Value::string("ALL", Span::unknown()),
                    };

                    let algorithm = Value::string(key.algorithm().to_string(), Span::unknown());
                    let public_key = Value::binary(key.public_key(), Span::unknown());

                    Value::record(
                        record![
                            "key_type"      => key_type,
                            "key_name_type" => key_name_type,
                            "signatory"     => signatory,
                            "protocol"      => protocol,
                            "algorithm"     => algorithm,
                            "public_key"    => public_key,
                        ],
                        Span::unknown(),
                    )
                }
                DNSSECRData::NSEC(nsec) => {
                    let next_domain_name =
                        Value::string(nsec.next_domain_name().to_string(), Span::unknown());
                    let types = Value::list(
                        nsec.type_bit_maps()
                            .iter()
                            .map(|rtype| Value::string(rtype.to_string(), Span::unknown()))
                            .collect(),
                        Span::unknown(),
                    );

                    Value::record(
                        record![
                            "next_domain_name" => next_domain_name,
                            "types"            => types,
                        ],
                        Span::unknown(),
                    )
                }
                DNSSECRData::NSEC3(nsec3) => {
                    let hash_algorithm = Value::string(
                        Into::<String>::into(match nsec3.hash_algorithm() {
                            dnssec::Nsec3HashAlgorithm::SHA1 => "SHA-1",
                        }),
                        Span::unknown(),
                    );
                    let opt_out = Value::bool(nsec3.opt_out(), Span::unknown());
                    let iterations = Value::int(nsec3.iterations() as i64, Span::unknown());
                    let salt = Value::binary(nsec3.salt(), Span::unknown());
                    let next_hashed_owner_name =
                        Value::binary(nsec3.next_hashed_owner_name(), Span::unknown());
                    let types = Value::list(
                        nsec3
                            .type_bit_maps()
                            .iter()
                            .map(|rtype| Value::string(rtype.to_string(), Span::unknown()))
                            .collect(),
                        Span::unknown(),
                    );

                    Value::record(
                        record![
                            "hash_algorithm"         => hash_algorithm,
                            "opt_out"                => opt_out,
                            "iterations"             => iterations,
                            "salt"                   => salt,
                            "next_hashed_owner_name" => next_hashed_owner_name,
                            "types"                  => types,
                        ],
                        Span::unknown(),
                    )
                }
                DNSSECRData::NSEC3PARAM(nsec3param) => {
                    let hash_algorithm = Value::string(
                        Into::<String>::into(match nsec3param.hash_algorithm() {
                            dnssec::Nsec3HashAlgorithm::SHA1 => "SHA-1",
                        }),
                        Span::unknown(),
                    );
                    let opt_out = Value::bool(nsec3param.opt_out(), Span::unknown());
                    let iterations = Value::int(nsec3param.iterations() as i64, Span::unknown());
                    let salt = Value::binary(nsec3param.salt(), Span::unknown());
                    let flags = Value::int(nsec3param.flags() as i64, Span::unknown());

                    Value::record(
                        record![
                            "hash_algorithm" => hash_algorithm,
                            "opt_out"        => opt_out,
                            "iterations"     => iterations,
                            "salt"           => salt,
                            "flags"          => flags,
                        ],
                        Span::unknown(),
                    )
                }
                DNSSECRData::SIG(sig) => {
                    let type_covered =
                        Value::string(sig.type_covered().to_string(), Span::unknown());
                    let algorithm = Value::string(sig.algorithm().to_string(), Span::unknown());
                    let num_labels = Value::int(sig.num_labels() as i64, Span::unknown());
                    let original_ttl = util::sec_to_duration(sig.original_ttl());
                    let sig_expiration = util::sec_to_date(sig.sig_expiration(), call.head)?;
                    let sig_inception = util::sec_to_date(sig.sig_inception(), call.head)?;
                    let key_tag = Value::int(sig.key_tag() as i64, Span::unknown());
                    let signer_name = Value::string(sig.signer_name().to_string(), Span::unknown());
                    let sig = Value::binary(sig.sig(), Span::unknown());

                    Value::record(
                        record![
                            "type_covered"         => type_covered,
                            "algorithm"            => algorithm,
                            "num_labels"           => num_labels,
                            "original_ttl"         => original_ttl,
                            "signature_expiration" => sig_expiration,
                            "signature_inception"  => sig_inception,
                            "key_tag"              => key_tag,
                            "signer_name"          => signer_name,
                            "signature"            => sig,
                        ],
                        Span::unknown(),
                    )
                }
                DNSSECRData::TSIG(tsig) => {
                    // [NOTE] oid, error, and other do not have accessors
                    let algorithm = Value::string(tsig.algorithm().to_string(), Span::unknown());
                    let time = util::sec_to_date(tsig.time() as i64, call.head)?;
                    let fudge = Value::int(tsig.fudge() as i64, Span::unknown());
                    let mac = Value::binary(tsig.mac(), Span::unknown());
                    // let oid = Value::int(tsig.oid() as i64, Span::unknown());
                    // let error = Value::int(tsig.error() as i64, Span::unknown());
                    // let other = Value::binary(tsig.other(), Span::unknown());

                    Value::record(
                        record![
                            "algorithm" => algorithm,
                            "time"      => time,
                            "fudge"     => fudge,
                            "mac"       => mac,
                            // "oid"      => oid,
                            // "error"    => error,
                            // "other"    => other,
                        ],
                        Span::unknown(),
                    )
                }
                DNSSECRData::Unknown { code, rdata } => Value::record(
                    record![
                        "code"  => Value::int(code as i64, Span::unknown()),
                        "rdata" => Value::binary(rdata.anything(), Span::unknown()),
                    ],
                    Span::unknown(),
                ),
                rdata => Value::string(rdata.to_string(), Span::unknown()),
            },
            hickory_proto::rr::RData::Unknown { code: rtype, rdata } => Value::record(
                record![
                    "code"  => Value::int(u16::from(rtype) as i64, Span::unknown()),
                    "rdata" => Value::binary(rdata.anything(), Span::unknown()),
                ],
                Span::unknown(),
            ),
            rdata => Value::string(rdata.to_string(), Span::unknown()),
        };

        Ok(val)
    }
}

fn parse_ds<D: Deref<Target = dnssec::rdata::DS>>(ds: D) -> Value {
    let key_tag = Value::int(ds.key_tag() as i64, Span::unknown());
    let algorithm = Value::string(ds.algorithm().to_string(), Span::unknown());
    let digest_type = Value::string(
        Into::<String>::into(match ds.digest_type() {
            dnssec::DigestType::SHA1 => "SHA-1",
            dnssec::DigestType::SHA256 => "SHA-256",
            dnssec::DigestType::GOSTR34_11_94 => "GOST R 34.11-94",
            dnssec::DigestType::SHA384 => "SHA-384",
            dnssec::DigestType::SHA512 => "SHA-512",
            dnssec::DigestType::ED25519 => "ED25519",
            _ => "unknown",
        }),
        Span::unknown(),
    );
    let digest = Value::binary(ds.digest(), Span::unknown());
    Value::record(
        record![
            "key_tag"     => key_tag,
            "algorithm"   => algorithm,
            "digest_type" => digest_type,
            "digest"      => digest,
        ],
        Span::unknown(),
    )
}

fn parse_dnskey<D: Deref<Target = dnssec::rdata::DNSKEY>>(dnskey: D) -> Value {
    let zone_key = Value::bool(dnskey.zone_key(), Span::unknown());
    let secure_entry_point = Value::bool(dnskey.secure_entry_point(), Span::unknown());
    let revoke = Value::bool(dnskey.revoke(), Span::unknown());
    let algorithm = Value::string(dnskey.algorithm().to_string(), Span::unknown());
    let public_key = Value::binary(dnskey.public_key(), Span::unknown());
    Value::record(
        record![
            "zone_key"           => zone_key,
            "secure_entry_point" => secure_entry_point,
            "revoke"             => revoke,
            "algorithm"          => algorithm,
            "public_key"         => public_key,
        ],
        Span::unknown(),
    )
}

pub struct Edns(pub(crate) hickory_proto::op::Edns);

impl Edns {
    pub fn into_value(self, call: &EvaluatedCall) -> Value {
        let edns = self.0;
        let rcode_high = Value::int(edns.rcode_high() as i64, Span::unknown());
        let version = Value::int(edns.version() as i64, Span::unknown());
        let dnssec_ok = Value::bool(edns.dnssec_ok(), Span::unknown());
        let max_payload = Value::filesize(edns.max_payload() as i64, Span::unknown());
        let opts = Opt(edns.options()).into_value(call);

        Value::record(
            record![
                "rcode_high"  => rcode_high,
                "version"     => version,
                "dnssec_ok"   => dnssec_ok,
                "max_payload" => max_payload,
                "opts"        => opts,
            ],
            Span::unknown(),
        )
    }
}

pub struct Opt<'o>(pub(crate) &'o hickory_proto::rr::rdata::OPT);

impl<'o> Opt<'o> {
    pub fn into_value(self, _call: &EvaluatedCall) -> Value {
        let opts: HashMap<_, _> = self
            .0
            .as_ref()
            .iter()
            .map(|(code, option)| {
                let code = match code {
                    EdnsCode::Zero => "zero".into(),
                    EdnsCode::LLQ => "LLQ".into(),
                    EdnsCode::UL => "UL".into(),
                    EdnsCode::NSID => "NSID".into(),
                    EdnsCode::DAU => "DAU".into(),
                    EdnsCode::DHU => "DHU".into(),
                    EdnsCode::N3U => "N3U".into(),
                    EdnsCode::Subnet => "subnet".into(),
                    EdnsCode::Expire => "EXPIRE".into(),
                    EdnsCode::Cookie => "cookie".into(),
                    EdnsCode::Keepalive => "keepalive".into(),
                    EdnsCode::Padding => "padding".into(),
                    EdnsCode::Chain => "chain".into(),
                    EdnsCode::Unknown(code) => format!("unknown({})", code),
                    ednscode => format!("unknown Edns: {:?}", ednscode),
                };

                let option = match option {
                    EdnsOption::DAU(supported)
                    | EdnsOption::DHU(supported)
                    | EdnsOption::N3U(supported) => Value::list(
                        supported
                            .iter()
                            .map(|alg| Value::string(alg.to_string(), Span::unknown()))
                            .collect(),
                        Span::unknown(),
                    ),
                    EdnsOption::Unknown(code, val) => Value::record(
                        record![
                            "code" => Value::int(*code as i64, Span::unknown()),
                            "data" => util::string_or_binary(val.clone()),
                        ],
                        Span::unknown(),
                    ),
                    _ => todo!(),
                };

                (code, option)
            })
            .collect();

        Value::record(nu_protocol::Record::from_iter(opts), Span::unknown())
    }
}

pub struct RType(pub(crate) hickory_proto::rr::RecordType);

impl TryFrom<Value> for RType {
    type Error = LabeledError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let qtype_err = |err: ProtoError, span: Span| LabeledError {
            label: "InvalidRecordType".into(),
            msg: format!("Error parsing record type: {}", err),
            span: Some(span),
        };

        match value {
            Value::String { .. } => Ok(RType(
                RecordType::from_str(&value.as_string().unwrap().to_uppercase())
                    .map_err(|err| qtype_err(err, value.span()))?,
            )),
            Value::Int { val, .. } => {
                let rtype = RecordType::from(val as u16);

                if let RecordType::Unknown(r) = rtype {
                    return Err(LabeledError {
                        label: "InvalidRecordType".into(),
                        msg: format!("Error parsing record type: unknown code: {}", r),
                        span: Some(value.span()),
                    });
                }

                Ok(RType(rtype))
            }
            value => Err(LabeledError {
                label: "InvalidRecordType".into(),
                msg: "Invalid type for record type argument. Must be either string or int.".into(),
                span: Some(value.span()),
            }),
        }
    }
}

pub struct DNSClass(pub(crate) hickory_proto::rr::DNSClass);

impl TryFrom<Value> for DNSClass {
    type Error = LabeledError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let class_err = |err: ProtoError, span: Span| LabeledError {
            label: "InvalidDNSClass".into(),
            msg: format!("Error parsing DNS class: {}", err),
            span: Some(span),
        };

        let dns_class: DNSClass = match value {
            Value::String { .. } => DNSClass(
                hickory_proto::rr::DNSClass::from_str(&value.as_string().unwrap().to_uppercase())
                    .map_err(|err| class_err(err, value.span()))?,
            ),
            Value::Int { val, .. } => DNSClass(hickory_proto::rr::DNSClass::from(val as u16)),
            value => {
                return Err(LabeledError {
                    label: "InvalidClassType".into(),
                    msg: "Invalid type for class type argument. Must be either string or int."
                        .into(),
                    span: Some(value.span()),
                });
            }
        };

        Ok(dns_class)
    }
}

pub struct Protocol(pub(crate) hickory_resolver::config::Protocol);

impl TryFrom<Value> for Protocol {
    type Error = LabeledError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let result = match value {
            Value::String { .. } => match value.as_string().unwrap().to_uppercase().as_str() {
                "UDP" => Protocol(hickory_resolver::config::Protocol::Udp),
                "TCP" => Protocol(hickory_resolver::config::Protocol::Tcp),
                "TLS" => Protocol(hickory_resolver::config::Protocol::Tls),
                "HTTPS" => Protocol(hickory_resolver::config::Protocol::Https),
                "QUIC" => Protocol(hickory_resolver::config::Protocol::Quic),
                proto => {
                    return Err(LabeledError {
                        label: "InvalidProtocol".into(),
                        msg: format!("Invalid or unsupported protocol: {proto}"),
                        span: Some(value.span()),
                    })
                }
            },
            _ => {
                return Err(LabeledError {
                    label: "InvalidInput".into(),
                    msg: "Input must be a string".into(),
                    span: Some(value.span()),
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
            Value::String { .. } => Ok(match value.as_string().unwrap().to_uppercase().as_str() {
                "NONE" => DnssecMode::None,
                "STRICT" => DnssecMode::Strict,
                "OPPORTUNISTIC" => DnssecMode::Opportunistic,
                _ => {
                    return Err(LabeledError {
                        label: "InvalidDnssecModeError".into(),
                        msg: "Invalid DNSSEC mode. Must be one of: none, strict, opportunistic"
                            .into(),
                        span: Some(value.span()),
                    });
                }
            }),
            _ => Err(LabeledError {
                label: "InvalidInputError".into(),
                msg: "Input must be a string".into(),
                span: Some(value.span()),
            }),
        }
    }
}

pub mod util {
    use std::time::Duration;

    use chrono::TimeZone;
    use nu_plugin::LabeledError;
    use nu_protocol::{Span, Value};

    pub fn string_or_binary<V>(bytes: V) -> Value
    where
        V: Into<Vec<u8>>,
    {
        match String::from_utf8(bytes.into()) {
            Ok(s) => Value::string(s, Span::unknown()),
            Err(err) => Value::binary(err.into_bytes(), Span::unknown()),
        }
    }

    pub fn sec_to_duration<U: Into<u64>>(sec: U) -> Value {
        Value::duration(
            Duration::from_secs(sec.into()).as_nanos() as i64,
            Span::unknown(),
        )
    }

    pub fn sec_to_date<U: Into<i64>>(sec: U, input_span: Span) -> Result<Value, LabeledError> {
        let secs = sec.into();
        let datetime = match chrono::Utc.timestamp_opt(secs, 0) {
            chrono::LocalResult::None => Err(LabeledError {
                label: "InvalidTimeError".into(),
                msg: format!("Invalid time: {}", secs),
                span: Some(input_span),
            }),
            chrono::LocalResult::Single(dt) => Ok(dt),
            chrono::LocalResult::Ambiguous(dt1, dt2) => Err(LabeledError {
                label: "InvalidTimeError".into(),
                msg: format!(
                    "Time {} produced ambiguous result: {} vs {}",
                    secs, dt1, dt2
                ),
                span: Some(input_span),
            }),
        }?
        .fixed_offset();

        Ok(Value::date(datetime, Span::unknown()))
    }
}
