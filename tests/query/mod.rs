use std::str::FromStr;

use hickory_proto::rr::{IntoName, Name, RecordType};
use nu_plugin_dns::dns::constants;
use nu_protocol::{ShellError, Span, Value};

use super::{HARNESS, HickoryResponseCode, TestCase, record_values};

mod expected;

#[test]
pub(crate) fn rr_a() -> Result<(), Box<ShellError>> {
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type a '{}'", *expected::name::ORIGIN),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(code, expected::rr::A.clone());
            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_aaaa() -> Result<(), Box<ShellError>> {
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type aaaa '{}'", *expected::name::ORIGIN),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(code, expected::rr::AAAA.clone());
            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_aname() -> Result<(), Box<ShellError>> {
    let aname = expected::name::ORIGIN.prepend_label("acal").unwrap();
    let expected_aname_rr = (
        aname.clone(),
        expected::rr::THIRTY_MIN,
        hickory_proto::rr::RData::ANAME(hickory_proto::rr::rdata::ANAME(
            expected::name::ORIGIN.clone(),
        )),
    );

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type aname '{}'", aname),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(code, [expected_aname_rr.clone()]);
            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);
        },
    )?;

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type a '{}'", aname),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected_answer = record_values(
                code,
                expected::rr::A
                    .clone()
                    .into_iter()
                    // ttl of 0 ???
                    .map(|(_, _, rdata)| (aname.clone(), chrono::TimeDelta::zero(), rdata)),
            );
            let actual_answer = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected_answer, actual_answer);

            let expected_additional = record_values(
                code,
                [expected_aname_rr.clone()]
                    .into_iter()
                    .chain(expected::rr::A.clone()),
            );
            let actual_additional = message
                .get(constants::columns::message::ADDITIONAL)
                .unwrap();
            assert_eq!(&expected_additional, actual_additional);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_caa() -> Result<(), Box<ShellError>> {
    let caa_issue = expected::name::ORIGIN
        .prepend_label("caa")
        .unwrap()
        .prepend_label("issue")
        .unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type caa '{}'", caa_issue),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            use hickory_proto::rr::rdata::caa::KeyValue;

            let expected = record_values(
                code,
                [hickory_proto::rr::RData::CAA(
                    hickory_proto::rr::rdata::CAA::new_issue(
                        true,
                        Some("dynadot.com".into_name().unwrap()),
                        vec![KeyValue::new("foo", "bar"), KeyValue::new("baz", "quux")],
                    ),
                )]
                .into_iter()
                .map(|rdata| (caa_issue.clone(), expected::rr::THIRTY_MIN, rdata)),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);
        },
    )?;

    let caa_issuewild = expected::name::ORIGIN
        .prepend_label("caa")
        .unwrap()
        .prepend_label("issuewild")
        .unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type caa '{}'", caa_issuewild),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [
                    hickory_proto::rr::RData::CAA(hickory_proto::rr::rdata::CAA::new_issuewild(
                        false,
                        Some("dynadot.com".into_name().unwrap()),
                        vec![],
                    )),
                    hickory_proto::rr::RData::CAA(hickory_proto::rr::rdata::CAA::new_issuewild(
                        false,
                        None,
                        vec![],
                    )),
                ]
                .into_iter()
                .map(|rdata| (caa_issuewild.clone(), expected::rr::THIRTY_MIN, rdata)),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);
        },
    )?;

    let caa_iodef = expected::name::ORIGIN
        .prepend_label("caa")
        .unwrap()
        .prepend_label("report")
        .unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type caa '{}'", caa_iodef),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [
                    hickory_proto::rr::RData::CAA(hickory_proto::rr::rdata::CAA::new_iodef(
                        false,
                        "mailto:bob@nushell.sh".parse().unwrap(),
                    )),
                    hickory_proto::rr::RData::CAA(hickory_proto::rr::rdata::CAA::new_iodef(
                        false,
                        "https://nushell.sh/".parse().unwrap(),
                    )),
                ]
                .into_iter()
                .map(|rdata| (caa_iodef.clone(), expected::rr::THIRTY_MIN, rdata)),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_cert() -> Result<(), Box<ShellError>> {
    let cert = expected::name::ORIGIN.prepend_label("cert").unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type cert '{}'", cert),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [hickory_proto::rr::RData::CERT(
                    hickory_proto::rr::rdata::CERT::new(
                        hickory_proto::rr::rdata::cert::CertType::PKIX,
                        12345,
                        hickory_proto::rr::rdata::cert::Algorithm::RSASHA256,
                        (*b"foobar").into(),
                    ),
                )]
                .into_iter()
                .map(|rdata| (cert.clone(), expected::rr::THIRTY_MIN, rdata)),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_cname() -> Result<(), Box<ShellError>> {
    // querying a cname specifically only returns the cname record
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type cname '{}'", *expected::name::CALDAV),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(code, expected::rr::CNAME_CALDAV.clone());
            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);
        },
    )?;

    // [NOTE] there's a very weird behavior from the hickory nameserver here. At the
    // time of writing, it appears that in the case of a single-layer CNAME, the
    // hickory resolver will simply return the answer as is: with the CNAME in
    // the answers section and the corresponding A records for that CNAME in the
    // additionals
    //
    // However, in the case where a CNAME points to another CNAME, it appears
    // that the hickory resolver will choose to recursively do an additional
    // query for the CNAMEs in the responses, seemingly ignoring that the
    // answers are in the first response's additionals section. It puts all
    // CNAME and A records into the answers section, with nothing in the
    // additionals.
    //
    // Furthermore, this list of answers contians a duplicate record for the
    // first CNAME.
    //
    // By all appearances, this seems like a bug in hickory's server; but,
    // the use of the hickory server is purely for convenience in these
    // tests, so it doesn't actually matter too much what records go
    // in which section of the response message.
    //
    // Considering this, to validate, we can just combine all records from
    // the answers and additionals sections, deduplicate, and compare to the
    // expected output records.

    // querying for A on a CNAME returns the CNAME and A records
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type a '{}'", *expected::name::CALDAV),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(code, expected::rr::CNAME_CALDAV.clone());
            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);

            // apparently the A records get put into ADDITIONAL
            let expected = record_values(code, expected::rr::A.clone());
            let actual = message
                .get(constants::columns::message::ADDITIONAL)
                .unwrap();

            assert_eq!(&expected, actual);
        },
    )?;

    // CNAME chain
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type a '{}'", *expected::name::CAL),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(code, expected::rr::CNAME_CAL.clone());
            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(&expected, actual);

            let expected = record_values(
                code,
                expected::rr::CNAME_CALDAV
                    .clone()
                    .into_iter()
                    .chain(expected::rr::A.clone()),
            );

            let actual = message
                .get(constants::columns::message::ADDITIONAL)
                .unwrap();

            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_csync() -> Result<(), Box<ShellError>> {
    let csync = expected::name::ORIGIN.prepend_label("csync").unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type csync '{}'", csync),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            // these are encoded in a bitmap, and therefore effectively sorted
            // by type code
            let mut types = vec![RecordType::A, RecordType::AAAA, RecordType::NS];
            types.sort();

            let expected = record_values(
                code,
                [(
                    csync.clone(),
                    expected::rr::THIRTY_MIN,
                    hickory_proto::rr::RData::CSYNC(hickory_proto::rr::rdata::CSYNC::new(
                        42, true, true, types,
                    )),
                )],
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_hinfo() -> Result<(), Box<ShellError>> {
    let hinfo = expected::name::ORIGIN.prepend_label("hinfo").unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type hinfo '{}'", hinfo),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [(
                    hinfo.clone(),
                    expected::rr::THIRTY_MIN,
                    hickory_proto::rr::RData::HINFO(hickory_proto::rr::rdata::HINFO::new(
                        "foo".into(),
                        "bar".into(),
                    )),
                )],
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
#[ignore = "hickory missing support for dname in zone file parsing"]
pub(crate) fn rr_dname() -> Result<(), Box<ShellError>> {
    Ok(())
}

#[test]
pub(crate) fn rr_mx() -> Result<(), Box<ShellError>> {
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type mx '{}'", *expected::name::ORIGIN),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [
                    hickory_proto::rr::rdata::MX::new(
                        10,
                        expected::name::ORIGIN
                            .clone()
                            .prepend_label("mail1")
                            .unwrap(),
                    ),
                    hickory_proto::rr::rdata::MX::new(
                        20,
                        expected::name::ORIGIN
                            .clone()
                            .prepend_label("mail2")
                            .unwrap(),
                    ),
                ]
                .into_iter()
                .map(|mx| {
                    (
                        expected::name::ORIGIN.clone(),
                        expected::rr::THIRTY_MIN,
                        hickory_proto::rr::RData::MX(mx),
                    )
                }),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_naptr() -> Result<(), Box<ShellError>> {
    let naptr = expected::name::ORIGIN.prepend_label("naptr").unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type naptr '{}'", naptr),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [hickory_proto::rr::RData::NAPTR(
                    hickory_proto::rr::rdata::NAPTR::new(
                        100,
                        10,
                        (*b"u").into(),
                        (*b"E2U+pstn:tel").into(),
                        (*br"!^(.*)$!tel:\1!").into(),
                        Name::from_str(".").unwrap(),
                    ),
                )]
                .into_iter()
                .map(|rdata| (naptr.clone(), expected::rr::THIRTY_MIN, rdata)),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_ptr() -> Result<(), Box<ShellError>> {
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type ptr '{}'", *expected::name::ORIGIN),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [expected::name::ORIGIN.clone().prepend_label("ptr").unwrap()]
                    .into_iter()
                    .map(|ptr_rr| {
                        (
                            expected::name::ORIGIN.clone(),
                            expected::rr::THIRTY_MIN,
                            hickory_proto::rr::RData::PTR(hickory_proto::rr::rdata::PTR(ptr_rr)),
                        )
                    }),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_soa() -> Result<(), Box<ShellError>> {
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type soa '{}'", *expected::name::ORIGIN),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(code, [expected::rr::SOA.clone()]);
            let actual = message.get(constants::columns::message::ANSWER).unwrap();
            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_srv() -> Result<(), Box<ShellError>> {
    let srv = expected::name::ORIGIN
        .prepend_label("_tcp")
        .unwrap()
        .prepend_label("_caldav")
        .unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type srv '{}'", srv),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [hickory_proto::rr::RData::SRV(
                    hickory_proto::rr::rdata::SRV::new(1, 5, 8080, expected::name::CALDAV.clone()),
                )]
                .into_iter()
                .map(|srv_rr| (srv.clone(), expected::rr::THIRTY_MIN, srv_rr)),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(&expected, actual);

            // let expected = record_values(code, expected_cname.clone().chain(expected::rr::A.clone()));
            let expected = record_values(
                code,
                expected::rr::CNAME_CALDAV
                    .clone()
                    .into_iter()
                    .chain(expected::rr::A.clone())
                    .chain(expected::rr::AAAA.clone()),
            );

            let actual = message
                .get(constants::columns::message::ADDITIONAL)
                .unwrap();

            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_txt() -> Result<(), Box<ShellError>> {
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type txt '{}'", *expected::name::ORIGIN),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [hickory_proto::rr::RData::TXT(
                    hickory_proto::rr::rdata::TXT::new(vec![
                        "v=spf1 include:spf.nushell.sh. ?all".into(),
                    ]),
                )]
                .into_iter()
                .map(|txt| {
                    (
                        expected::name::ORIGIN.clone(),
                        expected::rr::THIRTY_MIN,
                        txt,
                    )
                }),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

/// A zone with a name exists, but not with the record type in the request. An
/// empty answer is returned.
#[test]
pub(crate) fn empty() -> Result<(), Box<ShellError>> {
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type hinfo '{}'", *expected::name::ORIGIN),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected_soa = record_values(code, [expected::rr::SOA.clone()]);

            let expected_answer = Value::list(Vec::new(), Span::unknown());
            let actual_answer = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(&expected_answer, actual_answer);

            // empty rrset has the soa included
            let actual_authority = message.get(constants::columns::message::AUTHORITY).unwrap();
            assert_eq!(&expected_soa, actual_authority);
        },
    )?;

    Ok(())
}
