use std::str::FromStr;

use hickory_resolver::Name;
use nu_plugin_dns::dns::constants;
use nu_protocol::{ShellError, Span, Value};

use super::{record_values, HickoryResponseCode, TestCase, HARNESS};

mod expected;

#[test]
pub(crate) fn rr_a() -> Result<(), ShellError> {
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
pub(crate) fn rr_aaaa() -> Result<(), ShellError> {
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
pub(crate) fn rr_cert() -> Result<(), ShellError> {
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
pub(crate) fn rr_cname() -> Result<(), ShellError> {
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
#[ignore = "hickory missing support for dname in zone file parsing"]
pub(crate) fn rr_dname() -> Result<(), ShellError> {
    Ok(())
}

#[test]
pub(crate) fn rr_mx() -> Result<(), ShellError> {
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
pub(crate) fn rr_naptr() -> Result<(), ShellError> {
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
pub(crate) fn rr_ptr() -> Result<(), ShellError> {
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
pub(crate) fn rr_soa() -> Result<(), ShellError> {
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
pub(crate) fn rr_srv() -> Result<(), ShellError> {
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
pub(crate) fn rr_txt() -> Result<(), ShellError> {
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
                        "v=spf1 include:spf.nushell.sh. ?all".into()
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
pub(crate) fn empty() -> Result<(), ShellError> {
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
