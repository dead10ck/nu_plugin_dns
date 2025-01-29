use std::{net::Ipv6Addr, str::FromStr, sync::LazyLock};

use hickory_resolver::Name;
use nu_plugin_dns::dns::constants;
use nu_protocol::{ShellError, Span, Value};

use super::{record_values, HickoryResponseCode, TestCase, HARNESS};

const THIRTY_MIN: chrono::TimeDelta = chrono::TimeDelta::minutes(30);

static NAME: LazyLock<Name> = LazyLock::new(|| "nushell.sh.".parse().unwrap());

static EXPECTED_SOA: LazyLock<(Name, chrono::TimeDelta, hickory_proto::rr::RData)> =
    LazyLock::new(|| {
        (
            NAME.clone(),
            THIRTY_MIN,
            hickory_proto::rr::RData::SOA(hickory_proto::rr::rdata::SOA::new(
                "dns1.registrar-servers.com.".parse().unwrap(),
                "hostmaster.registrar-servers.com.".parse().unwrap(),
                1677639553,
                43200,
                1800,
                // [FIXME] so there is actually a bug in hickory-server
                // that parses the zone file such that it uses the
                // `expire` field of the SOA record as the TTL of the
                // record itself. Change this to something else in the
                // future once this is fixed upstream
                1800,
                1800,
            )),
        )
    });

#[test]
pub(crate) fn rr_aaaa() -> Result<(), ShellError> {
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type aaaa '{}'", *NAME),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                ["2606:50c0:8000::153"]
                    .into_iter()
                    .map(|ip| Ipv6Addr::from_str(ip).unwrap())
                    .map(|ip| (NAME.clone(), THIRTY_MIN, ip)),
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
            cmd: &format!("dns query --type soa '{}'", *NAME),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(code, [EXPECTED_SOA.clone()]);
            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(
                &expected, actual,
                "expected:\n{:#?}\n\nactual: {:#?}",
                expected, actual,
            );
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
            cmd: &format!("dns query --type ptr '{}'", *NAME),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [NAME.clone().prepend_label("ptr").unwrap()]
                    .into_iter()
                    .map(|mut ptr_rr| {
                        ptr_rr.set_fqdn(true);

                        (
                            NAME.clone(),
                            THIRTY_MIN,
                            hickory_proto::rr::RData::PTR(hickory_proto::rr::rdata::PTR(ptr_rr)),
                        )
                    }),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(
                &expected, actual,
                "expected:\n{:#?}\n\nactual: {:#?}",
                expected, actual,
            );
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_mx() -> Result<(), ShellError> {
    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type mx '{}'", *NAME),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [
                    hickory_proto::rr::rdata::MX::new(10, {
                        let mut name = NAME.clone().prepend_label("mail1").unwrap();
                        name.set_fqdn(true);
                        name
                    }),
                    hickory_proto::rr::rdata::MX::new(20, {
                        let mut name = NAME.clone().prepend_label("mail2").unwrap();
                        name.set_fqdn(true);
                        name
                    }),
                ]
                .into_iter()
                .map(|mx| (NAME.clone(), THIRTY_MIN, hickory_proto::rr::RData::MX(mx))),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(
                &expected, actual,
                "expected:\n{:#?}\n\nactual: {:#?}",
                expected, actual,
            );
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
            cmd: &format!("dns query --type txt '{}'", *NAME),
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
                .map(|txt| (NAME.clone(), THIRTY_MIN, txt)),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(
                &expected, actual,
                "expected:\n{:#?}\n\nactual: {:#?}",
                expected, actual,
            );
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
            cmd: &format!("dns query --type hinfo '{}'", *NAME),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected_soa = record_values(code, [EXPECTED_SOA.clone()]);

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
