use std::{net::Ipv6Addr, str::FromStr};

use hickory_resolver::Name;
use nu_plugin_dns::dns::constants;
use nu_protocol::{ShellError, Span, Value};

use super::{record_values, HickoryResponseCode, TestCase, HARNESS};

#[test]
pub(crate) fn rr_aaaa() -> Result<(), ShellError> {
    const TTL: chrono::TimeDelta = chrono::TimeDelta::minutes(30);
    let name: Name = "nushell.sh.".parse().unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type aaaa '{name}'"),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                ["2606:50c0:8000::153"]
                    .into_iter()
                    .map(|ip| Ipv6Addr::from_str(ip).unwrap())
                    .map(|ip| (name.clone(), TTL, ip)),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}

#[test]
pub(crate) fn rr_soa() -> Result<(), ShellError> {
    const TTL: chrono::TimeDelta = chrono::TimeDelta::minutes(30);
    let name: Name = "nushell.sh.".parse().unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type soa '{name}'"),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [(
                    name.clone(),
                    TTL,
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
                )],
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
    const TTL: chrono::TimeDelta = chrono::TimeDelta::minutes(30);
    let name: Name = "nushell.sh.".parse().unwrap();

    HARNESS.plugin_test(
        TestCase {
            config: None,
            input: None,
            cmd: &format!("dns query --type cname '{name}'"),
        },
        HickoryResponseCode::NoError,
        |code, message| {
            let expected_soa = record_values(
                code,
                [(
                    name.clone(),
                    TTL,
                    hickory_proto::rr::RData::SOA(hickory_proto::rr::rdata::SOA::new(
                        "dns1.registrar-servers.com.".parse().unwrap(),
                        "hostmaster.registrar-servers.com.".parse().unwrap(),
                        1677639553,
                        43200,
                        1800,
                        1800,
                        1800,
                    )),
                )],
            );

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
