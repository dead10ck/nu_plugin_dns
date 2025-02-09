pub mod name {
    use std::sync::LazyLock;

    use hickory_resolver::Name;

    pub static ORIGIN: LazyLock<Name> = LazyLock::new(|| "nushell.sh.".parse().unwrap());
    pub static CALDAV: LazyLock<Name> = LazyLock::new(|| {
        let mut cname = ORIGIN.prepend_label("caldav").unwrap();
        cname.set_fqdn(true);
        cname
    });
    pub static CAL: LazyLock<Name> = LazyLock::new(|| {
        let mut cname = ORIGIN.prepend_label("cal").unwrap();
        cname.set_fqdn(true);
        cname
    });
}

pub mod rr {
    use hickory_resolver::Name;

    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::LazyLock;

    pub const THIRTY_MIN: chrono::TimeDelta = chrono::TimeDelta::minutes(30);

    pub(crate) static SOA: LazyLock<(Name, chrono::TimeDelta, hickory_proto::rr::RData)> =
        LazyLock::new(|| {
            (
                super::name::ORIGIN.clone(),
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

    pub(crate) static A: LazyLock<Vec<(Name, chrono::TimeDelta, hickory_proto::rr::RData)>> =
        LazyLock::new(|| {
            [
                "185.199.108.153",
                "185.199.109.153",
                "185.199.110.153",
                "185.199.111.153",
            ]
            .into_iter()
            .map(|ip| hickory_proto::rr::RData::from(Ipv4Addr::from_str(ip).unwrap()))
            .map(|ip| (super::name::ORIGIN.clone(), THIRTY_MIN, ip))
            .collect()
        });

    pub(crate) static AAAA: LazyLock<Vec<(Name, chrono::TimeDelta, hickory_proto::rr::RData)>> =
        LazyLock::new(|| {
            ["2606:50c0:8000::153"]
                .into_iter()
                .map(|ip| hickory_proto::rr::RData::from(Ipv6Addr::from_str(ip).unwrap()))
                .map(|ip| (super::name::ORIGIN.clone(), THIRTY_MIN, ip))
                .collect()
        });

    pub(crate) static CNAME_CALDAV: LazyLock<
        Vec<(Name, chrono::TimeDelta, hickory_proto::rr::RData)>,
    > = LazyLock::new(|| {
        [super::name::CALDAV.clone()]
            .into_iter()
            .map(|name| {
                (
                    name,
                    super::rr::THIRTY_MIN,
                    hickory_proto::rr::RData::CNAME(hickory_proto::rr::rdata::CNAME(
                        super::name::ORIGIN.clone(),
                    )),
                )
            })
            .collect()
    });

    pub(crate) static CNAME_CAL: LazyLock<
        Vec<(Name, chrono::TimeDelta, hickory_proto::rr::RData)>,
    > = LazyLock::new(|| {
        [super::name::CAL.clone()]
            .into_iter()
            .map(|name| {
                (
                    name,
                    super::rr::THIRTY_MIN,
                    hickory_proto::rr::RData::CNAME(hickory_proto::rr::rdata::CNAME(
                        super::name::CALDAV.clone(),
                    )),
                )
            })
            .collect()
    });
}
