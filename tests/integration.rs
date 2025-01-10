use std::{
    net::{Ipv4Addr, SocketAddrV6},
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, LazyLock},
};

use hickory_resolver::{IntoName, Name};
use hickory_server::{
    authority::{Catalog, ZoneType},
    store::file::{FileAuthority, FileConfig},
    ServerFuture,
};
use nu_plugin_dns::{
    dns::{self, constants},
    Dns,
};
use nu_plugin_test_support::PluginTest;
use nu_protocol::{record, IntoValue, PipelineData, ShellError, Span, TryIntoValue, Value};
use tokio::net::UdpSocket;

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

static HARNESS: LazyLock<TestHarness> = LazyLock::new(|| TestHarness::new().unwrap());

struct TestHarness {
    runtime: tokio::runtime::Runtime,
    _server: ServerFuture<Catalog>,
}

impl TestHarness {
    const TEST_RESOLVER_SOCKET_ADDR: &str = "[::1]:8053";
    const ZONE_FILE_EXT: &str = ".zone";

    pub fn new() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let _server = Self::init_hickory_server(&runtime);

        Ok(Self { runtime, _server })
    }

    async fn collect_zones() -> Catalog {
        let root_dir = PathBuf::from_str(CARGO_MANIFEST_DIR)
            .unwrap()
            .join("tests/fixtures/zones");

        let mut catalog = Catalog::new();
        let mut entries = tokio::fs::read_dir(&root_dir).await.unwrap();

        while let Some(entry) = entries.next_entry().await.unwrap() {
            if !entry.metadata().await.unwrap().is_file() {
                continue;
            }

            let file_name = entry.file_name().into_string().unwrap();

            if !file_name.ends_with(Self::ZONE_FILE_EXT) {
                continue;
            }

            let origin = &file_name[..(file_name.len() - Self::ZONE_FILE_EXT.len())]
                .into_name()
                .unwrap();

            let file_config = FileConfig {
                zone_file_path: file_name,
            };

            let authority = FileAuthority::try_from_config(
                origin.clone(),
                ZoneType::Primary,
                false,
                Some(&root_dir),
                &file_config,
                None,
            )
            .unwrap();

            catalog.upsert(origin.into(), vec![Arc::new(authority)]);
        }

        catalog
    }

    fn test_plugin_config(test_config: Option<nu_protocol::Record>) -> nu_protocol::Record {
        let mut config = record!(
            constants::flags::SERVER => Value::test_string(Self::TEST_RESOLVER_SOCKET_ADDR),
            constants::flags::CODE => true.into_value(Span::unknown()),
            constants::flags::DNSSEC => "none".into_value(Span::unknown()),
        );

        if let Some(test_config) = test_config {
            test_config.into_iter().for_each(|(key, val)| {
                config.insert(key, val);
            });
        }

        config
    }

    fn init_hickory_server(runtime: &tokio::runtime::Runtime) -> ServerFuture<Catalog> {
        runtime.block_on(async {
            let socket = UdpSocket::bind(
                Self::TEST_RESOLVER_SOCKET_ADDR
                    .parse::<SocketAddrV6>()
                    .unwrap(),
            )
            .await;

            let catalog = Self::collect_zones().await;
            let mut server = ServerFuture::new(catalog);
            server.register_socket(socket.unwrap());
            server
        })
    }

    fn plugin_test(
        &self,
        test_config: Option<nu_protocol::Record>,
        cmd: impl AsRef<str>,
        input: Option<PipelineData>,
        expected_resp_code: HickoryResponseCode,
        validate: impl Fn(bool, &nu_protocol::Record),
    ) -> Result<PluginTest, ShellError> {
        let mut test = PluginTest::new(Dns::PLUGIN_NAME, nu_plugin_dns::Dns::new().into()).unwrap();
        let state = test.engine_state_mut();
        let mut config = state.get_config().deref().clone();
        let plugin_config = Value::test_record(Self::test_plugin_config(test_config));

        config
            .plugins
            .insert(Dns::PLUGIN_NAME.into(), plugin_config);

        state.set_config(Arc::new(config));

        let code = test
            .engine_state()
            .get_plugin_config(Dns::PLUGIN_NAME)
            .unwrap()
            .get_data_by_key(constants::flags::CODE)
            .unwrap()
            .as_bool()
            .unwrap();

        let input = input.unwrap_or(PipelineData::Empty);
        let actual = self.runtime.block_on(async {
            test.eval_with(cmd.as_ref(), input)?
                .into_value(Span::test_data())
        })?;

        let mut values = actual.into_list().unwrap();
        assert_eq!(1, values.len());

        let message = values.pop().unwrap().into_record().unwrap();
        assert_message_response(&message, expected_resp_code)?;

        validate(code, &message);

        Ok(test)
    }
}

type HickoryResponseCode = hickory_proto::op::ResponseCode;

fn assert_message_response(
    message: &nu_protocol::Record,
    expected_resp_code: HickoryResponseCode,
) -> Result<(), ShellError> {
    let header = message
        .get(constants::columns::message::HEADER)
        .unwrap()
        .as_record()?;

    let resp_code = header
        .get(constants::columns::message::header::RESPONSE_CODE)
        .unwrap()
        .as_record()?
        .get(constants::flags::CODE)
        .unwrap()
        .as_int()?;

    assert_eq!(expected_resp_code.low() as i64, resp_code);

    Ok(())
}

fn record_values<I, R, N>(code: bool, iter: I) -> Value
where
    N: IntoName,
    I: IntoIterator<Item = (N, chrono::Duration, R)>,
    R: Into<hickory_proto::rr::RData>,
{
    iter.into_iter()
        .map(|(name, ttl, rdata)| {
            dns::serde::Record(hickory_proto::rr::Record::from_rdata(
                name.into_name().unwrap(),
                ttl.num_seconds() as u32,
                rdata.into(),
            ))
            .into_value(code)
            .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into_value(Span::unknown())
        .unwrap()
}

// fn test_dns_query()

#[test]
fn a() -> Result<(), ShellError> {
    const TTL: chrono::TimeDelta = chrono::TimeDelta::minutes(30);
    let name: Name = "nushell.sh.".parse().unwrap();

    HARNESS.plugin_test(
        None,
        format!("dns query --type a '{name}'"),
        None,
        HickoryResponseCode::NoError,
        |code, message| {
            let expected = record_values(
                code,
                [
                    "185.199.108.153",
                    "185.199.109.153",
                    "185.199.110.153",
                    "185.199.111.153",
                ]
                .into_iter()
                .map(|ip| Ipv4Addr::from_str(ip).unwrap())
                .map(|ip| (name.clone(), TTL, ip)),
            );

            let actual = message.get(constants::columns::message::ANSWER).unwrap();

            assert_eq!(&expected, actual);
        },
    )?;

    Ok(())
}
