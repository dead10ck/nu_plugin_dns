use std::{
    net::SocketAddrV6,
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, LazyLock},
};

use hickory_proto::rr::{DNSClass, RecordType};
use hickory_resolver::IntoName;
use hickory_server::{
    authority::{Catalog, ZoneType},
    store::file::{FileAuthority, FileConfig},
    ServerFuture,
};
use nu_plugin_test_support::PluginTest;
use nu_protocol::{record, IntoValue, ShellError, Span, Value};
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
            "server" => Value::test_string(Self::TEST_RESOLVER_SOCKET_ADDR),
            "code" => true.into_value(Span::unknown()),
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

    fn plugin_test(test_config: Option<nu_protocol::Record>) -> PluginTest {
        let mut test = PluginTest::new("dns", nu_plugin_dns::Dns::new().into()).unwrap();
        let state = test.engine_state_mut();
        let mut config = state.get_config().deref().clone();
        let plugin_config = Value::test_record(Self::test_plugin_config(test_config));

        config.plugins.insert("dns".into(), plugin_config);
        state.set_config(Arc::new(config));

        test
    }
}

fn assert_message_success(message: &nu_protocol::Record) -> Result<(), ShellError> {
    let header = message.get("header").unwrap().as_record().unwrap();

    let resp_code = header
        .get("response_code")
        .unwrap()
        .as_record()?
        .get("code")
        .unwrap()
        .as_int()?;

    assert_eq!(0, resp_code);
    Ok(())
}

#[test]
fn a() -> Result<(), ShellError> {
    let actual = HARNESS.runtime.block_on(async {
        TestHarness::plugin_test(Some(
            record!("dnssec" => "none".into_value(Span::unknown())),
        ))
        .eval("dns query --type a 'nushell.sh.'")?
        .into_value(Span::test_data())
    })?;

    let mut values = actual.into_list().unwrap();
    assert_eq!(1, values.len());

    let message = values.pop().unwrap().into_record().unwrap();
    assert_message_success(&message)?;

    let rec_base = record!(
        "name" => Value::test_string(String::from("nushell.sh.")),
        "type" => Value::test_record(record!(
            "name" => Value::test_string(String::from("A")),
            "code" => Value::test_int(Into::<u16>::into(RecordType::A) as i64),
        )),
        "class" => Value::test_record(record!(
            "name" => Value::test_string(String::from("IN")),
            "code" => Value::test_int(Into::<u16>::into(DNSClass::IN) as i64),
        )),
        "ttl" => Value::test_duration(chrono::TimeDelta::minutes(30).num_nanoseconds().unwrap()),
        "proof" => Value::test_string(String::from("indeterminate")),
    );

    let expected_records = Value::test_list(
        [
            "185.199.108.153",
            "185.199.109.153",
            "185.199.110.153",
            "185.199.111.153",
        ]
        .into_iter()
        .map(|ip| {
            let mut rec = rec_base.clone();
            rec.insert("rdata", Value::test_string(ip));
            Value::test_record(rec)
        })
        .collect::<Vec<_>>(),
    );

    let actual = message.get("answer").unwrap();

    assert_eq!(&expected_records, actual);

    Ok(())
}
