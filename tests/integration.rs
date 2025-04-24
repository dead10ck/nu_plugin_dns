use std::{
    net::SocketAddrV6,
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, LazyLock},
};

use hickory_resolver::IntoName;
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
use nu_protocol::{
    record, IntoPipelineData, IntoValue, PipelineData, ShellError, Span, TryIntoValue, Value,
};
use tokio::net::UdpSocket;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod query;

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

            let origin = &file_name[..(file_name.len() - Self::ZONE_FILE_EXT.len() + 1)]
                .into_name()
                .unwrap();

            tracing::debug!(?origin);

            let file_config = FileConfig {
                zone_file_path: entry.path(),
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
        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

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
        test_case: TestCase,
        expected_resp_code: HickoryResponseCode,
        validate: impl Fn(bool, &nu_protocol::Record),
    ) -> Result<PluginTest, ShellError> {
        let mut test = PluginTest::new(Dns::PLUGIN_NAME, nu_plugin_dns::Dns::new().into()).unwrap();

        let state = test.engine_state_mut();
        let mut config = state.get_config().deref().clone();
        let plugin_config = Value::test_record(Self::test_plugin_config(test_case.config));

        config
            .plugins
            .insert(Dns::PLUGIN_NAME.into(), plugin_config);

        state.set_config(Arc::new(config));

        // add the table command for debugging
        test.add_decl(Box::new(nu_command::Table)).unwrap();
        test.add_decl(Box::new(nu_command::Cd)).unwrap();

        let code = test
            .engine_state()
            .get_plugin_config(Dns::PLUGIN_NAME)
            .unwrap()
            .get_data_by_key(constants::flags::CODE)
            .unwrap()
            .as_bool()
            .unwrap();

        let input = test_case.input.unwrap_or(PipelineData::Empty);
        let actual = self.runtime.block_on(async {
            test.eval_with(test_case.cmd.as_ref(), input)?
                .into_value(Span::test_data())
        })?;

        let table = self
            .runtime
            .block_on(async {
                test.eval_with(
                    // this cd business is necessary because apparently the
                    // nushell engine for these tests do not set $env.PWD, so
                    // calling cd first sets it
                    "let msg = $in; cd .; $msg | table -ew 1000000000",
                    actual.clone().into_pipeline_data(),
                )?
                .into_value(Span::test_data())
            })?
            .into_string()
            .unwrap();

        tracing::debug!("\n{table}");

        let mut values = actual.into_list().unwrap();
        assert_eq!(1, values.len());

        let message = values.pop().unwrap().into_record().unwrap();
        assert_message_response(&message, expected_resp_code)?;

        validate(code, &message);

        Ok(test)
    }
}

pub struct TestCase<'c> {
    pub config: Option<nu_protocol::Record>,
    pub input: Option<PipelineData>,
    pub cmd: &'c str,
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
