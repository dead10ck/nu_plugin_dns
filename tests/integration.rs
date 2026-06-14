use std::{
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, LazyLock},
};

use hickory_proto::rr::IntoName;
use hickory_server::{
    Server,
    store::file::{FileConfig, FileZoneHandler},
    zone_handler::{AxfrPolicy, Catalog, ZoneType},
};
use nu_plugin_dns::{
    Dns,
    dns::{
        self,
        config::get_param_name,
        constants::{self, columns},
    },
};
use nu_plugin_test_support::PluginTest;
use nu_protocol::{
    IntoPipelineData, IntoValue, OneOf, PipelineData, ShellError, Span, TryIntoValue, Type, Value,
    record,
};
use tokio::net::UdpSocket;
use tracing::{Instrument, info_span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod query;

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

static HARNESS: LazyLock<TestHarness> = LazyLock::new(|| TestHarness::new().unwrap());

struct TestHarness {
    _runtime: tokio::runtime::Runtime,
    _server: Server<Catalog>,
}

impl TestHarness {
    const TEST_RESOLVER_IP: &str = "::1";
    const TEST_RESOLVER_PORT: i64 = 8053;
    const ZONE_FILE_EXT: &str = ".zone";

    pub fn new() -> std::io::Result<Self> {
        let _ = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_span_events(tracing_subscriber::fmt::format::FmtSpan::ACTIVE)
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .json(),
            )
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let _server = Self::init_hickory_server(&runtime);

        Ok(Self {
            _runtime: runtime,
            _server,
        })
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
                zone_path: entry.path(),
            };

            let authority = FileZoneHandler::try_from_config(
                origin.clone(),
                ZoneType::Primary,
                AxfrPolicy::Deny,
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
            get_param_name(&constants::params::CONFIG) => Value::test_record(record!(
                "name_servers" => Value::test_list(vec![
                    Value::test_record(record!(
                        "ip" => Value::test_string(Self::TEST_RESOLVER_IP),
                        "connections" => Value::test_list(vec![
                            Value::test_record(record!(
                                "port" => Value::test_int(Self::TEST_RESOLVER_PORT),
                                "protocol" => Value::test_record(record!(
                                    "type" => Value::test_string("udp"),
                                )),
                            ))
                        ])
                    ))
                ]),
                "validation" => Value::test_bool(false),
            )),
            get_param_name(&constants::params::CODE) => true.into_value(Span::unknown()),
        );

        if let Some(test_config) = test_config {
            test_config.into_iter().for_each(|(key, val)| {
                config.insert(key, val);
            });
        }

        config
    }

    fn init_hickory_server(runtime: &tokio::runtime::Runtime) -> Server<Catalog> {
        runtime.block_on(
            async {
                let socket =
                    UdpSocket::bind((Self::TEST_RESOLVER_IP, Self::TEST_RESOLVER_PORT as u16))
                        .await;

                let catalog = Self::collect_zones().await;
                let mut server = Server::new(catalog);
                server.register_socket(socket.unwrap());
                server
            }
            .instrument(info_span!("server")),
        )
    }

    #[tracing::instrument(skip(self, validate), fields(test_case = %format!("{:#?}", test_case)))]
    fn plugin_test(
        &self,
        test_case: TestCase,
        expected_resp_code: HickoryResponseCode,
        validate: impl Fn(bool, &nu_protocol::Record),
    ) -> Result<PluginTest, Box<ShellError>> {
        let mut test = PluginTest::new(Dns::PLUGIN_NAME, nu_plugin_dns::Dns::new().into())?;

        let state = test.engine_state_mut();
        let mut config = state.get_config().deref().clone();
        let plugin_config = Value::test_record(Self::test_plugin_config(test_case.config));

        config
            .plugins
            .insert(Dns::PLUGIN_NAME.into(), plugin_config);

        state.set_config(Arc::new(config));

        // add the table command for debugging
        test.add_decl(Box::new(nu_command::Table))?;
        test.add_decl(Box::new(nu_command::Cd))?;

        let code = test
            .engine_state()
            .get_plugin_config(Dns::PLUGIN_NAME)
            .map(|val| {
                val.get_data_by_key(get_param_name(&constants::params::CODE))
                    .map(|val| val.as_bool().map_err(Box::new))
                    .unwrap_or(Ok(false))
            })
            .unwrap_or(Ok(false))?;

        let input = test_case.input.unwrap_or(PipelineData::Empty);

        let actual = test
            .eval_with(test_case.cmd.as_ref(), input)?
            .into_value(Span::test_data())?;

        if tracing::enabled!(tracing::Level::DEBUG) {
            let table = test
                .eval_with(
                    // this cd business is necessary because apparently the
                    // nushell engine for these tests do not set $env.PWD, so
                    // calling cd first sets it
                    "let msg = $in; cd .; $msg | table -ew 1000000000",
                    actual.clone().into_pipeline_data(),
                )?
                .into_value(Span::test_data())?
                .into_string()?;

            tracing::debug!(response = %format!("\n{table}"));
        }

        let mut values = actual.into_list()?;
        assert_eq!(1, values.len());

        let message = values
            .pop()
            .expect("dns response had no value")
            .into_record()?;

        assert_message_response(&message, expected_resp_code)?;

        validate(code, &message);

        Ok(test)
    }
}

#[derive(Debug)]
pub struct TestCase<'c> {
    pub config: Option<nu_protocol::Record>,
    pub input: Option<PipelineData>,
    pub cmd: &'c str,
}

type HickoryResponseCode = hickory_proto::op::ResponseCode;

fn assert_message_response(
    message: &nu_protocol::Record,
    expected_resp_code: HickoryResponseCode,
) -> Result<(), Box<ShellError>> {
    let header = message
        .get(constants::columns::message::HEADER)
        .expect("dns response missing header")
        .as_record()?;

    let resp_code = header
        .get(constants::columns::message::header::RESPONSE_CODE)
        .expect("dns response missing response code");

    let expected_resp_code_name = Value::test_string(expected_resp_code.to_str());

    match resp_code {
        Value::Record { val, .. } => {
            let expected_resp_code_num = Value::test_int(expected_resp_code.low() as i64);
            let expected_resp_code_val = record!(
                columns::rr::NAME => expected_resp_code_name,
                columns::rr::code::CODE => expected_resp_code_num,
            );

            assert_eq!(&expected_resp_code_val, val.as_ref());
        }
        val @ Value::String { .. } => {
            assert_eq!(&expected_resp_code_name, val);
        }
        val => {
            return Err(ShellError::RuntimeTypeMismatch {
                expected: Type::OneOf(OneOf::from_iter([Type::record(), Type::String])),
                actual: val.get_type(),
                span: Span::unknown(),
            }
            .into());
        }
    }

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
            dns::serde::Record(&hickory_proto::rr::Record::from_rdata(
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
