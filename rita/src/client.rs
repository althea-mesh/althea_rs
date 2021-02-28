//! This is the main source file for the Rita client binary, by 'client' we mean 'not an exit server'
//! all meshing and billing functionaltiy is contained in `rita_common` and is common to both rita and
//! `rita_exit`. The major difference is billing and connection code for the 'exit', the mandatory
//! vpn system integrated into the Althea network design, as well as API endpoints for a management
//! dashboard of router functions like wifi, which the exit is not expected to have.
//!
//! This file initilizes the dashboard endpoints for the client as well as the common and client
//! specific actors.

#![warn(clippy::all)]
#![allow(clippy::pedantic)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
#[macro_use]
extern crate serde_json;
#[cfg(test)]
#[macro_use]
extern crate hex_literal;
extern crate arrayvec;

use actix_web::http::Method;
use actix_web::{http, server, App};
use althea_types::SystemChain;
use docopt::Docopt;
use env_logger;
use openssl_probe;
use settings::client::{RitaClientSettings, RitaSettingsStruct};
use settings::payment::XDAI_FEE_MULTIPLIER;
use settings::RitaCommonSettings;
use std::env;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[cfg(not(test))]
use settings::FileWrite;

#[cfg(test)]
use std::sync::Mutex;

mod middleware;
mod rita_client;
mod rita_common;

use crate::rita_client::enable_remote_logging;
use crate::rita_client::rita_loop::check_rita_client_actors;
use crate::rita_client::rita_loop::start_rita_client_endpoints;
use crate::rita_common::rita_loop::check_rita_common_actors;
use crate::rita_common::rita_loop::start_core_rita_endpoints;

use crate::rita_client::dashboard::backup_created::*;
use crate::rita_client::dashboard::eth_private_key::*;
use crate::rita_client::dashboard::exits::*;
use crate::rita_client::dashboard::interfaces::*;
use crate::rita_client::dashboard::localization::*;
use crate::rita_client::dashboard::logging::*;
use crate::rita_client::dashboard::mesh_ip::*;
use crate::rita_client::dashboard::neighbors::*;
use crate::rita_client::dashboard::notifications::*;
use crate::rita_client::dashboard::prices::*;
use crate::rita_client::dashboard::release_feed::*;
use crate::rita_client::dashboard::remote_access::*;
use crate::rita_client::dashboard::router::*;
use crate::rita_client::dashboard::system_chain::*;
use crate::rita_client::dashboard::usage::*;
use crate::rita_client::dashboard::wifi::*;
use crate::rita_common::dashboard::auth::*;
use crate::rita_common::dashboard::babel::*;
use crate::rita_common::dashboard::dao::*;
use crate::rita_common::dashboard::debts::*;
use crate::rita_common::dashboard::development::*;
use crate::rita_common::dashboard::nickname::*;
use crate::rita_common::dashboard::own_info::*;
use crate::rita_common::dashboard::settings::*;
use crate::rita_common::dashboard::token_bridge::*;
use crate::rita_common::dashboard::usage::*;
use crate::rita_common::dashboard::wallet::*;
use crate::rita_common::dashboard::wg_key::*;
use crate::rita_common::network_endpoints::*;

#[derive(Debug, Deserialize, Default)]
pub struct Args {
    flag_config: String,
    flag_platform: String,
    flag_future: bool,
}

lazy_static! {
    static ref USAGE: String = format!(
        "Usage: rita --config=<settings> --platform=<platform> [--future]
Options:
    -c, --config=<settings>     Name of config file
    -p, --platform=<platform>   Platform (linux or openwrt)
    --future                    Enable B side of A/B releases
About:
    Version {}
    git hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );
}

use althea_kernel_interface::KernelInterface;

#[cfg(not(test))]
use althea_kernel_interface::LinuxCommandRunner;
#[cfg(test)]
use althea_kernel_interface::TestCommandRunner;

#[cfg(test)]
lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(TestCommandRunner {
        run_command: Arc::new(Mutex::new(Box::new(|_program, _args| {
            panic!("kernel interface used before initialized");
        })))
    });
}

#[cfg(test)]
lazy_static! {
    pub static ref ARGS: Args = Args::default();
}

#[cfg(not(test))]
lazy_static! {
    pub static ref KI: Box<dyn KernelInterface> = Box::new(LinuxCommandRunner {});
}

#[cfg(not(test))]
lazy_static! {
    pub static ref ARGS: Args = Docopt::new((*USAGE).as_str())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
}

#[cfg(not(test))]
lazy_static! {
    pub static ref SETTING: Arc<RwLock<RitaSettingsStruct>> = {
        let settings_file = &ARGS.flag_config;
        let platform = &ARGS.flag_platform;

        let s = RitaSettingsStruct::new_watched(settings_file).unwrap();

        s.set_future(ARGS.flag_future);

        clu::init(platform, s.clone());

        s.read().unwrap().write(settings_file).unwrap();
        s
    };
}

#[cfg(test)]
lazy_static! {
    pub static ref SETTING: Arc<RwLock<RitaSettingsStruct>> =
        Arc::new(RwLock::new(RitaSettingsStruct::default()));
}

fn env_vars_contains(var_name: &str) -> bool {
    for (key, _value) in env::vars_os() {
        if key == var_name {
            return true;
        }
    }
    false
}

/// Some devices (n600/n750) will provide junk file reads during disk init
/// post flashing, this ads in retry for the settings file read for up to
/// two minutes
fn wait_for_settings(settings_file: &str) -> RitaSettingsStruct {
    let start = Instant::now();
    let timeout = Duration::from_secs(120);
    let mut res = RitaSettingsStruct::new(settings_file);
    while (Instant::now() - start) < timeout {
        if let Ok(val) = res {
            return val;
        }
        res = RitaSettingsStruct::new(settings_file);
    }
    match res {
        Ok(val) => val,
        Err(e) => panic!("Settings parse failure {:?}", e),
    }
}

fn main() {
    // Remove in Beta 12 updates payment multiplier for xdai routers
    // scope to ensure the reference is dropped before continuing
    {
        let mut payment = SETTING.get_payment_mut();
        if payment.system_chain == SystemChain::Xdai {
            payment.dynamic_fee_multiplier = XDAI_FEE_MULTIPLIER;
        }
    }

    // On Linux static builds we need to probe ssl certs path to be able to
    // do TLS stuff.
    openssl_probe::init_ssl_cert_env_vars();

    if !SETTING.get_log().enabled || env_vars_contains("NO_REMOTE_LOG") {
        env_logger::init();
    } else {
        let res = enable_remote_logging();
        println!("logging status {:?}", res);
    }

    if cfg!(feature = "development") {
        println!("Warning!");
        println!("This build is meant only for development purposes.");
        println!("Running this on production is unsupported and not safe!");
    }

    // If we are an an OpenWRT device try and rescue it from update issues
    if KI.is_openwrt() && KI.check_cron().is_err() {
        error!("Failed to setup cron!");
    }

    let args: Args = Docopt::new((*USAGE).as_str())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let settings_file = args.flag_config;

    // to get errors before lazy static and make sure the config is ready to
    // be read
    wait_for_settings(&settings_file);

    info!(
        "crate ver {}, git hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );
    trace!("Starting with Identity: {:?}", SETTING.get_identity());

    let system = actix::System::new(format!("main {:?}", SETTING.get_network().mesh_ip));

    check_rita_common_actors();
    check_rita_client_actors();
    start_core_rita_endpoints(2);
    start_rita_client_endpoints(1);
    start_client_dashboard();

    system.run();
    info!("Started Rita Client!");
}

fn start_client_dashboard() {
    // dashboard
    server::new(|| {
        App::new()
            .middleware(middleware::Headers)
            .middleware(middleware::Auth)
            .route("/backup_created", Method::GET, get_backup_created)
            .route("/backup_created/{status}", Method::POST, set_backup_created)
            .route("/dao_list", Method::GET, get_dao_list)
            .route("/dao_list/add/{address}", Method::POST, add_to_dao_list)
            .route(
                "/dao_list/remove/{address}",
                Method::POST,
                remove_from_dao_list,
            )
            .route("/debts", Method::GET, get_debts)
            .route("/debts/reset", Method::POST, reset_debt)
            .route("/exits/sync", Method::POST, exits_sync)
            .route("/exits", Method::GET, get_exit_info)
            .route("/exits", Method::POST, add_exits)
            .route("/exits/{name}/register", Method::POST, register_to_exit)
            .route("/exits/{name}/reset", Method::POST, reset_exit)
            .route("/exits/{name}/select", Method::POST, select_exit)
            .route("/local_fee", Method::GET, get_local_fee)
            .route("/local_fee/{fee}", Method::POST, set_local_fee)
            .route("/dao_fee", Method::GET, get_dao_fee)
            .route("/dao_fee/{fee}", Method::POST, set_dao_fee)
            .route("/metric_factor", Method::GET, get_metric_factor)
            .route("/metric_factor/{factor}", Method::POST, set_metric_factor)
            .route(
                "/exits/{name}/verify/{code}",
                Method::POST,
                verify_on_exit_with_code,
            )
            .route("/info", Method::GET, get_own_info)
            .route("/interfaces", Method::GET, get_interfaces_endpoint)
            .route("/interfaces", Method::POST, set_interfaces_endpoint)
            .route("/interfaces/mesh", Method::GET, wlan_mesh_get)
            .route("/interfaces/lightclient", Method::GET, wlan_lightclient_get)
            .route("/interfaces/mesh/{enabled}", Method::POST, wlan_mesh_set)
            .route(
                "/interfaces/lightclient/{enabled}",
                Method::POST,
                wlan_lightclient_set,
            )
            .route("/eth_private_key", Method::GET, get_eth_private_key)
            .route("/eth_private_key", Method::POST, set_eth_private_key)
            .route("/mesh_ip", Method::GET, get_mesh_ip)
            .route("/mesh_ip", Method::POST, set_mesh_ip)
            .route("/neighbors", Method::GET, get_neighbor_info)
            .route("/routes", Method::GET, get_routes)
            .route("/remote_logging/enabled", Method::GET, get_remote_logging)
            .route(
                "/remote_logging/enabled/{enabled}",
                Method::POST,
                remote_logging,
            )
            .route(
                "/remote_logging/level",
                Method::GET,
                get_remote_logging_level,
            )
            .route(
                "/remote_logging/level/{level}",
                Method::POST,
                remote_logging_level,
            )
            .route("/settings", Method::GET, get_settings)
            .route("/settings", Method::POST, set_settings)
            .route("/version", Method::GET, version)
            .route("/wg_public_key", Method::GET, get_wg_public_key)
            .route("/wifi_settings", Method::POST, set_wifi_multi)
            .route("/wifi_settings/pass", Method::POST, set_wifi_pass)
            .route("/wifi_settings/ssid", Method::POST, set_wifi_ssid)
            .route("/wifi_settings/channel", Method::POST, set_wifi_channel)
            .route(
                "/wifi_settings/get_channels/{radio}",
                Method::GET,
                get_allowed_wifi_channels,
            )
            .route("/wifi_settings", Method::GET, get_wifi_config)
            .route("/withdraw/{address}/{amount}", Method::POST, withdraw)
            .route("/withdraw_all/{address}", Method::POST, withdraw_all)
            .route(
                "/withdraw_eth/{address}/{amount}",
                Method::POST,
                withdraw_eth,
            )
            .route(
                "/auto_price/enabled/{status}",
                Method::POST,
                set_auto_pricing,
            )
            .route("/auto_price/enabled", Method::GET, auto_pricing_status)
            .route("/prices", Method::GET, get_prices)
            .route(
                "/blockchain/set/{chain_id}",
                Method::POST,
                set_system_blockchain,
            )
            .route("/blockchain/get", Method::GET, get_system_blockchain)
            .route("/nickname/get", Method::GET, get_nickname)
            .route("/nickname/set", Method::POST, set_nickname)
            .route(
                "/low_balance_notification",
                Method::GET,
                get_low_balance_notification,
            )
            .route(
                "/low_balance_notification/{status}",
                Method::POST,
                set_low_balance_notification,
            )
            .route("/usage/relay", Method::GET, get_relay_usage)
            .route("/usage/client", Method::GET, get_client_usage)
            .route("/usage/payments", Method::GET, get_payments)
            .route("/token_bridge/status", Method::GET, get_bridge_status)
            .route("/router/reboot", Method::POST, reboot_router)
            .route("/router/update", Method::POST, update_router)
            .route("/router/password", Method::POST, set_pass)
            .route("/release_feed/get", Method::GET, get_release_feed_http)
            .route(
                "/release_feed/set/{feed}",
                Method::POST,
                set_release_feed_http,
            )
            .route("/remote_access", Method::GET, get_remote_access_status)
            .route(
                "/remote_access/{status}",
                Method::POST,
                set_remote_access_status,
            )
            .route("/wipe", Method::POST, wipe)
            .route("/crash_actors", Method::POST, crash_actors)
            .route("/localization", Method::GET, get_localization)
    })
    .workers(1)
    .bind(format!(
        "[::0]:{}",
        SETTING.get_network().rita_dashboard_port
    ))
    .unwrap()
    .shutdown_timeout(0)
    .start();
}
