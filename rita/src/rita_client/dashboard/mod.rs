//! This file contains all the network endpoints used for the client dashbaord. This management dashboard
//! is for users to use to configure and manage their router and should be firewalled from the outside
//! world.
//!
//! For more documentation on specific functions see the router-dashboard file in the docs folder

use actix::prelude::*;
use actix_web::Path;

use failure::Error;
use futures::Future;
use serde_json;
use serde_json::Value;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::string::ToString;
use std::{thread, time};

use althea_types::ExitState;
use babel_monitor::Babel;
use num256::Int256;
use rita_common::dashboard::Dashboard;
use rita_common::debt_keeper::{DebtKeeper, Dump};
use rita_common::peer_listener::PeerListener;
use rita_common::peer_listener::{Listen, UnListen};
use settings::ExitServer;
use settings::RitaClientSettings;
use settings::RitaCommonSettings;
use KI;
use SETTING;

pub mod network_endpoints;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WifiInterface {
    #[serde(default)]
    pub section_name: String,
    pub network: String,
    #[serde(default)]
    pub mesh: bool,
    pub mode: String,
    pub ssid: String,
    pub encryption: String,
    pub key: String,
    #[serde(default, skip_deserializing)]
    pub device: WifiDevice,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiDevice {
    #[serde(default)]
    pub section_name: String,
    #[serde(rename = "type")]
    pub i_type: String,
    pub channel: String,
    pub path: String,
    pub htmode: String,
    pub hwmode: String,
    pub disabled: String,
    #[serde(default)]
    pub radio_type: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiSSID {
    pub radio: String,
    pub ssid: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiPass {
    pub radio: String,
    pub pass: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WifiMesh {
    pub radio: String,
    pub mesh: bool,
}

struct GetWifiConfig;

impl Message for GetWifiConfig {
    type Result = Result<Vec<WifiInterface>, Error>;
}

impl Handler<GetWifiConfig> for Dashboard {
    type Result = Result<Vec<WifiInterface>, Error>;

    fn handle(&mut self, _msg: GetWifiConfig, _ctx: &mut Self::Context) -> Self::Result {
        let mut interfaces = Vec::new();
        let mut devices = HashMap::new();

        let config = KI.ubus_call("uci", "get", "{ \"config\": \"wireless\"}")?;

        let val: Value = serde_json::from_str(&config)?;

        let items = match val["values"].as_object() {
            Some(i) => i,
            None => {
                error!("No \"values\" key in parsed wifi config!");
                return Err(format_err!("No \"values\" key parsed wifi config")).into();
            }
        };

        for (k, v) in items {
            if v[".type"] == "wifi-device" {
                let mut device: WifiDevice = serde_json::from_value(v.clone())?;
                device.section_name = k.clone();

                let channel: String = serde_json::from_value(v["channel"].clone())?;
                let channel: u8 = channel.parse()?;
                if channel > 20 {
                    device.radio_type = "5ghz".to_string();
                } else {
                    device.radio_type = "2ghz".to_string();
                }

                devices.insert(device.section_name.to_string(), device);
            }
        }
        for (k, v) in items {
            if v[".type"] == "wifi-iface" {
                let mut interface: WifiInterface = serde_json::from_value(v.clone())?;
                interface.mesh = interface.mode.contains("adhoc");
                interface.section_name = k.clone();

                let device_name: String = serde_json::from_value(v["device"].clone())?;
                interface.device = devices[&device_name].clone();
                interfaces.push(interface);
            }
        }

        Ok(interfaces)
    }
}

struct SetWifiConfig(Vec<WifiInterface>);

impl Message for SetWifiConfig {
    type Result = Result<(), Error>;
}

impl Handler<SetWifiConfig> for Dashboard {
    type Result = Result<(), Error>;

    fn handle(&mut self, msg: SetWifiConfig, _ctx: &mut Self::Context) -> Self::Result {
        for i in msg.0 {
            //TODO parse ifname from the WifiDevice instead of this hack,
            // probably easy to add when we add the ability to change the default wireless channel
            let iface_number = i.section_name.clone().chars().last();

            if i.mesh && iface_number.is_some() {
                let iface_name = format!("wlan{}", iface_number.unwrap());

                KI.set_uci_var(&format!("wireless.{}.ssid", i.section_name), "AltheaMesh")?;
                KI.set_uci_var(&format!("wireless.{}.encryption", i.section_name), "none")?;
                KI.set_uci_var(&format!("wireless.{}.mode", i.section_name), "adhoc")?;
                KI.set_uci_var(&format!("wireless.{}.network", i.section_name), &iface_name)?;
                KI.set_uci_var(&format!("network.rita_{}", iface_name.clone()), "interface")?;
                KI.set_uci_var(
                    &format!("network.{}.ifname", iface_name.clone()),
                    &iface_name,
                )?;
                KI.set_uci_var(&format!("network.{}.proto", iface_name.clone()), "static")?;

                // These must run before listen/unlisten to avoid race conditions
                KI.uci_commit()?;
                KI.openwrt_reset_wireless()?;
                // when we run wifi reset it takes seconds for a new fe80 address to show up
                thread::sleep(time::Duration::from_millis(30000));

                PeerListener::from_registry().do_send(Listen(iface_name.clone()));
            } else if iface_number.is_some() {
                let iface_name = format!("wlan{}", iface_number.unwrap());
                KI.set_uci_var(&format!("wireless.{}.ssid", i.section_name), &i.ssid)?;
                KI.set_uci_var(&format!("wireless.{}.key", i.section_name), &i.key)?;
                KI.set_uci_var(&format!("wireless.{}.mode", i.section_name), "ap")?;
                KI.set_uci_var(
                    &format!("wireless.{}.encryption", i.section_name),
                    "psk2+tkip+aes",
                )?;
                KI.set_uci_var(&format!("wireless.{}.network", i.section_name), "lan")?;

                // Order is reversed here
                PeerListener::from_registry().do_send(UnListen(iface_name));

                KI.uci_commit()?;
                KI.openwrt_reset_wireless()?;
            }
        }

        KI.uci_commit()?;
        KI.openwrt_reset_wireless()?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;

        Ok(())
    }
}

#[derive(Serialize)]
pub struct NodeInfo {
    pub nickname: String,
    pub route_metric_to_exit: u16,
    pub total_payments: Int256,
    pub debt: i64,
    pub link_cost: u16,
    pub price_to_exit: u32,
}

pub struct GetNodeInfo;

impl Message for GetNodeInfo {
    type Result = Result<Vec<NodeInfo>, Error>;
}

impl Handler<GetNodeInfo> for Dashboard {
    type Result = ResponseFuture<Vec<NodeInfo>, Error>;

    fn handle(&mut self, _msg: GetNodeInfo, _ctx: &mut Self::Context) -> Self::Result {
        Box::new(
            DebtKeeper::from_registry()
                .send(Dump {})
                .from_err()
                .and_then(|res| {
                    let stream = TcpStream::connect::<SocketAddr>(
                        format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
                    )?;
                    let mut babel = Babel::new(stream);
                    babel.start_connection()?;
                    let route_table_sample = babel.parse_routes()?;

                    let res = res?;

                    let mut output = Vec::new();

                    let exit_client = SETTING.get_exit_client();
                    let current_exit = exit_client.get_current_exit();

                    for (identity, debt_info) in res.iter() {
                        if current_exit.is_some() {
                            let exit_ip = current_exit.unwrap().id.mesh_ip;
                            let maybe_route = babel.get_route_via_neigh(
                                identity.mesh_ip,
                                exit_ip,
                                &route_table_sample,
                            );

                            // We have a peer that is an exit, so we can't find a route
                            // from them to our selected exit. Other errors can also get
                            // caught here
                            if maybe_route.is_err() {
                                output.push(NodeInfo {
                                    nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                    route_metric_to_exit: u16::max_value(),
                                    total_payments: debt_info.total_payment_received.into(),
                                    debt: debt_info.debt.clone().into(),
                                    link_cost: u16::max_value(),
                                    price_to_exit: u32::max_value(),
                                });
                                continue;
                            }
                            let route = maybe_route?;

                            output.push(NodeInfo {
                                nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                route_metric_to_exit: route.metric,
                                total_payments: debt_info.total_payment_received.into(),
                                debt: debt_info.debt.clone().into(),
                                link_cost: route.refmetric,
                                price_to_exit: route.price,
                            })
                        } else {
                            output.push(NodeInfo {
                                nickname: serde_json::to_string(&identity.mesh_ip).unwrap(),
                                route_metric_to_exit: u16::max_value(),
                                total_payments: debt_info.total_payment_received.into(),
                                debt: debt_info.debt.clone().into(),
                                link_cost: u16::max_value(),
                                price_to_exit: u32::max_value(),
                            })
                        }
                    }

                    Ok(output)
                }),
        )
    }
}

#[derive(Serialize)]
pub struct ExitInfo {
    nickname: String,
    exit_settings: ExitServer,
    is_selected: bool,
    have_route: bool,
    is_reachable: bool,
    is_tunnel_working: bool,
}

pub struct GetExitInfo;

impl Message for GetExitInfo {
    type Result = Result<Vec<ExitInfo>, Error>;
}

/// Checks if the provided exit is selected
fn is_selected(exit: &ExitServer, current_exit: Option<&ExitServer>) -> Result<bool, Error> {
    match current_exit {
        None => Ok(false),
        Some(i) => Ok(i == exit),
    }
}

/// Determines if the provide exit is currently selected, if it's setup, and then if it can be reached over
/// the exit tunnel via a ping
fn is_tunnel_working(exit: &ExitServer, current_exit: Option<&ExitServer>) -> Result<bool, Error> {
    if current_exit.is_some() && is_selected(exit, current_exit)? {
        if current_exit.unwrap().info.general_details().is_some() {
            let internal_ip = current_exit
                .unwrap()
                .clone()
                .info
                .general_details()
                .unwrap()
                .server_internal_ip;
            KI.ping_check_v4(&internal_ip)
        } else {
            return Ok(false);
        }
    } else {
        return Ok(false);
    }
}

impl Handler<GetExitInfo> for Dashboard {
    type Result = Result<Vec<ExitInfo>, Error>;

    fn handle(&mut self, _msg: GetExitInfo, _ctx: &mut Self::Context) -> Self::Result {
        let stream = TcpStream::connect::<SocketAddr>(
            format!("[::1]:{}", SETTING.get_network().babel_port).parse()?,
        )?;
        let mut babel = Babel::new(stream);
        babel.start_connection()?;
        let route_table_sample = babel.parse_routes()?;

        let mut output = Vec::new();

        let exit_client = SETTING.get_exit_client();
        let current_exit = exit_client.get_current_exit();

        for exit in exit_client.exits.clone().into_iter() {
            let selected = is_selected(&exit.1, current_exit)?;
            let have_route = babel.do_we_have_route(&exit.1.id.mesh_ip, &route_table_sample)?;

            // failed pings block for one second, so we should be sure it's at least reasonable
            // to expect the pings to work before issuing them.
            let reachable = match have_route {
                true => KI.ping_check_v6(&exit.1.id.mesh_ip)?,
                false => false,
            };
            let tunnel_working = match (have_route, selected) {
                (true, true) => is_tunnel_working(&exit.1, current_exit)?,
                _ => false,
            };

            output.push(ExitInfo {
                nickname: exit.0,
                exit_settings: exit.1.clone(),
                is_selected: selected,
                have_route: have_route,
                is_reachable: reachable,
                is_tunnel_working: tunnel_working,
            })
        }

        Ok(output)
    }
}

#[derive(Debug)]
pub struct SetWiFiSSID(WifiSSID);

impl Message for SetWiFiSSID {
    type Result = Result<(), Error>;
}

impl Handler<SetWiFiSSID> for Dashboard {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: SetWiFiSSID, _ctx: &mut Self::Context) -> Self::Result {
        // think radio0, radio1
        let iface_name = msg.0.radio;
        let ssid = msg.0.ssid;
        let section_name = format!("default_{}", iface_name);
        KI.set_uci_var(&format!("wireless.{}.ssid", section_name), &ssid)?;

        KI.uci_commit()?;
        KI.openwrt_reset_wireless()?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SetWiFiPass(WifiPass);

impl Message for SetWiFiPass {
    type Result = Result<(), Error>;
}

impl Handler<SetWiFiPass> for Dashboard {
    type Result = Result<(), Error>;
    fn handle(&mut self, msg: SetWiFiPass, _ctx: &mut Self::Context) -> Self::Result {
        // think radio0, radio1
        let iface_name = msg.0.radio;
        let pass = msg.0.pass;
        let section_name = format!("default_{}", iface_name);
        KI.set_uci_var(&format!("wireless.{}.key", section_name), &pass)?;

        KI.uci_commit()?;
        KI.openwrt_reset_wireless()?;

        // We edited disk contents, force global sync
        KI.fs_sync()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct GetInterfaces;

impl Message for GetInterfaces {
    type Result = Result<HashMap<String, String>, Error>;
}

impl Handler<GetInterfaces> for Dashboard {
    type Result = Result<HashMap<String, String>, Error>;
    fn handle(&mut self, _msg: GetInterfaces, _ctx: &mut Self::Context) -> Self::Result {
        let mut retval = HashMap::new();

        // Wired
        for (setting_name, value) in KI.uci_show(Some("network"))? {
            // Only non-loopback non-bridge interface names should get past
            if setting_name.contains("ifname") && !value.contains("backhaul") && value != "lo" {
                retval.insert(
                    value.clone(),
                    ethernet2mode(&value, &setting_name)?.to_string(),
                );
            }
        }

        // Wireless
        for (setting_name, value) in KI.uci_show(Some("wireless"))? {
            if setting_name.contains("ifname") {
                retval.insert(value.clone(), wlan2mode(&value, &setting_name)?.to_string());
            }
        }

        Ok(retval)
    }
}

/// Find out a wired interface's mode (mesh, LAN, WAN) from the setting name
pub fn ethernet2mode(ifname: &str, setting_name: &str) -> Result<InterfaceMode, Error> {
    trace!(
        "ethernet2mode: ifname {:?}, setting_name {:?}",
        ifname,
        setting_name
    );

    // Match parent section name
    Ok(match &setting_name.replace(".ifname", "") {
        s if s.contains("rita_") => InterfaceMode::Mesh,
        s if s.contains("lan") => InterfaceMode::LAN,
        s if s.contains("backhaul") => InterfaceMode::WAN,
        other => bail!(
            "Unknown wired port mode for interface {:?}, section name {:?}",
            ifname,
            other
        ),
    })
}

/// Find out a wireless interface's mode (mesh, LAN, WAN) from the 802.11 mode of operation
pub fn wlan2mode(ifname: &str, setting_name: &str) -> Result<InterfaceMode, Error> {
    trace!(
        "wlan2mode: ifname {:?}, setting_name {:?}",
        ifname,
        setting_name
    );

    let uci = KI.uci_show(Some("wireless"))?;

    let radio_name = setting_name.replace("wireless.", "").replace(".ifname", "");

    // Find the mode entry
    let mode_entry_name = format!("wireless.default_{}.mode", radio_name);

    let mode_name = match uci.get(&mode_entry_name) {
        Some(mode_name) => mode_name,
        None => {
            error!("Mode setting entry {:?} not found", mode_entry_name);
            bail!("Mode setting entry {:?} not found", mode_entry_name);
        }
    };

    // Match mode
    Ok(match mode_name.as_str() {
        "adhoc" => InterfaceMode::Mesh,
        "ap" => InterfaceMode::LAN,
        "sta" => InterfaceMode::WAN,
        other => {
            warn!(
                "Ambiguous WiFi mode {:?} on interface {:?}, radio {:?}",
                other, ifname, radio_name
            );
            InterfaceMode::Unknown
        }
    })
}

pub enum InterfaceMode {
    Mesh,
    LAN,
    WAN,
    Unknown, // Ambiguous wireless modes like monitor or promiscuous
}

impl ToString for InterfaceMode {
    fn to_string(&self) -> String {
        match self {
            InterfaceMode::Mesh => "mesh".to_owned(),
            InterfaceMode::LAN => "LAN".to_owned(),
            InterfaceMode::WAN => "WAN".to_owned(),
            InterfaceMode::Unknown => "unknown".to_owned(),
        }
    }
}
