use std::time::{Duration, Instant};
use std::thread;
use std::path::Path;

use actix::prelude::*;
use actix::registry::SystemService;

use serde_json;

use babel_monitor::Babel;

use rita_exit::db_client::{DbClient, ListClients};

use rita_exit::traffic_watcher::{TrafficWatcher, Watch};

use exit_db::models::Client;

use failure::Error;

use SETTING;
use althea_kernel_interface::{ExitClient, KernelInterface};

use althea_types::Identity;

pub struct RitaLoop;

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        ctx.run_later(Duration::from_secs(5), |act, ctx| {
            let addr: Address<Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}

pub struct Tick;

impl Message for Tick {
    type Result = Result<(), Error>;
}

fn to_identity(client: Client) -> Identity {
    Identity {
        mesh_ip: client.mesh_ip.parse().unwrap(),
        eth_address: SETTING.read().unwrap().payment.eth_address, // we should never be paying them, but if somehow we do, it goes back to us
        wg_public_key: client.wg_pubkey,
    }
}

fn to_exit_client(client: Client) -> Result<ExitClient, Error> {
    Ok(ExitClient {
        mesh_ip: client.mesh_ip.parse()?,
        internal_ip: client.internal_ip.parse()?,
        port: client.wg_port.parse()?,
        public_key: client.wg_pubkey,
    })
}

impl Handler<Tick> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, ctx: &mut Context<Self>) -> Self::Result {
        trace!("Tick!");

        ctx.spawn(
        DbClient::from_registry()
            .send(ListClients {})
            .into_actor(self)
            .then(|res, act, ctx| {
                let clients = res.unwrap().unwrap();
                let ids = clients
                    .clone()
                    .into_iter()
                    .map(|c| to_identity(c))
                    .collect();
                TrafficWatcher::from_registry().do_send(Watch(ids));

                let ki = KernelInterface {};
                let mut wg_clients = Vec::new();

                trace!("got clients from db {:?}", clients);

                for c in clients {
                    if let Ok(c) = to_exit_client(c) {
                        wg_clients.push(c);
                    }
                }

                trace!("converted clients {:?}", wg_clients);

                ki.set_exit_wg_config(
                    wg_clients,
                    SETTING.read().unwrap().exit_network.wg_tunnel_port,
                );

                actix::fut::ok(())
            }));

        Ok(())
    }
}
