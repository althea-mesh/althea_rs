//! The common user infromation endpoints for Rita, these are http endpoints that exist for user
//! management and automation. They exist on port 4877 by default and should be firewalled
//! from the outside world for obvious security reasons.

use actix::prelude::*;
use actix::registry::SystemService;
use actix_web::http::StatusCode;
use actix_web::*;

use failure::Error;
use num_traits::ops::checked::CheckedDiv;
use num_traits::ToPrimitive;

use num256::Int256;

use futures::{future, Future};

use serde_json;

use std::{
    boxed::Box,
    collections::HashMap,
    net::{SocketAddr, TcpStream},
};

use settings::RitaCommonSettings;
use SETTING;

use babel_monitor::Babel;

use clarity::Address;

use rita_common::debt_keeper::GetDebtsList;
use rita_common::debt_keeper::{DebtKeeper, GetDebtsResult};
use rita_common::network_endpoints::JsonStatusResponse;
use rita_common::payment_controller::{GetOwnBalance, PaymentController};

pub mod babel;
pub mod dao;
pub mod debts;
pub mod development;
pub mod own_info;
pub mod settings;
pub mod wallet;

pub struct Dashboard;

impl Actor for Dashboard {
    type Context = Context<Self>;
}

impl Supervised for Dashboard {}
impl SystemService for Dashboard {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("Dashboard started");
    }
}

impl Default for Dashboard {
    fn default() -> Dashboard {
        Dashboard {}
    }
}
