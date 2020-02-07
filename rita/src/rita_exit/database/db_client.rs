use crate::rita_exit::database::get_database_connection;
use actix::Actor;
use actix::Arbiter;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::Supervised;
use actix::SystemService;
use actix_web::Result;
use diesel;
use diesel::dsl::delete;
use diesel::*;
use exit_db::schema;
use failure::Error;
use futures01::future::Future;

#[derive(Default)]
pub struct DbClient;

impl Actor for DbClient {
    type Context = Context<Self>;
}

impl Supervised for DbClient {}
impl SystemService for DbClient {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("DB Client started");
    }
}

pub struct TruncateTables;
impl Message for TruncateTables {
    type Result = Result<(), Error>;
}

impl Handler<TruncateTables> for DbClient {
    type Result = Result<(), Error>;

    fn handle(&mut self, _: TruncateTables, _: &mut Self::Context) -> Self::Result {
        use self::schema::clients::dsl::*;
        info!("Deleting all clients in database");
        Arbiter::spawn(
            get_database_connection()
                .and_then(|connection| {
                    (delete(clients).execute(&connection).unwrap());
                    Ok(())
                })
                .then(|_| Ok(())),
        );

        Ok(())
    }
}
