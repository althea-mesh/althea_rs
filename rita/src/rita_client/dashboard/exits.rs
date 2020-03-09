//! The Exit info endpoint gathers infromation about exit status and presents it to the dashbaord.

use crate::rita_client::exit_manager::exit_setup_request;
use crate::rita_common::dashboard::Dashboard;
use crate::ARGS;
use crate::KI;
use crate::SETTING;
use actix::{Handler, Message, ResponseFuture, SystemService};
use actix_web::client;
use actix_web::error::PayloadError;
use actix_web::http::StatusCode;
use actix_web::AsyncResponder;
use actix_web::HttpMessage;
use actix_web::Path;
use actix_web::{HttpRequest, HttpResponse, Json};
use althea_types::ExitState;
use babel_monitor::do_we_have_route;
use babel_monitor::open_babel_stream;
use babel_monitor::parse_routes;
use babel_monitor::start_connection;
use bytes::Bytes;
use failure::Error;
use futures01::{future, Future};
use settings::client::{ExitServer, RitaClientSettings};
use settings::FileWrite;
use settings::RitaCommonSettings;
use std::boxed::Box;
use std::collections::HashMap;
use std::time::Duration;

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

const EXIT_PING_TIMEOUT: Duration = Duration::from_millis(200);

/// Checks if the provided exit is selected
fn is_selected(exit: &ExitServer, current_exit: Option<&ExitServer>) -> bool {
    match current_exit {
        None => false,
        Some(i) => i == exit,
    }
}

/// Determines if the provided exit is currently selected, if it's setup, and then if it can be reached over
/// the exit tunnel via a ping
fn is_tunnel_working(exit: &ExitServer, current_exit: Option<&ExitServer>) -> bool {
    match (current_exit, is_selected(exit, current_exit)) {
        (Some(exit), true) => match exit.info.general_details() {
            Some(details) => match KI.ping_check(&details.server_internal_ip, EXIT_PING_TIMEOUT) {
                Ok(ping_result) => ping_result,
                Err(_) => false,
            },
            None => false,
        },
        (_, _) => false,
    }
}

impl Handler<GetExitInfo> for Dashboard {
    type Result = ResponseFuture<Vec<ExitInfo>, Error>;

    fn handle(&mut self, _msg: GetExitInfo, _ctx: &mut Self::Context) -> Self::Result {
        let babel_port = SETTING.get_network().babel_port;

        Box::new(
            open_babel_stream(babel_port)
                .from_err()
                .and_then(move |stream| {
                    start_connection(stream).and_then(move |stream| {
                        parse_routes(stream).and_then(move |routes| {
                            let route_table_sample = routes.1;
                            let mut output = Vec::new();

                            let exit_client = SETTING.get_exit_client();
                            let current_exit = exit_client.get_current_exit();

                            for exit in exit_client.exits.clone().into_iter() {
                                let selected = is_selected(&exit.1, current_exit);
                                let have_route =
                                    do_we_have_route(&exit.1.id.mesh_ip, &route_table_sample)?;

                                // failed pings block for one second, so we should be sure it's at least reasonable
                                // to expect the pings to work before issuing them.
                                let reachable = if have_route {
                                    KI.ping_check(&exit.1.id.mesh_ip, EXIT_PING_TIMEOUT)?
                                } else {
                                    false
                                };
                                let tunnel_working = match (have_route, selected) {
                                    (true, true) => is_tunnel_working(&exit.1, current_exit),
                                    _ => false,
                                };

                                output.push(ExitInfo {
                                    nickname: exit.0,
                                    exit_settings: exit.1.clone(),
                                    is_selected: selected,
                                    have_route,
                                    is_reachable: reachable,
                                    is_tunnel_working: tunnel_working,
                                })
                            }

                            Ok(output)
                        })
                    })
                }),
        )
    }
}

pub fn add_exits(
    new_exits: Json<HashMap<String, ExitServer>>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    debug!("/exits POST hit with {:?}", new_exits);
    let exits = &mut SETTING.get_exit_client_mut().exits;
    exits.extend(new_exits.into_inner());

    Box::new(future::ok(HttpResponse::Ok().json(exits.clone())))
}

pub fn exits_sync(
    list_url_json: Json<HashMap<String, String>>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    debug!("/exits/sync hit with {:?}", list_url_json);

    let list_url = match list_url_json.get("url") {
        Some(url) if url.starts_with("https://") => url,
        Some(_unsafe_url) => {
            let mut ret = HashMap::new();
            ret.insert(
                "error".to_owned(),
                "Attempted to use a non-HTTPS url".to_owned(),
            );
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::BAD_REQUEST)
                    .into_builder()
                    .json(ret),
            ));
        }
        None => {
            let mut ret = HashMap::new();

            ret.insert(
                "error".to_owned(),
                "Could not find a \"url\" key in supplied JSON".to_owned(),
            );
            return Box::new(future::ok(
                HttpResponse::new(StatusCode::BAD_REQUEST)
                    .into_builder()
                    .json(ret),
            ));
        }
    }
    .to_string();

    let res = client::get(list_url.clone())
        .header("User-Agent", "Actix-web")
        .finish()
        .unwrap()
        .send()
        .from_err()
        .and_then(move |response| {
            response
                .body()
                .then(move |message_body: Result<Bytes, PayloadError>| {
                    if let Err(e) = message_body {
                        return Box::new(future::ok(
                            HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                                .into_builder()
                                .json(format!("Actix encountered a payload error {:?}", e)),
                        ));
                    }
                    let message_body = message_body.unwrap();

                    // .json() only works on application/json content types unlike reqwest which handles bytes
                    // transparently actix requests need to get the body and deserialize using serde_json in
                    // an explicit fashion
                    match serde_json::from_slice::<HashMap<String, ExitServer>>(&message_body) {
                        Ok(mut new_exits) => {
                            info!("exit_sync list: {:#?}", new_exits);

                            let mut exit_client = SETTING.get_exit_client_mut();

                            // if the entry already exists copy the registration info over
                            for new_exit in new_exits.iter_mut() {
                                let nick = new_exit.0;
                                let new_settings = new_exit.1;
                                if let Some(old_exit) = exit_client.exits.get(nick) {
                                    new_settings.info = old_exit.info.clone();
                                }
                            }
                            exit_client.exits.extend(new_exits);
                            let exits = exit_client.exits.clone();
                            drop(exit_client);

                            // try and save the config and fail if we can't
                            if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
                                trace!("Failed to write settings");
                                return Box::new(future::err(e));
                            }

                            Box::new(future::ok(HttpResponse::Ok().json(exits)))
                        }
                        Err(e) => {
                            let mut ret = HashMap::<String, String>::new();

                            error!(
                                "Could not deserialize exit list at {:?} because of error: {:?}",
                                list_url, e
                            );
                            ret.insert(
                                "error".to_owned(),
                                format!(
                            "Could not deserialize exit list at URL {:?} because of error {:?}",
                             list_url, e
                             ),
                            );

                            Box::new(future::ok(
                                HttpResponse::new(StatusCode::BAD_REQUEST)
                                    .into_builder()
                                    .json(ret),
                            ))
                        }
                    }
                })
        });

    Box::new(res)
}

pub fn get_exit_info(
    _req: HttpRequest,
) -> Box<dyn Future<Item = Json<Vec<ExitInfo>>, Error = Error>> {
    debug!("Exit endpoint hit!");
    Dashboard::from_registry()
        .send(GetExitInfo {})
        .from_err()
        .and_then(move |reply| Ok(Json(reply?)))
        .responder()
}

pub fn reset_exit(path: Path<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let exit_name = path.into_inner();
    debug!("/exits/{}/reset hit", exit_name);

    let mut exits = SETTING.get_exits_mut();
    let mut ret = HashMap::new();

    if let Some(exit) = exits.get_mut(&exit_name) {
        info!(
            "Changing exit {:?} state to New, and deleting wg_exit tunnel",
            exit_name
        );
        exit.info = ExitState::New;

        if let Err(e) = KI.del_interface("wg_exit") {
            error!("Failed to delete wg_exit {:?}", e)
        };

        Box::new(future::ok(HttpResponse::Ok().json(ret)))
    } else {
        error!("Requested a reset on unknown exit {:?}", exit_name);
        ret.insert(
            "error".to_owned(),
            format!("Requested reset on unknown exit {:?}", exit_name),
        );
        Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ))
    }
}

pub fn select_exit(path: Path<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let exit_name = path.into_inner();
    debug!("/exits/{}/select hit", exit_name);

    let mut exit_client = SETTING.get_exit_client_mut();
    let mut ret = HashMap::new();

    if exit_client.exits.contains_key(&exit_name) {
        info!("Selecting exit {:?}", exit_name);
        exit_client.current_exit = Some(exit_name);

        // try and save the config and fail if we can't, this way we can run the save
        // loop less often and not lose exit configs
        drop(exit_client);
        if let Err(e) = SETTING.write().unwrap().write(&ARGS.flag_config) {
            return Box::new(future::err(e));
        }

        Box::new(future::ok(HttpResponse::Ok().json(ret)))
    } else {
        error!("Requested selection of an unknown exit {:?}", exit_name);
        ret.insert(
            "error".to_owned(),
            format!("Requested selection of an unknown exit {:?}", exit_name),
        );
        Box::new(future::ok(
            HttpResponse::new(StatusCode::BAD_REQUEST)
                .into_builder()
                .json(ret),
        ))
    }
}

pub fn register_to_exit(path: Path<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let exit_name = path.into_inner();
    debug!("/exits/{}/register hit", exit_name);

    debug!("Attempting to register on exit {:?}", exit_name);

    Box::new(exit_setup_request(exit_name, None).then(|res| {
        let mut ret = HashMap::new();
        match res {
            Ok(_) => future::ok(HttpResponse::Ok().json(ret)),
            Err(e) => {
                error!("exit_setup_request() failed with: {:?}", e);
                ret.insert("error".to_owned(), "Exit setup request failed".to_owned());
                ret.insert("rust_error".to_owned(), format!("{:?}", e));
                future::ok(
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                        .into_builder()
                        .json(ret),
                )
            }
        }
    }))
}

pub fn verify_on_exit_with_code(
    path: Path<(String, String)>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let (exit_name, code) = path.into_inner();
    debug!("/exits/{}/verify/{} hit", exit_name, code);

    Box::new(exit_setup_request(exit_name, Some(code)).then(|res| {
        let mut ret = HashMap::new();
        match res {
            Ok(_) => future::ok(HttpResponse::Ok().json(ret)),
            Err(e) => {
                error!("exit_setup_request() failed with: {:?}", e);
                ret.insert("error".to_owned(), "Exit setup request failed".to_owned());
                ret.insert("rust_error".to_owned(), format!("{:?}", e));
                future::ok(
                    HttpResponse::new(StatusCode::BAD_REQUEST)
                        .into_builder()
                        .json(ret),
                )
            }
        }
    }))
}
