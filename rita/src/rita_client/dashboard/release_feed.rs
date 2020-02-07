use crate::KI;
use actix_web::http::StatusCode;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Path;
use althea_kernel_interface::opkg_feeds::get_release_feed;
use althea_kernel_interface::opkg_feeds::set_release_feed;
use failure::Error;

pub fn get_release_feed_http(_req: HttpRequest) -> Result<HttpResponse, Error> {
    if !KI.is_openwrt() {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST));
    }
    let res = get_release_feed()?;
    Ok(HttpResponse::Ok().json(res))
}

pub fn set_release_feed_http(path: Path<String>) -> Result<HttpResponse, Error> {
    if !KI.is_openwrt() {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST));
    }

    let val = path.into_inner().parse();
    if val.is_err() {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST)
            .into_builder()
            .json(format!(
                "Could not parse {:?} into a ReleaseStatus enum!",
                val
            )));
    }
    let val = val.unwrap();
    if let Err(e) = set_release_feed(val) {
        return Ok(HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
            .into_builder()
            .json(format!("Failed to write new release feed with {:?}", e)));
    }

    Ok(HttpResponse::Ok().json(()))
}
