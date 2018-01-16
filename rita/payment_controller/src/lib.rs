#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derive_error;

#[macro_use] extern crate log;

// use std::sync::mpsc::{Receiver, Sender};

extern crate serde;
extern crate serde_json;

// extern crate althea_types;
// use althea_types::EthAddress;

extern crate debt_keeper;
use debt_keeper::Identity;

extern crate num256;
use num256::Uint256;

extern crate reqwest;
use reqwest::{Client, Response, StatusCode};

use std::net::{Ipv6Addr};

#[derive(Debug, Error)]
pub enum Error {
    HttpError(reqwest::Error),
    SerdeError(serde_json::Error),
    #[error(msg_embedded, no_from, non_std)] PaymentControllerError(String),
    #[error(msg_embedded, no_from, non_std)] PaymentSendingError(String),
    #[error(msg_embedded, no_from, non_std)] BountyError(String),
}


pub struct PaymentController {
    pub client: Client,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PaymentTx {
    pub to: Identity,
    pub from: Identity,
    pub amount: Uint256,
}

impl PaymentController {
    pub fn new() -> Self {
        PaymentController {
            client: Client::new(),
        }
    }
    /// This is exposed to the Guac light client, or whatever else is
    /// being used for payments. It gets called when a payment from a counterparty
    /// has arrived, and will return if it is valid.
    pub fn payment_received(&self, pmt: PaymentTx) -> Result<(), Error> {
        trace!("Sending payment to Guac: {:?}", pmt);
        // TODO: Pass the paymentTx to guac, get a channel summary back, reject if incorrect

        let mut r = self.client
            .post(&format!("http://[{}]:80/update", "2001::4".parse::<Ipv6Addr>().unwrap())) //TODO: what port do we use?, how do we get the IP for the bounty hunter?
            .body(serde_json::to_string(&pmt)?) //TODO: send the channel summary as well
            .send()?;

        if r.status() == StatusCode::Ok {
            trace!("Successfully sent bounty hunter update");
            Ok(())
        } else {
            trace!("Unsuccessfully in sending update to bounty hunter");
            trace!("Received error from bounty hunter: {:?}", r.text().unwrap_or(String::from("No message received")));
            Err(Error::BountyError(
                String::from(format!("Received error from bounty hunter: {:?}",
                                     r.text().unwrap_or(String::from("No message received"))
                ))
            ))
        }
    }

    /// This is called by the other modules in Rita to make payments.
    pub fn make_payment(&self, pmt: PaymentTx) -> Result<(), Error> {
        trace!("Making payments to {:?}", pmt);
        trace!("Sending payments to http://[{}]:4876/make_payment", pmt.to.ip_address);

        let mut r = self.client
            .post(&format!("http://[{}]:4876/make_payment", pmt.to.ip_address))
            .body(serde_json::to_string(&pmt)?)
            .send()?;

        if r.status() == StatusCode::Ok {
            trace!("Successfully paid");
            trace!("Received success from payee: {:?}", r.text().unwrap_or(String::from("No message received")));
            Ok(())
        } else {
            trace!("Unsuccessfully paid");
            trace!("Received error from payee: {:?}", r.text().unwrap_or(String::from("No message received")));
            Err(Error::PaymentSendingError(
                String::from(format!("Received error from payee: {:?}",
                                     r.text().unwrap_or(String::from("No message received"))
                ))
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
