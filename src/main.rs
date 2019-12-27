#[macro_use]
extern crate lazy_static;

extern crate base64;
extern crate ws;

use std::thread;
use std::time::Duration;
use rust_sodium::crypto::box_;
use rust_sodium::crypto::box_::PublicKey;
use rust_sodium::crypto::box_::SecretKey;
use rust_sodium::crypto::box_::Nonce;
use ws::{connect, Handler, Sender, Handshake, Result, Message, CloseCode};
use base64::{encode, decode, decode_config_slice};
use serde_json::{json, Value};

lazy_static! {
    static ref BOX : (PublicKey, SecretKey) = box_::gen_keypair();
}

struct Client {
    out: Sender,
}

impl Handler for Client {
    fn on_open(&mut self, _: Handshake) -> Result<()> {
        let user = json!({
            "username": "test2",
            "ip": "127.0.0.1",
            "port": "5555",
            "pk": encode(BOX.0.as_ref())
        });

        self.out.send(user.to_string())
    }

    fn on_message(&mut self, msg: Message) -> Result<()> {
        // let response: Value = serde_json::from_str(&msg.into_text().unwrap()).unwrap();
        // let encrypted = decode(response["encrypted"].as_str().unwrap()).unwrap();

        // let mut key = [0; 32];
        // decode_config_slice(response["key"].as_str().unwrap(), base64::STANDARD, &mut key).unwrap();
        // let pk = PublicKey(key);

        // let mut nonce = [0; 24];
        // decode_config_slice(response["nonce"].as_str().unwrap(), base64::STANDARD, &mut nonce).unwrap();
        // let n = Nonce(nonce);

        // let plaintext = box_::open(&encrypted, &n, &pk, &BOX.1).unwrap();

        println!("Got message: {:?}", msg);
        //println!("Got message: {:?}", std::str::from_utf8(&plaintext).unwrap());
        Ok(())
        //self.out.close(CloseCode::Normal)
    }
}

fn main() {
    
    // Spin up our persistent REP thread
    thread::spawn(|| {
        let server_context = zmq::Context::new();
        let responder = server_context.socket(zmq::REP).unwrap();

        assert!(responder.bind("tcp://*:5555").is_ok());
        let mut msg = zmq::Message::new();
        loop {
            responder.recv(&mut msg, 0).unwrap();
            println!("Received {}", msg.as_str().unwrap());
            thread::sleep(Duration::from_millis(1000));
            responder.send("World", 0).unwrap();
        }
    });

    // Spin up our persistent connection to router
    thread::spawn(|| {
        connect("ws://127.0.0.1:3000", |out| Client { out: out } ).unwrap()
    });
    

    // let client_context = zmq::Context::new();
    // let requester = client_context.socket(zmq::REQ).unwrap();

    // assert!(requester.connect("tcp://localhost:5555").is_ok());

    // let mut msg = zmq::Message::new();

    // for request_nbr in 0..10 {
    //     requester.send("Hello", 0).unwrap();
    //     requester.recv(&mut msg, 0).unwrap();
    //     println!("Received World {}: {}", msg.as_str().unwrap(), request_nbr);
    // }
}