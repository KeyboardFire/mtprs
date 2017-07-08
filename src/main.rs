extern crate mtprs;
use mtprs::Mtprs;

fn main() {
    let mut client = Mtprs::new();
    client.auth().unwrap();
}
