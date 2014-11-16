#![feature(phase)]

extern crate hyper;
#[phase(plugin)]
extern crate regex_macros;
extern crate regex;

use hyper::Url;
use hyper::client::Request;
use std::io::net::udp::UdpSocket;
use std::io::net::ip::{Ipv4Addr, SocketAddr};
use std::str::from_utf8;

fn get_location(response: &[u8]) -> Option<&str> {
    let location_header = "LOCATION: ";
    match from_utf8(response) {
        Some(response) => {
            for line in response.lines_any() {
                if line.starts_with(location_header) {
                    return Some(line.slice_from(location_header.len()));
                }
            }
            None
        },
        None => None
    }
}

fn get_friendly_name(body: &str) -> Option<&str> {
    let re = regex!(r"<friendlyName>(.+?)</friendlyName>");
    match re.captures(body) {
        Some(cap) => Some(cap.at(1)),
        None => None
    }
}

fn main() {
    let any_addr = SocketAddr { ip: Ipv4Addr(0, 0, 0, 0), port: 0 };
    let dst_addr = SocketAddr { ip: Ipv4Addr(239, 255, 255, 250), port: 1900 };
    let ssdp_msearch =
        "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 2\r\n\
        ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n";

    let mut socket = UdpSocket::bind(any_addr).ok().expect("couldn't bind socket");
    println!("Sending to {}:\n{}", dst_addr, ssdp_msearch);
    socket.send_to(ssdp_msearch.as_bytes(), dst_addr).ok().expect("send_to");
    socket.set_timeout(Some(3000));  // 3 second timeout

    loop {
        let mut buf = [0, ..4096];
        match socket.recv_from(buf) {
            Ok((len, addr)) => {
                println!("Received from {}:", addr.ip);
                let location = get_location(buf.slice(0, len)).expect("no location");
                println!("{}", location);
                let url = match Url::parse(location) {
                    Ok(url) => url,
                    Err(e) => panic!("Invalid URL: {}", e)
                };
                let req = match Request::get(url) {
                    Ok(req) => req,
                    Err(err) => panic!("Failed to connect to {}: {}", location, err)
                };
                let mut res = req
                    .start().unwrap() // failure: Error writing Headers
                    .send().unwrap(); // failure: Error reading Response head.
                let app_url = match res.headers.get_raw("Application-URL") {
                    Some([ref app_url]) => app_url,
                    _ => panic!("No app url from {}", location)
                };
                println!("App url: {}", from_utf8(app_url.as_slice()).unwrap());
                let body = res.read_to_string().ok().expect("read body");
                let friendly_name = get_friendly_name(body.as_slice());
                println!("Friendly name: {}", friendly_name);
            }
            _ => break
        }
    }

    println!("YAY done!");
}
