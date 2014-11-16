#![feature(phase)]

extern crate hyper;
#[phase(plugin, link)] extern crate log;
#[phase(plugin)] extern crate regex_macros;
extern crate regex;

use hyper::Url;
use hyper::client::Request;
use std::io::IoResult;
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


fn discover_dial_locations() -> IoResult<Vec<String>> {
    let any_addr = SocketAddr { ip: Ipv4Addr(0, 0, 0, 0), port: 0 };
    let dst_addr = SocketAddr { ip: Ipv4Addr(239, 255, 255, 250), port: 1900 };
    let ssdp_msearch =
        "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 2\r\n\
        ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n";

    let mut socket = try!(UdpSocket::bind(any_addr));
    debug!("Sending to {}:\n{}", dst_addr, ssdp_msearch);
    try!(socket.send_to(ssdp_msearch.as_bytes(), dst_addr));
    socket.set_timeout(Some(3000));  // 3 second timeout

    let mut result = Vec::new();
    loop {
        let mut buf = [0, ..4096];
        match socket.recv_from(buf) {
            Ok((len, addr)) => {
                debug!("Received from {}:", addr.ip);
                match get_location(buf.slice(0, len)) {
                    Some(location) => result.push(location.to_string()),
                    None => ()
                }
            },
            _ => break,
        }
    }
    Ok(result)
}


fn main() {
    let locations = discover_dial_locations().ok().expect("discovery failed");
    for location in locations.iter() {
        let url = match Url::parse(location.as_slice()) {
            Ok(url) => url,
            Err(e) => {
                error!("Invalid URL: {}", e);
                continue;
            },
        };
        let host = url.serialize_host();
        let req = match Request::get(url) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to connect to {}: {}", location, e);
                continue;
            },
        };
        let mut res = match req.start() {
            Ok(started) => match started.send() {
                Ok(res) => res,
                Err(e) => {
                    error!("Error reading response headers: {}", e);
                    continue;
                },
            },
            Err(e) => {
                error!("Error writing headers: {}", e);
                continue;
            },
        };
        let app_url = match res.headers.get_raw("Application-URL") {
            Some([ref app_url]) => app_url,
            _ => {
                error!("No app url from {}", location);
                continue;
            },
        };
        let name = match res.read_to_string() {
            Ok(body) => match get_friendly_name(body.as_slice()) {
                Some(name) => name.to_string(),
                None => match host { // TODO: factor this out
                    Some(host) => host,
                    None => {
                        error!("No friendly name or host");
                        continue;
                    },
                },
            },
            Err(e) => {
                error!("Couldn't read body: {}", e);
                match host { // TODO: factor this out
                    Some(host) => host,
                    None => {
                        error!("No friendly name or host");
                        continue;
                    },
                }
            },
        };
        println!("Name: {}", name);
        println!("App url: {}", from_utf8(app_url.as_slice()).unwrap());
    }

    println!("YAY done!");
}
