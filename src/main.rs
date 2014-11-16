#![feature(macro_rules)]
#![feature(phase)]

extern crate hyper;
#[phase(plugin, link)] extern crate log;
#[phase(plugin)] extern crate regex_macros;
extern crate regex;
extern crate url;

use hyper::Url;
use hyper::client::Request;
use std::error;
use std::error::FromError;
use std::io::net::udp::UdpSocket;
use std::io::net::ip::{Ipv4Addr, SocketAddr};
use std::str::from_utf8;


#[deriving(Show)]
enum DialError {
    DialProtocolError,
    HttpError(hyper::HttpError),
    IoError(std::io::IoError),
    UrlParseError(url::ParseError),
}
type DialResult<T> = Result<T, DialError>;

impl error::Error for DialError {
    fn description(&self) -> &str {
        match *self {
            DialProtocolError => "Dial protocol error",
            HttpError(_) => "HTTP error",
            IoError(_) => "I/O error",
            UrlParseError(_) => "Url parsing error",
        }
    }

    fn detail(&self) -> Option<String> {
        match *self {
            DialProtocolError => None,
            HttpError(ref err) => err.detail(),
            IoError(ref err) => err.detail(),
            UrlParseError(_) => None,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            DialProtocolError => None,
            HttpError(ref err) => Some(err as &error::Error),
            IoError(ref err) => Some(err as &error::Error),
            UrlParseError(_) => None, // sadface
        }
    }
}

impl FromError<std::io::IoError> for DialError {
    fn from_error(err: std::io::IoError) -> DialError {
        IoError(err)
    }
}

impl FromError<hyper::HttpError> for DialError {
    fn from_error(err: hyper::HttpError) -> DialError {
        HttpError(err)
    }
}

impl FromError<url::ParseError> for DialError {
    fn from_error(err: url::ParseError) -> DialError {
        UrlParseError(err)
    }
}
// TODO: it seems like it should be possible to write a macro which generates
// Error-wrapping types for you.


macro_rules! try_log(
    ($e:expr, $($arg:tt)*) => (match $e {
        Ok(e) => e,
        Err(e) => {
            error!($($arg)*, e);
            return Err(::std::error::FromError::from_error(e));
        },
    })
)


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


fn discover_dial_locations() -> DialResult<Vec<String>> {
    let any_addr = SocketAddr { ip: Ipv4Addr(0, 0, 0, 0), port: 0 };
    let dst_addr = SocketAddr { ip: Ipv4Addr(239, 255, 255, 250), port: 1900 };
    let ssdp_msearch =
        "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 2\r\n\
        ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n";

    let mut socket = try_log!(UdpSocket::bind(any_addr), "bind: {}");
    debug!("Sending to {}:\n{}", dst_addr, ssdp_msearch);
    try_log!(socket.send_to(ssdp_msearch.as_bytes(), dst_addr), "send_to: {}");
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


struct DialServer {
    name: String,
    app_url: String
}


impl DialServer {
    fn new(location: &str) -> DialResult<DialServer> {
        let url = try_log!(Url::parse(location), "invalid url: {}");
        let host = url.serialize_host();
        let req = try_log!(Request::get(url), "Failed to connect to {}: {}", location);
        let mut res = try_log!(try_log!(req
                .start(), "Error writing headers: {}")
                .send(), "Error reading response headers: {}");
        let app_url = match res.headers.get_raw("Application-URL") {
            Some([ref app_url]) => match from_utf8(app_url.as_slice()) {
                Some(app_url) => app_url,
                None => {
                    error!("invalid app url: {}", app_url);
                    return Err(DialProtocolError);
                },
            },
            _ => {
                error!("No app url from {}", location);
                return Err(DialProtocolError);
            },
        };
        let body = match res.read_to_string() {
            Ok(body) => Some(body),
            Err(e) => {
                error!("Couldn't read body: {}", e);
                None
            },
        };
        let friendly_name = match body {
            Some(body) => Some(get_friendly_name(body.as_slice()).to_string()),
            None => None,
        };
        let name = match friendly_name {
            Some(name) => name,
            None => match host {
                Some(host) => host,
                None => {
                    error!("No friendly name or host");
                    return Err(DialProtocolError);
                },
            },
        };
        Ok(DialServer { name: name, app_url: app_url.to_string() } )
    }
}


fn main() {
    let locations = discover_dial_locations().ok().expect("discovery failed");
    for location in locations.iter() {
        match DialServer::new(location.as_slice()) {
            Ok(DialServer { name, app_url } ) => {
                println!("Name: {}", name);
                println!("App url: {}", app_url);
            },
            Err(e) => {
                error!("Couldn't understand DIAL server at location {}: {}", location, e);
            }
        }
    }

    println!("YAY done!");
}
