#![feature(plugin)]
#![plugin(regex_macros)]

extern crate getopts;
extern crate hyper;
#[macro_use] extern crate log;
extern crate regex;
extern crate url;

use getopts::Options;
use hyper::client::Request;
use hyper::header::{ContentLength, ContentType};
use hyper::method::Method;
use hyper::mime::Mime;
use hyper::mime::TopLevel::Text;
use hyper::mime::SubLevel::Plain;
use hyper::Url;
use std::error::Error;
use std::error::FromError;
use std::fmt;
use std::old_io::net::ip::{Ipv4Addr, SocketAddr};
use std::old_io::net::udp::UdpSocket;
use std::os;
use std::str::from_utf8;


#[derive(Debug)]
enum DialError {
    DialProtocolError,
    HttpError(hyper::HttpError),
    IoError(std::old_io::IoError),
    UrlParseError(url::ParseError),
}
type DialResult<T> = Result<T, DialError>;

use self::DialError::*;

impl Error for DialError {
    fn description(&self) -> &str {
        match *self {
            DialProtocolError => "Dial protocol error",
            HttpError(_) => "HTTP error",
            IoError(_) => "I/O error",
            UrlParseError(_) => "Url parsing error",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            DialProtocolError => None,
            HttpError(ref err) => Some(err as &Error),
            IoError(ref err) => Some(err as &Error),
            UrlParseError(_) => None, // sadface
        }
    }
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl FromError<std::old_io::IoError> for DialError {
    fn from_error(err: std::old_io::IoError) -> DialError {
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
);


macro_rules! try_log_return(
    ($e:expr, $r:expr, $($arg:tt)*) => (match $e {
        Ok(e) => e,
        Err(e) => {
            error!($($arg)*, e);
            return $r;
        },
    })
);


fn get_location(response: &[u8]) -> Option<&str> {
    let location_header = "LOCATION: ";
    match from_utf8(response) {
        Ok(response) => {
            for line in response.lines_any() {
                if line.starts_with(location_header) {
                    return Some(&line[location_header.len() ..]);
                }
            }
            None
        },
        Err(_) => None
    }
}


fn get_friendly_name(body: &str) -> Option<&str> {
    let re = regex!(r"<friendlyName>(.+?)</friendlyName>");
    match re.captures(body) {
        Some(cap) => cap.at(1),
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
        let buf: &mut[u8] = &mut [0; 4096];
        match socket.recv_from(buf) {
            Ok((len, addr)) => {
                debug!("Received from {}:\n{:?}", addr.ip, from_utf8(buf.slice(0, len)));
                match get_location(&buf[0 .. len]) {
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
    rest_url: String
}


impl DialServer {
    fn new(location: &str) -> DialResult<DialServer> {
        let url = try_log!(Url::parse(location), "invalid url: {}");
        let host = url.serialize_host();
        let req = try_log!(Request::new(Method::Get, url), "Failed to connect to {}: {}", location);
        let mut res = try_log!(try_log!(req
                .start(), "Error writing headers: {}")
                .send(), "Error reading response headers: {}");
        let body = match res.read_to_string() {
            Ok(body) => Some(body),
            Err(e) => {
                error!("Couldn't read body: {}", e);
                None
            },
        };
        let rest_url = match res.headers.get_raw("Application-URL") {
            Some([ref rest_url]) => match from_utf8(rest_url.as_slice()) {
                Ok(rest_url) => rest_url,
                Err(_) => {
                    error!("invalid app url: {:?}", rest_url);
                    return Err(DialProtocolError);
                },
            },
            _ => {
                error!("No app url from {}", location);
                return Err(DialProtocolError);
            },
        };
        let friendly_name = match body {
            Some(body) => match get_friendly_name(body.as_slice()) {
                Some(name) => Some(name.to_string()),
                None => None,
            },
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
        Ok(DialServer { name: name, rest_url: rest_url.to_string() } )
    }

    fn get_app_url(&self, app_name: &str) -> String {
        if self.rest_url.ends_with("/") {
            self.rest_url.clone() + app_name
        } else {
            self.rest_url.clone() + "/" + app_name
        }
    }

    fn has_app(&self, app_name: &str) -> bool {
        let url_string = self.get_app_url(app_name);
        let url = try_log_return!(Url::parse(url_string.as_slice()), false, "invalid url: {}");
        let req = try_log_return!(Request::new(Method::Get, url), false, "Failed to connect to {}: {}", url_string);
        let started = try_log_return!(req.start(), false, "Error writing headers: {}");
        let res = try_log_return!(started.send(), false, "Error reading response headers: {}");
        res.status == hyper::status::StatusCode::Ok
    }

    fn launch_app(&self, app_name: &str, payload: Option<&str>) -> DialResult<()> {
        info!("Launching {} with payload {:?}", app_name, payload);
        let url_string = self.get_app_url(app_name);
        let url = try_log!(Url::parse(url_string.as_slice()), "invalid url: {}");
        let mut req = try_log!(Request::new(Method::Post, url), "Failed to connect to {}: {}", url_string);
        match payload {
            Some(payload) => req.headers_mut().set(ContentLength(payload.len() as u64)),
            None => req.headers_mut().set(ContentLength(0))
        };
        req.headers_mut().set(ContentType(Mime(Text, Plain, vec![])));
        let mut started = try_log!(req.start(), "Error writing headers: {}");
        match payload {
            Some(payload) => try_log!(started.write_all(payload.as_bytes()), "Error writing body: {}"),
            None => (),
        };
        let res = try_log!(started.send(), "Error reading response headers: {}");
        match res.status.class() {
            hyper::status::StatusClass::Success => Ok(()),
            _ => Err(DialProtocolError),
        }
    }
}


fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] [payload]", program);
    print!("{}", opts.usage(brief.as_slice()));
}


fn main() {
    let args: Vec<String> = os::args();
    let ref program = args[0];

    let mut options = Options::new();
    options.optopt("a", "", "set application name", "NAME");
    options.optflag("h", "help", "print this help message");
    let matches = match options.parse(args.tail()) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(program.as_slice(), options);
        return;
    }

    let app = matches.opt_str("a");
    let payload = if !matches.free.is_empty() {
        Some(matches.free[0].as_slice())
    } else {
        None
    };

    let locations = discover_dial_locations().ok().expect("discovery failed");
    let servers = locations.iter().filter_map(|loc| {
        match DialServer::new(loc.as_slice()) {
            Ok(server) => Some(server),
            Err(e)     => {
                error!("Couldn't understand DIAL server at location {}: {}", loc, e);
                None
            },
        }
    });

    match app {
        Some(app) => {
            let servers: Vec<DialServer> = servers.filter(|s| s.has_app(app.as_slice())).collect();
            match servers.len() {
                0 => panic!("Found no DIAL servers with application {:?}", app),
                1 => servers[0].launch_app(app.as_slice(), payload).ok().expect("failure to launch"),
                _ => unimplemented!(), // TODO: allow a choice betwwen multiple servers
            }
        },
        None => {
            println!("Discovered these DIAL servers:");
            for server in servers {
                let foo: String = server.name;
                println!("Name: {}", foo);
                println!("App url: {}", server.rest_url);
            }
        }
    }
}
