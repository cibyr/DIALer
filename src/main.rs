use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::{debug, error, info};
use regex::Regex;
use reqwest::Url;

use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::str::from_utf8;
use std::time::Duration;

fn get_location(response: &[u8]) -> Option<&str> {
    let location_header = "LOCATION: ";
    match from_utf8(response) {
        Ok(response) => {
            for line in response.lines() {
                if line.starts_with(location_header) {
                    return Some(&line[location_header.len()..]);
                }
            }
            None
        }
        Err(_) => None,
    }
}

fn get_friendly_name(body: &str) -> Option<&str> {
    let re = Regex::new(r"<friendlyName>(.+?)</friendlyName>").unwrap();
    match re.captures(body) {
        Some(cap) => cap.get(1).map(|m| m.as_str()),
        None => None,
    }
}

fn discover_dial_locations() -> Result<Vec<String>> {
    let any_addr = (Ipv4Addr::new(0, 0, 0, 0), 0);
    let dst_addr = (Ipv4Addr::new(239, 255, 255, 250), 1900);
    let ssdp_msearch = "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 2\r\n\
        ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n";

    let socket = UdpSocket::bind(any_addr).context("bind to UDP Socket")?;
    debug!("Sending to {:?}:\n{}", dst_addr, ssdp_msearch);
    socket
        .send_to(ssdp_msearch.as_bytes(), dst_addr)
        .context("send_to()")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("set_read_timeout")?;

    let mut result = Vec::new();
    loop {
        let buf: &mut [u8] = &mut [0; 4096];
        match socket.recv_from(buf) {
            Ok((len, addr)) => {
                debug!("Received from {}:\n{:?}", addr, from_utf8(&buf[0..len]));
                match get_location(&buf[0..len]) {
                    Some(location) => result.push(location.to_string()),
                    None => (),
                }
            }
            _ => break,
        }
    }
    Ok(result)
}

struct DialServer {
    name: String,
    rest_url: String,
}

impl DialServer {
    fn new(location: &str) -> Result<Self> {
        let url = Url::parse(location).context("invalid url")?;
        let host = url.host_str().ok_or(anyhow!("No host"))?;
        let resp = reqwest::blocking::get(location)
            .with_context(|| format!("Failed to connect to {}", location))?;
        let rest_url = resp
            .headers()
            .get("Application-URL")
            .with_context(|| format!("No app URL from {}", location))?
            .to_str()?
            .to_string();
        let body = resp.text()?;
        let friendly_name = get_friendly_name(&body);
        let name = match friendly_name {
            Some(name) => name,
            None => host,
        };
        Ok(DialServer {
            name: name.to_string(),
            rest_url: rest_url,
        })
    }

    fn get_app_url(&self, app_name: &str) -> String {
        if self.rest_url.ends_with("/") {
            self.rest_url.clone() + app_name
        } else {
            self.rest_url.clone() + "/" + app_name
        }
    }

    fn try_has_app(&self, app_name: &str) -> Result<reqwest::StatusCode> {
        let resp = reqwest::blocking::get(self.get_app_url(app_name))?;
        return Ok(resp.status());
    }

    fn has_app(&self, app_name: &str) -> bool {
        match self.try_has_app(app_name) {
            Ok(status) => status.is_success(),
            Err(e) => {
                error!("{}", e);
                false
            }
        }
    }

    fn launch_app(&self, app_name: &str, payload: Option<&str>) -> Result<()> {
        use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT};

        info!("Launching {} with payload {:?}", app_name, payload);

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("DAILer"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));

        let client = reqwest::blocking::Client::new();
        let req = client.post(self.get_app_url(app_name));
        let req = if let Some(payload) = payload {
            req.body(payload.to_string())
        } else {
            req
        };
        let req = req.headers(headers);
        req.send()?.error_for_status()?;
        Ok(())
    }
}

/// DIAL protocol client
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Application name
    #[arg(short, long)]
    app: Option<String>,
    /// Payload for launching application
    payload: Option<String>,
}

fn main() {
    pretty_env_logger::init();

    let args = Args::parse();

    let locations = discover_dial_locations().ok().expect("discovery failed");
    let servers = locations
        .iter()
        .filter_map(|loc| match DialServer::new(&loc) {
            Ok(server) => Some(server),
            Err(e) => {
                error!("Couldn't understand DIAL server at location {}: {}", loc, e);
                None
            }
        });

    match args.app {
        Some(app) => {
            let servers: Vec<DialServer> = servers.filter(|s| s.has_app(&app)).collect();
            match servers.len() {
                0 => panic!("Found no DIAL servers with application {:?}", app),
                1 => servers[0]
                    .launch_app(&app, args.payload.as_deref())
                    .ok()
                    .expect("failure to launch"),
                _ => unimplemented!(), // TODO: allow a choice betwwen multiple servers
            }
        }
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
