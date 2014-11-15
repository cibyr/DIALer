use std::io::net::udp::UdpSocket;
use std::io::net::ip::{Ipv4Addr, SocketAddr};
use std::str::from_utf8;

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
                println!("Received from {}:", addr);
                println!("{}", from_utf8(buf.slice(0, len)).expect("utf8"));
            }
            _ => break
        }
    }

    println!("YAY done!");
}
