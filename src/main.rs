use std::{
    io::{Cursor, Write},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::Arc,
};

use clap::Parser;
use rand::Rng;
use tun_tap::{Iface, Mode};

#[derive(Parser)]
struct Opts {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

fn main() {
    let opts = Opts::parse();

    let socket = Arc::new(UdpSocket::bind(opts.local_addr).unwrap());
    UdpSocket::connect(&socket, opts.peer_addr).unwrap();

    let iface = Arc::new(Iface::new("tun%d", Mode::Tun).unwrap());
    let name = iface.name();

    eprintln!("Setup TUN device {name}");
    // Should probably set MTU to something lower than 255 / (8/5)

    let iptodns_thread = std::thread::spawn({
        let socket = socket.clone();
        let iface = iface.clone();

        move || iptodns(socket, iface)
    });
    let dnstoip_thread = std::thread::spawn({
        let socket = socket.clone();
        let iface = iface.clone();

        move || dnstoip(socket, iface)
    });

    iptodns_thread.join().unwrap();
    dnstoip_thread.join().unwrap();
}

fn dnstoip(socket: Arc<UdpSocket>, iface: Arc<Iface>) {
    let mut buf = vec![0u8; 1024];
    let mut ip_recv_buf = String::with_capacity(1024);
    loop {
        let len = socket.recv(&mut buf).unwrap();
        let buf = &buf[..len];

        println!("Received DNS packet of length {len}");

        let packet = &buf[0x0c..]; // Skip DNS stuff

        ip_recv_buf.clear();
        let mut rest = packet;
        while rest[0] != 0x00 {
            let next = rest[0] as usize;
            let part = &rest[1..][..next];
            ip_recv_buf.push_str(std::str::from_utf8(part).unwrap());
            rest = &rest[1 + next..];
        }

        let ip_packet =
            base_encode::from_str(&ip_recv_buf, ALPHABET_SIZE as u8, &ALPHABET).unwrap();

        describe_ipv4_packet(&ip_packet);
        println!("{}", ip_packet.len());

        iface.send(&ip_packet).unwrap();
    }
}

fn iptodns(socket: Arc<UdpSocket>, iface: Arc<Iface>) {
    let mut rng = rand::thread_rng();

    let mut buf = vec![0u8; 1024];
    let mut dns_buf = Vec::with_capacity(1024);
    loop {
        let len = iface.recv(&mut buf).unwrap();
        let buf = &buf[..len];

        let _flags = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let proto = u16::from_be_bytes(buf[2..4].try_into().unwrap());

        match recognise_proto(proto) {
            Some(Proto::IPv4) => {
                // let packet = &buf[4..];
                let packet = &buf[0..];

                describe_ipv4_packet(packet);
                println!("{}", packet.len());

                dns_buf.clear();
                let mut dns_cursor = Cursor::new(&mut dns_buf);

                // Header
                dns_cursor
                    .write_all(&rng.gen::<u16>().to_be_bytes()) // ID
                    .unwrap();
                dns_cursor.write_all(&[0x01, 0x20]).unwrap();

                // Counts
                dns_cursor.write_all(&1u16.to_be_bytes()).unwrap(); // Questions
                dns_cursor.write_all(&0u16.to_be_bytes()).unwrap(); // Answers
                dns_cursor.write_all(&0u16.to_be_bytes()).unwrap(); // Nameservers
                dns_cursor.write_all(&0u16.to_be_bytes()).unwrap(); // Additionals

                let rest_str =
                    base_encode::to_string(packet, ALPHABET_SIZE as u8, &ALPHABET).unwrap();
                let mut rest = rest_str.as_bytes();
                eprintln!("Size before: {}, size after: {}", packet.len(), rest.len());
                while rest.len() > 0 {
                    let next = rest.len().min(63);
                    dns_cursor.write_all(&(next as u8).to_be_bytes()).unwrap();
                    dns_cursor.write_all(&rest[..next]).unwrap();

                    rest = &rest[next..];
                }
                dns_cursor
                    .write_all(&[
                        0x00, // Null terminator
                        0x00, 0x01, // A
                        0x00, 0x01, // in
                    ])
                    .unwrap();

                drop(dns_cursor);
                socket.send(&dns_buf).unwrap();
            }
            Some(Proto::IPv6) => {
                eprintln!("Ignoring IPv6 packet");
            }
            None => {
                eprintln!("Unrecognised protocol {proto:0>4x}");
            }
        }
    }
}

enum Proto {
    IPv4,
    IPv6,
}

fn recognise_proto(n: u16) -> Option<Proto> {
    match n {
        0x0800 => Some(Proto::IPv4),
        0x86dd => Some(Proto::IPv6),
        _ => None,
    }
}

fn describe_ipv4_packet(packet: &[u8]) {
    let source_addr = &packet[12..16];
    let target_addr = &packet[16..20];

    let source_addr = Ipv4Addr::new(
        source_addr[0],
        source_addr[1],
        source_addr[2],
        source_addr[3],
    );
    let target_addr = Ipv4Addr::new(
        target_addr[0],
        target_addr[1],
        target_addr[2],
        target_addr[3],
    );

    let ihl = u8::from_be_bytes([packet[0]]) & 0x0f;
    let len = u16::from_be_bytes([packet[2], packet[3]]);
    let more_fragments = packet[6] & 0b0010_0000 != 0;
    let fragmentation_offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1f_ff;

    eprintln!("Received packet of length {len} (IHL {ihl}) from {source_addr} to {target_addr}");
    if more_fragments {
        eprintln!("The packet is followed by more fragments");
    }
    if fragmentation_offset != 0 {
        eprintln!("The packet has fragmentation offset {fragmentation_offset}");
    }
}

const ALPHABET_SIZE: usize = 63;
const ALPHABET: [u8; ALPHABET_SIZE] =
    *b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
