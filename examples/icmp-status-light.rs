//! Turn an authenticated ICMP echo request into a reply without reallocating.
//!
//! A real firmware integration can use the same event to pulse an activity LED
//! while returning the modified packet through WireGuard.

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};

use tailscale_esp32::netmap::icmp_echo_reply_in_place;

const DEVICE_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 4);
const MONITOR_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);

fn main() -> Result<(), Box<dyn Error>> {
    let mut packet = ipv4_echo_request(MONITOR_IP, DEVICE_IP, b"status");
    let reply = icmp_echo_reply_in_place(&mut packet)?;

    let mut light = DemoStatusLight::default();
    light.pulse();

    assert_eq!(reply.source, IpAddr::V4(MONITOR_IP));
    assert_eq!(reply.destination, IpAddr::V4(DEVICE_IP));
    assert_eq!(packet[20], 0);
    println!("ICMP reply prepared in place: {} bytes", reply.packet_len);
    println!("status light pulses: {}", light.pulses);
    Ok(())
}

#[derive(Default)]
struct DemoStatusLight {
    pulses: u64,
}

impl DemoStatusLight {
    fn pulse(&mut self) {
        self.pulses = self.pulses.saturating_add(1);
    }
}

fn ipv4_echo_request(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    packet[20] = 8;
    packet[24..26].copy_from_slice(&7_u16.to_be_bytes());
    packet[26..28].copy_from_slice(&1_u16.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let icmp_checksum = internet_checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    packet
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]) as u32)
        .sum::<u32>();
    if let Some(last) = bytes.chunks_exact(2).remainder().first() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
