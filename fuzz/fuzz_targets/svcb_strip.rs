#![no_main]
//! The SVCB/HTTPS private-hint scrubber (rebind protection, v0.21.0) walks
//! attacker-controlled RDATA. It's the newest untrusted-input path and runs on
//! every HTTPS/SVCB answer when rebind_protect is on. A panic here is a DoS
//! reachable through any public name.
use libfuzzer_sys::fuzz_target;
use numa::svcb::strip_private_hints;
use std::net::IpAddr;

fuzz_target!(|data: &[u8]| {
    // Strip everything private so the scrubber exercises its rewrite path, not
    // just the early-return.
    let _ = strip_private_hints(data, |ip: IpAddr| match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    });
});
