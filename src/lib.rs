use std::io::{self, Read, Write};
use std::net::TcpStream;

use std::mem;

extern crate time;

extern crate crc;
use crc::crc32;
use crc::Hasher32;

extern crate rand;
use rand::Rng;

extern crate num;
use num::bigint::BigUint;
use num::integer::gcd;
use num::pow;
use num::FromPrimitive;
use num::ToPrimitive;
use num::Zero;

extern crate openssl;
use openssl::{hash, rsa, aes, symm};

pub struct Mtprs {
    stream: TcpStream,
    seq_num: u32,
    server_seq_num: u32,
    rsa: rsa::Rsa
}

impl Mtprs {
    pub fn new() -> Mtprs {
        Mtprs {
            stream: TcpStream::connect("149.154.167.40:443").unwrap(),
            seq_num: 0,
            server_seq_num: 0,
            rsa: rsa::Rsa::public_key_from_pem(b"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwVACPi9w23mF3tBkdZz+
zwrzKOaaQdr01vAbU4E1pvkfj4sqDsm6lyDONS789sVoD/xCS9Y0hkkC3gtL1tSf
TlgCMOOul9lcixlEKzwKENj1Yz/s7daSan9tqw3bfUV/nqgbhGX81v/+7RFAEd+R
wFnK7a+XYl9sluzHRyVVaTTveB2GazTwEfzk2DWgkBluml8OREmvfraX3bkHZJTK
X4EQSjBbbdJ2ZXIsRrYOXfaA+xayEGB+8hdlLmAjbCVfaigxX0CDqWeR1yFL9kwd
9P0NsZRPsmoqVwMbMu7mStFai6aIhc3nSlv8kg9qv1m6XHVQY3PnEw+QQtqSIXkl
HwIDAQAB
-----END PUBLIC KEY-----").unwrap()
        }
    }

    pub fn auth(&mut self) -> io::Result<()> {
        let mut nonce = [0; 16];
        let mut server_nonce = [0; 16];
        let mut new_nonce = [0; 32];

        let mut buf = [0x78, 0x97, 0x46, 0x60,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        rand::thread_rng().fill_bytes(&mut buf[4..]);
        nonce.copy_from_slice(&buf[4..]);
        self.send(&buf)?;

        let mut buf = self.recv()?;
        if buf.drain(..4).collect::<Vec<u8>>() != vec![0x63, 0x24, 0x16, 0x05] {
            println!("!!! AUTH: resPQ NOT RECEIVED !!!");
            panic!();  // TODO do something better
        }
        if buf.drain(..16).collect::<Vec<u8>>() != nonce {
            println!("!!! AUTH: NONCE MISMATCH !!!");
            panic!();  // TODO do something better
        }
        server_nonce.copy_from_slice(buf.drain(..16).collect::<Vec<u8>>().as_slice());
        let mut raw_pq = [0; 12];
        let mut pq_buf = [0; 8];
        raw_pq.copy_from_slice(buf.drain(..12).collect::<Vec<u8>>().as_slice());
        pq_buf.copy_from_slice(&raw_pq[1..9]);
        let pq = dec64(pq_buf).to_be();
        // TODO we don't actually need the rest of the response,
        // but check it maybe

        let p = factor(pq);
        let q = (pq / (p as u64)) as u32;
        let mut raw_p = [4, 0, 0, 0, 0, 0, 0, 0];
        let mut raw_q = [4, 0, 0, 0, 0, 0, 0, 0];
        raw_p[1..5].copy_from_slice(&enc(if p < q { p } else { q }.to_be()));
        raw_q[1..5].copy_from_slice(&enc(if p > q { p } else { q }.to_be()));

        let mut data = [0; 256];
        data[21..25].copy_from_slice(&[0xEC, 0x5A, 0xC9, 0x83]);
        data[25..37].copy_from_slice(&raw_pq);
        data[37..45].copy_from_slice(&raw_p);
        data[45..53].copy_from_slice(&raw_q);
        data[53..69].copy_from_slice(&nonce);
        data[69..85].copy_from_slice(&server_nonce);
        rand::thread_rng().fill_bytes(&mut new_nonce);
        data[85..117].copy_from_slice(&new_nonce);
        let sha1 = hash::hash2(hash::MessageDigest::sha1(), &data[21..117]).unwrap();
        data[1..21].copy_from_slice(&sha1);

        let mut buf = [0; 320];
        buf[0..4].copy_from_slice(&[0xBE, 0xE4, 0x12, 0xD7]);
        buf[4..20].copy_from_slice(&nonce);
        buf[20..36].copy_from_slice(&server_nonce);
        buf[36..44].copy_from_slice(&raw_p);
        buf[44..52].copy_from_slice(&raw_q);
        buf[52..60].copy_from_slice(&[0x21, 0x6B, 0xE8, 0x6C, 0x02, 0x2B, 0xB4, 0xC3]);
        buf[60..64].copy_from_slice(&[0xFE, 0x00, 0x01, 0x00]);
        self.rsa.public_encrypt(&data, &mut buf[64..320], rsa::NO_PADDING).unwrap();
        self.send(&buf)?;

        let mut buf = self.recv()?;
        if buf.drain(..4).collect::<Vec<u8>>() != vec![0x5C, 0x07, 0xE8, 0xD0] {
            println!("!!! AUTH: server_DH_params_ok NOT RECEIVED !!!");
            panic!();  // TODO do something better
        }
        if buf.drain(..16).collect::<Vec<u8>>() != nonce {
            println!("!!! AUTH: NONCE MISMATCH !!!");
            panic!();  // TODO do something better
        }
        if buf.drain(..16).collect::<Vec<u8>>() != server_nonce {
            println!("!!! AUTH: SERVER NONCE MISMATCH !!!");
            panic!();  // TODO do something better
        }
        buf.drain(..4); // TODO maybe verify this?
        let (mut ns, mut sn, mut nn) = ([0; 48], [0; 48], [0; 64]);
        ns[0..32].copy_from_slice(&new_nonce);
        ns[32..48].copy_from_slice(&server_nonce);
        sn[0..16].copy_from_slice(&server_nonce);
        sn[16..48].copy_from_slice(&new_nonce);
        nn[0..32].copy_from_slice(&new_nonce);
        nn[32..64].copy_from_slice(&new_nonce);
        let (sha1ns, sha1sn, sha1nn) =
            (hash::hash2(hash::MessageDigest::sha1(), &ns).unwrap(),
             hash::hash2(hash::MessageDigest::sha1(), &sn).unwrap(),
             hash::hash2(hash::MessageDigest::sha1(), &nn).unwrap());
        let (mut key, mut iv) = ([0; 32], [0; 32]);
        key[0..20].copy_from_slice(&sha1ns);
        key[20..32].copy_from_slice(&sha1sn[0..12]);
        iv[0..8].copy_from_slice(&sha1sn[12..20]);
        iv[8..28].copy_from_slice(&sha1nn);
        iv[28..32].copy_from_slice(&new_nonce[0..4]);
        let dec_key = aes::AesKey::new_decrypt(&key).unwrap();
        let mut data = vec![0; buf.len()];
        let mut iv2 = iv.clone();
        aes::aes_ige(&buf, &mut data, &dec_key, &mut iv, symm::Mode::Decrypt);

        data.drain(..20); // TODO check this random sha1 that's here for some reason
        if data.drain(..4).collect::<Vec<u8>>() != vec![0xBA, 0x0D, 0x89, 0xB5] {
            println!("!!! AUTH: server_DH_inner_data NOT RECEIVED !!!");
            panic!();  // TODO do something better
        }
        if data.drain(..16).collect::<Vec<u8>>() != nonce {
            println!("!!! AUTH: NONCE MISMATCH !!!");
            panic!();  // TODO do something better
        }
        if data.drain(..16).collect::<Vec<u8>>() != server_nonce {
            println!("!!! AUTH: SERVER NONCE MISMATCH !!!");
            panic!();  // TODO do something better
        }
        let g = *data.first().unwrap();
        data.drain(..8); // TODO maybe check last 4
        let p = BigUint::from_bytes_be(&data.drain(..256).collect::<Vec<u8>>());
        data.drain(..4); // TODO maybe check
        let g_a = BigUint::from_bytes_be(&data.drain(..256).collect::<Vec<u8>>());
        // TODO maybe check server time

        let mut raw_b = [0; 256];
        rand::thread_rng().fill_bytes(&mut raw_b);
        let b = BigUint::from_bytes_be(&raw_b);
        let g_b = pow_mod(g, b, &p);
        let raw_g_b = g_b.to_bytes_be();

        let (mut data, mut buf) = ([0; 336], [0; 376]);
        data[20..24].copy_from_slice(&[0x54, 0xB6, 0x43, 0x66]);
        data[24..40].copy_from_slice(&nonce);
        data[40..56].copy_from_slice(&server_nonce);
        data[64..68].copy_from_slice(&[0xFE, 0x00, 0x01, 0x00]);
        data[(68 + (256 - raw_g_b.len()))..324].copy_from_slice(&raw_g_b);
        let sha1 = hash::hash2(hash::MessageDigest::sha1(), &data[20..324]).unwrap();
        data[0..20].copy_from_slice(&sha1);
        let enc_key = aes::AesKey::new_encrypt(&key).unwrap();
        aes::aes_ige(&data, &mut buf[40..376], &enc_key, &mut iv2, symm::Mode::Encrypt);

        buf[0..4].copy_from_slice(&[0x1F, 0x5F, 0x04, 0xF5]);
        buf[4..20].copy_from_slice(&nonce);
        buf[20..36].copy_from_slice(&server_nonce);
        buf[36..40].copy_from_slice(&[0xFE, 0x50, 0x01, 0x00]);
        self.send(&buf)?;

        let mut buf = self.recv()?;
        if buf.drain(..4).collect::<Vec<u8>>() != vec![0x34, 0xF7, 0xCB, 0x3B] {
            println!("!!! AUTH: dh_gen_ok NOT RECEIVED !!!");
            panic!();  // TODO do something better
        }
        if buf.drain(..16).collect::<Vec<u8>>() != nonce {
            println!("!!! AUTH: NONCE MISMATCH !!!");
            panic!();  // TODO do something better
        }
        if buf.drain(..16).collect::<Vec<u8>>() != server_nonce {
            println!("!!! AUTH: SERVER NONCE MISMATCH !!!");
            panic!();  // TODO do something better
        }

        Ok(())
    }

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        let packet_len = (bytes.len() + 32) as u32;
        let raw_packet_len: [u8; 4] = enc(packet_len);

        let seq_num = self.seq_num;
        let raw_seq_num: [u8; 4] = enc(seq_num);
        self.seq_num += 1;

        let now = time::get_time();
        let id = ((now.sec as f64 + now.nsec as f64 / 10f64.powi(9))
                  * 2f64.powi(32)) as u64;
        let raw_id: [u8; 8] = enc64(id);

        let len = bytes.len() as u32;
        let raw_len: [u8; 4] = enc(len);

        let mut buf: Vec<u8> = Vec::new();
        buf.write(&raw_packet_len)?;  // 4 bytes
        buf.write(&raw_seq_num)?;     // 4 bytes
        buf.write(&[0; 8])?;          // 8 bytes
        buf.write(&raw_id)?;          // 8 bytes
        buf.write(&raw_len)?;         // 4 bytes
        buf.write(bytes)?;

        let checksum = crc32::checksum_ieee(&buf[..]);
        let raw_checksum: [u8; 4] = enc(checksum);
        buf.write(&raw_checksum)?;    // 4 bytes

        println!("PRE: {:?}", buf);
        println!("SENDING DATA: {:?}", bytes);
        self.stream.write(&buf)?;

        Ok(())
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut raw_packet_len = [0; 4];
        self.stream.read(&mut raw_packet_len)?;
        let packet_len: u32 = dec(raw_packet_len);

        let mut raw_seq_num = [0; 4];
        self.stream.read(&mut raw_seq_num)?;
        let seq_num: u32 = dec(raw_seq_num);
        if seq_num != self.server_seq_num {
            println!("!!! BAD SEQUENCE NUMBER !!!");
            println!("{} (expected) != {} (received)",
                self.server_seq_num, seq_num);
        }
        self.server_seq_num += 1;

        let mut data = Vec::with_capacity((packet_len - 12) as usize);
        <TcpStream as Read>::by_ref(&mut self.stream)
            .take((packet_len - 12) as u64).read_to_end(&mut data)?;

        let mut raw_checksum = [0; 4];
        self.stream.read(&mut raw_checksum)?;
        let checksum = dec(raw_checksum);

        let mut digest = crc32::Digest::new(crc32::IEEE);
        digest.write(&raw_packet_len);
        digest.write(&raw_seq_num);
        digest.write(&data);
        let computed_checksum = digest.sum32();

        if checksum != computed_checksum {
            println!("!!! CHECKSUM MISMATCH !!!");
            println!("{} (received) != {} (computed)",
                checksum, computed_checksum);
        }

        println!("PRE: {:?}", data);
        data.drain(..20);
        println!("RECIEVING DATA: {:?}", data);
        Ok(data)
    }
}

fn enc(i: u32) -> [u8; 4] { unsafe { mem::transmute(i) } }
fn dec(a: [u8; 4]) -> u32 { unsafe { mem::transmute(a) } }
fn enc64(i: u64) -> [u8; 8] { unsafe { mem::transmute(i) } }
fn dec64(a: [u8; 8]) -> u64 { unsafe { mem::transmute(a) } }

// pollard rho algorithm
fn factor(n: u64) -> u32 {
    let mut x = 2u64;
    let mut y = 2u64;
    // TODO make this less disgusting
    let bn = BigUint::from_u64(n).unwrap();
    let f = |i| (pow(BigUint::from_u64(i).unwrap(), 2) % bn.clone()).to_u64().unwrap() + 1;
    loop {
        x = f(x);
        y = f(f(y));
        let d = gcd(if x > y { x - y } else { y - x }, n);
        if d != 1 { return d as u32; }
    }
}

// (b ** e) % m
fn pow_mod(b: u8, e: BigUint, m: &BigUint) -> BigUint {
    let mut b = BigUint::from_u8(b).unwrap();
    let mut e = e.clone();
    let one = BigUint::from_u32(1).unwrap();
    let mut res = one.clone();
    while e > BigUint::zero() {
        if &e % BigUint::from_u32(2).unwrap() == one {
            res = (&res * &b) % m;
        }
        e = e >> 1;
        b = (&b * &b) % m;
    }
    res
}
