use anyhow::{ensure, Error};
use byteorder::{BigEndian, ByteOrder};
use serde::{Deserialize, Serialize};

use crate::dns;

// DNS record types
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const TYPE_CAA: u16 = 257;

// DNS classes
const CLASS_IN: u16 = 1;

// Google DNS JSON API response format
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DnsJsonResponse {
    pub status: u16,
    #[serde(rename = "TC")]
    pub tc: bool,
    #[serde(rename = "RD")]
    pub rd: bool,
    #[serde(rename = "RA")]
    pub ra: bool,
    #[serde(rename = "AD")]
    pub ad: bool,
    #[serde(rename = "CD")]
    pub cd: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub question: Option<Vec<DnsQuestion>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answer: Option<Vec<DnsAnswer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<Vec<DnsAnswer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional: Option<Vec<DnsAnswer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    #[serde(rename = "type")]
    pub qtype: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: u16,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    pub data: String,
}

pub fn parse_dns_to_json(packet: &[u8]) -> Result<DnsJsonResponse, Error> {
    ensure!(packet.len() >= 12, "DNS packet too short");

    // Parse header
    let flags = BigEndian::read_u16(&packet[2..4]);
    let qdcount = dns::qdcount(packet);
    let ancount = dns::ancount(packet);
    let nscount = BigEndian::read_u16(&packet[8..10]);
    let arcount = dns::arcount(packet);

    let mut response = DnsJsonResponse {
        status: dns::rcode(packet) as u16,
        tc: (flags & 0x0200) != 0,
        rd: (flags & 0x0100) != 0,
        ra: (flags & 0x0080) != 0,
        ad: (flags & 0x0020) != 0,
        cd: (flags & 0x0010) != 0,
        question: None,
        answer: None,
        authority: None,
        additional: None,
        comment: None,
    };

    let mut offset = 12;

    // Parse questions
    if qdcount > 0 {
        let mut questions = Vec::new();
        for _ in 0..qdcount {
            let (name, new_offset) = parse_name(packet, offset)?;
            offset = new_offset;
            ensure!(offset + 4 <= packet.len(), "Incomplete question");
            let qtype = BigEndian::read_u16(&packet[offset..offset + 2]);
            offset += 4; // Skip type and class
            questions.push(DnsQuestion { name, qtype });
        }
        response.question = Some(questions);
    }

    // Parse answers
    if ancount > 0 {
        let (answers, new_offset) = parse_rrs(packet, offset, ancount)?;
        offset = new_offset;
        if !answers.is_empty() {
            response.answer = Some(answers);
        }
    }

    // Parse authority section
    if nscount > 0 {
        let (authority, new_offset) = parse_rrs(packet, offset, nscount)?;
        offset = new_offset;
        if !authority.is_empty() {
            response.authority = Some(authority);
        }
    }

    // Parse additional section
    if arcount > 0 {
        let (additional, _) = parse_rrs(packet, offset, arcount)?;
        if !additional.is_empty() {
            response.additional = Some(additional);
        }
    }

    Ok(response)
}

fn parse_name(packet: &[u8], mut offset: usize) -> Result<(String, usize), Error> {
    let mut name = String::new();
    let mut jumped = false;
    let mut jump_offset = 0;
    let packet_len = packet.len();

    loop {
        ensure!(offset < packet_len, "Name extends beyond packet");
        let len = packet[offset];

        if len & 0xc0 == 0xc0 {
            // Compression pointer
            ensure!(offset + 1 < packet_len, "Incomplete compression pointer");
            if !jumped {
                jump_offset = offset + 2;
            }
            offset = (((len & 0x3f) as usize) << 8) | (packet[offset + 1] as usize);
            jumped = true;
            continue;
        }

        offset += 1;
        if len == 0 {
            break;
        }

        if !name.is_empty() {
            name.push('.');
        }

        ensure!(
            offset + len as usize <= packet_len,
            "Label extends beyond packet"
        );
        name.push_str(&String::from_utf8_lossy(
            &packet[offset..offset + len as usize],
        ));
        offset += len as usize;
    }

    if jumped {
        Ok((name, jump_offset))
    } else {
        Ok((name, offset))
    }
}

fn parse_rrs(
    packet: &[u8],
    mut offset: usize,
    count: u16,
) -> Result<(Vec<DnsAnswer>, usize), Error> {
    let mut records = Vec::new();
    let packet_len = packet.len();

    for _ in 0..count {
        let (name, new_offset) = parse_name(packet, offset)?;
        offset = new_offset;

        ensure!(offset + 10 <= packet_len, "Incomplete resource record");
        let rtype = BigEndian::read_u16(&packet[offset..offset + 2]);
        let class = BigEndian::read_u16(&packet[offset + 2..offset + 4]);
        let ttl = BigEndian::read_u32(&packet[offset + 4..offset + 8]);
        let rdlength = BigEndian::read_u16(&packet[offset + 8..offset + 10]) as usize;
        offset += 10;

        ensure!(
            offset + rdlength <= packet_len,
            "Resource data extends beyond packet"
        );

        // Skip non-IN class records and OPT records
        if class != CLASS_IN || rtype == dns::DNS_TYPE_OPT {
            offset += rdlength;
            continue;
        }

        let data = match rtype {
            TYPE_A if rdlength == 4 => {
                std::net::Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                )
                .to_string()
            }
            TYPE_AAAA if rdlength == 16 => {
                let addr_bytes: [u8; 16] = packet[offset..offset + 16].try_into().unwrap();
                std::net::Ipv6Addr::from(addr_bytes).to_string()
            }
            TYPE_CNAME | TYPE_NS | TYPE_PTR => {
                let (domain, _) = parse_name(packet, offset)?;
                domain
            }
            TYPE_MX if rdlength >= 2 => {
                let preference = BigEndian::read_u16(&packet[offset..offset + 2]);
                let (exchange, _) = parse_name(packet, offset + 2)?;
                format!("{} {}", preference, exchange)
            }
            TYPE_TXT => {
                let mut txt_data = String::new();
                let mut txt_offset = offset;
                while txt_offset < offset + rdlength {
                    let txt_len = packet[txt_offset] as usize;
                    txt_offset += 1;
                    if txt_offset + txt_len <= offset + rdlength {
                        if !txt_data.is_empty() {
                            txt_data.push(' ');
                        }
                        txt_data.push_str(&String::from_utf8_lossy(
                            &packet[txt_offset..txt_offset + txt_len],
                        ));
                        txt_offset += txt_len;
                    } else {
                        break;
                    }
                }
                txt_data
            }
            TYPE_SOA => {
                // For SOA, we'll just return a simple representation
                format!("<SOA record, {} bytes>", rdlength)
            }
            TYPE_SRV if rdlength >= 6 => {
                let priority = BigEndian::read_u16(&packet[offset..offset + 2]);
                let weight = BigEndian::read_u16(&packet[offset + 2..offset + 4]);
                let port = BigEndian::read_u16(&packet[offset + 4..offset + 6]);
                let (target, _) = parse_name(packet, offset + 6)?;
                format!("{} {} {} {}", priority, weight, port, target)
            }
            TYPE_CAA => {
                // Basic CAA record parsing
                if rdlength >= 2 {
                    let flags = packet[offset];
                    let tag_len = packet[offset + 1] as usize;
                    if offset + 2 + tag_len <= offset + rdlength {
                        let tag =
                            String::from_utf8_lossy(&packet[offset + 2..offset + 2 + tag_len]);
                        let value = String::from_utf8_lossy(
                            &packet[offset + 2 + tag_len..offset + rdlength],
                        );
                        format!("{} {} \"{}\"", flags, tag, value)
                    } else {
                        BASE64_STD.encode(&packet[offset..offset + rdlength])
                    }
                } else {
                    BASE64_STD.encode(&packet[offset..offset + rdlength])
                }
            }
            _ => {
                // For unknown types, return base64 encoded data
                BASE64_STD.encode(&packet[offset..offset + rdlength])
            }
        };

        offset += rdlength;
        records.push(DnsAnswer {
            name,
            rtype,
            ttl,
            data,
        });
    }

    Ok((records, offset))
}

/// Parse a DNS record type from either a number string or a canonical type name.
/// Supports both numeric values ("1", "28") and string names ("A", "AAAA", "any").
pub fn parse_dns_type(s: &str) -> Option<u16> {
    if let Ok(n) = s.parse::<u16>() {
        return Some(n);
    }
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        "DS" => Some(43),
        "SSHFP" => Some(44),
        "RRSIG" => Some(46),
        "NSEC" => Some(47),
        "DNSKEY" => Some(48),
        "NSEC3" => Some(50),
        "TLSA" => Some(52),
        "HTTPS" => Some(65),
        "SVCB" => Some(64),
        "CAA" => Some(257),
        "ANY" => Some(255),
        _ => None,
    }
}

// Parse JSON API query parameters
#[derive(Debug, Deserialize)]
pub struct DnsJsonQuery {
    pub name: String,
    #[serde(rename = "type")]
    pub qtype: Option<u16>,
    pub cd: Option<bool>,
    pub ct: Option<String>,
    pub do_: Option<bool>,
    pub edns_client_subnet: Option<String>,
}

// Build DNS query packet from JSON parameters
pub fn build_dns_query(query: &DnsJsonQuery) -> Result<Vec<u8>, Error> {
    let qtype = query.qtype.unwrap_or(TYPE_A);
    let mut packet = vec![0; 12];

    // Transaction ID (random)
    packet[0] = rand::random();
    packet[1] = rand::random();

    // Flags: RD (recursion desired) set by default
    packet[2] = 0x01;
    packet[3] = 0x00;

    // Set CD flag if requested
    if query.cd.unwrap_or(false) {
        packet[3] |= 0x10;
    }

    // Question count = 1
    BigEndian::write_u16(&mut packet[4..6], 1);

    // Add question
    for label in query.name.split('.') {
        if !label.is_empty() {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
    }
    packet.push(0); // Root label

    // Query type and class
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());

    // Add EDNS if DO flag is set or if we need client subnet
    if query.do_.unwrap_or(false) || query.edns_client_subnet.is_some() {
        // Increment additional count
        BigEndian::write_u16(&mut packet[10..12], 1);

        // OPT record
        packet.push(0); // Root domain
        packet.extend_from_slice(&dns::DNS_TYPE_OPT.to_be_bytes());
        packet.extend_from_slice(&[0x10, 0x00]); // UDP payload size 4096
        packet.push(0); // Extended RCODE
        packet.push(0); // Version
        let mut flags = 0u16;
        if query.do_.unwrap_or(false) {
            flags |= 0x8000; // DO flag
        }
        packet.extend_from_slice(&flags.to_be_bytes());

        // RDLENGTH placeholder
        let rdlength_pos = packet.len();
        packet.extend_from_slice(&[0, 0]);

        let mut opt_data = Vec::new();

        // Add client subnet if provided
        if let Some(subnet) = &query.edns_client_subnet {
            // Parse subnet (simplified - assumes IPv4 /24)
            if let Ok(addr) = subnet.parse::<std::net::Ipv4Addr>() {
                opt_data.extend_from_slice(&[0x00, 0x08]); // Option code 8 (client subnet)
                opt_data.extend_from_slice(&[0x00, 0x07]); // Option length
                opt_data.extend_from_slice(&[0x00, 0x01]); // Family: IPv4
                opt_data.push(24); // Source prefix length
                opt_data.push(0); // Scope prefix length
                opt_data.extend_from_slice(&addr.octets()[..3]); // First 3 octets
            }
        }

        // Update RDLENGTH
        BigEndian::write_u16(
            &mut packet[rdlength_pos..rdlength_pos + 2],
            opt_data.len() as u16,
        );
        packet.extend_from_slice(&opt_data);
    }

    Ok(packet)
}

// Export base64 for reuse
use base64::Engine;
pub const BASE64_STD: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_type_numeric() {
        assert_eq!(parse_dns_type("1"), Some(1));
        assert_eq!(parse_dns_type("28"), Some(28));
        assert_eq!(parse_dns_type("255"), Some(255));
        assert_eq!(parse_dns_type("65535"), Some(65535));
        assert_eq!(parse_dns_type("99999"), None); // out of u16 range
    }

    #[test]
    fn test_parse_dns_type_string() {
        assert_eq!(parse_dns_type("A"), Some(1));
        assert_eq!(parse_dns_type("AAAA"), Some(28));
        assert_eq!(parse_dns_type("MX"), Some(15));
        assert_eq!(parse_dns_type("TXT"), Some(16));
        assert_eq!(parse_dns_type("NS"), Some(2));
        assert_eq!(parse_dns_type("CNAME"), Some(5));
        assert_eq!(parse_dns_type("SOA"), Some(6));
        assert_eq!(parse_dns_type("PTR"), Some(12));
        assert_eq!(parse_dns_type("SRV"), Some(33));
        assert_eq!(parse_dns_type("CAA"), Some(257));
        assert_eq!(parse_dns_type("ANY"), Some(255));
    }

    #[test]
    fn test_parse_dns_type_case_insensitive() {
        assert_eq!(parse_dns_type("aaaa"), Some(28));
        assert_eq!(parse_dns_type("Aaaa"), Some(28));
        assert_eq!(parse_dns_type("any"), Some(255));
        assert_eq!(parse_dns_type("mx"), Some(15));
    }

    #[test]
    fn test_parse_dns_type_unknown() {
        assert_eq!(parse_dns_type("UNKNOWN"), None);
        assert_eq!(parse_dns_type(""), None);
        assert_eq!(parse_dns_type("notatype"), None);
    }

    #[test]
    fn test_ipv6_formatting() {
        // Build a fake AAAA answer for ::1
        let addr = std::net::Ipv6Addr::LOCALHOST;
        let bytes = addr.octets();
        let formatted = std::net::Ipv6Addr::from(bytes).to_string();
        assert_eq!(formatted, "::1");
    }

    // ── parse_dns_to_json ─────────────────────────────────────────────────────

    /// Build a minimal DNS response for `example.com` A = 1.2.3.4, TTL = 3600.
    fn make_a_response() -> Vec<u8> {
        vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags: QR=1, RD=1, RA=1, RCODE=0 (NOERROR)
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
            // Answer: example.com -> 1.2.3.4, TTL=3600
            0xc0, 0x0c, // Name: pointer to offset 12
            0x00, 0x01, // TYPE: A
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x04, // RDLENGTH: 4
            0x01, 0x02, 0x03, 0x04, // 1.2.3.4
        ]
    }

    /// Build a minimal DNS response for `example.com` AAAA = ::1, TTL = 60.
    fn make_aaaa_response() -> Vec<u8> {
        let mut p = vec![
            0x00, 0x02, // Transaction ID
            0x81, 0x80, // Flags: QR=1, RD=1, RA=1, RCODE=0
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // Question: example.com AAAA IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x1c, // QTYPE: AAAA
            0x00, 0x01, // QCLASS: IN
            // Answer: example.com -> ::1, TTL=60
            0xc0, 0x0c, // Name: pointer to offset 12
            0x00, 0x1c, // TYPE: AAAA
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x00, 0x3c, // TTL: 60
            0x00, 0x10, // RDLENGTH: 16
        ];
        // ::1 in 16 bytes
        p.extend_from_slice(&[0u8; 15]);
        p.push(0x01);
        p
    }

    #[test]
    fn test_parse_dns_to_json_a_record() {
        let packet = make_a_response();
        let result = parse_dns_to_json(&packet);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
        let json = result.unwrap();

        assert_eq!(json.status, 0); // NOERROR
        assert!(!json.tc);
        assert!(json.rd);
        assert!(json.ra);

        let questions = json.question.expect("question section missing");
        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].name, "example.com");
        assert_eq!(questions[0].qtype, 1); // A

        let answers = json.answer.expect("answer section missing");
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].rtype, 1); // A
        assert_eq!(answers[0].ttl, 3600);
        assert_eq!(answers[0].data, "1.2.3.4");
    }

    #[test]
    fn test_parse_dns_to_json_aaaa_record() {
        let packet = make_aaaa_response();
        let result = parse_dns_to_json(&packet);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
        let json = result.unwrap();

        assert_eq!(json.status, 0);
        let answers = json.answer.expect("answer section missing");
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].rtype, 28); // AAAA
        assert_eq!(answers[0].ttl, 60);
        assert_eq!(answers[0].data, "::1");
    }

    #[test]
    fn test_parse_dns_to_json_no_answer() {
        // A minimal query (no answers) – status should reflect flags
        let packet = vec![
            0x00, 0x01,
            0x81, 0x83, // QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01,
            0x00, 0x01,
        ];
        let result = parse_dns_to_json(&packet);
        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(json.status, 3); // NXDOMAIN
        assert!(json.answer.is_none());
    }

    #[test]
    fn test_parse_dns_to_json_short_packet_error() {
        let packet = vec![0u8; 5];
        assert!(parse_dns_to_json(&packet).is_err());
    }

    // ── build_dns_query ───────────────────────────────────────────────────────

    fn make_default_query(name: &str) -> DnsJsonQuery {
        DnsJsonQuery {
            name: name.to_string(),
            qtype: None,
            cd: None,
            ct: None,
            do_: None,
            edns_client_subnet: None,
        }
    }

    #[test]
    fn test_build_dns_query_basic() {
        let q = make_default_query("example.com");
        let result = build_dns_query(&q);
        assert!(result.is_ok());
        let pkt = result.unwrap();
        // Must be at least 17 bytes (12 header + minimal question)
        assert!(pkt.len() >= 17);
        // QDCOUNT = 1
        assert_eq!(byteorder::BigEndian::read_u16(&pkt[4..6]), 1);
        // Flags: RD set (byte 2 bit 0)
        assert_ne!(pkt[2] & 0x01, 0);
        // QTYPE defaults to A (1)
        // Find the QTYPE in the question section (after the encoded name)
        let name_end = pkt[12..].iter().position(|&b| b == 0).unwrap();
        let qtype_offset = 12 + name_end + 1;
        let qtype = byteorder::BigEndian::read_u16(&pkt[qtype_offset..qtype_offset + 2]);
        assert_eq!(qtype, 1); // A
    }

    #[test]
    fn test_build_dns_query_with_explicit_qtype() {
        let mut q = make_default_query("example.com");
        q.qtype = Some(28); // AAAA
        let pkt = build_dns_query(&q).unwrap();
        let name_end = pkt[12..].iter().position(|&b| b == 0).unwrap();
        let qtype_offset = 12 + name_end + 1;
        let qtype = byteorder::BigEndian::read_u16(&pkt[qtype_offset..qtype_offset + 2]);
        assert_eq!(qtype, 28); // AAAA
    }

    #[test]
    fn test_build_dns_query_cd_flag() {
        let mut q = make_default_query("example.com");
        q.cd = Some(true);
        let pkt = build_dns_query(&q).unwrap();
        // CD flag is bit 4 of byte 3
        assert_ne!(pkt[3] & 0x10, 0, "CD flag should be set");
    }

    #[test]
    fn test_build_dns_query_no_cd_flag() {
        let q = make_default_query("example.com");
        let pkt = build_dns_query(&q).unwrap();
        assert_eq!(pkt[3] & 0x10, 0, "CD flag should not be set");
    }

    #[test]
    fn test_build_dns_query_with_do_flag_adds_edns() {
        let mut q = make_default_query("example.com");
        q.do_ = Some(true);
        let pkt = build_dns_query(&q).unwrap();
        // ARCOUNT should be 1 (OPT record added)
        assert_eq!(byteorder::BigEndian::read_u16(&pkt[10..12]), 1);
    }

    #[test]
    fn test_build_dns_query_no_edns_by_default() {
        let q = make_default_query("example.com");
        let pkt = build_dns_query(&q).unwrap();
        // ARCOUNT should be 0
        assert_eq!(byteorder::BigEndian::read_u16(&pkt[10..12]), 0);
    }
}
