use anyhow::{ensure, Error};
use byteorder::{BigEndian, ByteOrder};

const DNS_HEADER_SIZE: usize = 12;
pub const DNS_OFFSET_FLAGS: usize = 2;
const DNS_MAX_HOSTNAME_SIZE: usize = 256;
const DNS_MAX_PACKET_SIZE: usize = 4096;
const DNS_OFFSET_QUESTION: usize = DNS_HEADER_SIZE;

const DNS_FLAGS_TC: u16 = 1u16 << 9;

pub const DNS_TYPE_OPT: u16 = 41;

const DNS_PTYPE_PADDING: u16 = 12;

const DNS_RCODE_SERVFAIL: u8 = 2;
const DNS_RCODE_REFUSED: u8 = 5;

#[inline]
pub fn rcode(packet: &[u8]) -> u8 {
    packet[3] & 0x0f
}

#[inline]
pub fn qdcount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[4..])
}

#[inline]
pub fn ancount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[6..])
}

#[inline]
pub fn arcount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[10..])
}

fn arcount_inc(packet: &mut [u8]) -> Result<(), Error> {
    let mut arcount = arcount(packet);
    ensure!(arcount < 0xffff, "Too many additional records");
    arcount += 1;
    BigEndian::write_u16(&mut packet[10..], arcount);
    Ok(())
}

#[inline]
fn nscount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[8..])
}

#[inline]
pub fn is_recoverable_error(packet: &[u8]) -> bool {
    let rcode = rcode(packet);
    rcode == DNS_RCODE_SERVFAIL || rcode == DNS_RCODE_REFUSED
}

#[inline]
pub fn is_truncated(packet: &[u8]) -> bool {
    BigEndian::read_u16(&packet[DNS_OFFSET_FLAGS..]) & DNS_FLAGS_TC == DNS_FLAGS_TC
}

pub(crate) fn skip_name(packet: &[u8], offset: usize) -> Result<usize, Error> {
    let packet_len = packet.len();
    ensure!(offset < packet_len - 1, "Short packet");
    let mut qname_len: usize = 0;
    let mut offset = offset;
    loop {
        let label_len = match packet[offset] as usize {
            label_len if label_len & 0xc0 == 0xc0 => {
                ensure!(packet_len - offset >= 2, "Incomplete offset");
                offset += 2;
                break;
            }
            label_len => label_len,
        } as usize;
        ensure!(label_len < 0x40, "Long label");
        ensure!(
            packet_len - offset - 1 > label_len,
            "Malformed packet with an out-of-bounds name"
        );
        qname_len += label_len + 1;
        ensure!(qname_len <= DNS_MAX_HOSTNAME_SIZE, "Name too long");
        offset += label_len + 1;
        if label_len == 0 {
            break;
        }
    }
    Ok(offset)
}

pub(crate) fn traverse_rrs<F: FnMut(usize) -> Result<(), Error>>(
    packet: &[u8],
    mut offset: usize,
    rrcount: usize,
    mut cb: F,
) -> Result<usize, Error> {
    let packet_len = packet.len();
    for _ in 0..rrcount {
        offset = skip_name(packet, offset)?;
        ensure!(packet_len - offset >= 10, "Short packet");
        cb(offset)?;
        let rdlen = BigEndian::read_u16(&packet[offset + 8..]) as usize;
        offset += 10;
        ensure!(
            packet_len - offset >= rdlen,
            "Record length would exceed packet length"
        );
        offset += rdlen;
    }
    Ok(offset)
}

fn traverse_rrs_mut<F: FnMut(&mut [u8], usize) -> Result<(), Error>>(
    packet: &mut [u8],
    mut offset: usize,
    rrcount: usize,
    mut cb: F,
) -> Result<usize, Error> {
    let packet_len = packet.len();
    for _ in 0..rrcount {
        offset = skip_name(packet, offset)?;
        ensure!(packet_len - offset >= 10, "Short packet");
        cb(packet, offset)?;
        let rdlen = BigEndian::read_u16(&packet[offset + 8..]) as usize;
        offset += 10;
        ensure!(
            packet_len - offset >= rdlen,
            "Record length would exceed packet length"
        );
        offset += rdlen;
    }
    Ok(offset)
}

pub fn min_ttl(packet: &[u8], min_ttl: u32, max_ttl: u32, failure_ttl: u32) -> Result<u32, Error> {
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(packet_len <= DNS_MAX_PACKET_SIZE, "Large packet");
    ensure!(qdcount(packet) == 1, "No question");
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    assert!(offset > DNS_OFFSET_QUESTION);
    ensure!(packet_len - offset > 4, "Short packet");
    offset += 4;
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    let rrcount = ancount as usize + nscount as usize + arcount as usize;
    let mut found_min_ttl = if rrcount > 0 { max_ttl } else { failure_ttl };

    offset = traverse_rrs(packet, offset, rrcount, |offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        let ttl = BigEndian::read_u32(&packet[offset + 4..]);
        if qtype != DNS_TYPE_OPT && ttl < found_min_ttl {
            found_min_ttl = ttl;
        }
        Ok(())
    })?;
    if found_min_ttl < min_ttl {
        found_min_ttl = min_ttl;
    }
    ensure!(packet_len == offset, "Garbage after packet");
    Ok(found_min_ttl)
}

fn add_edns_section(packet: &mut Vec<u8>, max_payload_size: u16) -> Result<(), Error> {
    let opt_rr: [u8; 11] = [
        0,
        (DNS_TYPE_OPT >> 8) as u8,
        DNS_TYPE_OPT as u8,
        (max_payload_size >> 8) as u8,
        max_payload_size as u8,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    ensure!(
        DNS_MAX_PACKET_SIZE - packet.len() >= opt_rr.len(),
        "Packet would be too large to add a new record"
    );
    arcount_inc(packet)?;
    packet.extend(opt_rr);
    Ok(())
}

pub fn set_edns_max_payload_size(packet: &mut Vec<u8>, max_payload_size: u16) -> Result<(), Error> {
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(packet_len <= DNS_MAX_PACKET_SIZE, "Large packet");
    ensure!(qdcount(packet) == 1, "No question");
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    assert!(offset > DNS_OFFSET_QUESTION);
    ensure!(packet_len - offset >= 4, "Short packet");
    offset += 4;
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(
        packet,
        offset,
        ancount as usize + nscount as usize,
        |_offset| Ok(()),
    )?;
    let mut edns_payload_set = false;
    traverse_rrs_mut(packet, offset, arcount as _, |packet, offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        if qtype == DNS_TYPE_OPT {
            ensure!(!edns_payload_set, "Duplicate OPT RR found");
            BigEndian::write_u16(&mut packet[offset + 2..], max_payload_size);
            edns_payload_set = true;
        }
        Ok(())
    })?;
    if edns_payload_set {
        return Ok(());
    }
    add_edns_section(packet, max_payload_size)?;
    Ok(())
}

fn padded_len(unpadded_len: usize) -> usize {
    const BOUNDARIES: [usize; 16] = [
        64, 128, 192, 256, 320, 384, 512, 704, 768, 896, 960, 1024, 1088, 1152, 2688, 4080,
    ];
    BOUNDARIES
        .iter()
        .find(|&&boundary| boundary >= unpadded_len)
        .copied()
        .unwrap_or(DNS_MAX_PACKET_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Minimal DNS query for `example.com` A IN (no additional records).
    fn make_query() -> Vec<u8> {
        vec![
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // Question: "example.com" A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
        ]
    }

    /// DNS response for `example.com` A = 1.2.3.4, TTL = 3600.
    fn make_response_a() -> Vec<u8> {
        vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags: QR=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // Question
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
            // Answer
            0xc0, 0x0c, // Name: pointer to offset 12
            0x00, 0x01, // TYPE: A
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x04, // RDLENGTH: 4
            0x01, 0x02, 0x03, 0x04, // 1.2.3.4
        ]
    }

    // ── Header field accessors ────────────────────────────────────────────────

    #[test]
    fn test_rcode_noerror() {
        let mut p = make_query();
        p[3] = 0x00;
        assert_eq!(rcode(&p), 0);
    }

    #[test]
    fn test_rcode_servfail() {
        let mut p = make_query();
        p[3] = 0x02;
        assert_eq!(rcode(&p), 2);
    }

    #[test]
    fn test_rcode_nxdomain() {
        let mut p = make_query();
        p[3] = 0x03;
        assert_eq!(rcode(&p), 3);
    }

    #[test]
    fn test_rcode_refused() {
        let mut p = make_query();
        p[3] = 0x05;
        assert_eq!(rcode(&p), 5);
    }

    #[test]
    fn test_qdcount() {
        let p = make_query();
        assert_eq!(qdcount(&p), 1);
    }

    #[test]
    fn test_ancount_zero() {
        let p = make_query();
        assert_eq!(ancount(&p), 0);
    }

    #[test]
    fn test_ancount_one() {
        let p = make_response_a();
        assert_eq!(ancount(&p), 1);
    }

    #[test]
    fn test_arcount_zero() {
        let p = make_query();
        assert_eq!(arcount(&p), 0);
    }

    // ── Flag checks ───────────────────────────────────────────────────────────

    #[test]
    fn test_is_recoverable_error_servfail() {
        let mut p = make_query();
        p[3] = 0x02; // SERVFAIL
        assert!(is_recoverable_error(&p));
    }

    #[test]
    fn test_is_recoverable_error_refused() {
        let mut p = make_query();
        p[3] = 0x05; // REFUSED
        assert!(is_recoverable_error(&p));
    }

    #[test]
    fn test_is_not_recoverable_noerror() {
        let mut p = make_query();
        p[3] = 0x00;
        assert!(!is_recoverable_error(&p));
    }

    #[test]
    fn test_is_not_recoverable_nxdomain() {
        let mut p = make_query();
        p[3] = 0x03; // NXDOMAIN
        assert!(!is_recoverable_error(&p));
    }

    #[test]
    fn test_is_truncated_false() {
        let mut p = make_query();
        p[2] = 0x01; // RD only, TC bit clear
        p[3] = 0x00;
        assert!(!is_truncated(&p));
    }

    #[test]
    fn test_is_truncated_true() {
        let mut p = make_query();
        // DNS_FLAGS_TC = 1u16 << 9 = 0x0200  ->  byte 2 has bit 1 set
        p[2] = 0x02; // TC bit set
        p[3] = 0x00;
        assert!(is_truncated(&p));
    }

    #[test]
    fn test_is_truncated_with_rd_and_tc() {
        let mut p = make_query();
        p[2] = 0x03; // RD and TC both set
        p[3] = 0x00;
        assert!(is_truncated(&p));
    }

    // ── Name parsing ──────────────────────────────────────────────────────────

    #[test]
    fn test_skip_name_simple() {
        let p = make_query();
        // Name at offset 12: 7"example" 3"com" 0
        // Expected end offset: 12 + 8 + 4 + 1 = 25
        let result = skip_name(&p, DNS_OFFSET_QUESTION);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 25);
    }

    #[test]
    fn test_skip_name_compressed_pointer() {
        let p = make_response_a();
        // Answer name at offset 29 is a compression pointer (0xc0 0x0c)
        let result = skip_name(&p, 29);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 31); // pointer advances by 2 bytes
    }

    #[test]
    fn test_skip_name_short_packet_error() {
        // A 1-byte packet at offset 0: ensure!(0 < 1-1) → 0 < 0 = false → Err
        let p = vec![0u8; 1];
        assert!(skip_name(&p, 0).is_err());
    }

    #[test]
    fn test_skip_name_label_exceeds_packet_error() {
        // First byte claims label length 5, but only 1 more byte follows
        let p = vec![5u8, b'a'];
        assert!(skip_name(&p, 0).is_err());
    }

    #[test]
    fn test_skip_name_incomplete_pointer_error() {
        // Compression pointer at the very end of packet (missing second byte)
        let p = vec![0xc0u8]; // just one byte of a pointer
        assert!(skip_name(&p, 0).is_err());
    }

    // ── TTL calculation ───────────────────────────────────────────────────────

    #[test]
    fn test_min_ttl_with_one_record() {
        let p = make_response_a(); // TTL = 3600
        let result = min_ttl(&p, 10, 86400, 2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3600);
    }

    #[test]
    fn test_min_ttl_clamped_to_minimum() {
        let mut p = make_response_a();
        // Set TTL to 1 second (below min_ttl of 10)
        p[35] = 0x00;
        p[36] = 0x00;
        p[37] = 0x00;
        p[38] = 0x01;
        let result = min_ttl(&p, 10, 86400, 2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10);
    }

    #[test]
    fn test_min_ttl_clamped_to_maximum() {
        let mut p = make_response_a();
        // Set TTL to a huge value (above max_ttl of 100)
        p[35] = 0x00;
        p[36] = 0x01;
        p[37] = 0x00;
        p[38] = 0x00; // TTL = 65536
        let result = min_ttl(&p, 10, 100, 2);
        assert!(result.is_ok());
        // found_min_ttl starts at max_ttl (100), record TTL is 65536 which is NOT less than 100
        // so found_min_ttl stays at 100
        assert_eq!(result.unwrap(), 100);
    }

    #[test]
    fn test_min_ttl_query_only_packet_error() {
        // A query packet (header + question only) has exactly 4 bytes remaining
        // after the name, but min_ttl requires > 4 bytes to distinguish the
        // question type/class from record data — so it returns Err for such packets.
        let p = make_query();
        let result = min_ttl(&p, 0, 86400, 7);
        assert!(result.is_err());
    }

    #[test]
    fn test_min_ttl_short_packet_error() {
        let p = vec![0u8; 5];
        assert!(min_ttl(&p, 10, 86400, 2).is_err());
    }

    #[test]
    fn test_min_ttl_no_question_error() {
        let mut p = make_query();
        p[4] = 0x00;
        p[5] = 0x00; // QDCOUNT = 0
        assert!(min_ttl(&p, 10, 86400, 2).is_err());
    }

    // ── EDNS max payload size ─────────────────────────────────────────────────

    #[test]
    fn test_set_edns_max_payload_size_adds_opt_record() {
        let mut p = make_query();
        assert_eq!(arcount(&p), 0);
        let result = set_edns_max_payload_size(&mut p, 4096);
        assert!(result.is_ok());
        // A new OPT record should have been appended
        assert_eq!(arcount(&p), 1);
    }

    #[test]
    fn test_set_edns_max_payload_size_updates_existing_opt() {
        let mut p = make_query();
        // Add a first OPT record at 1280 bytes
        set_edns_max_payload_size(&mut p, 1280).unwrap();
        assert_eq!(arcount(&p), 1);
        let len_after_first = p.len();

        // Update to 4096 – should not add another OPT record
        set_edns_max_payload_size(&mut p, 4096).unwrap();
        assert_eq!(arcount(&p), 1);
        assert_eq!(p.len(), len_after_first); // same length
    }

    #[test]
    fn test_set_edns_max_payload_size_short_packet_error() {
        let mut p = vec![0u8; 5];
        assert!(set_edns_max_payload_size(&mut p, 4096).is_err());
    }

    // ── EDNS padding ──────────────────────────────────────────────────────────

    #[test]
    fn test_add_edns_padding_grows_packet() {
        let mut p = make_query();
        set_edns_max_payload_size(&mut p, 4096).unwrap();
        let len_before = p.len();
        let result = add_edns_padding(&mut p);
        assert!(result.is_ok());
        assert!(p.len() >= len_before);
    }

    #[test]
    fn test_add_edns_padding_adds_opt_if_missing() {
        let mut p = make_query();
        assert_eq!(arcount(&p), 0);
        let result = add_edns_padding(&mut p);
        assert!(result.is_ok());
        // padding also creates OPT record when absent
        assert_eq!(arcount(&p), 1);
    }

    #[test]
    fn test_add_edns_padding_short_packet_error() {
        let mut p = vec![0u8; 5];
        assert!(add_edns_padding(&mut p).is_err());
    }
}

pub fn add_edns_padding(packet: &mut Vec<u8>) -> Result<(), Error> {
    let mut packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(packet_len <= DNS_MAX_PACKET_SIZE, "Large packet");
    ensure!(qdcount(packet) == 1, "No question");
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    assert!(offset > DNS_OFFSET_QUESTION);
    ensure!(packet_len - offset >= 4, "Short packet");
    offset += 4;
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(
        packet,
        offset,
        ancount as usize + nscount as usize,
        |_offset| Ok(()),
    )?;
    let mut edns_offset = None;
    traverse_rrs_mut(packet, offset, arcount as _, |packet, offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        if qtype == DNS_TYPE_OPT {
            ensure!(edns_offset.is_none(), "Duplicate OPT RR found");
            edns_offset = Some(offset)
        }
        Ok(())
    })?;
    let edns_offset = match edns_offset {
        Some(edns_offset) => edns_offset,
        None => {
            let edns_offset = packet.len() + 1;
            add_edns_section(packet, DNS_MAX_PACKET_SIZE as _)?;
            packet_len = packet.len();
            edns_offset
        }
    };
    let padding_len = padded_len(packet_len) - packet_len;
    let mut edns_padding_prr = vec![b'X'; 4 + padding_len];
    BigEndian::write_u16(&mut edns_padding_prr[0..], DNS_PTYPE_PADDING);
    BigEndian::write_u16(&mut edns_padding_prr[2..], padding_len as u16);
    let edns_padding_prr_len = edns_padding_prr.len();
    let edns_rdlen_offset: usize = edns_offset + 8;
    ensure!(packet_len - edns_rdlen_offset >= 2, "Short packet");
    let edns_rdlen = BigEndian::read_u16(&packet[edns_rdlen_offset..]);
    ensure!(
        edns_offset + edns_rdlen as usize <= packet_len,
        "Out of range EDNS size"
    );
    ensure!(
        0xffff - edns_rdlen as usize >= edns_padding_prr_len,
        "EDNS section too large for padding"
    );
    ensure!(
        DNS_MAX_PACKET_SIZE - packet_len >= edns_padding_prr_len,
        "Large packet"
    );
    BigEndian::write_u16(
        &mut packet[edns_rdlen_offset..],
        edns_rdlen + edns_padding_prr_len as u16,
    );
    packet.extend(&edns_padding_prr);
    Ok(())
}
