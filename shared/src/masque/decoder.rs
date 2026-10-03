//! Incremental capsule parsing with bounds checked before buffering a payload.

use super::{read_varint, MAX_CAPSULE_BUF};

#[derive(Debug)]
pub struct CapsuleTooLarge;

impl std::fmt::Display for CapsuleTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CONNECT-IP capsule exceeds limit")
    }
}

impl std::error::Error for CapsuleTooLarge {}

#[derive(Default)]
pub struct CapsuleDecoder {
    buffer: Vec<u8>,
    header: Option<(u64, usize, usize)>,
    complete: bool,
}

impl CapsuleDecoder {
    /// Consumes only the bytes needed for one capsule. Multiple capsules in a
    /// DATA frame need no aggregate allocation, and fragmented varints work too.
    /// After an error the caller must close the stream.
    pub fn next<'a>(
        &'a mut self,
        input: &mut &[u8],
    ) -> Result<Option<(u64, &'a [u8])>, CapsuleTooLarge> {
        if self.complete {
            self.buffer.clear();
            self.header = None;
            self.complete = false;
        }
        let (kind, start, end) = loop {
            if let Some(header) = self.header {
                break header;
            }
            if let Some((kind, n1)) = read_varint(&self.buffer) {
                if let Some((len, n2)) = read_varint(&self.buffer[n1..]) {
                    let start = n1 + n2;
                    let end = usize::try_from(len)
                        .ok()
                        .and_then(|len| start.checked_add(len))
                        .filter(|&end| end <= MAX_CAPSULE_BUF)
                        .ok_or(CapsuleTooLarge)?;
                    self.header = Some((kind, start, end));
                    break (kind, start, end);
                }
            }
            let Some((&byte, rest)) = input.split_first() else {
                return Ok(None);
            };
            self.buffer.push(byte);
            *input = rest;
        };
        let take = (end - self.buffer.len()).min(input.len());
        self.buffer.extend_from_slice(&input[..take]);
        *input = &input[take..];
        if self.buffer.len() < end {
            return Ok(None);
        }
        self.complete = true;
        Ok(Some((kind, &self.buffer[start..end])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masque::{encode_capsule, write_varint, CAPSULE_MAVI_CONFIG};

    #[test]
    fn rejects_advertised_length_before_receiving_payload() {
        for kind in [0, CAPSULE_MAVI_CONFIG, (1 << 62) - 1] {
            for len in [MAX_CAPSULE_BUF as u64, (1 << 32) + 1, (1 << 62) - 1] {
                let mut bytes = Vec::new();
                write_varint(kind, &mut bytes);
                write_varint(len, &mut bytes);
                let mut decoder = CapsuleDecoder::default();
                for byte in &bytes[..bytes.len() - 1] {
                    assert!(decoder
                        .next(&mut std::slice::from_ref(byte))
                        .unwrap()
                        .is_none());
                }
                assert!(decoder.next(&mut &bytes[bytes.len() - 1..]).is_err());
                assert!(decoder.buffer.len() <= 16);
            }
        }
    }

    #[test]
    fn accepts_all_fragment_boundaries_and_coalesced_capsules() {
        let mut bytes = Vec::new();
        encode_capsule(CAPSULE_MAVI_CONFIG, b"config", &mut bytes);
        encode_capsule(0, b"packet", &mut bytes);
        for split in 0..=bytes.len() {
            let mut decoder = CapsuleDecoder::default();
            let mut capsules = Vec::new();
            for mut chunk in [&bytes[..split], &bytes[split..]] {
                while let Some((kind, payload)) = decoder.next(&mut chunk).unwrap() {
                    capsules.push((kind, payload.to_vec()));
                }
            }
            assert_eq!(
                capsules,
                [
                    (CAPSULE_MAVI_CONFIG, b"config".to_vec()),
                    (0, b"packet".to_vec())
                ]
            );
        }
    }

    #[test]
    fn accepts_noncanonical_varints_and_the_exact_frame_limit() {
        let mut decoder = CapsuleDecoder::default();
        let mut noncanonical = &[0x40, 0, 0x80, 0, 0, 1, 42][..];
        assert_eq!(
            decoder.next(&mut noncanonical).unwrap(),
            Some((0, &[42][..]))
        );
        let mut bytes = Vec::new();
        encode_capsule(0, &vec![7; MAX_CAPSULE_BUF - 5], &mut bytes);
        assert_eq!(bytes.len(), MAX_CAPSULE_BUF);
        let mut input = bytes.as_slice();
        let (kind, payload) = decoder.next(&mut input).unwrap().unwrap();
        assert_eq!(kind, 0);
        assert_eq!(payload.len(), MAX_CAPSULE_BUF - 5);
        assert!(input.is_empty());
    }

    #[test]
    fn large_batch_of_small_capsules_does_not_hit_per_capsule_limit() {
        let bytes = [0, 1, 42].repeat(MAX_CAPSULE_BUF);
        let mut input = bytes.as_slice();
        let mut decoder = CapsuleDecoder::default();
        let mut count = 0;
        while let Some((kind, payload)) = decoder.next(&mut input).unwrap() {
            assert_eq!((kind, payload), (0, &[42][..]));
            count += 1;
        }
        assert_eq!(count, MAX_CAPSULE_BUF);
        assert!(decoder.buffer.capacity() < 64);
    }
}
