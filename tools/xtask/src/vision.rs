//! A structured, bounded driver for the production Vision unpadder.
//!
//! The generated payload ranges are the oracle; they are recorded while constructing the wire,
//! not obtained by decoding it a second time. Pending does not deliver bytes, a transport error
//! never calls `finish_input`, and bytes after END/DIRECT bypass the unpadder, as in VisionStream.
//! This tests framing, not TLS authentication or the async transport's own error propagation.

use std::io::ErrorKind;
use std::ops::Range;
use std::task::Poll;

use crate::vision_unpad::{UnpadCommand, VisionUnpadder};

const UUID: [u8; 16] = *b"vision-fuzz-uuid";
const MAX_INPUT: usize = 4096;

struct Random(u64);

impl Random {
    fn new(data: &[u8]) -> Self {
        let seed = data.iter().fold(0xcbf29ce484222325u64, |state, byte| {
            (state ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        });
        Self(seed | 1)
    }

    fn next(&mut self) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 32) as usize
    }
}

#[derive(Default)]
struct Wire {
    bytes: Vec<u8>,
    payloads: Vec<Range<usize>>,
    terminal: Option<(usize, UnpadCommand)>,
    invalid_at: Option<usize>,
}

impl Wire {
    fn frame(&mut self, command: u8, content: &[u8], padding: usize) {
        let command_at = self.bytes.len();
        self.bytes.push(command);
        self.bytes
            .extend_from_slice(&(content.len() as u16).to_be_bytes());
        self.bytes
            .extend_from_slice(&(padding as u16).to_be_bytes());
        let start = self.bytes.len();
        self.bytes.extend_from_slice(content);
        self.payloads.push(start..self.bytes.len());
        self.bytes.resize(self.bytes.len() + padding, 0xa5);
        match command {
            1 => self.terminal = Some((self.bytes.len(), UnpadCommand::End)),
            2 => self.terminal = Some((self.bytes.len(), UnpadCommand::Direct)),
            0 => {}
            _ => self.invalid_at = Some(command_at),
        }
    }

    fn expected(&self, received: usize, clean: bool) -> Vec<u8> {
        if received < UUID.len() {
            return if clean {
                UUID[..received].to_vec()
            } else {
                Vec::new()
            };
        }
        self.payloads
            .iter()
            .filter(|range| range.start < received)
            .flat_map(|range| &self.bytes[range.start..range.end.min(received)])
            .copied()
            .collect()
    }
}

#[derive(Clone, Copy)]
enum End {
    Clean,
    Error,
}

struct Source<'a> {
    bytes: &'a [u8],
    position: usize,
    random: Random,
    pending: usize,
    end: End,
    chunk: usize,
}

impl<'a> Source<'a> {
    fn poll(&mut self) -> Poll<Result<&'a [u8], ErrorKind>> {
        if self.pending > 0 {
            self.pending -= 1;
            return Poll::Pending;
        }
        if self.position == self.bytes.len() {
            return Poll::Ready(match self.end {
                End::Clean => Ok(&[]),
                End::Error => Err(ErrorKind::UnexpectedEof),
            });
        }
        let start = self.position;
        let length = if self.chunk > 0 {
            self.chunk
        } else {
            1 + self.random.next() % 47
        };
        self.position = (self.position + length).min(self.bytes.len());
        self.pending = self.random.next() % 4;
        Poll::Ready(Ok(&self.bytes[start..self.position]))
    }
}

fn run(wire: &Wire, cutoff: usize, end: End, seed: &[u8], chunk: usize) {
    let mut parser = VisionUnpadder::new(UUID);
    let mut source = Source {
        bytes: &wire.bytes[..cutoff],
        position: 0,
        random: Random::new(seed),
        pending: 2,
        end,
        chunk,
    };
    let mut received = Vec::new();
    let mut raw = false;
    let mut terminal = None;
    let mut ended = false;
    // At most 3 Pending polls per positive read, plus initial Pending and EOF.
    let budget = cutoff.saturating_mul(4) + 4;
    for _ in 0..budget {
        match source.poll() {
            Poll::Pending => continue,
            Poll::Ready(Err(error)) => {
                assert_eq!(error, ErrorKind::UnexpectedEof);
                assert_eq!(received, wire.expected(cutoff, false));
                ended = true;
                break;
            }
            Poll::Ready(Ok([])) => {
                if !raw {
                    received.extend(parser.finish_input());
                    assert!(
                        parser.finish_input().is_empty(),
                        "EOF delivered a prefix twice"
                    );
                }
                assert_eq!(received, wire.expected(cutoff, true));
                ended = true;
                break;
            }
            Poll::Ready(Ok(data)) if raw => received.extend_from_slice(data),
            Poll::Ready(Ok(data)) => match parser.unpad(data) {
                Ok(result) => {
                    received.extend(result.content);
                    if matches!(
                        result.command,
                        Some(UnpadCommand::End | UnpadCommand::Direct)
                    ) {
                        assert!(terminal.is_none(), "terminal command delivered twice");
                        terminal = result.command;
                        raw = true;
                    }
                }
                Err(error) => {
                    assert_eq!(error.kind(), ErrorKind::InvalidData);
                    let invalid = wire.invalid_at.expect("valid framing was rejected");
                    assert!(
                        source.position > invalid,
                        "error before invalid command arrived"
                    );
                    // An error can discard content in that same call. Earlier delivered bytes
                    // must still be an exact prefix of the independently generated payload.
                    assert!(wire.expected(invalid, false).starts_with(&received));
                    ended = true;
                    break;
                }
            },
        }
        if wire
            .invalid_at
            .is_none_or(|offset| source.position <= offset)
        {
            assert_eq!(received, wire.expected(source.position, false));
        }
        let expected_terminal = wire
            .terminal
            .filter(|(offset, _)| source.position >= *offset)
            .map(|(_, command)| command);
        assert_eq!(
            terminal, expected_terminal,
            "END/DIRECT before its padding was consumed"
        );
    }
    assert!(
        ended,
        "parser did not finish within its finite input budget"
    );
}

/// Runs one bounded fuzz case, including valid frames, truncation, malformed commands and plain
/// UUID candidates. Input bytes control both the content and fragmentation schedule.
pub fn check(input: &[u8]) {
    let input = &input[..input.len().min(MAX_INPUT)];
    let mut random = Random::new(input);
    let count = 1 + random.next() % 5;
    let mut wire = Wire {
        bytes: UUID.to_vec(),
        ..Wire::default()
    };
    for index in 0..count {
        let length = random.next() % 257;
        let content: Vec<_> = (0..length)
            .map(|offset| {
                input
                    .get(offset % input.len().max(1))
                    .copied()
                    .unwrap_or(offset as u8)
            })
            .collect();
        let command = if index + 1 == count {
            (random.next() % 3) as u8
        } else {
            0
        };
        wire.frame(command, &content, random.next() % 129);
    }
    if wire.terminal.is_some() {
        let start = wire.bytes.len();
        wire.bytes.extend_from_slice(input);
        wire.payloads.push(start..wire.bytes.len());
    }
    for end in [End::Clean, End::Error] {
        run(&wire, wire.bytes.len(), end, input, 0);
        let cutoff = random.next() % (wire.bytes.len() + 1);
        run(&wire, cutoff, end, input, 0);
        run(&wire, random.next() % 16, end, input, 1);
    }
    let mut invalid = Wire {
        bytes: UUID.to_vec(),
        ..Wire::default()
    };
    invalid.frame(0, b"valid-prefix", 2);
    invalid.frame(3 + (random.next() % 253) as u8, input, 1);
    run(&invalid, invalid.bytes.len(), End::Clean, input, 0);
    run(&invalid, invalid.bytes.len(), End::Error, input, 1);

    // A candidate followed by a mismatch must yield both the saved prefix and this read.
    let matched = random.next() % 16;
    let mut parser = VisionUnpadder::new(UUID);
    for byte in &UUID[..matched] {
        assert!(
            parser
                .unpad(std::slice::from_ref(byte))
                .unwrap()
                .content
                .is_empty()
        );
    }
    let mismatch = [UUID[matched] ^ 0xff, 0x42, 0x24];
    let result = parser.unpad(&mismatch).unwrap();
    assert_eq!(result.content, [&UUID[..matched], &mismatch].concat());
    assert_eq!(result.command, None);
    assert!(parser.finish_input().is_empty());
}

/// Stable CI corpus: exhaustive UUID/header/body/padding cuts, then seeded mixed frames.
pub fn smoke() {
    for command in [0, 1, 2] {
        let mut wire = Wire {
            bytes: UUID.to_vec(),
            ..Wire::default()
        };
        wire.frame(command, b"payload\0with\xffbytes", 9);
        for cut in 0..=wire.bytes.len() {
            for end in [End::Clean, End::Error] {
                for chunk in [1, 2, 7, 0] {
                    run(&wire, cut, end, &[command, cut as u8], chunk);
                }
            }
        }
    }
    for seed in 0..1024u32 {
        let mut random = Random(u64::from(seed) + 1);
        let bytes: Vec<_> = (0..seed as usize % 193)
            .map(|_| random.next() as u8)
            .collect();
        check(&bytes);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn deterministic_fragmentation_pending_eof_and_invalid_command_corpus() {
        super::smoke();
    }
}
