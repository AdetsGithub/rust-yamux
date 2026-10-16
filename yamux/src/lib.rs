// Copyright (c) 2018-2019 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
//
// A copy of the Apache License, Version 2.0 is included in the software as
// LICENSE-APACHE and a copy of the MIT license is included in the software
// as LICENSE-MIT. You may also obtain a copy of the Apache License, Version 2.0
// at https://www.apache.org/licenses/LICENSE-2.0 and a copy of the MIT license
// at https://opensource.org/licenses/MIT.

//! This crate implements the [Yamux specification][1].
//!
//! It multiplexes independent I/O streams over reliable, ordered connections,
//! such as TCP/IP.
//!
//! The two primary objects, clients of this crate interact with, are:
//!
//! - [`Connection`], which wraps the underlying I/O resource, e.g. a socket, and
//!   provides methods for opening outbound or accepting inbound streams.
//! - [`Stream`], which implements [`futures::io::AsyncRead`] and
//!   [`futures::io::AsyncWrite`].
//!
//! [1]: https://github.com/hashicorp/yamux/blob/master/spec.md

#![forbid(unsafe_code)]

mod chunks;
mod error;
mod frame;

pub(crate) mod connection;
mod tagged_stream;

pub use crate::connection::{Connection, Mode, Packet, Stream};
pub use crate::error::ConnectionError;
pub use crate::frame::{
    header::{HeaderDecodeError, StreamId},
    FrameDecodeError,
};

#[cfg(feature = "fuzzing")]
pub use crate::frame::header::fuzz_header_codec;

/// Drive a Yamux [`Connection`] against attacker-controlled bytes on a mock
/// always-ready socket. Exercises the full frame reader (`header::decode` +
/// body assembly + `FrameTooLarge`) and connection state machine, including
/// stream credit / window-update / data paths.
///
/// The mock returns `Ok(0)` (EOF) when the fuzzer buffer is exhausted so the
/// async connection tears down instead of waiting forever on `Poll::Pending`.
/// A hard poll budget is a second backstop against sticky Pending.
///
/// Unlike an accept-and-drop harness, inbound (and a few outbound) streams are
/// kept alive and driven with `poll_read` / `poll_write`. `Poll::Pending` from
/// `poll_next_inbound` is not fatal while the mock still has unread bytes or
/// stream I/O made progress — that is what unblocks Data → buffer →
/// WindowUpdate credit paths.
///
/// Config is clamped for DoS hunting: at most 100 streams and a connection
/// receive window of `100 * DEFAULT_CREDIT` (25 MiB). Yamux 0.14 has no
/// `set_max_buffer_size`; the receive-window cap is the memory clamp.
///
/// Invariant: processing arbitrary remote bytes must never panic and must
/// terminate within a bounded poll budget. Watch ASan/libFuzzer RSS for OOM
/// (unclamped buffering) separately from Crash.
#[cfg(feature = "fuzzing")]
pub fn fuzz_connection(data: &[u8], server: bool) {
    fuzz_connection_ex(data, server, false, true);
}

/// Like [`fuzz_connection`], with optional write loopback and graceful close.
///
/// - `loopback`: local writes are readable as further remote traffic (ACK /
///   Ping-RTT / WindowUpdate races). Loopback growth is capped.
/// - `graceful_close`: after the drive loop (or on early teardown), half-close
///   held streams then [`Connection::poll_close`] so `connection/closing.rs`
///   runs (drain stream commands → Term → socket close).
#[cfg(feature = "fuzzing")]
pub fn fuzz_connection_ex(data: &[u8], server: bool, loopback: bool, graceful_close: bool) {
    use std::{
        cell::RefCell,
        collections::VecDeque,
        io,
        pin::Pin,
        rc::Rc,
        task::{Context, Poll},
        time::{Duration, Instant},
    };

    use futures::{
        io::{AsyncRead, AsyncWrite},
        task::noop_waker_ref,
    };

    struct SharedBuf {
        q: VecDeque<u8>,
    }

    struct MockIo {
        buf: Rc<RefCell<SharedBuf>>,
        loopback: bool,
        /// Remaining bytes this mock may echo back as further remote traffic.
        ///
        /// `loopback` echoes local writes into the read buffer to exercise
        /// ACK / Ping-RTT / WindowUpdate races. Without a hard total budget,
        /// a write can loop back, grant credit / trigger a response, produce
        /// another write, and so on forever — keeping [`Connection::poll`]
        /// spinning inside a single `poll_next_inbound` call, which the
        /// drive-loop wall-clock deadline cannot interrupt.
        loopback_budget: usize,
        /// When true, empty reads return `Pending` instead of EOF so the
        /// connection stays `Active` for local [`Connection::poll_close`]
        /// (`closing.rs`). EOF would transition to `Cleanup` instead.
        hold_eof: bool,
    }

    impl AsyncRead for MockIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let mut shared = this.buf.borrow_mut();
            let n = shared.q.len().min(buf.len());
            for b in buf.iter_mut().take(n) {
                *b = shared.q.pop_front().expect("len checked");
            }
            if n == 0 {
                if this.hold_eof {
                    return Poll::Pending;
                }
                // Entropy exhausted → EOF (Cleanup path).
                return Poll::Ready(Ok(0));
            }
            Poll::Ready(Ok(n))
        }
    }

    impl AsyncWrite for MockIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.loopback && this.loopback_budget > 0 {
                let mut shared = this.buf.borrow_mut();
                const MAX_LOOPBACK: usize = 64 * 1024;
                let room = MAX_LOOPBACK
                    .saturating_sub(shared.q.len())
                    .min(this.loopback_budget);
                shared.q.extend(buf.iter().copied().take(room));
                this.loopback_budget = this.loopback_budget.saturating_sub(room);
            }
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    const MAX_STREAMS: usize = 100;
    // Cap how many live streams we retain for read/write driving.
    const MAX_HELD_STREAMS: usize = 32;
    // Total bytes `loopback` may echo back before it stops (hard cap on the
    // self-echo feedback loop; the per-read-buffer cap above only bounds the
    // queue depth, not the total volume).
    const MAX_LOOPBACK_BYTES: usize = 64 * 1024;
    // Minimum legal window for MAX_STREAMS (assert in Config setters).
    const MAX_RECV_WINDOW: usize = MAX_STREAMS * DEFAULT_CREDIT as usize;
    const MAX_POLLS: usize = 100_000;
    // Wall-clock bound so a pathological loopback/credit cycle can't stall a
    // single unit for minutes (the fuzzer's between-unit -max_total_time check
    // can't fire while one unit is running).
    const MAX_DRIVE_TIME: Duration = Duration::from_secs(5);
    // Consecutive no-progress Pending iterations before giving up once the
    // mock is drained (stream wakes won't fire with a noop waker).
    const MAX_IDLE_PENDING: usize = 64;
    // Extra writes per stream to push send-window / credit-exhaust.
    const CREDIT_BURST: usize = 8;
    // After wire drain, keep writing until send-window Pending (DEFAULT_CREDIT
    // is 256 KiB → ~32 bursts of 8×1 KiB). Without this soak, graceful_close
    // exits before stream.rs / flow_control credit-exhaust arms warm up.
    const CREDIT_SOAK_ROUNDS: usize = 64;

    let mut config = Config::default();
    config.set_max_num_streams(MAX_STREAMS);
    config.set_max_connection_receive_window(Some(MAX_RECV_WINDOW));

    let shared = Rc::new(RefCell::new(SharedBuf {
        q: data.iter().copied().collect(),
    }));
    let mode = if server { Mode::Server } else { Mode::Client };
    let mut conn = Connection::new(
        MockIo {
            buf: Rc::clone(&shared),
            loopback,
            // Total echo budget so the loopback feedback loop always drains.
            loopback_budget: MAX_LOOPBACK_BYTES,
            hold_eof: graceful_close,
        },
        config,
        mode,
    );
    let mut cx = Context::from_waker(noop_waker_ref());
    let mut streams: Vec<Stream> = Vec::new();
    let mut read_buf = [0u8; 1024];
    // Larger writes stress send credit; Pending = window exhausted.
    let write_buf = [0x61u8; 1024];
    let mut idle_pending = 0usize;
    let mut open_outbound = !server; // client opens; server mostly accepts
    let mut half_close_budget = 4usize;
    let mut credit_soak_left = CREDIT_SOAK_ROUNDS;
    let drive_deadline = Instant::now() + MAX_DRIVE_TIME;

    // Drive until idle / error / poll budget / wall-clock deadline, then
    // optionally graceful-close.
    //
    // Important: `Closing` is only entered from `ConnectionState::Active` via
    // `poll_close`. Remote GoAway / socket EOF transition Active → Cleanup, so
    // when `graceful_close` is set we must stop *before* `poll_next_inbound`
    // observes EOF (`Ok(0)` on the mock).
    'drive: for poll_i in 0..MAX_POLLS {
        if Instant::now() >= drive_deadline {
            break 'drive;
        }
        let mut progress = false;
        let unread = shared.borrow().q.len();

        // Stay Active for local `poll_close` — do not ingest EOF.
        if graceful_close && unread == 0 {
            // Open / keep streams so credit-soak + Closing have something to drain.
            if (open_outbound || credit_soak_left > 0) && streams.len() < MAX_HELD_STREAMS {
                if let Poll::Ready(Ok(s)) = conn.poll_new_outbound(&mut cx) {
                    streams.push(s);
                    progress = true;
                    open_outbound = false;
                }
            }
            // Fall through to stream I/O (incl. credit soak) below.
        } else {
            // Occasionally open an outbound stream so write/credit paths run even
            // when the remote never SYNs (client mode, or after accepts).
            if open_outbound && streams.len() < MAX_HELD_STREAMS {
                match conn.poll_new_outbound(&mut cx) {
                    Poll::Ready(Ok(s)) => {
                        streams.push(s);
                        progress = true;
                        // One opportunistic open per outer iteration.
                        open_outbound = false;
                    }
                    Poll::Ready(Err(_)) => open_outbound = false,
                    Poll::Pending => {}
                }
            }

            match conn.poll_next_inbound(&mut cx) {
                Poll::Ready(None) | Poll::Ready(Some(Err(_))) => break 'drive,
                Poll::Ready(Some(Ok(stream))) => {
                    if streams.len() < MAX_HELD_STREAMS {
                        streams.push(stream);
                    }
                    // else: drop extras (still exercised accept / TooManyStreams)
                    progress = true;
                    idle_pending = 0;
                    // After an accept, try an outbound too (ACK backlog / credit).
                    open_outbound = true;
                }
                Poll::Pending => {}
            }
        }

        // Drive stream I/O: drain recv buffers (window updates) and write a
        // burst (consume send credit / emit Data frames). Periodically
        // half-close streams so Closing can drain CloseStream commands.
        let mut i = 0;
        while i < streams.len() {
            let mut drop_stream = false;
            let half_close = graceful_close
                && half_close_budget > 0
                && (poll_i.wrapping_add(i) % 7 == 0);
            {
                let s = &mut streams[i];
                match Pin::new(&mut *s).poll_read(&mut cx, &mut read_buf) {
                    Poll::Ready(Ok(0)) => drop_stream = true,
                    Poll::Ready(Ok(_)) => progress = true,
                    Poll::Ready(Err(_)) => drop_stream = true,
                    Poll::Pending => {}
                }
                if !drop_stream {
                    for _ in 0..CREDIT_BURST {
                        match Pin::new(&mut *s).poll_write(&mut cx, &write_buf) {
                            Poll::Ready(Ok(0)) => {
                                drop_stream = true;
                                break;
                            }
                            Poll::Ready(Ok(_)) => {
                                progress = true;
                                let _ = Pin::new(&mut *s).poll_flush(&mut cx);
                            }
                            Poll::Ready(Err(_)) => {
                                drop_stream = true;
                                break;
                            }
                            Poll::Pending => break, // credit exhausted
                        }
                    }
                }
                if !drop_stream && half_close {
                    match Pin::new(&mut *s).poll_close(&mut cx) {
                        Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => {
                            drop_stream = true;
                            half_close_budget = half_close_budget.saturating_sub(1);
                            progress = true;
                        }
                        Poll::Pending => {
                            half_close_budget = half_close_budget.saturating_sub(1);
                        }
                    }
                }
            }
            if drop_stream {
                streams.swap_remove(i);
                progress = true;
            } else {
                i += 1;
            }
        }

        let unread_after = shared.borrow().q.len();

        // Graceful path: soak send-credit to Pending before poll_close, otherwise
        // short wires never exhaust DEFAULT_CREDIT (256 KiB).
        if graceful_close && unread_after == 0 {
            if credit_soak_left > 0 && !streams.is_empty() {
                credit_soak_left = credit_soak_left.saturating_sub(1);
                if progress {
                    idle_pending = 0;
                    continue; // keep writing while send window remains
                }
                // `poll_write` Pending → credit exhausted (or stream stalled).
            }
            break 'drive;
        }

        if progress {
            idle_pending = 0;
            continue;
        }

        // No progress this iteration.
        idle_pending = idle_pending.saturating_add(1);
        if unread_after == 0 && idle_pending >= MAX_IDLE_PENDING {
            break 'drive;
        }
        // Still have wire bytes: keep polling so Data frames after SYN are
        // ingested into held streams (Pending alone must not abort).
        if unread_after == 0 && streams.is_empty() {
            break 'drive;
        }
    }

    if graceful_close {
        // Half-close any remaining streams so Closing drains CloseStream cmds.
        for s in streams.iter_mut() {
            for _ in 0..32 {
                match Pin::new(&mut *s).poll_close(&mut cx) {
                    Poll::Ready(_) => break,
                    Poll::Pending => continue,
                }
            }
        }
        drop(streams);
        // Enter `connection/closing.rs`: drain receivers → Term → socket close.
        for _ in 0..4096 {
            match conn.poll_close(&mut cx) {
                Poll::Ready(_) => break,
                Poll::Pending => continue,
            }
        }
    }
}

#[cfg(all(test, feature = "fuzzing"))]
mod fuzz_closing_tests {
    #[test]
    fn graceful_close_empty_and_syn_smoke() {
        // Empty wire: local poll_close while Active → closing.rs.
        super::fuzz_connection_ex(&[], true, false, true);
        // SYN Data + FIN (no GoAway).
        let mut wire = Vec::new();
        wire.extend_from_slice(&[
            0, 0, 0, 1, // Data + SYN
            0, 0, 0, 1, // stream 1
            0, 0, 0, 4, // len 4
            b'a', b'b', b'c', b'd',
            0, 0, 0, 4, // Data + FIN
            0, 0, 0, 1, 0, 0, 0, 0,
        ]);
        super::fuzz_connection_ex(&wire, true, true, true);
        // Non-graceful still terminates (EOF → Cleanup).
        super::fuzz_connection_ex(&wire, true, false, false);
    }

    #[test]
    fn loopback_echo_bounded_terminates() {
        // Regression: loopback=true self-echo previously kept
        // `Connection::poll` spinning forever inside a single
        // `poll_next_inbound` (window-update/credit feedback), defeating the
        // drive-loop wall-clock deadline. A total loopback byte budget must
        // drain the echo so this terminates instead of hanging.
        //
        // wire: Data/SYN(stream 1536, len 1) · Data/SYN(stream 16134, len 2)
        //       · Ping(stream 393216, len 131072, truncated).
        let wire = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08,
            0x00, 0x00, 0xc3, 0x01, 0x00, 0x00, 0x3f, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x02, 0xec, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x02,
        ];
        // server=true, loopback=true, graceful_close=true — the exact
        // configuration that produced the libFuzzer timeout.
        super::fuzz_connection_ex(&wire, true, true, true);
    }

    #[test]
    fn credit_soak_and_rst_smoke() {
        // Client + empty wire: open outbound and soak send credit → Pending.
        super::fuzz_connection_ex(&[], false, false, true);
        // SYN Data then RST (reset after open) + tiny WindowUpdate.
        let mut wire = Vec::new();
        wire.extend_from_slice(&[
            0, 0, 0, 1, // Data + SYN
            0, 0, 0, 1, // stream 1
            0, 0, 0, 4,
            b'w', b'x', b'y', b'z',
            0, 0, 0, 8, // Data + RST
            0, 0, 0, 1, 0, 0, 0, 0,
            0, 1, 0, 0, // WindowUpdate
            0, 0, 0, 1, // stream 1
            0, 0, 0, 1, // +1 credit
        ]);
        super::fuzz_connection_ex(&wire, true, false, true);
        // RST without prior SYN (unknown stream).
        let rst_orphan = [
            0, 0, 0, 8, // Data + RST
            0, 0, 0, 7, // stream 7
            0, 0, 0, 0,
        ];
        super::fuzz_connection_ex(&rst_orphan, true, false, true);
    }
}

const KIB: usize = 1024;
const MIB: usize = KIB * 1024;
const GIB: usize = MIB * 1024;

pub const DEFAULT_CREDIT: u32 = 256 * KIB as u32; // as per yamux specification

pub type Result<T> = std::result::Result<T, ConnectionError>;

/// The maximum number of streams we will open without an acknowledgement from the other peer.
///
/// This enables a very basic form of backpressure on the creation of streams.
const MAX_ACK_BACKLOG: usize = 256;

/// Default maximum number of bytes a Yamux data frame might carry as its
/// payload when being send. Larger Payloads will be split.
///
/// The data frame payload size is not restricted by the yamux specification.
/// Still, this implementation restricts the size to:
///
/// 1. Reduce delays sending time-sensitive frames, e.g. window updates.
/// 2. Minimize head-of-line blocking across streams.
/// 3. Enable better interleaving of send and receive operations, as each is
///    carried out atomically instead of concurrently with its respective
///    counterpart.
///
/// For details on why this concrete value was chosen, see
/// https://github.com/paritytech/yamux/issues/100.
const DEFAULT_SPLIT_SEND_SIZE: usize = 16 * KIB;

/// Yamux configuration.
///
/// The default configuration values are as follows:
///
/// - max. for the total receive window size across all streams of a connection = 1 GiB
/// - max. number of streams = 512
/// - read after close = true
/// - split send size = 16 KiB
#[derive(Debug, Clone)]
pub struct Config {
    max_connection_receive_window: Option<usize>,
    max_num_streams: usize,
    read_after_close: bool,
    split_send_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_connection_receive_window: Some(GIB),
            max_num_streams: 512,
            read_after_close: true,
            split_send_size: DEFAULT_SPLIT_SEND_SIZE,
        }
    }
}

impl Config {
    /// Set the upper limit for the total receive window size across all streams of a connection.
    ///
    /// Must be `>= 256 KiB * max_num_streams` to allow each stream at least the Yamux default
    /// window size.
    ///
    /// The window of a stream starts at 256 KiB and is increased (auto-tuned) based on the
    /// connection's round-trip time and the stream's bandwidth (striving for the
    /// bandwidth-delay-product).
    ///
    /// Set to `None` to disable limit, i.e. allow each stream to grow receive window based on
    /// connection's round-trip time and stream's bandwidth without limit.
    ///
    /// ## DOS attack mitigation
    ///
    /// A remote node (attacker) might trick the local node (target) into allocating large stream
    /// receive windows, trying to make the local node run out of memory.
    ///
    /// This attack is difficult, as the local node only increases the stream receive window up to
    /// 2x the bandwidth-delay-product, where bandwidth is the amount of bytes read, not just
    /// received. In other words, the attacker has to send (and have the local node read)
    /// significant amount of bytes on a stream over a long period of time to increase the stream
    /// receive window. E.g. on a 60ms 10Gbit/s connection the bandwidth-delay-product is ~75 MiB
    /// and thus the local node will at most allocate ~150 MiB (2x bandwidth-delay-product) per
    /// stream.
    ///
    /// Despite the difficulty of the attack one should choose a reasonable
    /// `max_connection_receive_window` to protect against this attack, especially since an attacker
    /// might use more than one stream per connection.
    pub fn set_max_connection_receive_window(&mut self, n: Option<usize>) -> &mut Self {
        self.max_connection_receive_window = n;

        assert!(
            self.max_connection_receive_window.unwrap_or(usize::MAX)
                >= self.max_num_streams * DEFAULT_CREDIT as usize,
            "`max_connection_receive_window` must be `>= 256 KiB * max_num_streams` to allow each
            stream at least the Yamux default window size"
        );

        self
    }

    /// Set the max. number of streams per connection.
    pub fn set_max_num_streams(&mut self, n: usize) -> &mut Self {
        self.max_num_streams = n;

        assert!(
            self.max_connection_receive_window.unwrap_or(usize::MAX)
                >= self.max_num_streams * DEFAULT_CREDIT as usize,
            "`max_connection_receive_window` must be `>= 256 KiB * max_num_streams` to allow each
            stream at least the Yamux default window size"
        );

        self
    }

    /// Allow or disallow streams to read from buffered data after
    /// the connection has been closed.
    pub fn set_read_after_close(&mut self, b: bool) -> &mut Self {
        self.read_after_close = b;
        self
    }

    /// Set the max. payload size used when sending data frames. Payloads larger
    /// than the configured max. will be split.
    pub fn set_split_send_size(&mut self, n: usize) -> &mut Self {
        self.split_send_size = n;
        self
    }
}

// Check that we can safely cast a `usize` to a `u64`.
static_assertions::const_assert! {
    std::mem::size_of::<usize>() <= std::mem::size_of::<u64>()
}

// Check that we can safely cast a `u32` to a `usize`.
static_assertions::const_assert! {
    std::mem::size_of::<u32>() <= std::mem::size_of::<usize>()
}

#[cfg(test)]
impl quickcheck::Arbitrary for Config {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        use quickcheck::GenRange;

        let max_num_streams = g.gen_range(0..u16::MAX as usize);

        Config {
            max_connection_receive_window: if bool::arbitrary(g) {
                Some(g.gen_range((DEFAULT_CREDIT as usize * max_num_streams)..usize::MAX))
            } else {
                None
            },
            max_num_streams,
            read_after_close: bool::arbitrary(g),
            split_send_size: g.gen_range(DEFAULT_SPLIT_SEND_SIZE..usize::MAX),
        }
    }
}
