// Copyright (C) 2022, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! BBR Congestion Control
//!
//! This implementation is based on the following draft:
//! <https://tools.ietf.org/html/draft-cardwell-iccrg-bbr-congestion-control-00>

use crate::minmax::Minmax;
use crate::packet;
use crate::recovery::*;

use std::time::Duration;
use std::time::Instant;

pub static BBR: CongestionControlOps = CongestionControlOps {
    on_init,
    on_packet_sent,
    on_packets_acked,
    congestion_event,
    collapse_cwnd,
    checkpoint,
    rollback,
    has_custom_pacing,
    debug_fmt,
};

/// A constant specifying the length of the BBR.BtlBw max filter window for
/// BBR.BtlBwFilter, BtlBwFilterLen is 10 packet-timed round trips.
const BTLBW_FILTER_LEN: Duration = Duration::from_secs(10);

/// A constant specifying the minimum time interval between ProbeRTT states: 10
/// secs.
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10);

/// A constant specifying the length of the RTProp min filter window.
const RTPROP_FILTER_LEN: Duration = PROBE_RTT_INTERVAL;

/// A constant specifying the minimum gain value that will allow the sending
/// rate to double each round (2/ln(2) ~= 2.89), used in Startup mode for both
/// BBR.pacing_gain and BBR.cwnd_gain.
const BBR_HIGH_GAIN: f64 = 2.89;

/// The minimal cwnd value BBR tries to target using: 4 packets, or 4 * SMSS
const BBR_MIN_PIPE_CWND_PKTS: usize = 4;

/// The number of phases in the BBR ProbeBW gain cycle: 8.
const BBR_GAIN_CYCLE_LEN: usize = 8;

/// A constant specifying the minimum duration for which ProbeRTT state holds
/// inflight to BBRMinPipeCwnd or fewer packets: 200 ms.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// Pacing Gain Cycle.
const PACING_GAIN_CYCLE: [f64; BBR_GAIN_CYCLE_LEN] =
    [5.0 / 4.0, 3.0 / 4.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

/// A constant to check BBR.BtlBW is still growing.
const BTLBW_GROWTH_TARGET: f64 = 1.25;

/// BBR Internal State Machine.
#[derive(Debug, PartialEq, Eq)]
enum BBRStateMachine {
    Startup,
    Drain,
    ProbeBW,
    ProbeRTT,
}

/// Recovery State Machine
#[derive(Debug, PartialEq, Eq)]
enum RecoveryState {
    None,
    Enter,
    Recovery,
}

/// BBR Specific State Variables.
pub struct State {
    state: BBRStateMachine,

    // The current pacing rate for a BBR flow, which controls inter-packet
    // spacing.
    pacing_rate: u64,

    // BBR's estimated bottleneck bandwidth available to the transport flow,
    // estimated from the maximum delivery rate sample in a sliding window.
    btlbw: u64,

    // The max filter used to estimate BBR.BtlBw.
    btlbwfilter: Minmax<u64>,

    // BBR's estimated two-way round-trip propagation delay of the path,
    // estimated from the windowed minimum recent round-trip delay sample.
    rtprop: Duration,

    // The wall clock time at which the current BBR.RTProp sample was obtained.
    rtprop_stamp: Instant,

    // A boolean recording whether the BBR.RTprop has expired and is due for a
    // refresh with an application idle period or a transition into ProbeRTT
    // state.
    rtprop_expired: bool,

    // The dynamic gain factor used to scale BBR.BtlBw to produce
    // BBR.pacing_rate.
    pacing_gain: f64,

    // The dynamic gain factor used to scale the estimated BDP to produce a
    // congestion window (cwnd).
    cwnd_gain: f64,

    // A boolean that records whether BBR estimates that it has ever fully
    // utilized its available bandwidth ("filled the pipe").
    filled_pipe: bool,

    // Count of packet-timed round trips.
    round_count: u64,

    // A boolean that BBR sets to true once per packet-timed round trip,
    // on ACKs that advance BBR.round_count.
    round_start: bool,

    // packet.delivered value denoting the end of a packet-timed round trip.
    next_round_delivered: usize,

    probe_rtt_done_stamp: Option<Instant>,

    probe_rtt_round_done: bool,

    packet_conservation: bool,

    // Saved cwnd before loss recovery.
    prior_cwnd: usize,

    idle_restart: bool,

    full_bw: u64,

    full_bw_count: usize,

    // Last time cycle_index is updated.
    cycle_stamp: Instant,

    // Current index of pacing_gain_cycle[].
    cycle_index: usize,

    // The upper bound on the volume of data BBR allows in flight.
    target_cwnd: usize,

    // A state indicating we are in the recovery.
    recovery_state: RecoveryState,

    // Start time of the connection.
    start_time: Instant,

    // Newly marked lost packets in bytes.
    newly_lost_bytes: usize,

    // Newly bytes of acked data by this ACK.
    newly_acked_bytes: usize,

    // bytes_in_flight before processing this ACK.
    prior_bytes_in_flight: usize,
}

impl State {
    pub fn new() -> Self {
        let now = Instant::now();

        State {
            state: BBRStateMachine::Startup,

            pacing_rate: 0,

            btlbw: 0,

            btlbwfilter: Minmax::new(0),

            rtprop: Duration::ZERO,

            rtprop_stamp: now,

            rtprop_expired: false,

            pacing_gain: 0.0,

            cwnd_gain: 0.0,

            filled_pipe: false,

            round_count: 0,

            round_start: false,

            next_round_delivered: 0,

            probe_rtt_done_stamp: None,

            probe_rtt_round_done: false,

            packet_conservation: false,

            prior_cwnd: 0,

            idle_restart: false,

            full_bw: 0,

            full_bw_count: 0,

            cycle_stamp: now,

            cycle_index: 0,

            target_cwnd: 0,

            recovery_state: RecoveryState::None,

            start_time: now,

            newly_lost_bytes: 0,

            newly_acked_bytes: 0,

            prior_bytes_in_flight: 0,
        }
    }
}

// When entering the recovery episode.
fn bbr_enter_recovery(r: &mut Recovery) {
    r.bbr_state.prior_cwnd = per_ack::bbr_save_cwnd(r);
    r.congestion_window = r.bytes_in_flight +
        r.bbr_state.newly_acked_bytes.max(r.max_datagram_size);
    r.bbr_state.packet_conservation = true;

    r.bbr_state.recovery_state = RecoveryState::Recovery;
}

// When exiting the recovery episode.
fn bbr_exit_recovery(r: &mut Recovery) {
    r.congestion_recovery_start_time = None;
    r.bbr_state.packet_conservation = false;

    per_ack::bbr_restore_cwnd(r);

    r.bbr_state.recovery_state = RecoveryState::None;
}

// Congestion Control Hooks.
//
fn on_init(r: &mut Recovery) {
    init::bbr_init(r);
}

fn on_packet_sent(r: &mut Recovery, sent_bytes: usize, _now: Instant) {
    r.bytes_in_flight += sent_bytes;

    per_transmit::bbr_on_transmit(r);
}

fn on_packets_acked(
    r: &mut Recovery, packets: &[Acked], _epoch: packet::Epoch, now: Instant,
) {
    let acked_bytes: usize = packets
        .iter()
        .map(|p| {
            per_ack::bbr_update_model_and_state(r, p, now);
            p.size
        })
        .sum();

    r.bbr_state.newly_acked_bytes = acked_bytes;
    r.bbr_state.prior_bytes_in_flight = r.bytes_in_flight;

    r.bytes_in_flight = r.bytes_in_flight.saturating_sub(acked_bytes);

    let last_pkt = packets.last();

    match r.bbr_state.recovery_state {
        RecoveryState::Enter => {
            // Upon entering Fast Recovery.
            bbr_enter_recovery(r);
        },

        RecoveryState::Recovery => {
            if let Some(pkt) = last_pkt {
                if !r.in_congestion_recovery(pkt.time_sent) {
                    // Upon exiting loss recovery.
                    bbr_exit_recovery(r);
                } else {
                    // After one round-trip in Fast Recovery.
                    if let Some(recovery_start_time) =
                        r.congestion_recovery_start_time
                    {
                        if r.bbr_state.packet_conservation &&
                            now.saturating_duration_since(recovery_start_time) >
                                r.rtt()
                        {
                            r.bbr_state.packet_conservation = false;
                        }
                    }
                }
            }
        },

        RecoveryState::None => (),
    }

    per_ack::bbr_update_control_parameters(r);

    r.bbr_state.newly_lost_bytes = 0;
}

fn congestion_event(
    r: &mut Recovery, lost_bytes: usize, time_sent: Instant,
    _epoch: packet::Epoch, now: Instant,
) {
    r.bbr_state.newly_lost_bytes = lost_bytes;

    // Upon entering Fast Recovery.
    if !r.in_congestion_recovery(time_sent) {
        r.congestion_recovery_start_time = Some(now);
        r.bbr_state.recovery_state = RecoveryState::Enter;
    }
}

fn collapse_cwnd(r: &mut Recovery) {
    r.bbr_state.prior_cwnd = per_ack::bbr_save_cwnd(r);

    reno::collapse_cwnd(r);
}

fn checkpoint(_r: &mut Recovery) {}

fn rollback(_r: &mut Recovery) -> bool {
    false
}

fn has_custom_pacing() -> bool {
    true
}

fn debug_fmt(r: &Recovery, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    let bbr = &r.bbr_state;

    write!(
         f,
         "bbr={{ state={:?} recovery_state={:?} btlbw={} rtprop={:?} pacing_rate={} pacing_gain={} cwnd_gain={} target_cwnd={} send_quantum={} filled_pipe={} }}",
         bbr.state, bbr.recovery_state, bbr.btlbw, bbr.rtprop, bbr.pacing_rate, bbr.pacing_gain, bbr.cwnd_gain, bbr.target_cwnd, r.send_quantum(), bbr.filled_pipe
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::recovery;

    #[test]
    fn bbr_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR);

        let r = Recovery::new(&cfg);

        assert!(r.cwnd() > 0);
        assert_eq!(r.bytes_in_flight, 0);
    }

    #[test]
    fn bbr_send() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(recovery::CongestionControlAlgorithm::BBR);

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();

        r.on_packet_sent_cc(1000, now);

        assert_eq!(r.bytes_in_flight, 1000);
    }
}

mod init;
mod pacing;
mod per_ack;
mod per_transmit;
