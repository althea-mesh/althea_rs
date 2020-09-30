//! NetworkMonitor is an experimental system to apply traffic shaping to neighbors based on the neighbor rtt
//! it also monitors various network properties to display to the user and to log for later investigation
//! TODO: NetworkMonitor curently has a couple of major deficiencies, we base our throttling choices off of
//! round trip time, but that means that if the other side has been rebooted and the latency spike is due to them
//! uploading we may further limit the connection from our side without any good reason. This can be solved by
//! communcating the current throttle value in the hello seqence. The other problem is that we will respond to latency
//! spikes that are not correlated with traffic. This could lead to limiting connection throughput for reasons as mundane
//! as a bird flying through the connection rather than actual bloat. The solution here would be to also collect stats
//! on traffic over every interface and base our action off of spikes in throughput as well as spikes in latency.

use crate::rita_common::rita_loop::fast_loop::FAST_LOOP_SPEED;
use crate::rita_common::tunnel_manager::GotBloat;
use crate::rita_common::tunnel_manager::Neighbor as RitaNeighbor;
use crate::rita_common::tunnel_manager::TunnelManager;
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::Supervised;
use actix::SystemService;
use althea_types::WgKey;
use babel_monitor::Neighbor as BabelNeighbor;
use babel_monitor::Route as BabelRoute;
use failure::Error;
use std::collections::HashMap;

const SAMPLE_PERIOD: u8 = FAST_LOOP_SPEED as u8;
const SAMPLES_IN_FIVE_MINUTES: usize = 300 / SAMPLE_PERIOD as usize;

/// Implements https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
/// to keep track of neighbor latency in an online fashion
#[derive(Clone)]
pub struct RunningLatencyStats {
    count: u32,
    mean: f32,
    m2: f32,
}

impl RunningLatencyStats {
    pub fn new() -> RunningLatencyStats {
        RunningLatencyStats {
            count: 0u32,
            mean: 0f32,
            m2: 0f32,
        }
    }
    pub fn get_avg(&self) -> Option<f32> {
        if self.count > 2 {
            Some(self.mean)
        } else {
            None
        }
    }
    pub fn get_std_dev(&self) -> Option<f32> {
        if self.count > 2 {
            Some(self.m2 / self.count as f32)
        } else {
            None
        }
    }
    pub fn add_sample(&mut self, sample: f32) {
        self.count += 1;
        let delta = sample - self.mean;
        self.mean += delta / self.count as f32;
        let delta2 = sample - self.mean;
        self.m2 += delta * delta2;
    }
    /// A hand tuned heuristic used to determine if a connection is bloated
    pub fn is_bloated(&self) -> bool {
        let avg = self.get_avg();
        let std_dev = self.get_std_dev();
        match (avg, std_dev) {
            (Some(avg), Some(std_dev)) => std_dev > avg * 10f32,
            (Some(_avg), None) => false,
            (None, Some(_std_dev)) => false,
            (None, None) => false,
        }
    }
    pub fn reset(&mut self) {
        self.count = 0u32;
        self.mean = 0f32;
        self.m2 = 0f32;
    }
}

/// Due to the way babel communicates packet loss the functions here require slightly
/// more data processing to get correct values. 'Reach' is a 16 second bitvector of hello/IHU
/// outcomes, but we're sampling every 5 seconds, in order to keep samples from interfering with
/// each other we take the top 5 bits and use that to compute packet loss.
#[derive(Clone)]
pub struct RunningPacketLossStats {
    /// the number of packets lost during each 5 second sample period over the last five minutes
    five_minute_loss: [u8; SAMPLES_IN_FIVE_MINUTES],
    /// the 'front' of the looping five minute sample queue
    front: usize,
    /// Total packets observed since the system was started
    total_packets: u32,
    /// Total packets observed to be lost since the system was started
    total_lost: u32,
}

impl RunningPacketLossStats {
    pub fn new() -> RunningPacketLossStats {
        RunningPacketLossStats {
            five_minute_loss: [0u8; SAMPLES_IN_FIVE_MINUTES],
            front: 0usize,
            total_packets: 0u32,
            total_lost: 0u32,
        }
    }
    pub fn add_sample(&mut self, sample: u16) {
        // babel displays a 16 second window of hellos, so adjust this based on
        // any changes in run rate of this function
        let lost_packets = SAMPLE_PERIOD - get_first_n_set_bits(sample, SAMPLE_PERIOD);
        self.total_lost += u32::from(lost_packets);
        self.total_packets += u32::from(SAMPLE_PERIOD);
        self.five_minute_loss[self.front] = lost_packets;
        self.front = (self.front + 1) % SAMPLES_IN_FIVE_MINUTES;
    }
    pub fn get_avg(&self) -> Option<f32> {
        if self.total_packets > 0 {
            Some(self.total_lost as f32 / self.total_packets as f32)
        } else {
            None
        }
    }
    pub fn get_five_min_average(&self) -> f32 {
        let total_packets = SAMPLES_IN_FIVE_MINUTES * SAMPLE_PERIOD as usize;
        let sum_loss: usize = self.five_minute_loss.iter().map(|i| *i as usize).sum();
        sum_loss as f32 / total_packets as f32
    }
}

/// Counts the number of bits set to 1 in the first n bits (reading left to right so MSB first) of
/// the 16 bit bitvector
fn get_first_n_set_bits(sample: u16, n: u8) -> u8 {
    assert!(n <= 16);
    let mut mask = 0b1000_0000_0000_0000;
    let mut total_set_bits = 0u8;
    for i in ((16 - n)..16).rev() {
        trace!(
            "{:#b} {:#b} >> {} {:#b}",
            mask,
            sample & mask,
            i,
            ((sample & mask) >> i)
        );
        total_set_bits += ((sample & mask) >> i) as u8;
        mask >>= 1;
    }
    total_set_bits
}

fn has_packet_loss(sample: u16) -> bool {
    let lost_packets = SAMPLE_PERIOD - get_first_n_set_bits(sample, SAMPLE_PERIOD);
    lost_packets > 0
}

#[derive(Clone)]
pub struct NetworkMonitor {
    latency_history: HashMap<String, RunningLatencyStats>,
    packet_loss_history: HashMap<String, RunningPacketLossStats>,
    last_babel_dump: Option<NetworkInfo>,
}

impl Actor for NetworkMonitor {
    type Context = Context<Self>;
}

impl Supervised for NetworkMonitor {}
impl SystemService for NetworkMonitor {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {
        info!("NetworkMonitor started");
        // if this assertion is failing you're running this slowly enough
        // that all the sample period logic is not relevent, go disable it
        if !SAMPLE_PERIOD <= 16 {
            panic!("NetworkMonitor is running too slowly! Please adjust constants");
        }
    }
}

impl NetworkMonitor {
    pub fn new() -> Self {
        NetworkMonitor {
            latency_history: HashMap::new(),
            packet_loss_history: HashMap::new(),
            last_babel_dump: None,
        }
    }
}

impl Default for NetworkMonitor {
    fn default() -> NetworkMonitor {
        NetworkMonitor::new()
    }
}

#[derive(Default, Serialize, Copy, Clone)]
pub struct LatencyStats {
    avg: Option<f32>,
    std_dev: Option<f32>,
}

#[derive(Default, Serialize, Copy, Clone)]
pub struct PacketLossStats {
    avg: Option<f32>,
    five_min_avg: f32,
}

pub struct GetStats {}

#[derive(Serialize, Default, Copy, Clone)]
pub struct IfaceStats {
    latency: LatencyStats,
    packet_loss: PacketLossStats,
}

impl Message for GetStats {
    type Result = Result<Stats, Error>;
}

pub type Stats = HashMap<String, IfaceStats>;

impl Handler<GetStats> for NetworkMonitor {
    type Result = Result<Stats, Error>;

    fn handle(&mut self, _msg: GetStats, _ctx: &mut Context<Self>) -> Self::Result {
        let mut stats = Stats::new();

        for (iface, latency_stats) in self.latency_history.iter() {
            if let Some(packet_loss_stats) = self.packet_loss_history.get(iface) {
                stats.insert(
                    iface.clone(),
                    IfaceStats {
                        latency: LatencyStats {
                            avg: latency_stats.get_avg(),
                            std_dev: latency_stats.get_std_dev(),
                        },
                        packet_loss: PacketLossStats {
                            avg: packet_loss_stats.get_avg(),
                            five_min_avg: packet_loss_stats.get_five_min_average(),
                        },
                    },
                );
            } else {
                error!("Found entry in one that's not in the other ")
            }
        }

        Ok(stats)
    }
}

pub struct GetNetworkInfo;

impl Message for GetNetworkInfo {
    type Result = Result<NetworkInfo, Error>;
}

impl Handler<GetNetworkInfo> for NetworkMonitor {
    type Result = Result<NetworkInfo, Error>;

    fn handle(&mut self, _msg: GetNetworkInfo, _ctx: &mut Context<Self>) -> Self::Result {
        match self.last_babel_dump.clone() {
            Some(dump) => Ok(dump),
            None => Err(format_err!("No babel info ready!")),
        }
    }
}

#[derive(Message, Clone)]
pub struct NetworkInfo {
    pub babel_neighbors: Vec<BabelNeighbor>,
    pub babel_routes: Vec<BabelRoute>,
    pub rita_neighbors: Vec<RitaNeighbor>,
}

impl Handler<NetworkInfo> for NetworkMonitor {
    type Result = ();

    fn handle(&mut self, msg: NetworkInfo, _ctx: &mut Context<Self>) -> Self::Result {
        let babel_neighbors = &msg.babel_neighbors;
        let babel_routes = &msg.babel_routes;
        let rita_neighbors = &msg.rita_neighbors;
        observe_network(
            babel_neighbors,
            rita_neighbors,
            &mut self.latency_history,
            &mut self.packet_loss_history,
        );
        network_stats(babel_routes, babel_neighbors);
        self.last_babel_dump = Some(msg);
    }
}

/// Attempts to detect bufferbloat by looking at neighbor latency over time
fn observe_network(
    babel_neighbors: &[BabelNeighbor],
    rita_neighbors: &[RitaNeighbor],
    latency_history: &mut HashMap<String, RunningLatencyStats>,
    packet_loss_history: &mut HashMap<String, RunningPacketLossStats>,
) {
    for neigh in babel_neighbors.iter() {
        let iface = &neigh.iface;
        if !latency_history.contains_key(iface) {
            latency_history.insert(iface.clone(), RunningLatencyStats::new());
        }
        let running_stats = latency_history.get_mut(iface).unwrap();
        match (
            running_stats.is_bloated(),
            get_wg_key_by_ifname(neigh, rita_neighbors),
            running_stats.get_avg(),
            running_stats.get_std_dev(),
        ) {
            (true, Some(key), Some(avg), Some(std_dev)) => {
                info!(
                    "{} is now defined as bloated with AVG {} STDDEV {} and CV {}!",
                    key, avg, std_dev, neigh.rtt
                );
                // shape the misbehaving tunnel
                TunnelManager::from_registry().do_send(GotBloat {
                    iface: iface.to_string(),
                });
                // reset the values for this entry because we have modified
                // the qdisc and it's no longer an accurate representation
                running_stats.reset();
            }
            (false, Some(key), Some(avg), Some(std_dev)) => info!(
                "Neighbor {} is ok with AVG {} STDDEV {} and CV {}",
                key, avg, std_dev, neigh.rtt
            ),
            (true, None, _, _) => error!(
                "We have a bloated connection to {} but no Rita neighbor!",
                iface
            ),
            (_, _, _, _) => {}
        }
        running_stats.add_sample(neigh.rtt);
    }
    for neigh in babel_neighbors.iter() {
        let iface = &neigh.iface;
        if !packet_loss_history.contains_key(iface) {
            packet_loss_history.insert(iface.clone(), RunningPacketLossStats::new());
        }
        let running_stats = packet_loss_history.get_mut(iface).unwrap();
        running_stats.add_sample(neigh.reach);
        match (
            has_packet_loss(neigh.reach),
            running_stats.get_avg(),
            get_wg_key_by_ifname(neigh, rita_neighbors),
        ) {
            (true, Some(avg), Some(key)) => {
                let five_min_average = running_stats.get_five_min_average();
                info!(
                    "Lost packets to {} {}% five min average {}% power on average",
                    key, five_min_average, avg
                );
            }
            (true, Some(_avg), None) => {
                error!(
                    "We have a packet loss event to {} but no Rita neighbor!",
                    iface
                );
            }
            (true, None, _) => {}
            (false, _, _) => {}
        }
    }
}

fn get_wg_key_by_ifname(neigh: &BabelNeighbor, rita_neighbors: &[RitaNeighbor]) -> Option<WgKey> {
    for rita_neigh in rita_neighbors.iter() {
        if rita_neigh.iface_name.contains(&neigh.iface) {
            return Some(rita_neigh.identity.global.wg_public_key);
        }
    }
    None
}

/// Gathers interesting network info
fn network_stats(babel_routes: &[BabelRoute], babel_neighbors: &[BabelNeighbor]) {
    if let Some(avg_neigh_rtt) = mean(&extract_rtt(babel_neighbors)) {
        let num_neighs = babel_neighbors.len();
        info!(
            "The average neigh RTT is {} for {} neighs",
            avg_neigh_rtt, num_neighs
        );
    }
    if let Some(avg_route_rtt) = mean(&extract_fp_rtt(babel_routes)) {
        let num_routes = babel_routes.len();
        info!(
            "The average route RTT is {} for {} routes",
            avg_route_rtt, num_routes
        );
    }
}

/// Extracts the full path rtt for Neighbors
fn extract_rtt(neighbors: &[BabelNeighbor]) -> Vec<f32> {
    neighbors.iter().map(|neigh| neigh.rtt).collect()
}

/// Extracts the full path rtt for installed routes
fn extract_fp_rtt(routes: &[BabelRoute]) -> Vec<f32> {
    routes
        .iter()
        .filter(|route| route.installed)
        .map(|route| route.full_path_rtt)
        .collect()
}

fn mean(data: &[f32]) -> Option<f32> {
    let sum = data.iter().sum::<f32>();
    let count = data.len();

    match count {
        positive if positive > 0 => Some(sum / count as f32),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_first_n_set_bits() {
        let count = get_first_n_set_bits(0b1110_0000_0000_0000, 5);
        assert_eq!(count, 3);
    }
    #[test]
    fn test_get_first_n_set_bits_limit() {
        let count = get_first_n_set_bits(0b1111_1100_0000_0000, 5);
        assert_eq!(count, 5);
    }
    #[test]
    fn test_get_first_n_set_bits_lower_bits() {
        let count = get_first_n_set_bits(0b1110_0000_0000_1100, 5);
        assert_eq!(count, 3);
    }
    #[test]
    fn test_get_first_n_set_bits_lower_longer_range() {
        let count = get_first_n_set_bits(0b1110_0000_0000_1100, 16);
        assert_eq!(count, 5);
    }
    #[test]
    fn test_all_set() {
        let count = get_first_n_set_bits(0b1111_1111_1111_1111, 16);
        assert_eq!(count, 16);
    }
    // #[test]
    // #[should_panic]
    // fn test_get_first_n_set_bits_impossible() {
    //     let _count = get_first_n_set_bits(0b1110_0000_0000_1100, 32);
    // }
}
