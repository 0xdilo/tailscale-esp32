use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use thiserror::Error;

use super::control::NodeInfo;
use super::key::{Disco, Node, PublicKey};

const PROBE_INTERVAL_MS: u64 = 5_000;
const DIRECT_PATH_LIFETIME_MS: u64 = 120_000;
const MAX_CANDIDATES_PER_PEER: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Direct(SocketAddr),
    Derp(u16),
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Probe {
    pub peer: PublicKey<Node>,
    pub disco_key: PublicKey<Disco>,
    pub destination: SocketAddr,
    pub transaction_id: [u8; 12],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateSource {
    Control,
    CallMeMaybe,
    Inbound,
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    source: CandidateSource,
    last_probe_ms: Option<u64>,
    last_reply_ms: Option<u64>,
    latency_ms: u32,
}

struct PeerPaths {
    disco_key: PublicKey<Disco>,
    home_derp: u16,
    candidates: BTreeMap<SocketAddr, Candidate>,
    outstanding: BTreeMap<[u8; 12], (SocketAddr, u64)>,
}

#[derive(Default)]
pub struct EndpointTracker {
    peers: BTreeMap<PublicKey<Node>, PeerPaths>,
}

impl EndpointTracker {
    pub fn update_from_network_map<'a>(&mut self, peers: impl IntoIterator<Item = &'a NodeInfo>) {
        let mut present = BTreeSet::new();
        for peer in peers {
            present.insert(peer.key);
            let paths = self.peers.entry(peer.key).or_insert_with(|| PeerPaths {
                disco_key: peer.disco_key,
                home_derp: peer.home_derp,
                candidates: BTreeMap::new(),
                outstanding: BTreeMap::new(),
            });
            paths.disco_key = peer.disco_key;
            paths.home_derp = peer.home_derp;
            for endpoint in peer.endpoints.iter().filter_map(|value| value.parse().ok()) {
                paths.candidates.entry(endpoint).or_insert(Candidate {
                    source: CandidateSource::Control,
                    last_probe_ms: None,
                    last_reply_ms: None,
                    latency_ms: u32::MAX,
                });
            }
            trim_candidates(paths);
        }
        self.peers.retain(|key, _| present.contains(key));
    }

    pub fn update_call_me_maybe(
        &mut self,
        peer: PublicKey<Node>,
        disco_key: PublicKey<Disco>,
        endpoints: &[SocketAddr],
    ) -> bool {
        let Some(paths) = self.peers.get_mut(&peer) else {
            return false;
        };
        if paths.disco_key != disco_key {
            return false;
        }
        let advertised: BTreeSet<_> = endpoints.iter().copied().collect();
        paths.candidates.retain(|endpoint, candidate| {
            candidate.source != CandidateSource::CallMeMaybe || advertised.contains(endpoint)
        });
        for endpoint in advertised {
            paths.candidates.entry(endpoint).or_insert(Candidate {
                source: CandidateSource::CallMeMaybe,
                last_probe_ms: None,
                last_reply_ms: None,
                latency_ms: u32::MAX,
            });
        }
        trim_candidates(paths);
        true
    }

    pub fn plan_probes(
        &mut self,
        peer: PublicKey<Node>,
        now_ms: u64,
    ) -> Result<Vec<Probe>, PathError> {
        let Some(paths) = self.peers.get_mut(&peer) else {
            return Ok(Vec::new());
        };
        paths
            .outstanding
            .retain(|_, (_, sent_ms)| now_ms.saturating_sub(*sent_ms) < DIRECT_PATH_LIFETIME_MS);
        let mut probes = Vec::new();
        for (destination, candidate) in &mut paths.candidates {
            let due = candidate
                .last_probe_ms
                .is_none_or(|last| now_ms.saturating_sub(last) >= PROBE_INTERVAL_MS);
            if !due {
                continue;
            }
            let transaction_id = unique_transaction_id(&paths.outstanding)?;
            candidate.last_probe_ms = Some(now_ms);
            paths
                .outstanding
                .insert(transaction_id, (*destination, now_ms));
            probes.push(Probe {
                peer,
                disco_key: paths.disco_key,
                destination: *destination,
                transaction_id,
            });
        }
        Ok(probes)
    }

    pub fn record_pong(
        &mut self,
        peer: PublicKey<Node>,
        disco_key: PublicKey<Disco>,
        source: SocketAddr,
        transaction_id: [u8; 12],
        now_ms: u64,
    ) -> bool {
        let Some(paths) = self.peers.get_mut(&peer) else {
            return false;
        };
        if paths.disco_key != disco_key {
            return false;
        }
        let Some(&(destination, sent_ms)) = paths.outstanding.get(&transaction_id) else {
            return false;
        };
        if destination != source {
            return false;
        }
        paths.outstanding.remove(&transaction_id);
        let elapsed = now_ms.saturating_sub(sent_ms).min(u32::MAX as u64) as u32;
        let candidate = paths.candidates.entry(source).or_insert(Candidate {
            source: CandidateSource::Inbound,
            last_probe_ms: Some(sent_ms),
            last_reply_ms: None,
            latency_ms: elapsed,
        });
        candidate.last_reply_ms = Some(now_ms);
        candidate.latency_ms = if candidate.latency_ms == u32::MAX {
            elapsed
        } else {
            (candidate.latency_ms.saturating_mul(3) + elapsed) / 4
        };
        true
    }

    pub fn record_authenticated_inbound(
        &mut self,
        peer: PublicKey<Node>,
        disco_key: PublicKey<Disco>,
        source: SocketAddr,
        now_ms: u64,
    ) -> bool {
        let Some(paths) = self.peers.get_mut(&peer) else {
            return false;
        };
        if paths.disco_key != disco_key {
            return false;
        }
        let candidate = paths.candidates.entry(source).or_insert(Candidate {
            source: CandidateSource::Inbound,
            last_probe_ms: None,
            last_reply_ms: Some(now_ms),
            latency_ms: 0,
        });
        candidate.last_reply_ms = Some(now_ms);
        trim_candidates(paths);
        true
    }

    pub fn route(&self, peer: PublicKey<Node>, now_ms: u64) -> Route {
        let Some(paths) = self.peers.get(&peer) else {
            return Route::Unavailable;
        };
        if let Some((endpoint, _)) = paths
            .candidates
            .iter()
            .filter(|(_, candidate)| {
                candidate
                    .last_reply_ms
                    .is_some_and(|last| now_ms.saturating_sub(last) < DIRECT_PATH_LIFETIME_MS)
            })
            .min_by_key(|(_, candidate)| candidate.latency_ms)
        {
            return Route::Direct(*endpoint);
        }
        if paths.home_derp == 0 {
            Route::Unavailable
        } else {
            Route::Derp(paths.home_derp)
        }
    }
}

fn unique_transaction_id(
    outstanding: &BTreeMap<[u8; 12], (SocketAddr, u64)>,
) -> Result<[u8; 12], PathError> {
    for _ in 0..8 {
        let mut transaction_id = [0_u8; 12];
        getrandom::getrandom(&mut transaction_id).map_err(PathError::Random)?;
        if !outstanding.contains_key(&transaction_id) {
            return Ok(transaction_id);
        }
    }
    Err(PathError::TransactionCollision)
}

fn trim_candidates(paths: &mut PeerPaths) {
    while paths.candidates.len() > MAX_CANDIDATES_PER_PEER {
        let removable = paths
            .candidates
            .iter()
            .min_by_key(|(_, candidate)| {
                (candidate.last_reply_ms.is_some(), candidate.last_reply_ms)
            })
            .map(|(endpoint, _)| *endpoint);
        let Some(endpoint) = removable else {
            break;
        };
        paths.candidates.remove(&endpoint);
    }
}

#[derive(Debug, Error)]
pub enum PathError {
    #[error("endpoint probe random generation failed: {0}")]
    Random(getrandom::Error),
    #[error("could not generate a unique endpoint probe transaction")]
    TransactionCollision,
}

#[cfg(test)]
mod tests {
    use super::{EndpointTracker, Route};
    use crate::control::NodeInfo;
    use crate::key::{Disco, Machine, Node, PublicKey};

    fn peer() -> NodeInfo {
        NodeInfo {
            id: 1,
            stable_id: "peer".into(),
            name: "peer".into(),
            user: 1,
            key: PublicKey::<Node>::from_bytes([1; 32]),
            machine: PublicKey::<Machine>::from_bytes([2; 32]),
            disco_key: PublicKey::<Disco>::from_bytes([3; 32]),
            addresses: vec!["100.64.0.1/32".into()],
            allowed_ips: None,
            endpoints: vec!["192.0.2.1:41641".into()],
            home_derp: 4,
            online: Some(true),
            machine_authorized: true,
        }
    }

    #[test]
    fn probes_authenticated_paths_then_falls_back_to_derp() {
        let peer = peer();
        let mut tracker = EndpointTracker::default();
        tracker.update_from_network_map([&peer]);
        assert_eq!(tracker.route(peer.key, 0), Route::Derp(4));
        let probe = tracker.plan_probes(peer.key, 1_000).unwrap().remove(0);
        assert!(tracker.record_pong(
            peer.key,
            peer.disco_key,
            probe.destination,
            probe.transaction_id,
            1_025,
        ));
        assert_eq!(
            tracker.route(peer.key, 1_026),
            Route::Direct(probe.destination)
        );
        assert_eq!(tracker.route(peer.key, 122_000), Route::Derp(4));
    }

    #[test]
    fn rejects_unmatched_pongs_and_wrong_disco_keys() {
        let peer = peer();
        let mut tracker = EndpointTracker::default();
        tracker.update_from_network_map([&peer]);
        let probe = tracker.plan_probes(peer.key, 1_000).unwrap().remove(0);
        assert!(!tracker.record_pong(
            peer.key,
            PublicKey::<Disco>::from_bytes([9; 32]),
            probe.destination,
            probe.transaction_id,
            1_010,
        ));
        assert!(tracker.record_pong(
            peer.key,
            peer.disco_key,
            probe.destination,
            probe.transaction_id,
            1_020,
        ));
        assert!(!tracker.record_pong(
            peer.key,
            peer.disco_key,
            "192.0.2.2:41641".parse().unwrap(),
            probe.transaction_id,
            1_010,
        ));
    }

    #[test]
    fn accepts_and_replaces_authenticated_call_me_maybe_candidates() {
        let peer = peer();
        let mut tracker = EndpointTracker::default();
        tracker.update_from_network_map([&peer]);
        let endpoint = "198.51.100.2:41641".parse().unwrap();
        assert!(tracker.update_call_me_maybe(peer.key, peer.disco_key, &[endpoint]));
        assert!(tracker
            .plan_probes(peer.key, 1_000)
            .unwrap()
            .iter()
            .any(|probe| probe.destination == endpoint));
    }
}
