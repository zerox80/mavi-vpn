use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use shared::masque::{
    self, AssignedAddress, IpAddressRange, CAPSULE_ADDRESS_ASSIGN, CAPSULE_MAVI_CONFIG,
    CAPSULE_ROUTE_ADVERTISEMENT,
};

use crate::config::Config;
use crate::handlers::connection::build_config_message;
use crate::handlers::utils::prefix_len_from_mask;
use crate::state::AppState;

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_connect_ip_capsules(
    state: &AppState,
    config: &Config,
    assigned_ip: Ipv4Addr,
    assigned_ip6: Ipv6Addr,
    ipv6_enabled: bool,
) -> Result<Vec<u8>> {
    let success_msg = build_config_message(state, config, assigned_ip, assigned_ip6, ipv6_enabled);
    let mut capsule_stream = Vec::with_capacity(256);

    let mut address_assigns = vec![AssignedAddress {
        request_id: 0,
        ip: IpAddr::V4(assigned_ip),
        prefix_len: prefix_len_from_mask(state.network.mask()),
    }];
    if ipv6_enabled {
        address_assigns.push(AssignedAddress {
            request_id: 0,
            ip: IpAddr::V6(assigned_ip6),
            prefix_len: state.network_v6.prefix(),
        });
    }
    masque::encode_capsule(
        CAPSULE_ADDRESS_ASSIGN,
        &masque::encode_address_assign(&address_assigns),
        &mut capsule_stream,
    );

    let mut routes = vec![IpAddressRange {
        start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        end: IpAddr::V4(Ipv4Addr::BROADCAST),
        ip_protocol: 0,
    }];
    if ipv6_enabled {
        routes.push(IpAddressRange {
            start: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            end: IpAddr::V6(Ipv6Addr::from([0xff; 16])),
            ip_protocol: 0,
        });
    }
    masque::encode_capsule(
        CAPSULE_ROUTE_ADVERTISEMENT,
        &masque::encode_route_advertisement(&routes),
        &mut capsule_stream,
    );

    let mavi_config_bytes =
        bincode::serde::encode_to_vec(&success_msg, bincode::config::standard())?;
    masque::encode_capsule(CAPSULE_MAVI_CONFIG, &mavi_config_bytes, &mut capsule_stream);

    Ok(capsule_stream)
}
