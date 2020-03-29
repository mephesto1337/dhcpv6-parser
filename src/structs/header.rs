use nom::number::complete::{be_u8, be_u24};
use nom::IResult;
use nom::sequence::tuple;
use crate::structs::options::{parse_dhcpv6_options, DHCPv6Option};
use crate::structs::message_types::{parse_dhcpv6_message_type, DHCPv6MessageType};
use std::net::Ipv6Addr;

use crate::utils::parse_ipv6_address;

#[derive(Debug, Clone, PartialEq)]
pub enum DHCPv6Header<'a> {
    ClientServer {
        message_type: DHCPv6MessageType,
        transaction_id: u32,
        options: Vec<DHCPv6Option<'a>>,
    },
    RelayAgentServer {
        message_type: DHCPv6MessageType,
        hop_count: u8,
        link_address: Ipv6Addr,
        peer_address: Ipv6Addr,
        options: Vec<DHCPv6Option<'a>>,
    },
}

fn parse_dhcpv6_header_client_server(input: &[u8], message_type: DHCPv6MessageType) -> IResult<&[u8], DHCPv6Header> {
   let (rest, (transaction_id, options)) = tuple((be_u24, parse_dhcpv6_options))(input)?;

    Ok((rest, DHCPv6Header::ClientServer {
            message_type, transaction_id, options
        }))
}

fn parse_dhcpv6_header_relay_agent_server(input: &[u8], message_type: DHCPv6MessageType) -> IResult<&[u8], DHCPv6Header> {
    let (rest, (hop_count, link_address, peer_address, options)) = tuple((be_u8, parse_ipv6_address, parse_ipv6_address, parse_dhcpv6_options))(input)?;

        Ok((rest, DHCPv6Header::RelayAgentServer {
            message_type, hop_count, link_address, peer_address, options
        }))
}

pub fn parse_dhcpv6_header(input: &[u8]) -> IResult<&[u8], DHCPv6Header> {
    let (rest, message_type) = parse_dhcpv6_message_type(input)?;
    match message_type {
        DHCPv6MessageType::RelayForw | DHCPv6MessageType::RelayRepl => {
            parse_dhcpv6_header_relay_agent_server(rest, message_type)
        }
        _ => parse_dhcpv6_header_client_server(rest, message_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_dhcpv6_header() {
        let input = b"\x01\x00\x00\x01\x00\x01\x00\x04toto";
        assert_eq!(
            parse_dhcpv6_header(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Header::ClientServer {
                    message_type: DHCPv6MessageType::Solicit,
                    transaction_id: 1,
                    options: vec![DHCPv6Option::CliendID { duid: &b"toto"[..] }]
                }
            ))
        );
    }
}
