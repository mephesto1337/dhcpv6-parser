use message_types::*;
use nom::{be_u24, be_u8, IResult};
use options::*;
use std::net::Ipv6Addr;

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

named_args!(parse_dhcpv6_header_client_server(message_type: DHCPv6MessageType)<DHCPv6Header>,
    do_parse!(
        transaction_id: be_u24
        >> options: parse_dhcpv6_options
        >> (DHCPv6Header::ClientServer {
            message_type, transaction_id, options
        })
    )
);

named_args!(parse_dhcpv6_header_relay_agent_server(message_type: DHCPv6MessageType)<DHCPv6Header>,
    do_parse!(
        hop_count: be_u8
        >> link_address: map!(count_fixed!(u8, be_u8, 16), Ipv6Addr::from)
        >> peer_address: map!(count_fixed!(u8, be_u8, 16), Ipv6Addr::from)
        >> options: many0!(parse_dhcpv6_option)
        >> (DHCPv6Header::RelayAgentServer {
            message_type, hop_count, link_address, peer_address, options
        })
    )
);

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
