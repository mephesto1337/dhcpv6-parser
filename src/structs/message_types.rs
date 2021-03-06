use nom::combinator::map_opt;
use nom::number::complete::be_u8;
use nom::IResult;
use num_traits::FromPrimitive;

#[derive(Debug, Clone, Eq, PartialEq, Primitive)]
#[repr(u8)]
pub enum DHCPv6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForw = 12,
    RelayRepl = 13,
}

pub fn parse_dhcpv6_message_type(input: &[u8]) -> IResult<&[u8], DHCPv6MessageType> {
    map_opt(be_u8, DHCPv6MessageType::from_u8)(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_dhcpv6_message_type() {
        assert_eq!(
            parse_dhcpv6_message_type(&[1u8][..]),
            Ok((&b""[..], DHCPv6MessageType::Solicit))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[2u8][..]),
            Ok((&b""[..], DHCPv6MessageType::Advertise))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[3u8][..]),
            Ok((&b""[..], DHCPv6MessageType::Request))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[4u8][..]),
            Ok((&b""[..], DHCPv6MessageType::Confirm))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[5u8][..]),
            Ok((&b""[..], DHCPv6MessageType::Renew))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[6u8][..]),
            Ok((&b""[..], DHCPv6MessageType::Rebind))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[7u8][..]),
            Ok((&b""[..], DHCPv6MessageType::Reply))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[8u8][..]),
            Ok((&b""[..], DHCPv6MessageType::Release))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[9u8][..]),
            Ok((&b""[..], DHCPv6MessageType::Decline))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[10u8][..]),
            Ok((&b""[..], DHCPv6MessageType::Reconfigure))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[11u8][..]),
            Ok((&b""[..], DHCPv6MessageType::InformationRequest))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[12u8][..]),
            Ok((&b""[..], DHCPv6MessageType::RelayForw))
        );
        assert_eq!(
            parse_dhcpv6_message_type(&[13u8][..]),
            Ok((&b""[..], DHCPv6MessageType::RelayRepl))
        );
    }

    #[test]
    fn test_invalid_dhcpv6_message_type() {
        assert!(parse_dhcpv6_message_type(&[0u8][..]).is_err());
        assert!(parse_dhcpv6_message_type(&[14u8][..]).is_err());
    }
}
