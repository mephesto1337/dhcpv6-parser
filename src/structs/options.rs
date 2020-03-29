// use nom::{be_u16, be_u32, be_u64, be_u8, IResult};
use nom::bytes::complete::take;
use nom::combinator::verify;
use nom::multi::{many0, many_m_n};
use nom::number::complete::{be_u16, be_u32, be_u64};
use nom::sequence::tuple;
use nom::IResult;
use std::net::Ipv6Addr;

use crate::utils::parse_ipv6_address;

#[derive(Debug, Clone, PartialEq)]
pub enum DHCPv6Option<'a> {
    CliendID {
        duid: &'a [u8],
    },
    ServerID {
        duid: &'a [u8],
    },
    IdentityAssociationForNonTemporaryAddresses {
        id: u32,
        time_1: u32,
        time_2: u32,
        options: &'a [u8],
    },
    IdentityAssociationForTemporaryAddresses {
        id: u32,
        options: &'a [u8],
    },
    IdentityAssociationAddress {
        address: Ipv6Addr,
        prefered_lifetime: u32,
        valid_lifetime: u32,
        options: &'a [u8],
    },
    OptionRequest {
        options: Vec<u16>,
    },
    Preference {
        pref_value: u8,
    },
    ElapstedTime {
        elapsed_time: u16,
    },
    RelayMessage {
        data: &'a [u8],
    },
    Authentication {
        protocol: u8,
        algorithm: u8,
        rdm: u8,
        replay_detection: u64,
        authentication_information: &'a [u8],
    },
    ServerUnicast {
        address: Ipv6Addr,
    },
    StatusCode {
        code: u16,
        message: &'a str,
    },
    RapidCommit {},
    UserClass {
        data: &'a [u8],
    },
    VendorClass {
        enterprise_number: u32,
        data: &'a [u8],
    },
    VendorSpecificInformation {
        enterprise_number: u32,
        data: &'a [u8],
    },
    InterfaceID {
        data: &'a [u8],
    },
    ReconfigureMessage {
        message_type: u8,
    },
    ReconfigureAccept {},
}

fn parse_dhcpv6_option_client_id(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = be_u16(input)?;
    let (rest, duid) = take(len as usize)(rest)?;

    Ok((rest, DHCPv6Option::CliendID { duid }))
}

fn parse_dhcpv6_option_server_id(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = be_u16(input)?;
    let (rest, duid) = take(len as usize)(rest)?;

    Ok((rest, DHCPv6Option::ServerID { duid }))
}

fn parse_dhcpv6_option_ia_na(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = verify(be_u16, |len: &u16| *len >= 12)(input)?;
    let (rest, (id, time_1, time_2, options)) =
        tuple((be_u32, be_u32, be_u32, take(len as usize - 12usize)))(rest)?;

    Ok((
        rest,
        DHCPv6Option::IdentityAssociationForNonTemporaryAddresses {
            id,
            time_1,
            time_2,
            options,
        },
    ))
}

fn parse_dhcpv6_option_ia_ta(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = verify(be_u16, |len: &u16| *len >= 4)(input)?;
    let (rest, (id, options)) = tuple((be_u32, take(len as usize - 4usize)))(rest)?;

    Ok((
        rest,
        DHCPv6Option::IdentityAssociationForTemporaryAddresses { id, options },
    ))
}

fn parse_dhcpv6_option_ia(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = verify(be_u16, |len: &u16| *len >= 24)(input)?;
    let (rest, (address, prefered_lifetime, valid_lifetime, options)) = tuple((
        parse_ipv6_address,
        be_u32,
        be_u32,
        take(len as usize - 24usize),
    ))(rest)?;

    Ok((
        rest,
        DHCPv6Option::IdentityAssociationAddress {
            address,
            prefered_lifetime,
            valid_lifetime,
            options,
        },
    ))
}

fn parse_dhcpv6_option_option_request(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = verify(be_u16, |len: &u16| *len & 1 == 0)(input)?;
    let count = len as usize / 2;
    let (rest, options) = many_m_n(count, count, be_u16)(rest)?;

    Ok((rest, DHCPv6Option::OptionRequest { options }))
}

fn parse_dhcpv6_option_preference(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, _len) = verify(be_u16, |len: &u16| *len == 1)(input)?;
    let pref_value = rest[0];

    Ok((&rest[1..], DHCPv6Option::Preference { pref_value }))
}

fn parse_dhcpv6_option_elapsted_time(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, _len) = verify(be_u16, |len: &u16| *len == 2)(input)?;
    let (rest, elapsed_time) = be_u16(rest)?;

    Ok((rest, DHCPv6Option::ElapstedTime { elapsed_time }))
}

fn parse_dhcpv6_option_relay_message(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = be_u16(input)?;
    let (rest, data) = take(len as usize)(rest)?;

    Ok((rest, DHCPv6Option::RelayMessage { data }))
}

fn parse_dhcpv6_option_authentication(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = verify(be_u16, |len: &u16| *len >= 11)(input)?;
    let (protocol, algorithm, rdm) = (rest[0], rest[1], rest[2]);
    let (rest, (replay_detection, authentication_information)) =
        tuple((be_u64, take(len as usize - 11)))(&rest[3..])?;

    Ok((
        rest,
        DHCPv6Option::Authentication {
            protocol,
            algorithm,
            rdm,
            replay_detection,
            authentication_information,
        },
    ))
}

fn parse_dhcpv6_option_server_unicast(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, _len) = verify(be_u16, |len: &u16| *len == 16)(input)?;
    let (rest, address) = parse_ipv6_address(rest)?;

    Ok((rest, DHCPv6Option::ServerUnicast { address }))
}

fn parse_dhcpv6_option_status_code(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = verify(be_u16, |len: &u16| *len >= 2)(input)?;
    let (rest, (code, raw_message)) = tuple((be_u16, take(len as usize - 2)))(rest)?;

    if let Ok(message) = ::std::str::from_utf8(raw_message) {
        Ok((rest, DHCPv6Option::StatusCode { code, message }))
    } else {
        Err(::nom::Err::Error((rest, ::nom::error::ErrorKind::Verify)))
    }
}

fn parse_dhcpv6_option_rapid_commit(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, _len) = verify(be_u16, |len: &u16| *len == 0)(input)?;

    Ok((rest, DHCPv6Option::RapidCommit {}))
}

fn parse_dhcpv6_option_user_class(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = be_u16(input)?;
    let (rest, data) = take(len as usize)(rest)?;

    Ok((rest, DHCPv6Option::UserClass { data }))
}

fn parse_dhcpv6_option_vendor_class(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = verify(be_u16, |len: &u16| *len >= 4)(input)?;
    let (rest, (enterprise_number, data)) = tuple((be_u32, take(len as usize - 4)))(rest)?;

    Ok((
        rest,
        DHCPv6Option::VendorClass {
            enterprise_number,
            data,
        },
    ))
}

fn parse_dhcpv6_option_vendor_specific_information(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = verify(be_u16, |len: &u16| *len >= 4)(input)?;
    let (rest, (enterprise_number, data)) = tuple((be_u32, take(len as usize - 4)))(rest)?;

    Ok((
        rest,
        DHCPv6Option::VendorSpecificInformation {
            enterprise_number,
            data,
        },
    ))
}

fn parse_dhcpv6_option_interface_id(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, len) = be_u16(input)?;
    let (rest, data) = take(len as usize)(rest)?;

    Ok((rest, DHCPv6Option::InterfaceID { data }))
}

fn parse_dhcpv6_option_reconfigure_message(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, _len) = verify(be_u16, |len: &u16| *len == 1)(input)?;

    Ok((
        &rest[1..],
        DHCPv6Option::ReconfigureMessage {
            message_type: rest[0],
        },
    ))
}

fn parse_dhcpv6_option_reconfigure_accept(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, _len) = verify(be_u16, |len: &u16| *len == 0)(input)?;

    Ok((rest, DHCPv6Option::ReconfigureAccept {}))
}

pub fn parse_dhcpv6_option(input: &[u8]) -> IResult<&[u8], DHCPv6Option> {
    let (rest, kind) = be_u16(input)?;

    match kind {
        1u16 => parse_dhcpv6_option_client_id(rest),
        2u16 => parse_dhcpv6_option_server_id(rest),
        3u16 => parse_dhcpv6_option_ia_na(rest),
        4u16 => parse_dhcpv6_option_ia_ta(rest),
        5u16 => parse_dhcpv6_option_ia(rest),
        6u16 => parse_dhcpv6_option_option_request(rest),
        7u16 => parse_dhcpv6_option_preference(rest),
        8u16 => parse_dhcpv6_option_elapsted_time(rest),
        9u16 => parse_dhcpv6_option_relay_message(rest),
        // no 10u16
        11u16 => parse_dhcpv6_option_authentication(rest),
        12u16 => parse_dhcpv6_option_server_unicast(rest),
        13u16 => parse_dhcpv6_option_status_code(rest),
        14u16 => parse_dhcpv6_option_rapid_commit(rest),
        15u16 => parse_dhcpv6_option_user_class(rest),
        16u16 => parse_dhcpv6_option_vendor_class(rest),
        17u16 => parse_dhcpv6_option_vendor_specific_information(rest),
        18u16 => parse_dhcpv6_option_interface_id(rest),
        19u16 => parse_dhcpv6_option_reconfigure_message(rest),
        20u16 => parse_dhcpv6_option_reconfigure_accept(rest),
        _ => Err(::nom::Err::Error((rest, ::nom::error::ErrorKind::Switch))),
    }
}

pub fn parse_dhcpv6_options(input: &[u8]) -> IResult<&[u8], Vec<DHCPv6Option>> {
    let (rest, options) = many0(parse_dhcpv6_option)(input)?;

    assert!(rest.len() == 0);

    Ok((rest, options))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_valid_option_client_id() {
        let input = b"\x00\x01\x00\x04toto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((&b""[..], DHCPv6Option::CliendID { duid: &b"toto"[..] }))
        );
    }

    #[test]
    fn test_valid_option_server_id() {
        let input = b"\x00\x02\x00\x04toto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((&b""[..], DHCPv6Option::ServerID { duid: &b"toto"[..] }))
        );
    }

    #[test]
    fn test_valid_option_ia_na() {
        let input = b"\x00\x03\x00\x10\x00\x00\x00\x01\x01\x23\x45\x67\x89\xab\xcd\xeftoto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Option::IdentityAssociationForNonTemporaryAddresses {
                    id: 1,
                    time_1: 0x01234567,
                    time_2: 0x89abcdef,
                    options: &b"toto"[..]
                }
            ))
        );
    }

    #[test]
    fn test_valid_option_ia_ta() {
        let input = b"\x00\x04\x00\x08\x00\x00\x00\x01toto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Option::IdentityAssociationForTemporaryAddresses {
                    id: 1,
                    options: &b"toto"[..]
                }
            ))
        );
    }

    #[test]
    fn test_valid_option_ia() {
        let input = b"\x00\x05\x00\x1c\
                    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\
                    \xff\xff\xff\xff\xff\xff\xff\xff\
                    toto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Option::IdentityAssociationAddress {
                    address: Ipv6Addr::LOCALHOST,
                    prefered_lifetime: 0xffffffff,
                    valid_lifetime: 0xffffffff,
                    options: &b"toto"[..],
                }
            ))
        );
    }

    #[test]
    fn test_valid_option_option_request() {
        let input = b"\x00\x06\x00\x02\x13\x37";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Option::OptionRequest {
                    options: vec![0x1337u16]
                }
            ))
        );
    }

    #[test]
    fn test_valid_option_preference() {
        let input = b"\x00\x07\x00\x01\x01";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((&b""[..], DHCPv6Option::Preference { pref_value: 1 }))
        );
    }

    #[test]
    fn test_valid_option_elapsted_time() {
        let input = b"\x00\x08\x00\x02\x00\x01";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((&b""[..], DHCPv6Option::ElapstedTime { elapsed_time: 1 }))
        );
    }

    #[test]
    fn test_valid_option_relay_message() {
        let input = b"\x00\x09\x00\x04toto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((&b""[..], DHCPv6Option::RelayMessage { data: &b"toto"[..] }))
        );
    }

    #[test]
    fn test_valid_option_authentication() {
        let input = b"\x00\x0b\x00\x0f\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01toto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Option::Authentication {
                    protocol: 1,
                    algorithm: 1,
                    rdm: 1,
                    replay_detection: 1,
                    authentication_information: &b"toto"[..]
                }
            ))
        );
    }

    #[test]
    fn test_valid_option_server_unicast() {
        let input =
            b"\x00\x0c\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Option::ServerUnicast {
                    address: Ipv6Addr::LOCALHOST
                }
            ))
        );
    }

    #[test]
    fn test_valid_option_status_code() {
        let input = b"\x00\x0d\x00\x06\x00\x01toto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Option::StatusCode {
                    code: 1,
                    message: "toto"
                }
            ))
        );
    }

    #[test]
    fn test_valid_option_rapid_commit() {
        let input = b"\x00\x0e\x00\x00";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((&b""[..], DHCPv6Option::RapidCommit {}))
        );
    }

    #[test]
    fn test_valid_option_user_class() {
        let input = b"\x00\x0f\x00\x04toto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((&b""[..], DHCPv6Option::UserClass { data: &b"toto"[..] }))
        );
    }

    #[test]
    fn test_valid_option_vendor_class() {
        let input = b"\x00\x10\x00\x08\xde\xad\xbe\xeftoto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Option::VendorClass {
                    enterprise_number: 0xdeadbeef,
                    data: &b"toto"[..]
                }
            ))
        );
    }

    #[test]
    fn test_valid_option_vendor_specific_information() {
        let input = b"\x00\x11\x00\x08\xde\xad\xbe\xeftoto";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Option::VendorSpecificInformation {
                    enterprise_number: 0xdeadbeef,
                    data: &b"toto"[..]
                }
            ))
        );
    }

    #[test]
    fn test_valid_option_interface_id() {
        let input = b"\x00\x12\x00\x04eth0";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((&b""[..], DHCPv6Option::InterfaceID { data: &b"eth0"[..] }))
        );
    }

    #[test]
    fn test_valid_option_reconfigure_message() {
        let input = b"\x00\x13\x00\x01\x01";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((
                &b""[..],
                DHCPv6Option::ReconfigureMessage { message_type: 1 }
            ))
        );
    }

    #[test]
    fn test_valid_option_reconfigure_accept() {
        let input = b"\x00\x14\x00\x00";
        assert_eq!(
            parse_dhcpv6_option(&input[..]),
            Ok((&b""[..], DHCPv6Option::ReconfigureAccept {}))
        );
    }

    #[test]
    fn test_invalid_option_value() {
        let input = b"\x13\x37\x00\x12";
        assert!(parse_dhcpv6_option(&input[..]).is_err());
    }
}
