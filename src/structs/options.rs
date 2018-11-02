use nom::{be_u16, be_u32, be_u64, be_u8, IResult};
use std::net::Ipv6Addr;

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

named!(
    parse_dhcpv6_option_client_id<DHCPv6Option>,
    do_parse!(len: be_u16 >> duid: take!(len) >> (DHCPv6Option::CliendID { duid }))
);

named!(
    parse_dhcpv6_option_server_id<DHCPv6Option>,
    do_parse!(len: be_u16 >> duid: take!(len) >> (DHCPv6Option::ServerID { duid }))
);

named!(
    parse_dhcpv6_option_ia_na<DHCPv6Option>,
    do_parse!(
        len: verify!(be_u16, |x| x >= 12)
            >> id: be_u32
            >> time_1: be_u32
            >> time_2: be_u32
            >> options: take!(len - 12)
            >> (DHCPv6Option::IdentityAssociationForNonTemporaryAddresses {
                id,
                time_1,
                time_2,
                options
            })
    )
);

named!(
    parse_dhcpv6_option_ia_ta<DHCPv6Option>,
    do_parse!(
        len: verify!(be_u16, |x| x >= 4)
            >> id: be_u32
            >> options: take!(len - 4)
            >> (DHCPv6Option::IdentityAssociationForTemporaryAddresses { id, options })
    )
);

named!(
    parse_dhcpv6_option_ia<DHCPv6Option>,
    do_parse!(
        len: verify!(be_u16, |x| x >= 24)
            >> address: map!(count_fixed!(u8, be_u8, 16), Ipv6Addr::from)
            >> prefered_lifetime: be_u32
            >> valid_lifetime: be_u32
            >> options: take!(len - 24)
            >> (DHCPv6Option::IdentityAssociationAddress {
                address,
                prefered_lifetime,
                valid_lifetime,
                options
            })
    )
);

named!(
    parse_dhcpv6_option_option_request<DHCPv6Option>,
    do_parse!(
        len: verify!(be_u16, |x| x % 2 == 0)
            >> options: count!(be_u16, len as usize / 2usize)
            >> (DHCPv6Option::OptionRequest { options })
    )
);

named!(
    parse_dhcpv6_option_preference<DHCPv6Option>,
    do_parse!(
        _len: verify!(be_u16, |x| x == 1)
            >> pref_value: be_u8
            >> (DHCPv6Option::Preference { pref_value })
    )
);

named!(
    parse_dhcpv6_option_elapsted_time<DHCPv6Option>,
    do_parse!(
        _len: verify!(be_u16, |x| x == 2)
            >> elapsed_time: be_u16
            >> (DHCPv6Option::ElapstedTime { elapsed_time })
    )
);

named!(
    parse_dhcpv6_option_relay_message<DHCPv6Option>,
    do_parse!(len: be_u16 >> data: take!(len) >> (DHCPv6Option::RelayMessage { data }))
);

named!(
    parse_dhcpv6_option_authentication<DHCPv6Option>,
    do_parse!(
        len: verify!(be_u16, |x| x >= 11)
            >> protocol: be_u8
            >> algorithm: be_u8
            >> rdm: be_u8
            >> replay_detection: be_u64
            >> authentication_information: take!(len - 11)
            >> (DHCPv6Option::Authentication {
                protocol,
                algorithm,
                rdm,
                replay_detection,
                authentication_information
            })
    )
);

named!(
    parse_dhcpv6_option_server_unicast<DHCPv6Option>,
    do_parse!(
        _len: verify!(be_u16, |x| x == 16)
            >> address: map!(count_fixed!(u8, be_u8, 16), Ipv6Addr::from)
            >> (DHCPv6Option::ServerUnicast { address })
    )
);

named!(
    parse_dhcpv6_option_status_code<DHCPv6Option>,
    do_parse!(
        len: verify!(be_u16, |x| x >= 2)
            >> code: be_u16
            >> message: take_str!(len - 2)
            >> (DHCPv6Option::StatusCode { code, message })
    )
);

named!(
    parse_dhcpv6_option_rapid_commit<DHCPv6Option>,
    do_parse!(_len: verify!(be_u16, |x| x == 0) >> (DHCPv6Option::RapidCommit {}))
);

named!(
    parse_dhcpv6_option_user_class<DHCPv6Option>,
    do_parse!(len: be_u16 >> data: take!(len) >> (DHCPv6Option::UserClass { data }))
);

named!(
    parse_dhcpv6_option_vendor_class<DHCPv6Option>,
    do_parse!(
        len: verify!(be_u16, |x| x >= 4)
            >> enterprise_number: be_u32
            >> data: take!(len - 4)
            >> (DHCPv6Option::VendorClass {
                enterprise_number,
                data
            })
    )
);

named!(
    parse_dhcpv6_option_vendor_specific_information<DHCPv6Option>,
    do_parse!(
        len: verify!(be_u16, |x| x >= 4)
            >> enterprise_number: be_u32
            >> data: take!(len - 4)
            >> (DHCPv6Option::VendorSpecificInformation {
                enterprise_number,
                data
            })
    )
);

named!(
    parse_dhcpv6_option_interface_id<DHCPv6Option>,
    do_parse!(len: be_u16 >> data: take!(len) >> (DHCPv6Option::InterfaceID { data }))
);

named!(
    parse_dhcpv6_option_reconfigure_message<DHCPv6Option>,
    do_parse!(
        _len: verify!(be_u16, |x| x == 1)
            >> message_type: be_u8
            >> (DHCPv6Option::ReconfigureMessage { message_type })
    )
);

named!(
    parse_dhcpv6_option_reconfigure_accept<DHCPv6Option>,
    do_parse!(_len: verify!(be_u16, |x| x == 0) >> (DHCPv6Option::ReconfigureAccept {}))
);

named!(
    pub parse_dhcpv6_option<DHCPv6Option>,
    switch!(be_u16,
        1u16 => call!(parse_dhcpv6_option_client_id) |
        2u16 => call!(parse_dhcpv6_option_server_id) |
        3u16 => call!(parse_dhcpv6_option_ia_na) |
        4u16 => call!(parse_dhcpv6_option_ia_ta) |
        5u16 => call!(parse_dhcpv6_option_ia) |
        6u16 => call!(parse_dhcpv6_option_option_request) |
        7u16 => call!(parse_dhcpv6_option_preference) |
        8u16 => call!(parse_dhcpv6_option_elapsted_time) |
        9u16 => call!(parse_dhcpv6_option_relay_message) |
        // no 10u16
        11u16 => call!(parse_dhcpv6_option_authentication) |
        12u16 => call!(parse_dhcpv6_option_server_unicast) |
        13u16 => call!(parse_dhcpv6_option_status_code) |
        14u16 => call!(parse_dhcpv6_option_rapid_commit) |
        15u16 => call!(parse_dhcpv6_option_user_class) |
        16u16 => call!(parse_dhcpv6_option_vendor_class) |
        17u16 => call!(parse_dhcpv6_option_vendor_specific_information) |
        18u16 => call!(parse_dhcpv6_option_interface_id) |
        19u16 => call!(parse_dhcpv6_option_reconfigure_message) |
        20u16 => call!(parse_dhcpv6_option_reconfigure_accept)
    )
);

pub fn parse_dhcpv6_options(input: &[u8]) -> IResult<&[u8], Vec<DHCPv6Option>> {
    let mut options: Vec<DHCPv6Option> = Vec::new();
    let mut rest = input;

    while rest.len() > 0 {
        let (new_rest, option) = parse_dhcpv6_option(rest)?;
        options.push(option);
        rest = new_rest;
    }

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
