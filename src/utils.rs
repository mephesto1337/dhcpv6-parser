use nom::combinator::map;
use nom::number::complete::be_u128;
use nom::IResult;
use std::net::Ipv6Addr;

pub(crate) fn parse_ipv6_address(input: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    map(be_u128, Ipv6Addr::from)(input)
}
