// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Error;

use tezos_messages::p2p::encoding::prelude::*;
use tezos_messages::p2p::{
    binary_message::{BinaryRead, BinaryWrite},
    encoding::limits::ADVERTISE_ID_LIST_MAX_LENGTH,
};

#[test]
fn can_deserialize_advertise() -> Result<(), Error> {
    let message_bytes = hex::decode("0000001e5b666538303a3a653832383a323039643a3230653a633061655d3a333735000000133233342e3132332e3132342e39313a39383736000000133132332e3132332e3132342e32313a39383736")?;
    let message = AdvertiseMessage::from_bytes(message_bytes)?;
    assert_eq!(3, message.id().len());
    assert_eq!("[fe80::e828:209d:20e:c0ae]:375", &message.id()[0]);
    assert_eq!("234.123.124.91:9876", &message.id()[1]);
    Ok(assert_eq!("123.123.124.21:9876", &message.id()[2]))
}

#[test]
fn can_format_ip_address() {
    let addresses = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(123, 123, 124, 21)), 9876),
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                0xfe80, 0xe828, 0x209d, 0x20e, 0xc0ae, 0, 0, 0,
            )),
            375,
        ),
    ];
    let message = AdvertiseMessage::new(addresses);
    assert_eq!("123.123.124.21:9876", &message.id()[0]);
    assert_eq!("[fe80:e828:209d:20e:c0ae::]:375", &message.id()[1]);
}

#[test]
fn can_serialize_max_advertise() {
    let addr = SocketAddr::new(
        "fe80:e828:209d:20ed:c0ae:fe80:e828:209d".parse().unwrap(),
        12345,
    );
    let addresses = std::iter::repeat(addr)
        .take(ADVERTISE_ID_LIST_MAX_LENGTH)
        .collect::<Vec<_>>();
    let message = AdvertiseMessage::new(addresses);
    let res = message.as_bytes();
    assert!(res.is_ok());
    println!("{}", hex::encode(res.unwrap()));
}

#[test]
fn can_t_serialize_max_plus_advertise() {
    let addr = SocketAddr::new(
        "fe80:e828:209d:20ed:c0ae:fe80:e828:209d".parse().unwrap(),
        12345,
    );
    let addresses = std::iter::repeat(addr)
        .take(ADVERTISE_ID_LIST_MAX_LENGTH + 1)
        .collect::<Vec<_>>();
    let message = AdvertiseMessage::new(addresses);
    let res = message.as_bytes();
    assert!(res.is_err());
}

#[test]
fn can_deserialize_advertize_max() -> Result<(), Error> {
    let encoded = hex::decode(test_data::ADVERTISE_ENCODED_MAX)?;
    let message = AdvertiseMessage::from_bytes(encoded)?;
    assert_eq!(ADVERTISE_ID_LIST_MAX_LENGTH, message.id().len());
    assert_eq!(
        "[fe80:e828:209d:20ed:c0ae:fe80:e828:209d]:12345",
        &message.id()[0]
    );
    Ok(())
}

#[test]
fn can_t_deserialize_advertize_max_plus() -> Result<(), Error> {
    let encoded = hex::decode(test_data::ADVERTISE_ENCODED_OVER_MAX)?;
    let _err = AdvertiseMessage::from_bytes(encoded).expect_err("Error is expected");
    Ok(())
}

mod test_data {
    pub(crate) const ADVERTISE_ENCODED_MAX: &str = "\
0000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383\
a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061\
653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323\
039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b\
666538303a653832383a323039643a323065643a633061653a666538303a653832383a323039645\
d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538\
303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323\
065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a\
653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132333\
4350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832\
383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633\
061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a\
323039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002\
f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a323039\
645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a666\
538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a\
323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b6665383\
03a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132\
3334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653\
832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a\
633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a6538323\
83a323039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000\
002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a323\
039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a\
666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a3230396\
43a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b6665\
38303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3\
1323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a\
653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a3230656\
43a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a6538\
32383a323039643a323065643a633061653a666538303a653832383a323039645d3a31323334350\
000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a\
323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a6330616\
53a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a3230\
39643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b6\
66538303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d\
3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a6665383\
03a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a3230\
65643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a6\
53832383a323039643a323065643a633061653a666538303a653832383a323039645d3a31323334\
350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a6538323\
83a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a6330\
61653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a3\
23039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f\
5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a3230396\
45d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a6665\
38303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a3\
23065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b66653830\
3a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a31323\
334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a6538\
32383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a6\
33061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a65383238\
3a323039643a323065643a633061653a666538303a653832383a323039645d3a313233343500000\
02f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a3230\
39645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a6\
66538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a32303964\
3a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b66653\
8303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a31\
323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a6\
53832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a32306564\
3a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a65383\
2383a323039643a323065643a633061653a666538303a653832383a323039645d3a313233343500\
00002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a3\
23039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a63306165\
3a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a32303\
9643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b66\
6538303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3\
a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a66653830\
3a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a32306\
5643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a65\
3832383a323039643a323065643a633061653a666538303a653832383a323039645d3a313233343\
50000002f5b666538303a653832383a323039643a323065643a633061653a666538303a65383238\
3a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a63306\
1653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a32\
3039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5\
b666538303a653832383a323039643a323065643a633061653a666538303a653832383a32303964\
5d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a66653\
8303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a32\
3065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303\
a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a313233\
34350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a65383\
2383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a63\
3061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383\
a323039643a323065643a633061653a666538303a653832383a323039645d3a3132333435000000\
2f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a32303\
9645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a66\
6538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643\
a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538\
303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a313\
23334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a65\
3832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643\
a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832\
383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132333435000\
0002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a32\
3039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653\
a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039\
643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666\
538303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a\
31323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303\
a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065\
643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653\
832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132333435\
0000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383\
a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061\
653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323\
039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b\
666538303a653832383a323039643a323065643a633061653a666538303a653832383a323039645\
d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538\
303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323\
065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a\
653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132333\
4350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832\
383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633\
061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a\
323039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002\
f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a323039\
645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a666\
538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a\
323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b6665383\
03a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132\
3334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653\
832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a\
633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a6538323\
83a323039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000\
002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a323\
039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a\
666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a3230396\
43a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b6665\
38303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3\
132333435";

    pub(crate) const ADVERTISE_ENCODED_OVER_MAX: &str = "\
0000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383\
a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061\
653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323\
039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b\
666538303a653832383a323039643a323065643a633061653a666538303a653832383a323039645\
d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538\
303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323\
065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a\
653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132333\
4350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832\
383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633\
061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a\
323039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002\
f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a323039\
645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a666\
538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a\
323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b6665383\
03a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132\
3334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653\
832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a\
633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a6538323\
83a323039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000\
002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a323\
039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a\
666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a3230396\
43a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b6665\
38303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3\
1323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a\
653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a3230656\
43a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a6538\
32383a323039643a323065643a633061653a666538303a653832383a323039645d3a31323334350\
000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a\
323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a6330616\
53a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a3230\
39643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b6\
66538303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d\
3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a6665383\
03a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a3230\
65643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a6\
53832383a323039643a323065643a633061653a666538303a653832383a323039645d3a31323334\
350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a6538323\
83a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a6330\
61653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a3\
23039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f\
5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a3230396\
45d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a6665\
38303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a3\
23065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b66653830\
3a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a31323\
334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a6538\
32383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a6\
33061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a65383238\
3a323039643a323065643a633061653a666538303a653832383a323039645d3a313233343500000\
02f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a3230\
39645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a6\
66538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a32303964\
3a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b66653\
8303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a31\
323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a6\
53832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a32306564\
3a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a65383\
2383a323039643a323065643a633061653a666538303a653832383a323039645d3a313233343500\
00002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a3\
23039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a63306165\
3a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a32303\
9643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b66\
6538303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3\
a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a66653830\
3a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a32306\
5643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a65\
3832383a323039643a323065643a633061653a666538303a653832383a323039645d3a313233343\
50000002f5b666538303a653832383a323039643a323065643a633061653a666538303a65383238\
3a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a63306\
1653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a32\
3039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5\
b666538303a653832383a323039643a323065643a633061653a666538303a653832383a32303964\
5d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a66653\
8303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a32\
3065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303\
a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a313233\
34350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a65383\
2383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a63\
3061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383\
a323039643a323065643a633061653a666538303a653832383a323039645d3a3132333435000000\
2f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a32303\
9645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a66\
6538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643\
a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538\
303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a313\
23334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a65\
3832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643\
a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832\
383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132333435000\
0002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a32\
3039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653\
a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039\
643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666\
538303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a\
31323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303\
a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065\
643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653\
832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132333435\
0000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383\
a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061\
653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323\
039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b\
666538303a653832383a323039643a323065643a633061653a666538303a653832383a323039645\
d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538\
303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323\
065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a\
653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132333\
4350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832\
383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633\
061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a\
323039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000002\
f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a323039\
645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a666\
538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a\
323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b6665383\
03a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3132\
3334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a653\
832383a323039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a\
633061653a666538303a653832383a323039645d3a31323334350000002f5b666538303a6538323\
83a323039643a323065643a633061653a666538303a653832383a323039645d3a31323334350000\
002f5b666538303a653832383a323039643a323065643a633061653a666538303a653832383a323\
039645d3a31323334350000002f5b666538303a653832383a323039643a323065643a633061653a\
666538303a653832383a323039645d3a31323334350000002f5b666538303a653832383a3230396\
43a323065643a633061653a666538303a653832383a323039645d3a31323334350000002f5b6665\
38303a653832383a323039643a323065643a633061653a666538303a653832383a323039645d3a3\
1323334350000002f5b666538303a653832383a323039643a323065643a633061653a666538303a\
653832383a323039645d3a3132333435";
}
