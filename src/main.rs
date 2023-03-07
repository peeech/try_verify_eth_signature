use web3::signing::{keccak256, recover};

fn main() {}

pub fn eth_message(message: String) -> [u8; 32] {
    keccak256(
        format!(
            "{}{}{}",
            "\x19Ethereum Signed Message:\n",
            message.len(),
            message
        )
        .as_bytes(),
    )
}

#[test]
// Ignore this test
fn test_signature_verification() {
    // User's ETH account
    let account = "0x63f9a92d8d61b48a9fff8d58080425a3012d05c8".to_string();

    let message = "0x63f9a92d8d61b48a9fff8d58080425a3012d05c8igwyk4r1o7o".to_string();
    let message = eth_message(message);

    // Signature as created in js by web3.eth.personal.sign
    let signature = hex::decode("382a3e04daf88f322730f6a2972475fc5646ea8c4a7f3b5e83a90b10ba08a7364cd2f55348f2b6d210fbed7fc485abf19ecb2f3967e410d6349dd7dd1d4487751b").unwrap();

    let pubkey = recover(&message, &signature[..64], 0);
    assert!(pubkey.is_ok());
    let pubkey = pubkey.unwrap();
    let pubkey = format!("{:02X?}", pubkey);
    assert_eq!(account, pubkey)
}

#[test]
fn test_typed_signature_verification() {
    use eip_712::{hash_structured_data, EIP712};
    use serde_json::from_str;

    let expected_signing_pubkey: String = "0xfc4beff1fff82afb22f06879c8510bc84f7ec209".to_string();

    let data = r#"{
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "salt", "type": "bytes32" }
            ],
            "HfHotLink": [
                { "name": "HoloFuelAddress", "type": "string" },
                { "name": "HOTAddress", "type": "address"}
            ]
        },
        "domain": {
            "chainId": "0x5",
            "name": "HoloFuel Reserve Purchase Website",
            "version": "1",
            "salt": "0xf2d857f4a3edcb9b78b4d503bfe733db1e3f6cdc2b7971ee739626c97e86a558",
            "verifyingContract": "0xfc4beff1fff82afb22f06879c8510bc84f7ec209"
        },
        "primaryType": "HfHotLink",
        "message": {
            "HoloFuelAddress": "uhCAkBq7d8zBb0nf5u8qQWJFWFtn820pBgSvOV-tphYYyu3x1c96w",
            "HOTAddress": "0xfc4beff1fff82afb22f06879c8510bc84f7ec209"
        }

    }"#;
    let structured_data = from_str::<EIP712>(data).unwrap();

    let hashed_structured_data = hash_structured_data(structured_data).unwrap();

    // Signature as created from structured_data by [eth_signTypedData_v4](https://docs.metamask.io/guide/signing-data.html#signtypeddata-v4)
    // This signature is created in springboard's UI in [this line of code](https://github.com/Holo-Host/springboard/blob/develop/src/components/sections/ReserveSectionStepTwo.vue#L368)
    let signature = hex::decode("0f2c5088662e607844890ed2ce0856f52bc1db8243f9f5491dea4823e33b90b422406bff605668a300dd7afe139f99380581bfde1911e8b19527da4a48787cdc1c").unwrap();

    // Trim last bit from signature
    let pubkey = recover(&hashed_structured_data, &signature[..64], 0).unwrap();
    let pubkey = format!("{:02X?}", pubkey);

    // println!("{:?}", pubkey);
    assert_eq!(expected_signing_pubkey, pubkey);
}
