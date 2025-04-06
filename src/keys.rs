use std::ops::Range;

pub enum ReadError {
    UnsupportedKeyType,
    Underrun,
}

const KEY_TYPE_DSA: &[u8; 28] = b"ssh-dss-cert-v01@openssh.com";
const KEY_TYPE_ECDSA_P256: &[u8; 40] = b"ecdsa-sha2-nistp256-cert-v01@openssh.com";
const KEY_TYPE_ECDSA_P384: &[u8; 40] = b"ecdsa-sha2-nistp384-cert-v01@openssh.com";
const KEY_TYPE_ECDSA_P512: &[u8; 40] = b"ecdsa-sha2-nistp521-cert-v01@openssh.com";
const KEY_TYPE_ED25519: &[u8; 32] = b"ssh-ed25519-cert-v01@openssh.com";
const KEY_TYPE_RSA: &[u8; 28] = b"ssh-rsa-cert-v01@openssh.com";

const PRINCIPAL_PREFIX: &[u8; 9] = b"gitolite:";

pub fn is_supported_key_type(value: &[u8]) -> bool {
    KEY_TYPE_ED25519 == value
        || KEY_TYPE_RSA == value
        || KEY_TYPE_ECDSA_P256 == value
        || KEY_TYPE_ECDSA_P384 == value
        || KEY_TYPE_ECDSA_P512 == value
        || KEY_TYPE_DSA == value
}

pub fn find_user_name(key: &[u8]) -> Result<Option<String>, ReadError> {
    let key_type = &key[get_string(key, 0)?];

    let find = if KEY_TYPE_ED25519 == key_type {
        find_principals_ed25519
    } else if KEY_TYPE_RSA == key_type {
        find_principals_rsa
    } else if KEY_TYPE_ECDSA_P256 == key_type
        || KEY_TYPE_ECDSA_P384 == key_type
        || KEY_TYPE_ECDSA_P512 == key_type
    {
        find_principals_ecdsa
    } else if KEY_TYPE_DSA == key_type {
        find_principals_dsa
    } else {
        return Err(ReadError::UnsupportedKeyType);
    };

    let principals = &key[find(key, key_type.len() + 4)?];
    let end = principals.len();
    let mut i = 0;
    let mut result: Option<String> = None;

    while result.is_none() && i < end {
        let p = &principals[get_string(principals, i)?];
        i += 4 + p.len();

        if p.starts_with(PRINCIPAL_PREFIX) {
            result = match String::from_utf8(p[PRINCIPAL_PREFIX.len()..].to_vec()) {
                Ok(username) => Some(username),
                Err(_) => {
                    println!("NO!");
                    None
                }
            };
        }
    }

    Ok(result)
}

fn find_principals_dsa(data: &[u8], offset: usize) -> Result<Range<usize>, ReadError> {
    // string nonce
    let mut offset = skip_string(data, offset)?;
    // mpint p
    offset = skip_string(data, offset)?;
    // mpint q
    offset = skip_string(data, offset)?;
    // mpint g
    offset = skip_string(data, offset)?;
    // mpint y
    offset = skip_string(data, offset)?;
    // uint64 serial
    // uint32 type
    offset += 12;
    // string key id
    offset = skip_string(data, offset)?;

    // string valid principals
    get_string(data, offset)
}

fn find_principals_ecdsa(data: &[u8], offset: usize) -> Result<Range<usize>, ReadError> {
    // string nonce
    let mut offset = skip_string(data, offset)?;
    // string curve
    offset = skip_string(data, offset)?;
    // string public_key
    offset = skip_string(data, offset)?;
    // uint64 serial
    // uint32 type
    offset += 12;
    // string key id
    offset = skip_string(data, offset)?;

    // string valid principals
    get_string(data, offset)
}

fn find_principals_ed25519(data: &[u8], offset: usize) -> Result<Range<usize>, ReadError> {
    // string nonce
    let mut offset = skip_string(data, offset)?;
    // string pk
    offset = skip_string(data, offset)?;
    // uint64 serial
    // uint32 type
    offset += 12;
    // string key id
    offset = skip_string(data, offset)?;

    // string valid principals
    get_string(data, offset)
}

fn find_principals_rsa(data: &[u8], offset: usize) -> Result<Range<usize>, ReadError> {
    // string nonce
    let mut offset = skip_string(data, offset)?;
    // mpint e
    offset = skip_string(data, offset)?;
    // mpint n
    offset = skip_string(data, offset)?;
    // uint64 serial
    // uint32 type
    offset += 12;
    // string key id
    offset = skip_string(data, offset)?;

    // string valid principals
    get_string(data, offset)
}

fn skip_string(data: &[u8], offset: usize) -> Result<usize, ReadError> {
    Ok(offset + 4 + read_u32(data, offset)?)
}

fn get_string(data: &[u8], offset: usize) -> Result<Range<usize>, ReadError> {
    let len = read_u32(data, offset)?;
    let start = offset + 4;
    Ok(start..(start + len))
}

fn read_u32(data: &[u8], offset: usize) -> Result<usize, ReadError> {
    let len = data.len();
    if offset < len && (len - offset) >= 4 {
        Ok((((data[offset] as u32) << 24)
            | ((data[offset + 1] as u32) << 16)
            | ((data[offset + 2] as u32) << 8)
            | (data[offset + 3] as u32)) as usize)
    } else {
        Err(ReadError::Underrun)
    }
}
