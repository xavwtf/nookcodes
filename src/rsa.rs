use crate::{
    PasswordBytes, SELECT_TABLES, error::{self, DecodeError}
};

const RSA_INFO_IDX: usize = 15;
const R_PRIME_IDX: usize = 5;
const OVERFLOW_BITS_IDX: usize = 20;

const PRIME_NUMBERS: [usize; 256] = [
    17,   19,   23,   29,   31,   37,   41,   43,   47,   53,   59,   61,   67,   71,   73,   79,   83,   89,   97,
    101,  103,  107,  109,  113,  127,  131,  137,  139,  149,  151,  157,  163,  167,  173,  179,  181,  191,  193,
    197,  199,  211,  223,  227,  229,  233,  239,  241,  251,  257,  263,  269,  271,  277,  281,  283,  293,  307,
    311,  313,  317,  331,  337,  347,  349,  353,  359,  367,  373,  379,  383,  389,  397,  401,  409,  419,  421,
    431,  433,  439,  443,  449,  457,  461,  463,  467,  479,  487,  491,  499,  503,  509,  521,  523,  541,  547,
    557,  563,  569,  571,  577,  587,  593,  599,  601,  607,  613,  617,  619,  631,  641,  643,  647,  653,  659,
    661,  673,  677,  683,  691,  701,  709,  719,  727,  733,  739,  743,  751,  757,  761,  769,  773,  787,  797,
    809,  811,  821,  823,  827,  829,  839,  853,  857,  859,  863,  877,  881,  883,  887,  907,  911,  919,  929,
    937,  941,  947,  953,  967,  971,  977,  983,  991,  997,  1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051,
    1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193,
    1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319,
    1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481,
    1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607,
    1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667,
];

fn rsa_key_code(buf: &PasswordBytes) -> (usize, usize, usize, &'static [usize; 8]) {
    let bytes = buf.as_bytes();
    let rsa_info = bytes[RSA_INFO_IDX];
    let mut p_idx = rsa_info & 3;
    let mut q_idx = (rsa_info >> 2) & 3;

    if p_idx == 3 {
        p_idx = (p_idx ^ q_idx) & 3;
        if p_idx == 3 { p_idx = 0; }
    }

    if q_idx == 3 {
        q_idx = (p_idx + 1) & 3;
        if q_idx == 3 { q_idx = 1; }
    }

    if p_idx == q_idx {
        q_idx = (p_idx + 1) & 3;
        if q_idx == 3 { q_idx = 1; }
    }

    (
        PRIME_NUMBERS[p_idx as usize],
        PRIME_NUMBERS[q_idx as usize],
        PRIME_NUMBERS[bytes[R_PRIME_IDX] as usize],
        &SELECT_TABLES[((rsa_info >> 4) & 0xF) as usize]
    )
}

pub fn rsa_cipher(buf: &mut PasswordBytes) {
    let (p, q, r, table) = rsa_key_code(buf);
    let bytes = buf.as_bytes_mut();

    let mut overflow_bits = 0u32;
    let pq = p as u32 * q as u32;

    for i in 0..8 {
        let idx = table[i];
        let mut changed: u32 = bytes[idx].into();

        for _ in (1..r).rev() {
            changed = (changed * bytes[idx] as u32) % pq;
        }

        bytes[idx] = changed as u8;
        overflow_bits |= ((changed >> 8) & 1) << i;
    }

    bytes[OVERFLOW_BITS_IDX] = overflow_bits as u8;
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let temp = b;
        b = a % b;
        a = temp;
    }

    a
}

fn has_rsa_inverse(r: usize, p: usize, q: usize) -> bool {
    gcd(r, (p - 1) * (q - 1)) == 1
}

pub fn decode_rsa_cipher(buf: &mut PasswordBytes) -> Result<(), error::DecodeError> {
    let (p, q, mut r, table) = rsa_key_code(buf);
    let bytes = buf.as_bytes_mut();
    let phi = (p - 1) * (q - 1);

    if !has_rsa_inverse(r, p, q) { return Err(DecodeError::RsaDecryptionFailure) };
    let mut pow = 1;
    loop {
        let n = pow * phi + 1;
        if n % r == 0 {
            r = n / r;
            break;
        }

        pow += 1;
    }

    let overflow_bits = bytes[OVERFLOW_BITS_IDX];
    let pq = p as u32 * q as u32;

    for i in 0..8 {
        let b = bytes[table[i]] as u32 | (((overflow_bits as u32 >> i) & 1) << 8);
        let mut decrypted = b;

        for _ in (1..r).rev() {
            decrypted = ((decrypted as u64 * b as u64) % pq as u64) as u32;
        }

        bytes[table[i]] = decrypted as u8;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_inverse_validation() {
        assert!(has_rsa_inverse(3, 11, 5)); // gcd(3, 40) = 1
        assert!(!has_rsa_inverse(2, 11, 5)); // gcd(2, 40) = 2
    }
}