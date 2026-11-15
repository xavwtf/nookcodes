use crate::{
    PASSWORD_DATA_LEN, PASSWORD_LEN, PasswordBytes, SELECT_TABLES
};

const BIT_MIX_CODE_IDX: usize = 1;

#[derive(Clone, Copy)]
pub enum ShuffleStage {
    Stage0,
    Stage1
}

pub fn bit_shuffle(buf: &mut PasswordBytes, stage: ShuffleStage) {
    let bytes = buf.as_bytes_mut();
    let mut shuffle_input = [0u8; PASSWORD_DATA_LEN - 1];
    let mut work_buf = [0u8; PASSWORD_DATA_LEN - 1];

    let (count, key_idx) = match stage {
        ShuffleStage::Stage0 => (PASSWORD_DATA_LEN - 2, 13),
        ShuffleStage::Stage1 => (PASSWORD_DATA_LEN - 1, 2)
    };

    shuffle_input[..key_idx].copy_from_slice(&bytes[..key_idx]);
    shuffle_input[key_idx..key_idx + PASSWORD_DATA_LEN - 1 - key_idx].copy_from_slice(&bytes[key_idx + 1..key_idx + 1 + PASSWORD_DATA_LEN - 1 - key_idx]);

    let permutation_table = SELECT_TABLES[(bytes[key_idx] & 3) as usize];
    
    for (i, &b) in shuffle_input[..count].iter().enumerate() {
        for bit in 0..8 {
            let dst_idx = (i + permutation_table[bit]) % count;

            work_buf[dst_idx] |= (((b >> bit) & 1) << bit) as u8;
        }
    }

    bytes[..key_idx].copy_from_slice(&work_buf[..key_idx]);
    bytes[key_idx + 1..PASSWORD_DATA_LEN].copy_from_slice(&work_buf[key_idx..]);
}

pub fn decode_bit_shuffle(buf: &mut PasswordBytes, stage: ShuffleStage) {
    let bytes = buf.as_bytes_mut();
    let mut shuffled_input = [0u8; PASSWORD_DATA_LEN - 1];
    let mut work_buf = [0u8; PASSWORD_DATA_LEN - 1];

    let (count, key_idx) = match stage {
        ShuffleStage::Stage0 => (PASSWORD_DATA_LEN - 2, 13),
        ShuffleStage::Stage1 => (PASSWORD_DATA_LEN - 1, 2)
    };

    shuffled_input[..key_idx].copy_from_slice(&bytes[..key_idx]);
    shuffled_input[key_idx..key_idx + PASSWORD_DATA_LEN - 1 - key_idx].copy_from_slice(&bytes[key_idx + 1..key_idx + 1 + PASSWORD_DATA_LEN - 1 - key_idx]);

    let permutation_table = SELECT_TABLES[(bytes[key_idx] & 3) as usize];

    for i in 0..count {
        for bit in 0..8 {
            let dst_idx = (i + permutation_table[bit]) % count;
            work_buf[i] |= ((shuffled_input[dst_idx] >> bit) & 1) << bit
        }
    }

    bytes[..key_idx].copy_from_slice(&work_buf[..key_idx]);
    bytes[key_idx + 1..PASSWORD_DATA_LEN].copy_from_slice(&work_buf[key_idx..]);
}

pub fn bit_mix(buf: &mut PasswordBytes) {
    let bytes = buf.as_bytes_mut();
    let bit_mix_code = bytes[BIT_MIX_CODE_IDX] & 0x0F;

    if bit_mix_code > 12 {
        bit_arrange_reverse(bytes);
        bit_invert(bytes);
        bit_shift(bytes, (bit_mix_code * 3).into());
    } else if bit_mix_code > 8 {
        bit_arrange_reverse(bytes);
        bit_shift(bytes, -((bit_mix_code * 5) as isize));
    } else if bit_mix_code > 4 {
        bit_shift(bytes, -((bit_mix_code * 5) as isize));
        bit_invert(bytes);
    } else {
        bit_shift(bytes, (bit_mix_code * 3).into());
        bit_arrange_reverse(bytes);
    }
}

pub fn decode_bit_mix(buf: &mut PasswordBytes) {
    let bytes = buf.as_bytes_mut();
    let bit_mix_code = bytes[BIT_MIX_CODE_IDX] & 0x0F;

    if bit_mix_code > 12 {
        bit_shift(bytes, -((bit_mix_code * 3) as isize));
        bit_invert(bytes);
        bit_arrange_reverse(bytes);
    } else if bit_mix_code > 8 {
        bit_shift(bytes ,(bit_mix_code * 5).into());
        bit_arrange_reverse(bytes);
    } else if bit_mix_code > 4 {
        bit_invert(bytes);
        bit_shift(bytes, (bit_mix_code * 5).into());
    } else {
        bit_arrange_reverse(bytes);
        bit_shift(bytes, -((bit_mix_code * 3) as isize))
    }
}

fn bit_shift(buf: &mut [u8; PASSWORD_LEN], shift_by: isize) {
    if shift_by == 0 { return; }

    let mut shift_input = [0u8; PASSWORD_DATA_LEN - 1];
    let mut work_buf = [0u8; PASSWORD_DATA_LEN - 1];

    shift_input[0] = buf[0];
    shift_input[1..].copy_from_slice(&buf[2..PASSWORD_DATA_LEN]);

    let abs_shift = shift_by.unsigned_abs();
    let (mut shift_bytes, shift_bits) = (abs_shift / 8, abs_shift % 8);

    while shift_bytes > PASSWORD_DATA_LEN - 1 { shift_bytes -= PASSWORD_DATA_LEN - 1}

    let mask = (1 << shift_bits) - 1;
    if shift_by > 0 { // positive shift
        let mut byte = (shift_input[if shift_bits == 0 { 0 } else { PASSWORD_DATA_LEN - 2 }] >> (8 - shift_bits)) & mask;
        for b in shift_input[..PASSWORD_DATA_LEN - 1].iter() {
            work_buf[shift_bytes] = byte | (*b << shift_bits);
            byte = (b >> (8 - shift_bits)) & mask;
            shift_bytes = (shift_bytes + 1) % (PASSWORD_DATA_LEN - 1);
        }
    } else if shift_by < 0 { // negative shift
        let mut byte = (shift_input[if shift_bits == 0 { PASSWORD_DATA_LEN - 2 } else { 0 }] & mask) << (8 - shift_bits);
        let mut shift_idx = (PASSWORD_DATA_LEN - 2 - shift_bytes) % (PASSWORD_DATA_LEN - 1);

        for b in shift_input.iter().rev() {
            work_buf[shift_idx] = byte | (b >> shift_bits);
            byte = (b & mask) << (8 - shift_bits);

            shift_idx = (shift_idx + PASSWORD_DATA_LEN - 2) % (PASSWORD_DATA_LEN - 1);
        }
    }

    buf[0] = work_buf[0];
    buf[2..PASSWORD_DATA_LEN].copy_from_slice(&work_buf[1..]);
}

fn bit_invert(buf: &mut [u8; PASSWORD_LEN]) {
    for (i, b) in buf[..PASSWORD_DATA_LEN].iter_mut().enumerate() {
        if i != BIT_MIX_CODE_IDX { *b ^= 0xFF }
    };
}

fn bit_arrange_reverse(buf: &mut [u8; PASSWORD_LEN]) {
    let mut rev_input = [0u8; PASSWORD_DATA_LEN - 1];
    let mut work_buf = [0u8; PASSWORD_DATA_LEN - 1];

    rev_input[0] = buf[0];
    rev_input[1..].copy_from_slice(&buf[2..PASSWORD_DATA_LEN]);

    for (j, &byte) in rev_input.iter().rev().enumerate() {
        work_buf[j] = byte.reverse_bits();
    }

    buf[0] = work_buf[0];
    buf[2..PASSWORD_DATA_LEN].copy_from_slice(&work_buf[1..]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PASSWORD_LEN;

    const TEST_ARRAY: [u8; PASSWORD_LEN] = [
        0xFF, 0x08, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
        0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53,
        0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A
    ];

    #[test]
    fn bit_shift_accurate() {
        let mut test_buf = TEST_ARRAY;

        bit_shift(&mut test_buf, 3);

        assert_eq!(&test_buf[..], &[
            0xFA, 0x08, 0x0F, 0x12, 0x1A, 0x22, 0x2A,
            0x32, 0x3A, 0x42, 0x4A, 0x52, 0x5A, 0x62,
            0x6A, 0x72, 0x7A, 0x82, 0x8A, 0x92, 0x9A,
            0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
        ]);
    }

    #[test]
    fn bit_invert_accurate() {
        let mut test_buf = TEST_ARRAY;

        bit_invert(&mut test_buf);

        assert_eq!(&test_buf[..], &[
            0x00, 0x08, 0xBE, 0xBD, 0xBC, 0xBB, 0xBA,
            0xB9, 0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3,
            0xB2, 0xB1, 0xB0, 0xAF, 0xAE, 0xAD, 0xAC,
            0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
        ]);
    }

    #[test]
    fn bit_arrange_reverse_accurate() {
        let mut test_buf = TEST_ARRAY;

        bit_arrange_reverse(&mut test_buf);

        assert_eq!(&test_buf[..], &[
            0xCA, 0x08, 0x4A, 0x8A, 0x0A, 0xF2, 0x72,
            0xB2, 0x32, 0xD2, 0x52, 0x92, 0x12, 0xE2,
            0x62, 0xA2, 0x22, 0xC2, 0x42, 0x82, 0xFF,
            0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
        ]);
    }

    #[test]
    fn bit_shift_reversible() {
        let mut test_buf = TEST_ARRAY;

        bit_shift(&mut test_buf, 3);
        bit_shift(&mut test_buf, -3);

        assert_eq!(test_buf, TEST_ARRAY);
    }

    #[test]
    fn bit_invert_reversible() {
        let mut test_buf = TEST_ARRAY;

        bit_invert(&mut test_buf);
        bit_invert(&mut test_buf);

        assert_eq!(test_buf, TEST_ARRAY);
    }

    #[test]
    fn bit_arrange_reverse_reversible() {
        let mut test_buf = TEST_ARRAY;

        bit_arrange_reverse(&mut test_buf);
        bit_arrange_reverse(&mut test_buf);

        assert_eq!(test_buf, TEST_ARRAY);
    }

    #[test]
    fn bit_shuffle_inverse() {
        let mut test_buf = PasswordBytes(TEST_ARRAY);
        let mut expected = TEST_ARRAY;
        expected[PASSWORD_DATA_LEN - 1] = 0; // UB in the original C??
        
        bit_shuffle(&mut test_buf, ShuffleStage::Stage0);
        decode_bit_shuffle(&mut test_buf, ShuffleStage::Stage0);
        
        assert_eq!(test_buf.as_bytes(), &expected);

        let mut test_buf = PasswordBytes(TEST_ARRAY);

        bit_shuffle(&mut test_buf, ShuffleStage::Stage1);
        decode_bit_shuffle(&mut test_buf, ShuffleStage::Stage1);
        
        assert_eq!(test_buf.as_bytes(), &TEST_ARRAY);
    }
}