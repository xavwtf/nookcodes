use crate::{
    PASSWORD_DATA_LEN, PASSWORD_LEN, PasswordBytes
};

pub fn repack_bitstream(buf: &mut PasswordBytes, src_bits: usize, dst_bits: usize) {
    assert!(src_bits > 0 && src_bits <= 8);
    assert!(dst_bits > 0 && src_bits <= 8);

    let bytes = buf.as_bytes_mut();
    let mut work_buf = [0u8; PASSWORD_LEN];

    let total_bits = PASSWORD_DATA_LEN * 8;
    for bit_idx in 0..total_bits {
        let src_byte = bit_idx / src_bits;
        let src_bit = bit_idx % src_bits;

        let dst_byte = bit_idx / dst_bits;
        let dst_bit = bit_idx % dst_bits;

        let bit = (bytes[src_byte] >> src_bit) & 1;
        work_buf[dst_byte] |= bit << dst_bit;
    }

    bytes.copy_from_slice(&work_buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PASSWORD_LEN, PasswordBytes
    };

    const TEST_ARRAY: [u8; PASSWORD_LEN] = [
        0xFF, 0x08, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
        0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    #[test]
    fn repack_inverse() {
        let mut test_buf = PasswordBytes(TEST_ARRAY);

        repack_bitstream(&mut test_buf, 8, 6);
        repack_bitstream(&mut test_buf, 6, 8);

        assert_eq!(test_buf.as_bytes(), &TEST_ARRAY);
    }
}