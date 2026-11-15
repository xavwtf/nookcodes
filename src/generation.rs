use crate::{
    Password,
    PasswordBytes,
    NpcType,
    PLAYER_NAME_LEN,
    USABLE_TO_FONTNUM,

    substitution::substitution_cipher,
    transposition::*,
    bit_ops::*,
    rsa::rsa_cipher,
    repacking::repack_bitstream
};

fn encode_password(buf: &mut PasswordBytes, password: &Password) {
    let bytes = buf.as_bytes_mut();

    bytes[0] = (password.code_type().discriminant() << 5)
        | (password.code_type().encoded_hit_rate_index() << 1)
        | (password.npc_type().unwrap_or(NpcType::Normal) as u8);

    bytes[1] = password.npc_code().unwrap_or(0xFF);
    bytes[2..2 + PLAYER_NAME_LEN].copy_from_slice(&password.str0);
    bytes[10..10 + PLAYER_NAME_LEN].copy_from_slice(&password.str1);

    bytes[18..20].copy_from_slice(&password.item.to_be_bytes());

    let checksum: u32 = password.str0.iter()
        .chain(password.str1.iter())
        .map(|&b| b as u32)
        .sum::<u32>()
        + password.item as u32
        + password.npc_code().unwrap_or(0xFF) as u32;

    bytes[0] |= ((checksum & 3) << 3) as u8;
}

fn to_font(buf: &mut PasswordBytes) {
    for b in buf.as_bytes_mut() {
        *b = USABLE_TO_FONTNUM[*b as usize];
    }
}

/// Generates Animal Crossing-compatible password bytes.
pub fn generate(password: &Password) -> PasswordBytes {
    let mut buf = PasswordBytes::new();

    encode_password(&mut buf, password);
    substitution_cipher(&mut buf);
    transposition_cipher(&mut buf, TranspositionDir::Backward, CipherVariant::First);
    bit_shuffle(&mut buf, ShuffleStage::Stage0);
    rsa_cipher(&mut buf);
    bit_mix(&mut buf);
    bit_shuffle(&mut buf, ShuffleStage::Stage1);
    transposition_cipher(&mut buf, TranspositionDir::Forward, CipherVariant::Second);
    repack_bitstream(&mut buf, 8, 6);
    to_font(&mut buf);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        substitution::substitution_cipher,
        transposition::{
            CipherVariant,
            TranspositionDir,
            transposition_cipher
        },
        bit_ops::{
            ShuffleStage,
            bit_shuffle
        }
    };

    fn test_password() -> Password {
        Password::user(
            0x1234u16,
            *b"ABCDEFGH",
            *b"abcdefgh"
        )
    }

    #[test]
    fn encodes_item_big_endian() {
        let mut pass_buf = PasswordBytes::new();
        let password = test_password();
        encode_password(&mut pass_buf, &password);

        let bytes = pass_buf.as_bytes();

        assert_eq!(bytes[18], 0x12);
        assert_eq!(bytes[19], 0x34);
    }

    #[test]
    fn encodes_player_strings() {
        let mut pass_buf = PasswordBytes::new();
        let password = test_password();
        encode_password(&mut pass_buf, &password);

        let bytes = pass_buf.as_bytes();

        assert_eq!(&bytes[2..10], b"ABCDEFGH");
        assert_eq!(&bytes[10..18], b"abcdefgh");
    }

    #[test]
    fn encodes_checksum() {
        let mut pass_buf = PasswordBytes::new();
        let password = test_password();
        encode_password(&mut pass_buf, &password);

        let bytes = pass_buf.as_bytes();

        let checksum = ((bytes[0] >> 3) & 3) as u32;
        let expected_checksum: u32 = password.str0.iter()
            .chain(password.str1.iter())
            .map(|&b| b as u32)
            .sum::<u32>()
            + password.item as u32
            + password.npc_code().unwrap_or(0xFF) as u32;

        assert_eq!(checksum, expected_checksum & 3);
    }

    #[test]
    fn encodes_correct() {
        let mut pass_buf = PasswordBytes::new();
        let password = test_password();
        encode_password(&mut pass_buf, &password);

        assert_eq!(pass_buf.as_bytes(), &[
            0x9A, 0xFF, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x47, 0x48, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x67, 0x68, 0x12, 0x34, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);
    }

    #[test]
    fn substitution_accurate() {
        let mut pass_buf = PasswordBytes::new();
        let password = test_password();
        encode_password(&mut pass_buf, &password);
        substitution_cipher(&mut pass_buf);

        assert_eq!(pass_buf.as_bytes(), &[
            0x44, 0x7A, 0x78, 0xCB, 0x2E, 0x6D, 0xE4,
            0xE8, 0xDC, 0x40, 0x20, 0xD5, 0x39, 0x1A,
            0x67, 0x99, 0x41, 0xC7, 0xD2, 0xB9, 0xF0,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);
    }

    #[test]
    fn transposition_accurate() {
        let cases = [
            (
                TranspositionDir::Forward,
                CipherVariant::First,
                [
                    0xEE, 0x60, 0xAC, 0xA3, 0xAE, 0xAD, 0x8C,
                    0xAB, 0xB5, 0xBC, 0xC2, 0xD4, 0xD2, 0xD9,
                    0xB9, 0xC7, 0xD2, 0xC9, 0x12, 0x9F, 0x69,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            ),
            (
                TranspositionDir::Forward,
                CipherVariant::Second,
                [
                    0xDC, 0x68, 0xAD, 0xAE, 0x97, 0xB6, 0xAE,
                    0xB4, 0xAC, 0x48, 0xCF, 0xA4, 0xCC, 0xD0,
                    0xD1, 0xBA, 0xD9, 0xD1, 0x80, 0x99, 0x6E,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            ),
            (
                TranspositionDir::Backward,
                CipherVariant::First,
                [
                    0x46, 0x9E, 0xD6, 0xE1, 0xD8, 0xDB, 0xFE,
                    0xE1, 0xD9, 0xD4, 0x00, 0xF0, 0xF4, 0xEF,
                    0x11, 0x05, 0xFC, 0x07, 0x12, 0xC9, 0x97,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            ),
            (
                TranspositionDir::Backward,
                CipherVariant::Second,
                [
                    0x58, 0x96, 0xD5, 0xD6, 0xEF, 0xD2, 0xDC,
                    0xD8, 0xE2, 0x48, 0xF3, 0x20, 0xFA, 0xF8,
                    0xF9, 0x12, 0xF5, 0xFF, 0xA4, 0xCF, 0x92,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            )
        ];

        let mut pass_buf = PasswordBytes::new();
        let password = test_password();
        encode_password(&mut pass_buf, &password);

        for (dir, variant, expected) in cases {
            let mut test_buf = pass_buf.clone();
            transposition_cipher(&mut test_buf, dir, variant);

            assert_eq!(test_buf.as_bytes(), &expected);
        }
    }

    #[test]
    fn bit_shuffles_accurate() {
        let cases = [
            (
                ShuffleStage::Stage0,
                [
                    0x6B, 0x64, 0x61, 0x62, 0xC3, 0xE4, 0x07,
                    0x2E, 0x05, 0x42, 0x59, 0x5B, 0x52, 0x64,
                    0x55, 0x46, 0x46, 0x60, 0x60, 0x67, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            ),
            (
                ShuffleStage::Stage1,
                [
                    0xE0, 0x70, 0x41, 0x72, 0x46, 0x7D, 0x56,
                    0x05, 0x20, 0x03, 0x06, 0x43, 0x42, 0x4D,
                    0x40, 0x43, 0x66, 0x6D, 0x6C, 0x67, 0xE2,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            )
        ];

        let mut pass_buf = PasswordBytes::new();
        let password = test_password();
        encode_password(&mut pass_buf, &password);

        for (stage, expected) in cases {
            let mut test_buf = pass_buf.clone();
            bit_shuffle(&mut test_buf, stage);

            assert_eq!(test_buf.as_bytes(), &expected);
        }
    }

    #[test]
    fn rsa_accurate() {
        let mut pass_buf = PasswordBytes::new();
        let password = test_password();
        encode_password(&mut pass_buf, &password);
        rsa_cipher(&mut pass_buf);

        assert_eq!(pass_buf.as_bytes(), &[
            0x9A, 0xFF, 0x41, 0x4C, 0x43, 0x44, 0x45,
            0x46, 0x93, 0xF3, 0x87, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x5E, 0x26, 0x12, 0x47, 0x38,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
    }

    #[test]
    fn generation_accurate() {
        let password = test_password();
        let pass_buf = generate(&password);

        assert_eq!(pass_buf.as_bytes(), &[
            0x6A, 0x78, 0x57, 0x40, 0x6C, 0x40, 0x50,
            0x44, 0x56, 0x26, 0x4F, 0x4F, 0x79, 0x48,
            0x56, 0x50, 0x47, 0x73, 0x5A, 0x67, 0x74,
            0x43, 0x50, 0x33, 0xD1, 0x65, 0x48, 0x45,
        ]);
    }

    #[test]
    fn generates_famicom_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";

        let password = Password::famicom(0x1234, str0, str1);
        assert_eq!(generate(&password).as_bytes(), &[
            0x33, 0x78, 0x57, 0x40, 0x71, 0x74, 0x50,
            0x4B, 0x56, 0x26, 0x6E, 0x6F, 0x73, 0x48,
            0x65, 0x50, 0x75, 0x73, 0x4D, 0x39, 0x74,
            0x63, 0x49, 0x33, 0x33, 0x78, 0x7A, 0x37,
        ])
    }

    #[test]
    fn generates_popularity_contest_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";

        let password = Password::popularity_contest(0x1234, NpcType::Special, 0x11, str0, str1);
        assert_eq!(generate(&password).as_bytes(), &[
            0x68, 0x50, 0x66, 0x67, 0x47, 0x55, 0x52,
            0x72, 0x57, 0x35, 0x4D, 0x46, 0x67, 0x50,
            0x40, 0x33, 0x53, 0x76, 0x51, 0x33, 0x73,
            0x41, 0xD1, 0x55, 0x57, 0x50, 0x42, 0x55,
        ])
    }

    #[test]
    fn generates_card_e_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";

        let password = Password::card_e(0x1234, NpcType::Special, 0x34, 0x02, str0, str1);
        assert_eq!(generate(&password).as_bytes(), &[
            0x6A, 0x78, 0x57, 0x40, 0x6C, 0x39, 0x50,
            0x4B, 0x56, 0x26, 0x36, 0x4F, 0x79, 0x48,
            0x56, 0x50, 0x47, 0x73, 0x5A, 0x56, 0x74,
            0x43, 0x50, 0x72, 0xD1, 0x65, 0x46, 0x26,
        ])
    }

    #[test]
    fn generates_magazine_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";

        let password = Password::magazine(0x1234, 0x03, str0, str1);
        assert_eq!(generate(&password).as_bytes(), &[
            0x63, 0x4D, 0x57, 0x40, 0x59, 0x64, 0x50,
            0x44, 0x56, 0x26, 0x4F, 0x6F, 0x79, 0x48,
            0x74, 0x49, 0x47, 0x73, 0x5A, 0x67, 0x74,
            0x43, 0x50, 0x33, 0xD1, 0x78, 0x48, 0x26,
        ])
    }

    #[test]
    fn generates_user_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";

        let password = Password::user(0x1234, str0, str1);
        assert_eq!(generate(&password).as_bytes(), &[
            0x6A, 0x78, 0x57, 0x40, 0x6C, 0x40, 0x50,
            0x44, 0x56, 0x26, 0x4F, 0x4F, 0x79, 0x48,
            0x56, 0x50, 0x47, 0x73, 0x5A, 0x67, 0x74,
            0x43, 0x50, 0x33, 0xD1, 0x65, 0x48, 0x45,
        ])
    }

    #[test]
    fn generates_card_e_mini_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";

        let password = Password::card_e_mini(0x1234, str0, str1);
        assert_eq!(generate(&password).as_bytes(), &[
            0x37, 0x78, 0x57, 0x40, 0x59, 0x74, 0x50,
            0x38, 0x56, 0x26, 0x6E, 0x6F, 0x73, 0x48,
            0x65, 0x50, 0x75, 0x73, 0x4D, 0x39, 0x74,
            0x63, 0x49, 0x33, 0x33, 0x78, 0x7A, 0x33,
        ])
    }
}