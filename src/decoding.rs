use crate::{
    Password,
    PasswordBytes,
    PLAYER_NAME_LEN,
    USABLE_TO_FONTNUM,
    NpcType,
    CodeType,
    Item,

    error,
    bit_ops::*,
    repacking::repack_bitstream,
    rsa::decode_rsa_cipher,
    transposition::*,
    substitution::*
};

const CHAR_ZERO: u8 = 48;
const CHAR_O: u8 = 79;
const CHAR_ONE: u8 = 49;
const CHAR_L_LOWER: u8 = 108;

fn normalise_ambiguous(buf: &mut PasswordBytes) {
    for b in buf.as_bytes_mut() {
        *b = match *b {
            CHAR_ZERO => CHAR_O,
            CHAR_ONE => CHAR_L_LOWER,
            _ => *b
        }
    }
}

fn decode_font(buf: &mut PasswordBytes) -> Result<(), error::DecodeError> {
    for b in buf.as_bytes_mut() {
        *b = USABLE_TO_FONTNUM.iter().position(|x| *x == *b).ok_or(error::DecodeError::InvalidFontChar)? as u8;
    }

    Ok(())
}

fn decode_bytes(buf: &PasswordBytes) -> Result<Password, error::DecodeError> {
    let bytes = buf.as_bytes();

    let checksum = (bytes[0] >> 3) & 3;
    let code_type_discriminant = (bytes[0] >> 5) & 7;
    let npc_type = NpcType::from((bytes[0] & 1) != 0);
    let npc_code = bytes[1];
    let item: Item = ((bytes[18] as u16) << 8) | bytes[19] as u16;
    let hit_rate_index: u8 = match code_type_discriminant {
        3 => ((bytes[0] >> 1) & 3) | ((bytes[0] & 1) << 2),
        _ => (bytes[0] >> 1) & 3
    };

    let code_type = CodeType::from_parts(code_type_discriminant, npc_type, npc_code, hit_rate_index)
        .map_err(|_| error::DecodeError::InvalidCodeType)?;

    let mut str0 = [0u8; PLAYER_NAME_LEN];
    str0.copy_from_slice(&bytes[2..2 + PLAYER_NAME_LEN]);

    let mut str1 = [0u8; PLAYER_NAME_LEN];
    str1.copy_from_slice(&bytes[10..10 + PLAYER_NAME_LEN]);

    let expected: u32 = str0.iter()
            .chain(str1.iter())
            .map(|&b| b as u32)
            .sum::<u32>()
            + item as u32
            + npc_code as u32;
    
    if checksum as u32 != (expected & 3) { return Err(error::DecodeError::ChecksumFailure) }

    Ok(Password {
        code_type,
        item,
        str0,
        str1
    })
}

/// Creates a decoded and decrypted `Password` object given raw password bytes.
pub fn decode(buf: &PasswordBytes) -> Result<Password, error::DecodeError> {
    let mut buf = buf.clone();
    normalise_ambiguous(&mut buf);
    decode_font(&mut buf)?;
    repack_bitstream(&mut buf, 6, 8);
    transposition_cipher(&mut buf, TranspositionDir::Backward, CipherVariant::Second);
    decode_bit_shuffle(&mut buf, ShuffleStage::Stage1);
    decode_bit_mix(&mut buf);
    decode_rsa_cipher(&mut buf)?;
    decode_bit_shuffle(&mut buf, ShuffleStage::Stage0);
    transposition_cipher(&mut buf, TranspositionDir::Forward, CipherVariant::First);
    decode_substitution_cipher(&mut buf);

    decode_bytes(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CodeType,
        NpcType,
        PasswordBytes,
        Password,
        
        error::DecodeError
    };

    #[test]
    fn bytes_decode_accurate() {
        let test_buf = PasswordBytes([
            0x9A, 0xFF, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x47, 0x48, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x67, 0x68, 0x12, 0x34, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let password = decode_bytes(&test_buf).unwrap();

        assert_eq!(password, Password {
            code_type: CodeType::User,
            item: 0x1234,
            str0: *b"ABCDEFGH",
            str1: *b"abcdefgh"
        })
    }

    #[test]
    fn decodes_accurate() {
        let mut test_buf = PasswordBytes([
            0x6A, 0x78, 0x57, 0x40, 0x6C, 0x40, 0x50,
            0x44, 0x56, 0x26, 0x4F, 0x4F, 0x79, 0x48,
            0x56, 0x50, 0x47, 0x73, 0x5A, 0x67, 0x74,
            0x43, 0x50, 0x33, 0xD1, 0x65, 0x48, 0x45,
        ]);

        let password = decode(&mut test_buf).unwrap();

        assert_eq!(password, Password {
            code_type: CodeType::User,
            item: 0x1234,
            str0: *b"ABCDEFGH",
            str1: *b"abcdefgh"
        });
    }

    #[test]
    fn checksum_validation() {
        let mut test_buf = PasswordBytes([
            0x7A, 0x78, 0x57, 0x40, 0x6C, 0x40, 0x50,
            0x44, 0x56, 0x26, 0x4F, 0x4F, 0x79, 0x48,
            0x56, 0x50, 0x47, 0x73, 0x5A, 0x67, 0x74,
            0x43, 0x50, 0x33, 0xD1, 0x65, 0x48, 0x45,
        ]);

        assert!(matches!(decode(&mut test_buf), Err(DecodeError::ChecksumFailure)));
    }

    #[test]
    fn font_char_validation() {
        let mut test_buf = PasswordBytes([
            0x6A, 0x78, 0xFF, 0x40, 0x6C, 0x40, 0x50,
            0x44, 0x56, 0x26, 0x4F, 0x4F, 0x79, 0x48,
            0x56, 0x50, 0x47, 0x73, 0x5A, 0x67, 0x74,
            0x43, 0x50, 0x33, 0xD1, 0x65, 0x48, 0x45,
        ]);

        assert!(matches!(decode(&mut test_buf), Err(DecodeError::InvalidFontChar)));
    }

    #[test]
    fn code_type_validation() {
        let mut test_buf = PasswordBytes([
            0xFA, 0xFF, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x47, 0x48, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66, 0x67, 0x68, 0x12, 0x34, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        assert!(matches!(decode_bytes(&mut test_buf), Err(DecodeError::InvalidCodeType)));
    }

    #[test]
    fn decodes_famicom_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";
        let encoded = [
            0x33, 0x78, 0x57, 0x40, 0x71, 0x74, 0x50,
            0x4B, 0x56, 0x26, 0x6E, 0x6F, 0x73, 0x48,
            0x65, 0x50, 0x75, 0x73, 0x4D, 0x39, 0x74,
            0x63, 0x49, 0x33, 0x33, 0x78, 0x7A, 0x37,
        ];

        let decoded = decode(&PasswordBytes(encoded)).unwrap();
        assert_eq!(decoded, Password::famicom(0x1234, str0, str1));
    }

    #[test]
    fn decodes_popularity_contest_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";
        let encoded = [
            0x68, 0x50, 0x66, 0x67, 0x47, 0x55, 0x52,
            0x72, 0x57, 0x35, 0x4D, 0x46, 0x67, 0x50,
            0x40, 0x33, 0x53, 0x76, 0x51, 0x33, 0x73,
            0x41, 0xD1, 0x55, 0x57, 0x50, 0x42, 0x55,
        ];

        let decoded = decode(&PasswordBytes(encoded)).unwrap();
        assert_eq!(decoded, Password::popularity_contest(0x1234, NpcType::Special, 0x11, str0, str1));
    }

    #[test]
    fn decodes_card_e_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";
        let encoded = [
            0x6A, 0x78, 0x57, 0x40, 0x6C, 0x39, 0x50,
            0x4B, 0x56, 0x26, 0x36, 0x4F, 0x79, 0x48,
            0x56, 0x50, 0x47, 0x73, 0x5A, 0x56, 0x74,
            0x43, 0x50, 0x72, 0xD1, 0x65, 0x46, 0x26,
        ];

        let decoded = decode(&PasswordBytes(encoded)).unwrap();
        assert_eq!(decoded, Password::card_e(0x1234, NpcType::Special, 0x34, 0x02, str0, str1));
    }

    #[test]
    fn decodes_magazine_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";
        let encoded = [
            0x63, 0x4D, 0x57, 0x40, 0x59, 0x64, 0x50,
            0x44, 0x56, 0x26, 0x4F, 0x6F, 0x79, 0x48,
            0x74, 0x49, 0x47, 0x73, 0x5A, 0x67, 0x74,
            0x43, 0x50, 0x33, 0xD1, 0x78, 0x48, 0x26,
        ];

        let decoded = decode(&PasswordBytes(encoded)).unwrap();
        assert_eq!(decoded, Password::magazine(0x1234, 0x03, str0, str1));
    }

    #[test]
    fn decodes_user_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";
        let encoded = [
            0x6A, 0x78, 0x57, 0x40, 0x6C, 0x40, 0x50,
            0x44, 0x56, 0x26, 0x4F, 0x4F, 0x79, 0x48,
            0x56, 0x50, 0x47, 0x73, 0x5A, 0x67, 0x74,
            0x43, 0x50, 0x33, 0xD1, 0x65, 0x48, 0x45,
        ];

        let decoded = decode(&PasswordBytes(encoded)).unwrap();
        assert_eq!(decoded, Password::user(0x1234, str0, str1));
    }

    #[test]
    fn decodes_card_e_mini_accurate() {
        let str0 = *b"ABCDEFGH";
        let str1 = *b"abcdefgh";
        let encoded = [
            0x37, 0x78, 0x57, 0x40, 0x59, 0x74, 0x50,
            0x38, 0x56, 0x26, 0x6E, 0x6F, 0x73, 0x48,
            0x65, 0x50, 0x75, 0x73, 0x4D, 0x39, 0x74,
            0x63, 0x49, 0x33, 0x33, 0x78, 0x7A, 0x33,
        ];

        let decoded = decode(&PasswordBytes(encoded)).unwrap();
        assert_eq!(decoded, Password::card_e_mini(0x1234, str0, str1));
    }
}