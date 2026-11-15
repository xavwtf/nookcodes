mod transposition;
mod generation;
mod decoding;
mod bit_ops;
mod rsa;
mod substitution;
mod repacking;

pub use generation::generate;
pub use decoding::decode;

const PLAYER_NAME_LEN: usize = 8;
const PASSWORD_LEN: usize = 28;
const PASSWORD_DATA_LEN: usize = 21;

const SELECT_TABLES: [[usize; 8]; 16] = [
    [ 17, 11, 0, 10, 12, 6, 8, 4 ],
    [ 3, 8, 11, 16, 4, 6, 9, 19 ],
    [ 9, 14, 17, 18, 11, 10, 12, 2 ],
    [ 0, 2, 1, 4, 18, 10, 12, 8 ],
    [ 17, 19, 16, 7, 12, 8, 2, 9 ],
    [ 16, 3, 1, 8, 18, 4, 7, 6 ],
    [ 19, 6, 10, 17, 3, 16, 8, 9 ],
    [ 17, 7, 18, 16, 12, 2, 11, 0 ],
    [ 6, 2, 12, 1, 8, 14, 0, 16 ],
    [ 19, 16, 11, 8, 17, 3, 6, 14 ],
    [ 18, 12, 2, 7, 10, 11, 1, 14 ],
    [ 8, 0, 14, 2, 7, 11, 12, 17 ],
    [ 9, 3, 2, 0, 11, 8, 14, 10 ],
    [ 10, 11, 12, 16, 19, 7, 17, 8 ],
    [ 19, 8, 6, 1, 17, 9, 14, 10 ],
    [ 9, 7, 17, 12, 19, 10, 1, 11 ],
];

const USABLE_TO_FONTNUM: [u8; 64] = [
    98, 75, 122, 53, 99, 113, 89, 90, 79, 100,
    116, 54, 110, 108, 66, 121, 111, 56, 52, 76,
    107, 37, 65, 81, 109, 68, 80, 73, 55, 38,
    82, 115, 119, 85, 209, 114, 51, 69, 120, 77,
    67, 64, 101, 57, 103, 118, 86, 71, 117, 78,
    105, 88, 87, 102, 84, 74, 70, 83, 72, 112,
    50, 97, 106, 104,
];

pub mod error {
    use std::{error, fmt};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DecodeError {
        /// Checksum validation failed.
        ChecksumFailure,

        /// The decoder couldn't convert from font-safe characters to raw data.
        InvalidFontChar,

        /// No modular inverse exists for the given RSA data.
        RsaDecryptionFailure,

        /// The code type is invalid.
        InvalidCodeType
    }

    impl fmt::Display for DecodeError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                DecodeError::ChecksumFailure => write!(f, "checksum validation failed!"),
                DecodeError::InvalidFontChar => write!(f, "invalid font character!"),
                DecodeError::RsaDecryptionFailure => write!(f, "invalid RSA!"),
                DecodeError::InvalidCodeType => write!(f, "invalid code type!")
            }
        }
    }

    impl error::Error for DecodeError {
        fn source(&self) -> Option<&(dyn error::Error + 'static)> { None }
    }
}

type Item = u16;

/// The type of code. Certain types cause some fields to be interpreted differently, or not at all.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeType {
    /// Used in promotions to give away NES games in-game.
    Famicom,

    /// Used in character popularity polls. One could vote in a poll, then receive a code, 
    /// which they would mail to the villager they voted for to get exclusive letters and
    /// gifts. Originally from Doubutsu no Mori+, however unused in the GameCube version.
    PopularityContest {
        /// NPC type.
        npc_type: NpcType,

        /// NPC ID.
        npc_code: u8
    },

    /// e-Reader codes, they could be mailed to a villager to get a gift.
    CardE {
        /// NPC type.
        npc_type: NpcType,

        /// NPC ID.
        npc_code: u8,

        /// Hit rate index.
        hit_rate_index: u8
    },

    /// Promotional passwords published in Nintendo Power and the AC website. Universal
    /// in the sense that they are able to be used by any player regardless of their
    /// player or town name.
    Magazine {
        /// Hit rate index.
        hit_rate_index: u8
    },

    /// Tom Nook codes. Generated in-game by players to "send" items to a player
    /// in another town.
    User,

    /// Unused code type intended for prizes from e-Reader minigames. Much less
    /// restricted than typical user codes.
    CardEMini
}

impl CodeType {
    /// The raw code type value stored in the password.
    pub fn discriminant(self) -> u8 {
        match self {
            CodeType::Famicom => 0,
            CodeType::PopularityContest { .. } => 1,
            CodeType::CardE { .. } => 2,
            CodeType::Magazine { .. } => 3,
            CodeType::User => 4,
            CodeType::CardEMini => 5
        }
    }

    /// The NPC type, if this code type uses one.
    pub fn npc_type(self) -> Option<NpcType> {
        match self {
            CodeType::PopularityContest { npc_type, .. } |
            CodeType::CardE { npc_type, .. } => Some(npc_type),
            _ => None
        }
    }

    /// The internal NPC code, if this code type uses one.
    pub fn npc_code(self) -> Option<u8> {
        match self {
            CodeType::PopularityContest { npc_code, .. } |
            CodeType::CardE { npc_code, .. } => Some(npc_code),
            _ => None
        }
    }

    /// The hit rate index, if this code type uses one.
    pub fn hit_rate_index(self) -> Option<u8> {
        match self {
            CodeType::CardE { hit_rate_index, .. } |
            CodeType::Magazine { hit_rate_index } => Some(hit_rate_index),
            _ => None
        }
    }

    /// The hit rate index written into the password
    fn encoded_hit_rate_index(self) -> u8 {
        match self {
            CodeType::PopularityContest { .. } => 0x04,
            _ => self.hit_rate_index().unwrap_or(0x01)
        }
    }

    fn from_parts(
        discriminant: u8,
        npc_type: NpcType,
        npc_code: u8,
        hit_rate_index: u8
    ) -> Result<Self, ()> {
        Ok(match discriminant {
            0 => CodeType::Famicom,
            1 => CodeType::PopularityContest { npc_type, npc_code },
            2 => CodeType::CardE { npc_type, npc_code, hit_rate_index },
            3 => CodeType::Magazine { hit_rate_index },
            4 => CodeType::User,
            5 => CodeType::CardEMini,
            _ => return Err(())
        })
    }
}

/// NPC type for PopularityContest and CardE code types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpcType {
    Normal,
    Special
}

impl From<bool> for NpcType {
    fn from(value: bool) -> Self {
        if value { NpcType::Special } else { NpcType::Normal }
    }
}

/// A struct representing the components of a password.
#[derive(Debug, PartialEq, Eq)]
pub struct Password {
    /// The item ID contained in the password.
    item: Item,

    /// The code type, which also holds the fields specific to that type.
    code_type: CodeType,

    /// Code strings, which depending on the type of code could hold different things.
    /// 
    /// User, Famicom, PopularityContest:
    /// str0 holds the recipient's player name, and str1 holds the recipient's town name
    /// 
    /// Magazine:
    /// str0 and str1 are appended together to form the name of the magazine in which
    /// the code was published
    /// 
    /// CardEMini:
    /// str0 and str1 are appended together to form the name of the minigame
    str0: [u8; PLAYER_NAME_LEN],
    str1: [u8; PLAYER_NAME_LEN]
}

impl Password {
    /// Constructs a Famicom code.
    pub fn famicom(
        item: Item,
        str0: [u8; PLAYER_NAME_LEN],
        str1: [u8; PLAYER_NAME_LEN],
    ) -> Self {
        Self {
            item,
            code_type: CodeType::Famicom,
            str0,
            str1,
        }
    }

    /// Constructs a User code.
    pub fn user(
        item: Item,
        str0: [u8; PLAYER_NAME_LEN],
        str1: [u8; PLAYER_NAME_LEN],
    ) -> Self {
        Self {
            item,
            code_type: CodeType::User,
            str0,
            str1,
        }
    }

    /// Constructs a e-Reader minigame code.
    pub fn card_e_mini(
        item: Item,
        str0: [u8; PLAYER_NAME_LEN],
        str1: [u8; PLAYER_NAME_LEN],
    ) -> Self {
        Self {
            item,
            code_type: CodeType::CardEMini,
            str0,
            str1,
        }
    }

    /// Constructs a Popularity Contest code.
    pub fn popularity_contest(
        item: Item,
        npc_type: NpcType,
        npc_code: u8,
        str0: [u8; PLAYER_NAME_LEN],
        str1: [u8; PLAYER_NAME_LEN],
    ) -> Self {
        Self {
            item,
            code_type: CodeType::PopularityContest { npc_type, npc_code },
            str0,
            str1,
        }
    }

    /// Constructs a Magazine code.
    pub fn magazine(
        item: Item,
        hit_rate_index: u8,
        str0: [u8; PLAYER_NAME_LEN],
        str1: [u8; PLAYER_NAME_LEN],
    ) -> Self {
        Self {
            item,
            code_type: CodeType::Magazine { hit_rate_index },
            str0,
            str1,
        }
    }

    /// Constructs a e-Reader code.
    pub fn card_e(
        item: Item,
        npc_type: NpcType,
        npc_code: u8,
        hit_rate_index: u8,
        str0: [u8; PLAYER_NAME_LEN],
        str1: [u8; PLAYER_NAME_LEN],
    ) -> Self {
        Self {
            item,
            code_type: CodeType::CardE { npc_type, npc_code, hit_rate_index },
            str0,
            str1,
        }
    }

    pub fn item(&self) -> Item {
        self.item
    }

    pub fn npc_type(&self) -> Option<NpcType> {
        self.code_type.npc_type()
    }

    pub fn npc_code(&self) -> Option<u8> {
        self.code_type.npc_code()
    }

    pub fn code_type(&self) -> CodeType {
        self.code_type
    }

    pub fn hit_rate_index(&self) -> Option<u8> {
        self.code_type.hit_rate_index()
    }

    pub fn str0(&self) -> &[u8; PLAYER_NAME_LEN] {
        &self.str0
    }

    pub fn str1(&self) -> &[u8; PLAYER_NAME_LEN] {
        &self.str1
    }
}

/// A wrapper around `[u8; PASSWORD_LEN]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordBytes([u8; PASSWORD_LEN]);

impl PasswordBytes {
    pub fn new() -> Self {
        Self([0; PASSWORD_LEN])
    }

    pub fn as_bytes(&self) -> &[u8; PASSWORD_LEN] {
        &self.0
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; PASSWORD_LEN] {
        &mut self.0
    }
}

impl From<[u8; PASSWORD_LEN]> for PasswordBytes {
    fn from(value: [u8; PASSWORD_LEN]) -> Self {
        Self(value)
    }
}

impl Default for PasswordBytes {
    fn default() -> Self {
        Self([0; PASSWORD_LEN])
    }
}

impl AsRef<[u8]> for PasswordBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_cycle() {
        let password = Password {
            code_type: CodeType::User,
            item: 0x1234,
            str0: *b"ABCDEFGH",
            str1: *b"abcdefgh"
        };

        let mut generated = generate(&password);

        assert_eq!(generated.as_bytes(), &[
            0x6A, 0x78, 0x57, 0x40, 0x6C, 0x40, 0x50,
            0x44, 0x56, 0x26, 0x4F, 0x4F, 0x79, 0x48,
            0x56, 0x50, 0x47, 0x73, 0x5A, 0x67, 0x74,
            0x43, 0x50, 0x33, 0xD1, 0x65, 0x48, 0x45,
        ]);

        let decoded = decode(&mut generated).unwrap();

        assert_eq!(decoded, password);
    }
}