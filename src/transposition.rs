use crate::{
    PASSWORD_DATA_LEN, PasswordBytes,
};

const TRANSPOSITION_TABLES: [[&[u8]; 16]; 2] = [
    [
        b"NiiMasaru",
        b"KomatsuKunihiro",
        b"TakakiGentarou",
        b"MiyakeHiromichi",
        b"HayakawaKenzo",
        b"KasamatsuShigehiro",
        b"SumiyoshiNobuhiro",
        b"NomaTakafumi",
        b"EguchiKatsuya",
        b"NogamiHisashi",
        b"IidaToki",
        b"IkegawaNoriko",
        b"KawaseTomohiro",
        b"BandoTaro",
        b"TotakaKazuo",
        b"WatanabeKunio",
    ],
    [
        b"RichAmtower",
        b"KyleHudson",
        b"MichaelKelbaugh",
        b"RaycholeLAneff",
        b"LeslieSwan",
        b"YoshinobuMantani",
        b"KirkBuchanan",
        b"TimOLeary",
        b"BillTrinen",
        b"nAkAyOsInoNyuuSankin",
        b"zendamaKINAKUDAMAkin",
        b"OishikutetUYOKUNARU",
        b"AsetoAminofen",
        b"fcSFCn64GCgbCGBagbVB",
        b"YossyIsland",
        b"KedamonoNoMori"
    ]
];

#[derive(Copy, Clone)]
#[repr(isize)]
pub enum TranspositionDir {
    Forward = 1,
    Backward = -1
}

#[repr(usize)]
pub enum CipherVariant {
    First,
    Second
}

pub fn transposition_cipher(buf: &mut PasswordBytes, dir: TranspositionDir, idx: CipherVariant) {
    let key_idx = match idx {
        CipherVariant::First => 18,
        CipherVariant::Second => 9
    };

    let bytes = buf.as_bytes_mut();
    let cipher = TRANSPOSITION_TABLES[idx as usize][(bytes[key_idx] & 0x0F) as usize];
    let mut str_idx = 0;

    for (i, b) in bytes[..PASSWORD_DATA_LEN].iter_mut().enumerate() {
        if i == key_idx {
            continue;
        }

        *b = b.wrapping_add(
            (cipher[str_idx] as i16 * dir as i16) as u8
        );

        str_idx = (str_idx + 1) % cipher.len();
    }
}