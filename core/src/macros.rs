//! Useful macros

#[macro_export]
macro_rules! cast {
    (u16, $b:expr) => {
        u16::from_le_bytes([$b[0], $b[1]])
    };

    (be16, $b:expr) => {
        u16::from_be_bytes([$b[0], $b[1]])
    };

    (u32, $b:expr) => {
        u32::from_le_bytes([$b[0], $b[1], $b[2], $b[3]])
    };

    (be32, $b:expr) => {
        u32::from_be_bytes([$b[0], $b[1], $b[2], $b[3]])
    };

    (u64, $b:expr) => {
        u64::from_le_bytes([$b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7]])
    };

    (be64, $b:expr) => {
        u64::from_be_bytes([$b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7]])
    };

    (u128, $b:expr) => {
        u128::from_le_bytes([
            $b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7], $b[8], $b[9], $b[10], $b[11],
            $b[12], $b[13], $b[14], $b[15],
        ])
    };

    (be128, $b:expr) => {
        u128::from_be_bytes([
            $b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7], $b[8], $b[9], $b[10], $b[11],
            $b[12], $b[13], $b[14], $b[15],
        ])
    };
}
