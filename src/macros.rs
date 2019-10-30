/**
 * Helper macros
 */

macro_rules! read_n_bytes {
    ($reader:expr, $num:expr) => {
        {
            let mut __bytes: Vec<u8> = Vec::new();
            for byte in $reader.bytes().take($num) {
                __bytes.push(byte.unwrap());
            }
            __bytes
        }
    };
}

macro_rules! read_byte {
    ($reader:expr) => {
        {
            let mut __bytes: [u8; 1] = [0; 1];
            $reader.read(&mut __bytes)?;
            __bytes[0]
        }
    };
}

macro_rules! read_u16 {
    ($reader:expr, $data_format:expr) => {
        {
            let mut __bytes: [u8; 2] = [0; 2];
            let mut __temp: u16 = 0;
            $reader.read(&mut __bytes)?;
            unsafe {
                __temp = std::mem::transmute::<[u8; 2], u16>(__bytes);

                if $data_format == ELFData::BigEndian {
                    __temp = __temp.to_le();
                }
            }
            __temp
        }
    };
}

macro_rules! read_u32 {
    ($reader:expr, $data_format:expr) => {
        {
            let mut __bytes: [u8; 4] = [0; 4];
            let mut __temp: u32 = 0;
            $reader.read(&mut __bytes)?;
            unsafe {
                __temp = std::mem::transmute::<[u8; 4], u32>(__bytes);

                if $data_format == ELFData::BigEndian {
                    __temp = __temp.to_le();
                }
            }
            __temp
        }
    };
}

macro_rules! read_u64 {
    ($reader:expr, $data_format:expr) => {
        {
            let mut __bytes: [u8; 8] = [0; 8];
            let mut __temp: u64 = 0;
            $reader.read(&mut __bytes)?;
            unsafe {
                __temp = std::mem::transmute::<[u8; 8], u64>(__bytes);

                if $data_format == ELFData::BigEndian {
                    __temp = __temp.to_le();
                }
            }
            __temp
        }
    };
}
