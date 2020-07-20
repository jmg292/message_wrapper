use crate::identity::objects::LocalIdentity;
use std::default::Default;

#[derive(Clone)]
pub struct Header {
    _message_length: [u8; 4],
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub signature: [u8; 64]
}

impl Default for Header {
    fn default() -> Self { Header::empty() }
}


impl Header {

    fn u32_to_bytes(value: u32) -> [u8; 4] {
        let b1 : u8 = ((value >> 24) & 0xff) as u8;
        let b2 : u8 = ((value >> 16) & 0xff) as u8;
        let b3 : u8 = ((value >> 8) & 0xff) as u8;
        let b4 : u8 = (value & 0xff) as u8;
        return [b1, b2, b3, b4]
    }

    pub const fn len() -> usize {
        96
    }

    pub fn message_length(&self) -> u32 {
        let mut return_value = 0u32;
        return_value += (self._message_length[0] as u32) << 24;
        return_value += (self._message_length[1] as u32) << 16;
        return_value += (self._message_length[2] as u32) << 8;
        return_value += self._message_length[3] as u32;
        return_value
    }

    pub fn to_bytes(&self) -> [u8; Header::len()] {
        let mut return_value: [u8; Header::len()] = [0; Header::len()];
        for i in 0..Header::len() {
            match i {
                0..=3 => return_value[i] = self._message_length[i],
                4..=15 => return_value[i] = self.nonce[i - 4],
                16..=31 => return_value[i] = self.tag[i - 16],
                32..=95 => return_value[i] = self.signature[i - 32],
                _ => panic!(format!("{} is not a number in 0..{}.  How did this even happen?", i, Header::len()))
            }
        }
        return return_value;
    }

    pub fn from_slice(header_slice: &[u8]) -> Result<Header, ()> {
        if header_slice.len() == Header::len() {
            let mut return_value = Header::empty();
            for i in 0..Header::len() {
                match i {
                    0..=3 => return_value._message_length[i] = header_slice[i],
                    4..=15 => return_value.nonce[i - 4] = header_slice[i],
                    16..=31 => return_value.tag[i - 16] = header_slice[i],
                    32..=95 => return_value.signature[i - 32] = header_slice[i],
                    _ => panic!(format!("{} is not a number in 0..{}.  How did this even happen?", i, Header::len()))
                }
            }
            return Ok(return_value);
        }
        Err(())
    }

    pub fn new(message: &[u8], nonce: [u8; 12], tag: [u8; 16], private_key: &LocalIdentity) -> Result<Header, ()> {
        // Hmm.  Breaks compatibility with 16-bit and 8-bit processors.  Probably okay for now, but noting it for later.
        if message.len() <= (std::u32::MAX as usize)  {
            let message_length: u32 = (message.len() & 0xFFFFFFFF) as u32;
            return Ok(Header {
                _message_length: Header::u32_to_bytes(message_length),
                nonce: nonce,
                tag: tag,
                signature: private_key.sign(&tag)
            });
        }
        Err(())
    }

    pub fn empty() -> Header {
        Header {
            _message_length: [0; 4],
            nonce: [0; 12],
            tag: [0; 16],
            signature: [0; 64]
        }
    }

}
