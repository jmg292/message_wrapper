use base64;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use secp256k1::{SecretKey, PublicKey, Message, Signature, sign, verify};
use secp256k1::util::COMPRESSED_PUBLIC_KEY_SIZE;
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand_hc::Hc128Rng;
use std::default::Default;
use std::fs::File;
use std::io::prelude::{Read, Write};
use std::path::Path;
use std::string::ToString;

#[derive(Debug, Clone)]
pub struct RemoteIdentity {
    _public_key: PublicKey
}


#[derive(Debug, Clone)]
pub struct LocalIdentity {
    _secret_key: SecretKey,
    _public_key: PublicKey
}

pub trait Verification {

    fn get_public_key(&self) -> &PublicKey;

    fn tag_to_message(&self, message: &[u8]) -> Message {
        // ChaCha20/Poly1305 validation tag is 128-bit.  We need 256 bits to create a Message object.  Probably a better way to do this.
        let mut message_data: [u8; 32] = [0; 32];
        let mut hash_provider = Sha3::sha3_256();        
        hash_provider.input(message);
        hash_provider.result(&mut message_data);
        Message::parse(&message_data)
    }

    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let message_obj = self.tag_to_message(&message);
        let signature_obj = Signature::parse(signature);
        verify(&message_obj, &signature_obj, self.get_public_key())
    }
}


impl ToString for RemoteIdentity {
    fn to_string(&self) -> String {
        base64::encode(self._public_key.serialize_compressed().to_vec())
    }
}

impl Verification for RemoteIdentity {
    fn get_public_key(&self) -> &PublicKey {
        &self._public_key
    }
}

impl Default for RemoteIdentity {
    fn default() -> Self {
        let mut rng = Hc128Rng::from_rng(OsRng).expect("Unable to initialize RNG, unable to continue.");
        RemoteIdentity::from_secret_key(&SecretKey::random(&mut rng))
    }
}

impl Verification for LocalIdentity {
    fn get_public_key(&self) -> &PublicKey {
        &self._public_key
    }
}

impl Default for LocalIdentity {
    fn default() -> Self { LocalIdentity::random() }
}


impl RemoteIdentity {

    pub fn fingerprint(&self) -> String {
        let mut hash_provider = Sha3::sha3_256();
        hash_provider.input_str(&self.to_string());
        hash_provider.result_str()
    }

    pub fn save_to_file(&self, file_path: &str) -> Result<bool, ()> {
        let file_handle_result: std::io::Result<File>;
        let path = Path::new(file_path);
        if !path.exists() {
            file_handle_result = File::create(path);
        } else {
            file_handle_result = File::open(path);
        }
        if file_handle_result.is_ok() {
            let mut file_handle = file_handle_result.unwrap();
            let write_result = file_handle.write_all(self.to_string().as_bytes());
            if write_result.is_ok() {
                return Ok(true);
            }
        }
        Err(())
    }

    pub fn from_secret_key(secret_key: &SecretKey) -> RemoteIdentity {
        RemoteIdentity {
            _public_key: PublicKey::from_secret_key(secret_key)
        }
    }

    pub fn from_string(identity_string: &str) -> Result<RemoteIdentity, ()> {
        let decoded_identity_result = base64::decode(identity_string);
        if decoded_identity_result.is_ok() {            
            let mut public_key_bytes: [u8; COMPRESSED_PUBLIC_KEY_SIZE] = [0; COMPRESSED_PUBLIC_KEY_SIZE];
            let decoded_identity = decoded_identity_result.unwrap();
            for i in 0..COMPRESSED_PUBLIC_KEY_SIZE {
                public_key_bytes[i] = decoded_identity[i];
            }
            let public_key = PublicKey::parse_compressed(&public_key_bytes);
            if public_key.is_ok() {
                return Ok(RemoteIdentity {
                    _public_key: public_key.unwrap()
                });
            }
        }
        Err(())
    }

    pub fn from_file(file_path: &str) -> Result<RemoteIdentity, ()> {
        let path = Path::new(file_path);
        if path.exists() {
            let file_handle_result = File::open(path);
            if file_handle_result.is_ok() {
                let mut file_content = String::new();
                let mut file_handle = file_handle_result.unwrap();
                let read_result = file_handle.read_to_string(&mut file_content);
                if read_result.is_ok() && file_content.len() == 44 {
                    return RemoteIdentity::from_string(&file_content);
                }        
            }
        }
        Err(())
    }
}

impl LocalIdentity {

    pub fn load_from_file(&mut self, file_path: &str) -> Result<(), ()> {
        let file_handle_result = File::open(file_path);
        if file_handle_result.is_ok() {
            let mut file_handle = file_handle_result.unwrap();
            let mut file_content = String::new();
            let read_result = file_handle.read_to_string(&mut file_content);
            if read_result.is_ok() && file_content.len() == 44 {
                let decoded_secret = base64::decode(file_content);
                if decoded_secret.is_ok() {
                    let parsed_secret = SecretKey::parse_slice(decoded_secret.unwrap().as_slice());
                    if parsed_secret.is_ok() {
                        let secret = parsed_secret.unwrap();
                        self._secret_key = secret.clone();                        
                        self._public_key = PublicKey::from_secret_key(&secret);
                        return Ok(());
                    }
                }
            }
        }
        Err(())
    }

    fn new_from_file(file_path: &str) -> Result<LocalIdentity, ()> {
        let mut local_identity = LocalIdentity::default();
        if local_identity.load_from_file(file_path).is_ok() {
            return Ok(local_identity);
        }
        Err(())
    }

    pub fn sign(&self, tag: &[u8]) -> [u8; 64] {
        let message = self.tag_to_message(&tag);
        sign(&message, &self._secret_key).0.serialize()
    }

    pub fn to_remote_identity(&self) -> RemoteIdentity {
        RemoteIdentity::from_secret_key(&self._secret_key)
    }

    pub fn save_to_file(&self, file_path: &Path) -> Result<bool, ()> {
        if !file_path.exists() {
            let file_handle_result = File::create(file_path);
            if file_handle_result.is_ok() {
                let encoded_key = base64::encode(&self._secret_key.serialize());
                let mut file_handle = file_handle_result.unwrap();
                let write_result = file_handle.write_all(encoded_key.as_bytes());
                if write_result.is_ok() {
                    return Ok(true);
                }
            }
        }
        Err(())
    }

    pub fn random() -> LocalIdentity {
        let mut rng = Hc128Rng::from_rng(OsRng).expect("Unable to initialize RNG, unable to continue.");
        let secret = SecretKey::random(&mut rng);
        LocalIdentity {
            _secret_key: secret.clone(),
            _public_key: PublicKey::from_secret_key(&secret)
        }
    }

    pub fn from_file(file_path: &str) -> LocalIdentity {
        let path = Path::new(file_path);
        if !path.exists() {
            let identity = LocalIdentity::random();
            identity.save_to_file(path).expect("Unable to save identity to file, unable to continue.");
            return identity;
        }
        return LocalIdentity::new_from_file(file_path).expect("Unable to load identity from file, unable to continue");
    }
}