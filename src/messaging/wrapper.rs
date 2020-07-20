use base64;
use crate::authentication::Handshake;
use crate::identity::objects::{LocalIdentity, RemoteIdentity, Verification};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use chacha20poly1305::aead::{NewAead, AeadInPlace};
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use secp256k1::{SecretKey, PublicKey, SharedSecret};
use secp256k1::util::COMPRESSED_PUBLIC_KEY_SIZE;
use super::objects::Header;
use std::collections::HashSet;
use sha2::Sha256;
use rand::{SeedableRng, RngCore};
use rand::rngs::OsRng;
use rand_hc::Hc128Rng;


const MAX_MESSAGE_LENGTH: usize = 65535;

#[derive(Default, Debug, Clone)]
pub struct MessageWrapper {
    _identity: LocalIdentity,
    _peer_identity: RemoteIdentity,
    _ephemeral_private_key: SecretKey,
    _ephemeral_symmetric_key: [u8; 32],
    _used_nonces: HashSet<String>
}


impl MessageWrapper {

    fn new_private_key() -> SecretKey {
        let mut rng = Hc128Rng::from_rng(OsRng).expect("Unable to initialize RNG, unable to continue.");
        SecretKey::random(&mut rng)
    }

    fn secret_to_key(shared_secret: &[u8]) -> [u8; 32] {
        let mut output_value: [u8; 32] = [0; 32];
        let mut hash_provider = Sha3::sha3_256();
        hash_provider.input(&shared_secret);
        hash_provider.result(&mut output_value);
        return output_value;
    }

    fn unwrap_public_key_string(public_key_string: &str) -> Result<PublicKey, ()> {
        let decoded_identity_result = base64::decode(public_key_string);
        if decoded_identity_result.is_ok() {            
            let mut public_key_bytes: [u8; COMPRESSED_PUBLIC_KEY_SIZE] = [0; COMPRESSED_PUBLIC_KEY_SIZE];
            let decoded_identity = decoded_identity_result.unwrap();
            for i in 0..COMPRESSED_PUBLIC_KEY_SIZE {
                public_key_bytes[i] = decoded_identity[i];
            }
            let public_key = PublicKey::parse_compressed(&public_key_bytes);
            if public_key.is_ok() {
                return Ok(public_key.unwrap());
            }
        }
        Err(())
    }

    fn get_nonce(&mut self) -> [u8; 12] {
        let mut rng = Hc128Rng::from_rng(OsRng).expect("Unable to initialize RNG, unable to continue.");
        loop {
            let mut next_nonce: [u8; 12] = [0; 12];
            rng.fill_bytes(&mut next_nonce);
            let nonce_string = base64::encode(&next_nonce);
            if !self._used_nonces.contains(&nonce_string) {
                self._used_nonces.insert(nonce_string.clone());
                return next_nonce;
            }
        }
    }

    fn rotate_session_key(&mut self, peer_public_key: &PublicKey) -> Result<(), ()> {
        // SharedSecret requires a digest implementing the digest::digest::Digest trait, so I can't use crypto::sha3 here... *annoyed grumbling*
        let shared_secret_result = SharedSecret::<Sha256>::new(&peer_public_key, &self._ephemeral_private_key);
        if shared_secret_result.is_ok() {
            let shared_secret = shared_secret_result.unwrap();
            self._ephemeral_symmetric_key = MessageWrapper::secret_to_key(shared_secret.as_ref());
            return Ok(());
        }
        Err(())
    }

    pub fn rotate_private_key(&mut self) {
        self._ephemeral_private_key = MessageWrapper::new_private_key();
    }    

    pub fn exchange_keys(&mut self, peer_public_key_string: &str) -> Result<(), ()> {
        let public_key_result = MessageWrapper::unwrap_public_key_string(peer_public_key_string);
        if public_key_result.is_ok() {
            return self.rotate_session_key(&public_key_result.unwrap());
        }
        Err(())
    }

    pub fn get_public_key(&self) -> String {
        let public_key = PublicKey::from_secret_key(&self._ephemeral_private_key);
        base64::encode(public_key.serialize_compressed().to_vec())
    }

    pub fn get_message_count(&self) -> u32 {
        return (self._used_nonces.len() & 0xFFFFFFFF) as u32
    }

    pub fn wrap(&mut self, message: &[u8]) -> Result<Vec<u8>, ()> {
        // Wasn't sure how to pass null as the AEAD, so now we have this.
        let aead: [u8; 8] = [0; 8]; 
        if message.len() < MAX_MESSAGE_LENGTH {
            let nonce = self.get_nonce();
            let mut ciphertext: Vec<u8> = message.iter().map(|v| v.clone()).collect();
            let cipher = ChaCha20Poly1305::new(&Key::clone_from_slice(&self._ephemeral_symmetric_key));
            let encryption_result = cipher.encrypt_in_place_detached(&Nonce::clone_from_slice(&nonce), &aead, &mut ciphertext);
            if encryption_result.is_ok() {
                let mut tag: [u8; 16] = [0; 16];
                let tag_result = encryption_result.unwrap();
                tag.clone_from_slice(&tag_result);
                let header = Header::new(&message, nonce, tag, &self._identity);
                if header.is_ok() {                 
                    let mut return_value: Vec<u8> = Vec::new();
                    return_value.extend(header.unwrap().to_bytes().iter());
                    return_value.extend(ciphertext.iter());
                    return Ok(return_value);
                }
            }
        }
        Err(())
    }

    pub fn unwrap(&self, message: &[u8]) -> Result<Vec<u8>, ()> {
        // Did it for wrap, so I also have to do it for unwrap.
        let aead: [u8; 8] = [0; 8]; 
        if message.len() > Header::len() && message.len() <= MAX_MESSAGE_LENGTH + Header::len() {
            let header_bytes: Vec<u8> = message.iter().take(Header::len()).map(|b| b.clone()).collect();
            let unpacked_header = Header::from_slice(header_bytes.as_slice());
            if unpacked_header.is_ok() {
                let header = unpacked_header.unwrap();                
                if self._peer_identity.verify(&header.tag, &header.signature) {
                    let mut plaintext: Vec<u8> = message.iter().skip(Header::len()).take(header.message_length() as usize).map(|v| v.clone()).collect();
                    let cipher = ChaCha20Poly1305::new(&Key::clone_from_slice(&self._ephemeral_symmetric_key));                    
                    let decryption_result = cipher.decrypt_in_place_detached(
                        &Nonce::clone_from_slice(&header.nonce), 
                        &aead, 
                        &mut plaintext, 
                        &Tag::clone_from_slice(&header.tag)
                    );
                    if decryption_result.is_ok() {
                        return Ok(plaintext.iter().map(|b| b.clone()).collect());
                    }                  
                }
            } 
        }
        Err(())
    }

    pub fn load_from_handshake(&mut self, finalized_handshake: &Handshake) -> Result<(), ()> {
        if finalized_handshake.completed_successfully() {
            self._identity = finalized_handshake.identity.clone();
            self._peer_identity = finalized_handshake.peer_identity.as_ref().unwrap().clone();
            self._ephemeral_private_key = finalized_handshake.local_session_key.clone();
            return self.rotate_session_key(&finalized_handshake.peer_session_key.as_ref().unwrap());
        }
        Err(())
    }

    pub fn from_finalized_handshake(finalized_handshake: &Handshake) -> Result<MessageWrapper, ()> {
        let mut message_wrapper = MessageWrapper::default();
        if message_wrapper.load_from_handshake(finalized_handshake).is_ok() {
            return Ok(message_wrapper);
        }
        Err(())
    }
}