use crate::identity::authorized_hosts::AuthorizedHosts;
use crate::identity::objects::{LocalIdentity, RemoteIdentity, Verification};
use secp256k1::{SecretKey, PublicKey};
use rand::{RngCore, SeedableRng};
use rand::rngs::OsRng;
use rand_hc::Hc128Rng;


#[derive(Default, Debug, Clone)]
pub struct Handshake {
    pub identity: LocalIdentity,
    pub peer_identity: Option<RemoteIdentity>,
    pub local_session_key: SecretKey,
    pub peer_session_key: Option<PublicKey>,
    offered_nonce: Option<[u8; 16]>,
    was_challenger: bool,
    completed_successfully: bool

}

impl Handshake {

    fn nonces_equal(sent_nonce: &[u8; 16], received_nonce: &[u8; 16]) -> bool {
        let mut differences: usize = 0;
        for i in 0..16 {
            differences += (sent_nonce[i] ^ received_nonce[i]) as usize;
        }
        differences == 0
    }

    fn new_private_key() -> SecretKey {
        let mut rng = Hc128Rng::from_rng(OsRng).expect("Unable to initialize RNG, unable to continue.");
        SecretKey::random(&mut rng)
    }

    fn new_nonce() -> [u8; 16] {
        let mut return_value: [u8; 16] = [0; 16];
        let mut rng = Hc128Rng::from_rng(OsRng).expect("Unable to initialize RNG, unable to continue.");
        rng.fill_bytes(&mut return_value);
        return_value
    }

    pub fn completed_successfully(&self) -> bool {
        self.completed_successfully
    }

    pub fn challenge(&mut self, initial_challenge: bool) -> [u8; 16] {
        if initial_challenge {
            self.was_challenger = initial_challenge;
        }
        let challenge_nonce = Handshake::new_nonce();
        if self.offered_nonce.is_none() {
            self.offered_nonce = Some(challenge_nonce);
        }
        return challenge_nonce;
    }

    pub fn challenge_response(&mut self, challenge_nonce: &[u8]) -> [u8; 193] {
        let session_public_key = PublicKey::from_secret_key(&self.local_session_key);
        let public_identity = self.identity.to_remote_identity();
        let identity_string = public_identity.fingerprint();
        let identity_bytes = identity_string.as_bytes(); 
        let signature_bytes = self.identity.sign(&challenge_nonce);
        let compressed_session_public_key = session_public_key.serialize_compressed();
        let challenge_offering = self.challenge(false);
        let mut return_value: [u8; 193] = [0; 193];
        for i in 0..193 {
            match i {
                0..=15 => return_value[i] = challenge_nonce[i],
                16..=79 => return_value[i] = identity_bytes[i - 16],
                80..=143 => return_value[i] = signature_bytes[i - 80],
                144..=176 => return_value[i] = compressed_session_public_key[i - 144],
                177..=192 => return_value[i] = challenge_offering[i - 177],
                _ => panic!(format!("{} isn't in the range 0..193, how did this even happen?", i))
            }
        }
        return return_value;
    }

    pub fn finalize_challenge(&mut self, challenge_response: &[u8], authorized_hosts: &AuthorizedHosts) -> Result<Option<[u8; 193]>, ()> {
        if challenge_response.len() == 193 && self.offered_nonce.is_some() {
            let mut received_nonce: [u8; 16] = [0; 16];
            let mut identity_bytes: [u8; 64] = [0; 64];
            let mut signature_bytes: [u8; 64] = [0; 64];
            let mut offered_public_key_bytes: [u8; 33] = [0; 33];
            let mut offered_challenge: [u8; 16] = [0; 16];
            for i in 0..193 {
                match i {
                    0..=15 => received_nonce[i] = challenge_response[i],
                    16..=79 => identity_bytes[i - 16] = challenge_response[i],
                    80..=143 => signature_bytes[i - 80] = challenge_response[i],
                    144..=176 => offered_public_key_bytes[i - 144] = challenge_response[i],
                    177..=192 => offered_challenge[i - 177] = challenge_response[i],
                    _ => panic!(format!("{} isn't in the range 0..193, how did this even happen?", i))
                }
            }
            if Handshake::nonces_equal(&self.offered_nonce.unwrap(), &received_nonce) {
                let identity_string = std::str::from_utf8(&identity_bytes).unwrap_or_default();
                if authorized_hosts.is_authorized(identity_string) {
                    self.peer_identity = Some(authorized_hosts.get_key(identity_string));
                    if self.peer_identity.as_ref().unwrap().verify(&self.offered_nonce.unwrap(), &signature_bytes) {
                        let packed_public_key = PublicKey::parse_compressed(&offered_public_key_bytes);
                        if packed_public_key.is_ok() {
                            self.completed_successfully = true;
                            self.peer_session_key = Some(packed_public_key.unwrap());                            
                            if self.was_challenger {
                                return Ok(Some(self.challenge_response(&offered_challenge)));
                            } else {                                
                                return Ok(Option::None);
                            }
                        }
                        else {
                            println!("Can't unpack public key.");
                        }
                    } else {
                        println!("Unable to verify signature.");
                    }
                } else {
                    println!("Peer {} is not authorized.", &identity_string);
                }
            } else {
                println!("Nonce mismatch.");
            }
        } else if challenge_response.len() != 193 {
            println!("Invalid challenge response length: {}", challenge_response.len());
        } else {
            println!("Have not offered a challenge.");
        }
        Err(())
    }

    pub fn load_local_identity(&mut self, local_identity: LocalIdentity) {
        self.identity = local_identity.clone();
        self.local_session_key = Handshake::new_private_key();
    }

    pub fn from_local_identity(local_identity: LocalIdentity) -> Handshake {
        Handshake {
            identity: local_identity.clone(),
            peer_identity: Option::None,
            local_session_key: Handshake::new_private_key(),
            peer_session_key: Option::None,
            offered_nonce: Option::None,
            was_challenger: false,
            completed_successfully: false
        }
    }
}