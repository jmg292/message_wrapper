mod authentication;
mod messaging;
mod identity;

use crate::identity::authorized_hosts::AuthorizedHosts;
use crate::identity::objects::LocalIdentity;
use crate::messaging::wrapper::MessageWrapper;
use crate::authentication::Handshake;
use global::Global;
use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;


static AUTHORIZED_HOSTS: Global<AuthorizedHosts> = Global::new();
static MESSAGE_WRAPPER: Global<MessageWrapper> = Global::new();
static LOCAL_IDENTITY: Global<LocalIdentity> = Global::new();
static HANDSHAKE: Global<Handshake> = Global::new();


#[pyfunction] 
fn initialize(identity_file: &str, authorized_keys_folder: &str) -> PyResult<bool> {
    let mut local_identity = LOCAL_IDENTITY.lock_mut().unwrap();
    if local_identity.load_from_file(&identity_file).is_ok() {
        if AUTHORIZED_HOSTS.lock_mut().unwrap().load_keys(authorized_keys_folder).is_ok() {
            HANDSHAKE.lock_mut().unwrap().load_local_identity(local_identity.clone());
            return Ok(true);
        } else {
            
            return Err(PyErr::new::<exceptions::NotADirectoryError, _>("Unable to load Authorized Hosts directory."));
        }
    } else {
        return Err(PyErr::new::<exceptions::FileNotFoundError, _>("Unable to load identity key from file."));
    }
}

#[pyfunction]
fn save_public_key(file_path: &str) -> PyResult<bool> {
    if LOCAL_IDENTITY.lock().unwrap().to_remote_identity().save_to_file(file_path).is_ok() {
        return Ok(true);
    }
    Err(PyErr::new::<exceptions::IOError, _>("Unable to save public key file."))
}

#[pyfunction]
fn get_challenge() -> PyResult<Vec<u8>> {
    Ok(HANDSHAKE.lock_mut().unwrap().challenge(true).to_vec())
}

#[pyfunction] 
fn get_challenge_response(challenge: &[u8]) -> PyResult<Vec<u8>> {
    Ok(HANDSHAKE.lock_mut().unwrap().challenge_response(challenge).to_vec())
}

#[pyfunction]
fn finalize_challenge(challenge_response: &[u8]) -> PyResult<Vec<u8>> {
    let mut handshake = HANDSHAKE.lock_mut().unwrap();
    let challenge_finalization = handshake.finalize_challenge(challenge_response, &AUTHORIZED_HOSTS.lock().unwrap());
    if challenge_finalization.is_ok() {
        if MESSAGE_WRAPPER.lock_mut().unwrap().load_from_handshake(&handshake).is_ok() {
            let response_option = challenge_finalization.unwrap();
            if response_option.is_some() {
                let response = response_option.unwrap();
                return Ok(response.to_vec());
            }
            return Ok(Vec::new());
        }
    }
    Err(PyErr::new::<exceptions::PermissionError, _>("Connection from peer is not authorized."))
}

#[pyfunction]
fn encrypt(message: &[u8]) -> PyResult<Vec<u8>> {
    let ciphertext_result = MESSAGE_WRAPPER.lock_mut().unwrap().wrap(message);
    if ciphertext_result.is_ok() {
        let ciphertext = ciphertext_result.unwrap();
        return Ok(ciphertext.to_vec());
    }
    Err(PyErr::new::<exceptions::ValueError, _>("Plaintext message is too large."))
}

#[pyfunction]
fn decrypt(message: &[u8]) -> PyResult<Vec<u8>> {
    let plaintext_result = MESSAGE_WRAPPER.lock().unwrap().unwrap(message);
    if plaintext_result.is_ok() {
        let plaintext = plaintext_result.unwrap();
        return Ok(plaintext.to_vec());
    }
    Err(PyErr::new::<exceptions::ValueError, _>("Invalid ciphertext supplied."))
}

#[pymodule] 
fn message_wrapper(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(initialize))?;
    m.add_wrapped(wrap_pyfunction!(save_public_key))?;
    m.add_wrapped(wrap_pyfunction!(get_challenge))?;
    m.add_wrapped(wrap_pyfunction!(get_challenge_response))?;
    m.add_wrapped(wrap_pyfunction!(finalize_challenge))?;
    m.add_wrapped(wrap_pyfunction!(encrypt))?;
    m.add_wrapped(wrap_pyfunction!(decrypt))?;
    Ok(())
}
