use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use super::objects::RemoteIdentity;


#[derive(Default, Debug, Clone)]
pub struct AuthorizedHosts {
    _storage_path: String,
    _authorized_keys: HashMap<String, RemoteIdentity>
}


impl AuthorizedHosts {

    pub fn get_key_ref(&self, fingerprint: &str) -> &RemoteIdentity {
        self._authorized_keys.get(fingerprint).unwrap()
    }

    pub fn get_key(&self, fingerprint: &str) -> RemoteIdentity {
        self._authorized_keys.get(fingerprint).unwrap().clone()
    }

    pub fn is_authorized(&self, fingerprint: &str) -> bool {
        self._authorized_keys.contains_key(fingerprint)
    }

    pub fn authorize_key(&mut self, remote_key: RemoteIdentity) -> Result<(), ()> {
        let fingerprint = remote_key.fingerprint();
        if !self.is_authorized(&fingerprint) {
            let mut file_path = PathBuf::new();
            file_path.push(&self._storage_path);
            file_path.push(format!("{}.pub", fingerprint));
            if remote_key.save_to_file(file_path.to_str().unwrap()).is_ok() {
                self._authorized_keys.insert(fingerprint, remote_key.clone());
                return Ok(());
            }
        }
        Err(())
    }

    pub fn authorize_key_string(&mut self, remote_key_string: &str) -> Result<(), ()> {
        let remote_identity_result = RemoteIdentity::from_string(remote_key_string);
        if remote_identity_result.is_ok() {
            return self.authorize_key(remote_identity_result.unwrap());
        }
        Err(())
    }

    pub fn load_keys(&mut self, folder_path: &str) -> Result<(), ()> {
        self._storage_path = folder_path.to_string();
        let path = Path::new(folder_path);
        if path.exists() && path.is_dir() {
            let directory_entries_result = fs::read_dir(path);
            if directory_entries_result.is_ok() {
                let public_keys: Vec<PathBuf> = directory_entries_result.unwrap().map(|result| result.map(|e| e.path()).unwrap())
                                                    .filter(|p| p.is_file() && p.extension() == Some(OsStr::new("pub"))).collect();
                for public_key_path in public_keys {
                    let remote_identity_result = RemoteIdentity::from_file(public_key_path.to_str().unwrap());
                    if remote_identity_result.is_ok() {
                        let remote_identity = remote_identity_result.unwrap();
                        self._authorized_keys.insert(remote_identity.fingerprint(), remote_identity);
                    }
                }
                return Ok(());
            }
        }
        Err(())
    }

    pub fn load(folder_path: &str) -> Result<AuthorizedHosts, ()> {
        let mut authorized_host = AuthorizedHosts {
            _storage_path: String::from_str(folder_path).unwrap(),
            _authorized_keys: HashMap::new()
        };
        if authorized_host.load_keys(folder_path).is_ok() {
            return Ok(authorized_host);            
        }
        Err(())
    }
}