use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File},
    path::{Path, PathBuf},
};

const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PasswordEntry {
    pub label: String,
    pub password: String,
    pub website: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedStore {
    salt: String,
    encrypted_data: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PasswordStore {
    passwords: HashMap<String, PasswordEntry>,
}

pub struct Storage {
    store_path: PathBuf,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(store_path: P) -> Self {
        Self {
            store_path: store_path.as_ref().to_path_buf(),
        }
    }

    pub fn init(&self, master_password: &str) -> Result<()> {
        if self.store_path.exists() {
            anyhow::bail!("Password store already exists");
        }

        let store = PasswordStore {
            passwords: HashMap::new(),
        };

        self.save_store(&store, master_password)?;
        Ok(())
    }

    pub fn add_password(
        &self,
        label: String,
        password: String,
        website: Option<String>,
        username: Option<String>,
        notes: Option<String>,
        master_password: &str,
    ) -> Result<()> {
        let mut store = self.load_store(master_password)?;

        if store.passwords.contains_key(&label) {
            anyhow::bail!("Password with label '{}' already exists", label);
        }

        let entry = PasswordEntry {
            label: label.clone(),
            password,
            website,
            username,
            notes,
            created_at: chrono::Utc::now(),
        };

        store.passwords.insert(label, entry);

        self.save_store(&store, master_password)?;
        Ok(())
    }

    pub fn get_password(&self, label: &str, master_password: &str) -> Result<Option<PasswordEntry>> {
        let store = self.load_store(master_password)?;
        Ok(store.passwords.get(label).cloned())
    }

    pub fn list_passwords(&self, master_password: &str) -> Result<Vec<PasswordEntry>> {
        let store = self.load_store(master_password)?;
        Ok(store.passwords.values().cloned().collect())
    }

    pub fn delete_password(&self, label: &str, master_password: &str) -> Result<bool> {
        let mut store = self.load_store(master_password)?;
        let existed = store.passwords.remove(label).is_some();
        if existed {
            self.save_store(&store, master_password)?;
        }
        Ok(existed)
    }

    fn load_store(&self, master_password: &str) -> Result<PasswordStore> {
        let file = File::open(&self.store_path)
            .with_context(|| format!("Failed to open store at {:?}", self.store_path))?;

        let encrypted_store: EncryptedStore = serde_json::from_reader(file)?;
        let salt = BASE64.decode(encrypted_store.salt)?;
        let key = self.derive_key(master_password, &salt)?;
        let cipher = Aes256Gcm::new(&key);

        let encrypted_data = BASE64.decode(encrypted_store.encrypted_data)?;
        let nonce = Nonce::from_slice(&encrypted_data[..NONCE_LENGTH]);
        let ciphertext = &encrypted_data[NONCE_LENGTH..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Failed to decrypt password store"))?;

        let store: PasswordStore = serde_json::from_slice(&plaintext)?;
        Ok(store)
    }

    fn save_store(&self, store: &PasswordStore, master_password: &str) -> Result<()> {
        let mut salt = vec![0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);

        let key = self.derive_key(master_password, &salt)?;
        let cipher = Aes256Gcm::new(&key);

        let mut nonce = vec![0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        let plaintext = serde_json::to_vec(store)?;
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| anyhow::anyhow!("Failed to encrypt password store"))?;

        let mut encrypted_data = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
        encrypted_data.extend_from_slice(nonce);
        encrypted_data.extend_from_slice(&ciphertext);

        let encrypted_store = EncryptedStore {
            salt: BASE64.encode(salt),
            encrypted_data: BASE64.encode(encrypted_data),
        };

        let temp_path = self.store_path.with_extension("tmp");
        let file = File::create(&temp_path)?;
        serde_json::to_writer_pretty(file, &encrypted_store)?;

        fs::rename(temp_path, &self.store_path)?;
        Ok(())
    }

    fn derive_key(&self, master_password: &str, salt: &[u8]) -> Result<Key<Aes256Gcm>> {
        let salt = SaltString::encode_b64(salt).map_err(|e| anyhow::anyhow!("Salt error: {}", e))?;
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(master_password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Password hashing error: {}", e))?;

        let hash = password_hash.hash.unwrap();
        let hash_bytes = hash.as_bytes();
        let key = Key::<Aes256Gcm>::clone_from_slice(hash_bytes);
        Ok(key)
    }
} 