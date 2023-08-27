use std::collections::HashMap;

use age_core::{format::Stanza, secrecy::ExposeSecret};
use age_plugin::{identity, recipient};
use bincode::{config, Decode, Encode};
use rand::{rngs::StdRng, SeedableRng};

use crate::agile::{
    agile_setup_receiver, agile_setup_sender, AeadAlg, AgileAeadTag, AgileEncappedKey,
    AgileKeypair, AgileOpModeR, AgileOpModeRTy, AgileOpModeS, AgileOpModeSTy, AgilePrivateKey,
    AgilePublicKey, KdfAlg, KemAlg,
};

pub const STANZA_TAG: &str = "hpke";
pub const INFO_STR: &[u8] = b"age-plugin-hpke";
pub const PLUGIN_NAME: &str = "hpke";

#[derive(Debug, Encode, Decode, PartialEq, Clone)]
pub struct Identity {
    kem: KemAlg,
    aead: AeadAlg,
    kdf: KdfAlg,
    private_key: AgilePrivateKey,
}

impl Identity {
    pub fn new(kem: KemAlg, aead: AeadAlg, kdf: KdfAlg, private_key: &AgilePrivateKey) -> Self {
        Self {
            kem,
            aead,
            kdf,
            private_key: private_key.clone(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let (identity, _) = bincode::decode_from_slice(data, config::standard()).unwrap();
        identity
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, config::standard()).unwrap()
    }
}

impl age::Identity for Identity {
    fn unwrap_stanza(
        &self,
        stanza: &age_core::format::Stanza,
    ) -> Option<Result<age_core::format::FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        // TODO: consider having a helper stanza struct
        if stanza.args.len() != 3 {
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        let args: [Vec<u8>; 3] = [
            hex::decode(stanza.args[0].clone()).ok()?,
            hex::decode(stanza.args[1].clone()).ok()?,
            hex::decode(stanza.args[2].clone()).ok()?,
        ];
        let [associated_data, encapped_key_bytes, tag_bytes] = args;

        let tag: AgileAeadTag = tag_bytes;
        let encapped_key = AgileEncappedKey::new(self.kem.clone(), &encapped_key_bytes);

        let mut receiver_ctx = agile_setup_receiver(
            self.aead.clone(),
            self.kdf.clone(),
            self.kem.clone(),
            &AgileOpModeR::new(self.kem.clone(), AgileOpModeRTy::Base),
            &AgileKeypair::new(self.private_key.clone(), self.private_key.to_pk()),
            &encapped_key,
            INFO_STR,
        )
        .expect("invalid credentials!");

        let mut dst = stanza.body.clone();
        receiver_ctx
            .open_in_place_detached(&mut dst, &associated_data, &tag)
            .expect("invalid ciphertext!");

        let file_key: [u8; 16] = dst[..].try_into().ok()?;
        Some(Ok(file_key.into()))
    }
}

#[derive(Debug, Encode, Decode, PartialEq, Clone)]
pub struct Recipient {
    kem: KemAlg,
    aead: AeadAlg,
    kdf: KdfAlg,
    public_key: AgilePublicKey,
    associated_data: Vec<u8>,
}

impl Recipient {
    pub fn new(
        kem: KemAlg,
        aead: AeadAlg,
        kdf: KdfAlg,
        public_key: &AgilePublicKey,
        associated_data: &[u8],
    ) -> Self {
        Self {
            kem,
            aead,
            kdf,
            public_key: public_key.clone(),
            associated_data: associated_data.to_vec(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let (recipient, _) = bincode::decode_from_slice(data, config::standard()).unwrap();
        recipient
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, config::standard()).unwrap()
    }
}

impl age::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &age_core::format::FileKey,
    ) -> Result<Vec<age_core::format::Stanza>, age::EncryptError> {
        let src = file_key.expose_secret().as_slice();

        let mut csprng = StdRng::from_entropy();
        let (encapped_key, mut sender_ctx) = agile_setup_sender(
            self.aead.clone(),
            self.kdf.clone(),
            self.kem.clone(),
            &AgileOpModeS::new(self.kem.clone(), AgileOpModeSTy::Base),
            &self.public_key,
            INFO_STR,
            &mut csprng,
        )
        .expect("invalid setup");

        let mut ciphertext = src.to_vec();
        let tag = sender_ctx
            .seal_in_place_detached(&mut ciphertext, &self.associated_data)
            .expect("encryption failed!");

        Ok(vec![Stanza {
            tag: STANZA_TAG.to_string(),
            args: vec![
                hex::encode(&self.associated_data),
                hex::encode(encapped_key.to_bytes()),
                hex::encode(tag),
            ],
            body: ciphertext,
        }])
    }
}

pub struct IdentityPlugin {
    identities: Vec<Identity>,
}

impl IdentityPlugin {
    pub fn new() -> Self {
        Self { identities: vec![] }
    }
}

impl age_plugin::identity::IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), age_plugin::identity::Error> {
        if plugin_name == PLUGIN_NAME {
            self.identities.push(Identity::from_bytes(bytes));
            Ok(())
        } else {
            Err(identity::Error::Identity {
                index,
                message: "Invalid plugin name".to_owned(),
            })
        }
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<age_core::format::Stanza>>,
        _callbacks: impl age_plugin::Callbacks<age_plugin::identity::Error>,
    ) -> std::io::Result<
        std::collections::HashMap<
            usize,
            Result<age_core::format::FileKey, Vec<age_plugin::identity::Error>>,
        >,
    > {
        let mut file_keys = HashMap::with_capacity(files.len());

        for (file, stanzas) in files.iter().enumerate() {
            for (_stanza_index, stanza) in stanzas.iter().enumerate() {
                if stanza.tag != STANZA_TAG {
                    continue;
                }
                for (_identity_index, identity) in self.identities.iter().enumerate() {
                    let file_key = age::Identity::unwrap_stanza(identity, stanza).unwrap();
                    let r = file_key.map_err(|e| {
                        vec![identity::Error::Identity {
                            index: file,
                            message: format!("{e}"),
                        }]
                    });

                    file_keys.entry(file).or_insert_with(|| r);
                }
            }
        }

        Ok(file_keys)
    }
}

pub struct RecipientPlugin {
    identities: Vec<Identity>,
    recipients: Vec<Recipient>,
}

impl RecipientPlugin {
    pub fn new() -> Self {
        Self {
            identities: vec![],
            recipients: vec![],
        }
    }
}

impl age_plugin::recipient::RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), age_plugin::recipient::Error> {
        if plugin_name == PLUGIN_NAME {
            self.recipients.push(Recipient::from_bytes(bytes));
            Ok(())
        } else {
            Err(recipient::Error::Recipient {
                index,
                message: "Invalid plugin name".to_owned(),
            })
        }
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), age_plugin::recipient::Error> {
        if plugin_name == PLUGIN_NAME {
            self.identities.push(Identity::from_bytes(bytes));
            Ok(())
        } else {
            Err(recipient::Error::Recipient {
                index,
                message: "Invalid plugin name".to_owned(),
            })
        }
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<age_core::format::FileKey>,
        _callbacks: impl age_plugin::Callbacks<age_plugin::recipient::Error>,
    ) -> std::io::Result<
        Result<Vec<Vec<age_core::format::Stanza>>, Vec<age_plugin::recipient::Error>>,
    > {
        Ok(Ok(file_keys
            .into_iter()
            .map(|file_key| {
                self.recipients
                    .iter()
                    .flat_map(|recipient| {
                        age::Recipient::wrap_file_key(recipient, &file_key).unwrap()
                    })
                    .collect()
            })
            .collect()))
    }
}
