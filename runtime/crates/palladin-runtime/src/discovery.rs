use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use palladin_api::{AgentVisibleField, EntrySearchItem, EntrySearchResult};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::RuntimeError;

const MAX_INDEX_ENTRIES: usize = 10_000;
const MAX_PAGE_SIZE: usize = 200;
const DEFAULT_PAGE_SIZE: usize = 50;
const CURSOR_BYTES: usize = 49;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiscoveryPlaintext {
    pub agent_label: String,
    pub capabilities: u16,
    pub discovery_fields: BTreeMap<String, String>,
    pub entry_type: u16,
}

impl Drop for DiscoveryPlaintext {
    fn drop(&mut self) {
        self.agent_label.zeroize();
        for (mut label, mut value) in std::mem::take(&mut self.discovery_fields) {
            label.zeroize();
            value.zeroize();
        }
    }
}

impl DiscoveryPlaintext {
    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        if self.agent_label.trim().is_empty()
            || self.agent_label.len() > 512
            || self.capabilities == 0
            || self.entry_type == 0
            || self.discovery_fields.len() > 64
            || self.discovery_fields.iter().any(|(label, value)| {
                label.trim().is_empty()
                    || label.len() > 128
                    || value.is_empty()
                    || value.len() > 2_048
            })
        {
            return Err(RuntimeError::InvalidDiscoveryPayload);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct IndexedEntry {
    vault_id: String,
    entry_id: String,
    label: String,
    url_domain: Option<String>,
    approved_fields: Vec<AgentVisibleField>,
    searchable: String,
}

impl Drop for IndexedEntry {
    fn drop(&mut self) {
        self.vault_id.zeroize();
        self.entry_id.zeroize();
        self.label.zeroize();
        self.url_domain.zeroize();
        for field in &mut self.approved_fields {
            field.label.zeroize();
            field.value.zeroize();
        }
        self.searchable.zeroize();
    }
}

pub(crate) struct LocalDiscoveryIndex {
    entries: BTreeMap<(String, String), IndexedEntry>,
    vault_versions: BTreeMap<String, u32>,
    applied_sequences: BTreeMap<String, String>,
}

impl LocalDiscoveryIndex {
    pub(crate) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            vault_versions: BTreeMap::new(),
            applied_sequences: BTreeMap::new(),
        }
    }

    pub(crate) fn prepare_vault(&mut self, vault_id: &str, vdk_version: u32) -> bool {
        if self.vault_versions.get(vault_id) == Some(&vdk_version) {
            return self.applied_sequences.contains_key(vault_id);
        }
        self.remove_vault(vault_id);
        self.vault_versions.insert(vault_id.to_owned(), vdk_version);
        false
    }

    pub(crate) fn applied_sequence(&self, vault_id: &str) -> Option<&str> {
        self.applied_sequences.get(vault_id).map(String::as_str)
    }

    pub(crate) fn mark_applied(&mut self, vault_id: &str, sequence: String) {
        self.applied_sequences.insert(vault_id.to_owned(), sequence);
    }

    pub(crate) fn retain_vaults(&mut self, authorized: &std::collections::BTreeSet<String>) {
        self.entries
            .retain(|(vault, _), _| authorized.contains(vault));
        self.vault_versions
            .retain(|vault, _| authorized.contains(vault));
        self.applied_sequences
            .retain(|vault, _| authorized.contains(vault));
    }

    pub(crate) fn purge(&mut self) {
        self.entries.clear();
        self.vault_versions.clear();
        self.applied_sequences.clear();
    }

    pub(crate) fn remove_vault(&mut self, vault_id: &str) {
        self.entries.retain(|(vault, _), _| vault != vault_id);
        self.vault_versions.remove(vault_id);
        self.applied_sequences.remove(vault_id);
    }

    pub(crate) fn replace_vault(
        &mut self,
        vault_id: &str,
        heads: Vec<(String, DiscoveryPlaintext)>,
    ) -> Result<(), RuntimeError> {
        self.entries.retain(|(vault, _), _| vault != vault_id);
        self.applied_sequences.remove(vault_id);
        for (entry_id, plaintext) in heads {
            self.upsert(vault_id, &entry_id, plaintext)?;
        }
        Ok(())
    }

    pub(crate) fn upsert(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        mut plaintext: DiscoveryPlaintext,
    ) -> Result<(), RuntimeError> {
        plaintext.validate()?;
        let url_domain = plaintext.discovery_fields.get("urlDomain").cloned();
        let approved_fields = std::mem::take(&mut plaintext.discovery_fields)
            .into_iter()
            .map(|(label, value)| AgentVisibleField { label, value })
            .collect::<Vec<_>>();
        let mut searchable = plaintext.agent_label.to_lowercase();
        for field in &approved_fields {
            searchable.push('\u{0}');
            searchable.push_str(&field.label.to_lowercase());
            searchable.push('\u{0}');
            searchable.push_str(&field.value.to_lowercase());
        }
        self.entries.insert(
            (vault_id.to_owned(), entry_id.to_owned()),
            IndexedEntry {
                vault_id: vault_id.to_owned(),
                entry_id: entry_id.to_owned(),
                label: std::mem::take(&mut plaintext.agent_label),
                url_domain,
                approved_fields,
                searchable,
            },
        );
        if self.entries.len() > MAX_INDEX_ENTRIES {
            return Err(RuntimeError::DiscoveryIndexLimitExceeded);
        }
        Ok(())
    }

    pub(crate) fn remove(&mut self, vault_id: &str, entry_id: &str) {
        self.entries
            .remove(&(vault_id.to_owned(), entry_id.to_owned()));
    }

    pub(crate) fn search(
        &self,
        query: &str,
        cursor: Option<&str>,
        page_size: Option<u32>,
    ) -> Result<EntrySearchResult, RuntimeError> {
        let query = query.trim().to_lowercase();
        if query.is_empty() || query.len() > 512 {
            return Err(RuntimeError::InvalidDiscoveryQuery);
        }
        let page_size = usize::try_from(page_size.unwrap_or(DEFAULT_PAGE_SIZE as u32))
            .map_err(|_| RuntimeError::InvalidDiscoveryQuery)?;
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(RuntimeError::InvalidDiscoveryQuery);
        }
        let query_digest: [u8; 16] = Sha256::digest(query.as_bytes())[..16]
            .try_into()
            .map_err(|_| RuntimeError::InvalidDiscoveryCursor)?;
        let after = cursor
            .map(|cursor| self.decode_cursor(cursor, query_digest))
            .transpose()?;
        let matches = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.searchable.contains(&query))
            .collect::<Vec<_>>();
        let offset = after.map_or(Ok(0), |after| {
            matches
                .iter()
                .position(|(key, _)| **key == after)
                .map(|position| position + 1)
                .ok_or(RuntimeError::InvalidDiscoveryCursor)
        })?;
        let items = matches
            .iter()
            .skip(offset)
            .take(page_size)
            .map(|(_, entry)| EntrySearchItem {
                entry_id: entry.entry_id.clone(),
                vault_id: entry.vault_id.clone(),
                label: entry.label.clone(),
                url_domain: entry.url_domain.clone(),
                description: None,
                agent_fields: entry.approved_fields.clone(),
            })
            .collect::<Vec<_>>();
        let next_offset = offset.saturating_add(items.len());
        let next_cursor = (next_offset < matches.len())
            .then(|| {
                let (key, _) = matches
                    .get(next_offset - 1)
                    .ok_or(RuntimeError::InvalidDiscoveryCursor)?;
                self.encode_cursor(key, query_digest)
            })
            .transpose()?;
        Ok(EntrySearchResult { items, next_cursor })
    }

    fn encode_cursor(
        &self,
        key: &(String, String),
        query_digest: [u8; 16],
    ) -> Result<String, RuntimeError> {
        let mut bytes = Vec::with_capacity(CURSOR_BYTES);
        bytes.push(1);
        bytes.extend_from_slice(
            Uuid::parse_str(&key.0)
                .map_err(|_| RuntimeError::InvalidDiscoveryCursor)?
                .as_bytes(),
        );
        bytes.extend_from_slice(
            Uuid::parse_str(&key.1)
                .map_err(|_| RuntimeError::InvalidDiscoveryCursor)?
                .as_bytes(),
        );
        bytes.extend_from_slice(&query_digest);
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn decode_cursor(
        &self,
        cursor: &str,
        query_digest: [u8; 16],
    ) -> Result<(String, String), RuntimeError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(cursor)
            .map_err(|_| RuntimeError::InvalidDiscoveryCursor)?;
        if bytes.len() != CURSOR_BYTES
            || bytes[0] != 1
            || bytes[33..] != query_digest
            || URL_SAFE_NO_PAD.encode(&bytes) != cursor
        {
            return Err(RuntimeError::InvalidDiscoveryCursor);
        }
        let vault_id = Uuid::from_bytes(
            bytes[1..17]
                .try_into()
                .map_err(|_| RuntimeError::InvalidDiscoveryCursor)?,
        );
        let entry_id = Uuid::from_bytes(
            bytes[17..33]
                .try_into()
                .map_err(|_| RuntimeError::InvalidDiscoveryCursor)?,
        );
        Ok((vault_id.to_string(), entry_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{DiscoveryPlaintext, LocalDiscoveryIndex};

    fn account(label: &str, username: &str) -> DiscoveryPlaintext {
        DiscoveryPlaintext {
            agent_label: label.to_owned(),
            capabilities: 1,
            discovery_fields: BTreeMap::from([
                ("urlDomain".to_owned(), "example.com".to_owned()),
                ("username".to_owned(), username.to_owned()),
            ]),
            entry_type: 1,
        }
    }

    #[test]
    fn local_search_distinguishes_accounts_using_only_approved_fields() {
        let mut index = LocalDiscoveryIndex::new();
        index
            .upsert(
                "11111111-1111-4111-8111-111111111111",
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                account("Production", "alice"),
            )
            .unwrap();
        index
            .upsert(
                "11111111-1111-4111-8111-111111111111",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                account("Production", "bob"),
            )
            .unwrap();
        let alice = index.search("alice", None, None).unwrap();
        assert_eq!(alice.items.len(), 1);
        assert_eq!(
            alice.items[0].entry_id,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert_eq!(alice.items[0].agent_fields[1].value, "alice");
    }

    #[test]
    fn tombstones_and_query_bound_cursors_fail_closed() {
        let mut index = LocalDiscoveryIndex::new();
        for (suffix, entry_id) in [
            ("alice", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            ("bob", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            ("carol", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
        ] {
            index
                .upsert(
                    "11111111-1111-4111-8111-111111111111",
                    entry_id,
                    account("Example", suffix),
                )
                .unwrap();
        }
        let first = index.search("example", None, Some(1)).unwrap();
        let cursor = first.next_cursor.unwrap();
        assert!(index.search("different", Some(&cursor), Some(1)).is_err());
        let mut reconstructed = LocalDiscoveryIndex::new();
        for (suffix, entry_id) in [
            ("alice", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            ("bob", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            ("carol", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
        ] {
            reconstructed
                .upsert(
                    "11111111-1111-4111-8111-111111111111",
                    entry_id,
                    account("Example", suffix),
                )
                .unwrap();
        }
        assert_eq!(
            reconstructed
                .search("example", Some(&cursor), Some(1))
                .unwrap()
                .items[0]
                .entry_id,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        );
        index.remove(
            "11111111-1111-4111-8111-111111111111",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        );
        assert!(index.search("alice", None, None).unwrap().items.is_empty());
    }

    #[test]
    fn deactivation_purge_removes_all_discovery_heads_and_sync_state() {
        let mut index = LocalDiscoveryIndex::new();
        let vault_id = "11111111-1111-4111-8111-111111111111";
        index.prepare_vault(vault_id, 7);
        index
            .upsert(
                vault_id,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                account("Private account", "sentinel-user"),
            )
            .unwrap();
        index.mark_applied(vault_id, "42".into());

        index.purge();

        assert!(index.entries.is_empty());
        assert!(index.vault_versions.is_empty());
        assert!(index.applied_sequences.is_empty());
        assert!(
            index
                .search("sentinel", None, None)
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[test]
    fn vdk_version_loss_purges_cached_plaintext_and_sync_cursor() {
        let mut index = LocalDiscoveryIndex::new();
        assert!(!index.prepare_vault("vault-a", 6));
        index
            .upsert("vault-a", "entry-a", account("Production", "alice"))
            .unwrap();
        index.mark_applied("vault-a", "12".to_owned());
        assert!(index.prepare_vault("vault-a", 6));
        assert!(!index.prepare_vault("vault-a", 7));
        assert!(index.applied_sequence("vault-a").is_none());
        assert!(index.search("alice", None, None).unwrap().items.is_empty());
    }
}
