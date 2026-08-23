use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use palladin_api::{AgentVisibleField, EntrySearchItem, EntrySearchResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::RuntimeError;

const MAX_INDEX_ENTRIES: usize = 10_000;
const MAX_LOGICAL_INDEX_BYTES: usize = 64 * 1024 * 1024;
const MAX_PAGE_SIZE: usize = 200;
const DEFAULT_PAGE_SIZE: usize = 50;
const CURSOR_BYTES: usize = 49;
const DURABLE_CACHE_SCHEMA_VERSION: u32 = 1;
const MAX_DURABLE_CACHE_BYTES: usize = MAX_LOGICAL_INDEX_BYTES + 4 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableDiscoveryCache {
    schema_version: u32,
    profile_identity_id: String,
    agent_id: String,
    entries: Vec<DurableIndexedEntry>,
    checkpoints: Vec<DurableEntryCheckpoint>,
    vaults: Vec<DurableVaultState>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableIndexedEntry {
    vault_id: String,
    entry_id: String,
    label: String,
    approved_fields: Vec<AgentVisibleField>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableEntryCheckpoint {
    vault_id: String,
    entry_id: String,
    revision: u64,
    envelope_digest: [u8; 32],
    live: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableVaultState {
    vault_id: String,
    vdk_version: u32,
    applied_sequence: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiscoveryPlaintext {
    pub schema: String,
    pub agent_label: String,
    pub capabilities: Vec<String>,
    pub fields: Vec<DiscoveryField>,
    pub entry_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiscoveryField {
    pub id: String,
    pub value: String,
}

impl Drop for DiscoveryPlaintext {
    fn drop(&mut self) {
        self.schema.zeroize();
        self.agent_label.zeroize();
        self.entry_type.zeroize();
        for capability in &mut self.capabilities {
            capability.zeroize();
        }
        for field in &mut self.fields {
            field.id.zeroize();
            field.value.zeroize();
        }
    }
}

impl DiscoveryPlaintext {
    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        let mut field_ids = BTreeSet::new();
        let mut capabilities = BTreeSet::new();
        if self.schema != "palladin.agent-discovery.v1"
            || self.agent_label.trim().is_empty()
            || self.agent_label.len() > 512
            || !matches!(self.entry_type.as_str(), "key" | "credential" | "script")
            || self.capabilities.is_empty()
            || self.capabilities.len() > 3
            || self.capabilities.iter().any(|capability| {
                !matches!(capability.as_str(), "get" | "exec" | "inject")
                    || !capabilities.insert(capability)
            })
            || self.fields.len() > 64
            || self.fields.iter().any(|field| {
                field.id.trim().is_empty()
                    || field.id.len() > 128
                    || !field_ids.insert(field.id.as_str())
                    || field.value.len() > 2_048
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

#[derive(Clone, Copy)]
struct EntryRevisionCheckpoint {
    revision: u64,
    envelope_digest: [u8; 32],
    live: bool,
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

impl IndexedEntry {
    fn logical_bytes(&self) -> usize {
        self.vault_id
            .len()
            .saturating_add(self.entry_id.len())
            .saturating_add(self.label.len())
            .saturating_add(self.url_domain.as_ref().map_or(0, String::len))
            .saturating_add(self.searchable.len())
            .saturating_add(
                self.approved_fields
                    .iter()
                    .map(|field| field.label.len().saturating_add(field.value.len()))
                    .sum::<usize>(),
            )
    }
}

#[derive(Clone)]
pub(crate) struct LocalDiscoveryIndex {
    owner: Option<(String, String)>,
    entries: BTreeMap<(String, String), IndexedEntry>,
    entry_checkpoints: BTreeMap<(String, String), EntryRevisionCheckpoint>,
    vault_versions: BTreeMap<String, u32>,
    applied_sequences: BTreeMap<String, String>,
    logical_bytes: usize,
}

impl LocalDiscoveryIndex {
    pub(crate) fn new() -> Self {
        Self {
            owner: None,
            entries: BTreeMap::new(),
            entry_checkpoints: BTreeMap::new(),
            vault_versions: BTreeMap::new(),
            applied_sequences: BTreeMap::new(),
            logical_bytes: 0,
        }
    }

    pub(crate) fn encode_durable_cache(&self) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
        let (profile_identity_id, agent_id) = self
            .owner
            .as_ref()
            .ok_or(RuntimeError::InvalidDiscoveryPayload)?;
        let cache = DurableDiscoveryCache {
            schema_version: DURABLE_CACHE_SCHEMA_VERSION,
            profile_identity_id: profile_identity_id.clone(),
            agent_id: agent_id.clone(),
            entries: self
                .entries
                .values()
                .map(|entry| DurableIndexedEntry {
                    vault_id: entry.vault_id.clone(),
                    entry_id: entry.entry_id.clone(),
                    label: entry.label.clone(),
                    approved_fields: entry.approved_fields.clone(),
                })
                .collect(),
            checkpoints: self
                .entry_checkpoints
                .iter()
                .map(
                    |((vault_id, entry_id), checkpoint)| DurableEntryCheckpoint {
                        vault_id: vault_id.clone(),
                        entry_id: entry_id.clone(),
                        revision: checkpoint.revision,
                        envelope_digest: checkpoint.envelope_digest,
                        live: checkpoint.live,
                    },
                )
                .collect(),
            vaults: self
                .vault_versions
                .iter()
                .map(|(vault_id, vdk_version)| DurableVaultState {
                    vault_id: vault_id.clone(),
                    vdk_version: *vdk_version,
                    applied_sequence: self.applied_sequences.get(vault_id).cloned(),
                })
                .collect(),
        };
        let encoded = Zeroizing::new(
            serde_json::to_vec(&cache).map_err(|_| RuntimeError::InvalidDiscoveryPayload)?,
        );
        if encoded.len() > MAX_DURABLE_CACHE_BYTES {
            return Err(RuntimeError::DiscoveryIndexLimitExceeded);
        }
        Ok(encoded)
    }

    pub(crate) fn decode_durable_cache(
        encoded: &[u8],
        expected_profile_identity_id: &str,
        expected_agent_id: &str,
    ) -> Result<Self, RuntimeError> {
        if encoded.is_empty() || encoded.len() > MAX_DURABLE_CACHE_BYTES {
            return Err(RuntimeError::InvalidDiscoveryPayload);
        }
        let cache: DurableDiscoveryCache =
            serde_json::from_slice(encoded).map_err(|_| RuntimeError::InvalidDiscoveryPayload)?;
        if cache.schema_version != DURABLE_CACHE_SCHEMA_VERSION
            || cache.profile_identity_id != expected_profile_identity_id
            || cache.agent_id != expected_agent_id
            || !valid_cache_text(&cache.profile_identity_id, 256)
            || !valid_cache_text(&cache.agent_id, 256)
            || cache.entries.len() > MAX_INDEX_ENTRIES
            || cache.checkpoints.len() > MAX_INDEX_ENTRIES
            || cache.vaults.len() > MAX_INDEX_ENTRIES
        {
            return Err(RuntimeError::InvalidDiscoveryPayload);
        }

        let mut index = Self::new();
        index.owner = Some((cache.profile_identity_id, cache.agent_id));
        for vault in cache.vaults {
            if !valid_cache_text(&vault.vault_id, 256)
                || vault.vdk_version == 0
                || vault
                    .applied_sequence
                    .as_deref()
                    .is_some_and(|sequence| !is_canonical_sequence(sequence))
                || index
                    .vault_versions
                    .insert(vault.vault_id.clone(), vault.vdk_version)
                    .is_some()
            {
                return Err(RuntimeError::InvalidDiscoveryPayload);
            }
            if let Some(sequence) = vault.applied_sequence {
                index.applied_sequences.insert(vault.vault_id, sequence);
            }
        }
        for checkpoint in cache.checkpoints {
            let key = (checkpoint.vault_id, checkpoint.entry_id);
            if checkpoint.revision == 0
                || !valid_cache_text(&key.0, 256)
                || !valid_cache_text(&key.1, 256)
                || !index.vault_versions.contains_key(&key.0)
                || index
                    .entry_checkpoints
                    .insert(
                        key,
                        EntryRevisionCheckpoint {
                            revision: checkpoint.revision,
                            envelope_digest: checkpoint.envelope_digest,
                            live: checkpoint.live,
                        },
                    )
                    .is_some()
            {
                return Err(RuntimeError::InvalidDiscoveryPayload);
            }
        }
        for entry in cache.entries {
            let key = (entry.vault_id.clone(), entry.entry_id.clone());
            if !valid_cache_entry(&entry)
                || !index
                    .entry_checkpoints
                    .get(&key)
                    .is_some_and(|checkpoint| checkpoint.live)
                || index.entries.contains_key(&key)
            {
                return Err(RuntimeError::InvalidDiscoveryPayload);
            }
            let url_domain = entry
                .approved_fields
                .iter()
                .find(|field| field.label == "credential.urlDomain")
                .map(|field| field.value.clone());
            let searchable = searchable_text(&entry.label, &entry.approved_fields);
            let indexed = IndexedEntry {
                vault_id: entry.vault_id,
                entry_id: entry.entry_id,
                label: entry.label,
                url_domain,
                approved_fields: entry.approved_fields,
                searchable,
            };
            index.logical_bytes = index
                .logical_bytes
                .checked_add(indexed.logical_bytes())
                .ok_or(RuntimeError::DiscoveryIndexLimitExceeded)?;
            if index.logical_bytes > MAX_LOGICAL_INDEX_BYTES {
                return Err(RuntimeError::DiscoveryIndexLimitExceeded);
            }
            index.entries.insert(key, indexed);
        }
        if index
            .entry_checkpoints
            .iter()
            .any(|(key, checkpoint)| checkpoint.live != index.entries.contains_key(key))
        {
            return Err(RuntimeError::InvalidDiscoveryPayload);
        }
        Ok(index)
    }

    pub(crate) fn scope_to_identity(&mut self, profile_identity_id: &str, agent_id: &str) {
        let matches = self
            .owner
            .as_ref()
            .is_some_and(|(profile, agent)| profile == profile_identity_id && agent == agent_id);
        if !matches {
            self.purge();
            self.owner = Some((profile_identity_id.to_owned(), agent_id.to_owned()));
        }
    }

    pub(crate) fn is_scoped_to(&self, profile_identity_id: &str, agent_id: &str) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|(profile, agent)| profile == profile_identity_id && agent == agent_id)
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

    pub(crate) fn require_resnapshot(&mut self, vault_id: &str) {
        self.applied_sequences.remove(vault_id);
    }

    pub(crate) fn retain_vaults(&mut self, authorized: &std::collections::BTreeSet<String>) {
        self.entries
            .retain(|(vault, _), _| authorized.contains(vault));
        self.entry_checkpoints
            .retain(|(vault, _), _| authorized.contains(vault));
        self.vault_versions
            .retain(|vault, _| authorized.contains(vault));
        self.applied_sequences
            .retain(|vault, _| authorized.contains(vault));
        self.recount_logical_bytes();
    }

    pub(crate) fn purge(&mut self) {
        self.owner = None;
        self.entries.clear();
        self.entry_checkpoints.clear();
        self.vault_versions.clear();
        self.applied_sequences.clear();
        self.logical_bytes = 0;
    }

    pub(crate) fn clear_live_heads_and_cursors(&mut self) {
        self.entries.clear();
        self.applied_sequences.clear();
        self.logical_bytes = 0;
    }

    pub(crate) fn remove_vault(&mut self, vault_id: &str) {
        self.entries.retain(|(vault, _), _| vault != vault_id);
        self.entry_checkpoints
            .retain(|(vault, _), _| vault != vault_id);
        self.vault_versions.remove(vault_id);
        self.applied_sequences.remove(vault_id);
        self.recount_logical_bytes();
    }

    pub(crate) fn replace_vault(
        &mut self,
        vault_id: &str,
        heads: Vec<(String, u64, [u8; 32], DiscoveryPlaintext)>,
    ) -> Result<(), RuntimeError> {
        let mut next = self.clone();
        next.entries.retain(|(vault, _), _| vault != vault_id);
        next.applied_sequences.remove(vault_id);
        next.recount_logical_bytes();
        let mut snapshot_heads = BTreeSet::new();
        for (entry_id, revision, envelope_digest, plaintext) in heads {
            next.upsert_snapshot(vault_id, &entry_id, revision, envelope_digest, plaintext)?;
            snapshot_heads.insert((vault_id.to_owned(), entry_id));
        }
        for (key, checkpoint) in &mut next.entry_checkpoints {
            if key.0 == vault_id && !snapshot_heads.contains(key) {
                checkpoint.live = false;
            }
        }
        next.recount_logical_bytes();
        *self = next;
        Ok(())
    }

    pub(crate) fn upsert(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        revision: u64,
        envelope_digest: [u8; 32],
        plaintext: DiscoveryPlaintext,
    ) -> Result<(), RuntimeError> {
        let key = (vault_id.to_owned(), entry_id.to_owned());
        if revision == 0
            || self
                .entry_checkpoints
                .get(&key)
                .is_some_and(|checkpoint| revision <= checkpoint.revision)
        {
            return Err(RuntimeError::InvalidDiscoveryPayload);
        }
        self.store_entry(key, revision, envelope_digest, plaintext)
    }

    fn upsert_snapshot(
        &mut self,
        vault_id: &str,
        entry_id: &str,
        revision: u64,
        envelope_digest: [u8; 32],
        plaintext: DiscoveryPlaintext,
    ) -> Result<(), RuntimeError> {
        let key = (vault_id.to_owned(), entry_id.to_owned());
        if revision == 0 {
            return Err(RuntimeError::InvalidDiscoveryPayload);
        }
        if let Some(checkpoint) = self.entry_checkpoints.get(&key)
            && (revision < checkpoint.revision
                || (revision == checkpoint.revision
                    && (!checkpoint.live || envelope_digest != checkpoint.envelope_digest)))
        {
            return Err(RuntimeError::InvalidDiscoveryPayload);
        }
        self.store_entry(key, revision, envelope_digest, plaintext)
    }

    fn store_entry(
        &mut self,
        key: (String, String),
        revision: u64,
        envelope_digest: [u8; 32],
        mut plaintext: DiscoveryPlaintext,
    ) -> Result<(), RuntimeError> {
        plaintext.validate()?;
        let url_domain = plaintext
            .fields
            .iter()
            .find(|field| field.id == "credential.urlDomain")
            .map(|field| field.value.clone());
        let approved_fields = std::mem::take(&mut plaintext.fields)
            .into_iter()
            .map(|field| AgentVisibleField {
                label: field.id,
                value: field.value,
            })
            .collect::<Vec<_>>();
        let searchable = searchable_text(&plaintext.agent_label, &approved_fields);
        let entry = IndexedEntry {
            vault_id: key.0.clone(),
            entry_id: key.1.clone(),
            label: std::mem::take(&mut plaintext.agent_label),
            url_domain,
            approved_fields,
            searchable,
        };
        let replaced_bytes = self
            .entries
            .get(&key)
            .map_or(0, IndexedEntry::logical_bytes);
        let next_count =
            self.entry_checkpoints.len() + usize::from(!self.entry_checkpoints.contains_key(&key));
        let next_bytes = self
            .logical_bytes
            .saturating_sub(replaced_bytes)
            .saturating_add(entry.logical_bytes());
        if next_count > MAX_INDEX_ENTRIES || next_bytes > MAX_LOGICAL_INDEX_BYTES {
            return Err(RuntimeError::DiscoveryIndexLimitExceeded);
        }
        self.entries.insert(key.clone(), entry);
        self.entry_checkpoints.insert(
            key,
            EntryRevisionCheckpoint {
                revision,
                envelope_digest,
                live: true,
            },
        );
        self.logical_bytes = next_bytes;
        Ok(())
    }

    pub(crate) fn remove(&mut self, vault_id: &str, entry_id: &str) {
        let key = (vault_id.to_owned(), entry_id.to_owned());
        if let Some(entry) = self.entries.remove(&key) {
            self.logical_bytes = self.logical_bytes.saturating_sub(entry.logical_bytes());
        }
        if let Some(checkpoint) = self.entry_checkpoints.get_mut(&key) {
            checkpoint.live = false;
        }
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

    pub(crate) fn field_at_revision(
        &self,
        vault_id: &str,
        entry_id: &str,
        revision: u64,
        field_id: &str,
    ) -> Result<Option<String>, RuntimeError> {
        let key = (vault_id.to_owned(), entry_id.to_owned());
        let Some(checkpoint) = self.entry_checkpoints.get(&key) else {
            return Ok(None);
        };
        if !checkpoint.live {
            return Ok(None);
        }
        if checkpoint.revision != revision {
            return Err(RuntimeError::DiscoveryRevisionMismatch);
        }
        let entry = self
            .entries
            .get(&key)
            .ok_or(RuntimeError::InvalidDiscoveryPayload)?;
        Ok(entry
            .approved_fields
            .iter()
            .find(|field| field.label == field_id)
            .map(|field| field.value.clone()))
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

    fn recount_logical_bytes(&mut self) {
        self.logical_bytes = self.entries.values().map(IndexedEntry::logical_bytes).sum();
    }
}

fn valid_cache_text(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes && !value.contains('\0')
}

fn valid_cache_entry(entry: &DurableIndexedEntry) -> bool {
    valid_cache_text(&entry.vault_id, 256)
        && valid_cache_text(&entry.entry_id, 256)
        && valid_cache_text(&entry.label, 512)
        && entry.approved_fields.len() <= 64
        && entry.approved_fields.iter().all(|field| {
            valid_cache_text(&field.label, 128)
                && field.value.len() <= 2_048
                && !field.value.contains('\0')
        })
        && entry
            .approved_fields
            .iter()
            .map(|field| field.label.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == entry.approved_fields.len()
}

fn searchable_text(label: &str, approved_fields: &[AgentVisibleField]) -> String {
    let mut searchable = label.to_lowercase();
    for field in approved_fields {
        searchable.push('\u{0}');
        searchable.push_str(&field.label.to_lowercase());
        searchable.push('\u{0}');
        searchable.push_str(&field.value.to_lowercase());
    }
    searchable
}

fn is_canonical_sequence(value: &str) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|sequence| sequence.to_string() == value)
}

#[cfg(test)]
mod tests {
    use super::{
        DiscoveryField, DiscoveryPlaintext, LocalDiscoveryIndex, MAX_INDEX_ENTRIES,
        MAX_LOGICAL_INDEX_BYTES, MAX_PAGE_SIZE,
    };

    fn account(label: &str, username: &str) -> DiscoveryPlaintext {
        DiscoveryPlaintext {
            schema: "palladin.agent-discovery.v1".to_owned(),
            agent_label: label.to_owned(),
            capabilities: vec!["get".to_owned(), "exec".to_owned()],
            fields: vec![
                DiscoveryField {
                    id: "credential.urlDomain".to_owned(),
                    value: "example.com".to_owned(),
                },
                DiscoveryField {
                    id: "credential.username".to_owned(),
                    value: username.to_owned(),
                },
            ],
            entry_type: "credential".to_owned(),
        }
    }

    fn envelope_digest(revision: u8) -> [u8; 32] {
        [revision; 32]
    }

    #[test]
    fn local_search_distinguishes_accounts_using_only_approved_fields() {
        let mut index = LocalDiscoveryIndex::new();
        index
            .upsert(
                "11111111-1111-4111-8111-111111111111",
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                1,
                envelope_digest(1),
                account("Production", "alice"),
            )
            .unwrap();
        index
            .upsert(
                "11111111-1111-4111-8111-111111111111",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                1,
                envelope_digest(1),
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
    fn inject_metadata_requires_the_exact_discovery_revision() {
        let mut index = LocalDiscoveryIndex::new();
        let vault_id = "11111111-1111-4111-8111-111111111111";
        let entry_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        index
            .upsert(
                vault_id,
                entry_id,
                7,
                envelope_digest(7),
                account("Production", "alice"),
            )
            .unwrap();

        assert_eq!(
            index
                .field_at_revision(vault_id, entry_id, 7, "credential.username")
                .unwrap()
                .as_deref(),
            Some("alice")
        );
        assert!(matches!(
            index.field_at_revision(vault_id, entry_id, 6, "credential.username"),
            Err(crate::RuntimeError::DiscoveryRevisionMismatch)
        ));
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
                    1,
                    envelope_digest(1),
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
                    1,
                    envelope_digest(1),
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
    fn replayed_discovery_revisions_cannot_replace_or_resurrect_a_head() {
        let mut index = LocalDiscoveryIndex::new();
        let vault_id = "11111111-1111-4111-8111-111111111111";
        let entry_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        index
            .upsert(
                vault_id,
                entry_id,
                2,
                envelope_digest(2),
                account("Current", "alice"),
            )
            .expect("current head");

        assert!(
            index
                .upsert(
                    vault_id,
                    entry_id,
                    1,
                    envelope_digest(1),
                    account("Replayed", "mallory"),
                )
                .is_err()
        );
        assert!(
            index
                .upsert(
                    vault_id,
                    entry_id,
                    2,
                    envelope_digest(2),
                    account("Duplicate", "mallory"),
                )
                .is_err()
        );
        assert_eq!(index.search("alice", None, None).unwrap().items.len(), 1);

        index.remove(vault_id, entry_id);
        assert!(
            index
                .upsert(
                    vault_id,
                    entry_id,
                    2,
                    envelope_digest(2),
                    account("Resurrected", "mallory"),
                )
                .is_err()
        );
        index
            .upsert(
                vault_id,
                entry_id,
                3,
                envelope_digest(3),
                account("Recreated", "alice"),
            )
            .expect("strictly newer head");
    }

    #[test]
    fn same_vdk_resnapshot_preserves_revision_high_water_marks() {
        let mut index = LocalDiscoveryIndex::new();
        let vault_id = "11111111-1111-4111-8111-111111111111";
        let entry_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        index.prepare_vault(vault_id, 7);
        index
            .upsert(
                vault_id,
                entry_id,
                2,
                envelope_digest(2),
                account("Current", "alice"),
            )
            .expect("current head");
        index.mark_applied(vault_id, "12".to_owned());
        index.require_resnapshot(vault_id);

        assert!(
            index
                .replace_vault(
                    vault_id,
                    vec![(
                        entry_id.to_owned(),
                        1,
                        envelope_digest(1),
                        account("Replayed", "mallory"),
                    )],
                )
                .is_err()
        );
        assert_eq!(index.search("alice", None, None).unwrap().items.len(), 1);

        index
            .replace_vault(
                vault_id,
                vec![(
                    entry_id.to_owned(),
                    2,
                    envelope_digest(2),
                    account("Current", "alice"),
                )],
            )
            .expect("the already authenticated current head can rebuild the snapshot");
        assert_eq!(index.search("alice", None, None).unwrap().items.len(), 1);
        assert!(
            index
                .search("mallory", None, None)
                .unwrap()
                .items
                .is_empty()
        );

        index.clear_live_heads_and_cursors();
        assert!(index.search("alice", None, None).unwrap().items.is_empty());
        index
            .replace_vault(
                vault_id,
                vec![(
                    entry_id.to_owned(),
                    2,
                    envelope_digest(2),
                    account("Current", "alice"),
                )],
            )
            .expect("the same authenticated envelope can rebuild a cleared live head");
        index.clear_live_heads_and_cursors();
        assert!(
            index
                .replace_vault(
                    vault_id,
                    vec![(
                        entry_id.to_owned(),
                        2,
                        envelope_digest(9),
                        account("Substituted", "mallory"),
                    )],
                )
                .is_err()
        );

        index.require_resnapshot(vault_id);
        index
            .replace_vault(vault_id, Vec::new())
            .expect("a tombstoned head is omitted from the authoritative snapshot");
        assert!(index.search("alice", None, None).unwrap().items.is_empty());
        assert!(
            index
                .upsert(
                    vault_id,
                    entry_id,
                    2,
                    envelope_digest(2),
                    account("Resurrected", "mallory"),
                )
                .is_err()
        );
        index
            .upsert(
                vault_id,
                entry_id,
                3,
                envelope_digest(3),
                account("Recreated", "alice"),
            )
            .expect("a strictly newer revision may recreate the Entry");
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
                1,
                envelope_digest(1),
                account("Private account", "sentinel-user"),
            )
            .unwrap();
        index.mark_applied(vault_id, "42".into());

        index.purge();

        assert!(index.entries.is_empty());
        assert!(index.entry_checkpoints.is_empty());
        assert!(index.owner.is_none());
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
    fn changing_profile_or_agent_identity_purges_cached_discovery_state() {
        let mut index = LocalDiscoveryIndex::new();
        let vault_id = "11111111-1111-4111-8111-111111111111";
        index.scope_to_identity("profile-a", "agent-a");
        index.prepare_vault(vault_id, 7);
        index
            .upsert(
                vault_id,
                "entry-a",
                1,
                envelope_digest(1),
                account("Private account", "sentinel-user"),
            )
            .unwrap();
        index.mark_applied(vault_id, "42".into());

        index.scope_to_identity("profile-b", "agent-b");

        assert!(index.entries.is_empty());
        assert!(index.entry_checkpoints.is_empty());
        assert!(index.vault_versions.is_empty());
        assert!(index.applied_sequences.is_empty());
        assert_eq!(
            index.owner,
            Some(("profile-b".to_owned(), "agent-b".to_owned()))
        );
    }

    #[test]
    fn durable_cache_round_trip_preserves_heads_tombstones_and_delta_cursor() {
        let mut index = LocalDiscoveryIndex::new();
        let vault_id = "11111111-1111-4111-8111-111111111111";
        let live_entry = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let deleted_entry = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        index.scope_to_identity("profile-a", "agent-a");
        index.prepare_vault(vault_id, 7);
        index
            .upsert(
                vault_id,
                live_entry,
                4,
                envelope_digest(4),
                account("Private account", "sentinel-user"),
            )
            .expect("live head");
        index
            .upsert(
                vault_id,
                deleted_entry,
                8,
                envelope_digest(8),
                account("Deleted account", "deleted-user"),
            )
            .expect("head before tombstone");
        index.remove(vault_id, deleted_entry);
        index.mark_applied(vault_id, "42".to_owned());

        let encoded = index.encode_durable_cache().expect("encode cache");
        let restored = LocalDiscoveryIndex::decode_durable_cache(&encoded, "profile-a", "agent-a")
            .expect("decode cache");

        assert_eq!(restored.applied_sequence(vault_id), Some("42"));
        assert_eq!(
            restored.search("sentinel", None, None).unwrap().items.len(),
            1
        );
        assert!(
            restored
                .search("deleted", None, None)
                .unwrap()
                .items
                .is_empty()
        );
        assert!(
            restored
                .entry_checkpoints
                .get(&(vault_id.to_owned(), deleted_entry.to_owned()))
                .is_some_and(|checkpoint| checkpoint.revision == 8 && !checkpoint.live)
        );
    }

    #[test]
    fn durable_cache_rejects_a_different_profile_or_agent_identity() {
        let mut index = LocalDiscoveryIndex::new();
        index.scope_to_identity("profile-a", "agent-a");
        let encoded = index.encode_durable_cache().expect("encode cache");

        assert!(
            LocalDiscoveryIndex::decode_durable_cache(&encoded, "profile-b", "agent-a").is_err()
        );
        assert!(
            LocalDiscoveryIndex::decode_durable_cache(&encoded, "profile-a", "agent-b").is_err()
        );
    }

    #[test]
    fn ten_thousand_head_snapshot_and_one_percent_delta_stay_bounded() {
        let mut index = LocalDiscoveryIndex::new();
        let vault_id = "11111111-1111-4111-8111-111111111111";
        for position in 1..=MAX_INDEX_ENTRIES {
            let entry_id = uuid::Uuid::from_u128(position as u128).to_string();
            index
                .upsert(
                    vault_id,
                    &entry_id,
                    1,
                    envelope_digest(1),
                    account("entry", &format!("account-{position}")),
                )
                .unwrap();
        }
        for position in 1..=(MAX_INDEX_ENTRIES / 100) {
            let entry_id = uuid::Uuid::from_u128(position as u128).to_string();
            index
                .upsert(
                    vault_id,
                    &entry_id,
                    2,
                    envelope_digest(2),
                    account("entry", &format!("updated-{position}")),
                )
                .unwrap();
        }

        let mut cursor = None;
        let mut pages = 0;
        let mut items = 0;
        loop {
            let page = index
                .search("entry", cursor.as_deref(), Some(MAX_PAGE_SIZE as u32))
                .unwrap();
            pages += 1;
            items += page.items.len();
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        let report = format!(
            "discovery-budget heads={MAX_INDEX_ENTRIES} delta={} pages={pages} logical-bytes={}",
            MAX_INDEX_ENTRIES / 100,
            index.logical_bytes
        );
        assert_eq!(items, MAX_INDEX_ENTRIES, "{report}");
        assert_eq!(pages, MAX_INDEX_ENTRIES / MAX_PAGE_SIZE, "{report}");
        assert!(index.logical_bytes <= MAX_LOGICAL_INDEX_BYTES, "{report}");
    }

    #[test]
    fn index_budget_rejection_is_atomic() {
        let mut index = LocalDiscoveryIndex::new();
        let vault_id = "11111111-1111-4111-8111-111111111111";
        for position in 1..=MAX_INDEX_ENTRIES {
            index
                .upsert(
                    vault_id,
                    &uuid::Uuid::from_u128(position as u128).to_string(),
                    1,
                    envelope_digest(1),
                    account("entry", "bounded"),
                )
                .unwrap();
        }
        let bytes = index.logical_bytes;

        assert!(
            index
                .upsert(
                    vault_id,
                    &uuid::Uuid::from_u128((MAX_INDEX_ENTRIES + 1) as u128).to_string(),
                    1,
                    envelope_digest(1),
                    account("entry", "overflow"),
                )
                .is_err()
        );
        assert_eq!(index.entries.len(), MAX_INDEX_ENTRIES);
        assert_eq!(index.logical_bytes, bytes);
    }

    #[test]
    fn vdk_version_loss_purges_cached_plaintext_and_sync_cursor() {
        let mut index = LocalDiscoveryIndex::new();
        assert!(!index.prepare_vault("vault-a", 6));
        index
            .upsert(
                "vault-a",
                "entry-a",
                1,
                envelope_digest(1),
                account("Production", "alice"),
            )
            .unwrap();
        index.mark_applied("vault-a", "12".to_owned());
        assert!(index.prepare_vault("vault-a", 6));
        assert!(!index.prepare_vault("vault-a", 7));
        assert!(index.applied_sequence("vault-a").is_none());
        assert!(index.entry_checkpoints.is_empty());
        assert!(index.search("alice", None, None).unwrap().items.is_empty());
    }
}
