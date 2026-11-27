use crate::decoder::Decoder;
use crate::encoder::{
    count_delta_chunks_with_hash, encode_insert_instruction, get_parent_data, Encoder,
};
use crate::sbc_scrubber::ClusterPoint;
use crate::{ChunkType, SBCHash, SBCKey, SBCMap};
use chunkfs::Data;
use chunkfs::Database;
use marline_sketcher::speedsketch::{self, SpeedSketchConfig};
use marline_sketcher::SpeedSketchHash;
use std::cmp::min;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use zstd::stream;

/// Gdelta encoder that uses SpeedSketch to filter fingerprint table lookups.
#[derive(Debug)]
pub struct GdeltaEncoder {
    zstd_flag: bool,
    sketch_config: SpeedSketchConfig,
}

/// The bytes, fingerprint table and sketch of a base chunk.
struct BaseChunk<'a> {
    data: &'a [u8],
    word_hash_offsets: HashMap<u64, usize>,
    sketch: u64,
}

impl<'a> BaseChunk<'a> {
    fn new(data: &'a [u8], sketch: Option<u64>, config: &SpeedSketchConfig) -> Self {
        let word_size = speedsketch::WORD_SIZE;
        let mask_bts = ((data.len() as f64).log2() as usize).max(1);
        let mut word_hash_offsets = HashMap::new();
        let mut base_sketch = sketch.unwrap_or(0);
        let mut fp = 0;

        if data.len() >= word_size {
            for &byte in &data[..word_size - 1] {
                fp = speedsketch::fp_step(fp, byte);
            }

            for (offset, &byte) in data[word_size - 1..].iter().enumerate() {
                fp = speedsketch::fp_step(fp, byte);
                word_hash_offsets.insert(fp >> (64 - mask_bts), offset);
                if sketch.is_none() && speedsketch::is_proxy_with(fp, config.masks()) {
                    base_sketch |= 1u64 << speedsketch::class_of(fp);
                }
            }
        }

        Self { data, word_hash_offsets, sketch: base_sketch }
    }
}

impl Default for GdeltaEncoder {
    fn default() -> Self {
        Self::new(false)
    }
}

impl GdeltaEncoder {
    pub fn new(zstd_flag: bool) -> Self {
        Self::with_sketch_config(zstd_flag, SpeedSketchConfig::default())
    }

    /// Creates an encoder that uses the same sketch masks as the hasher that produced the
    /// chunk hashes.
    pub fn with_sketch_config(zstd_flag: bool, sketch_config: SpeedSketchConfig) -> Self {
        GdeltaEncoder { zstd_flag, sketch_config }
    }

    pub fn sketch_config(&self) -> &SpeedSketchConfig {
        &self.sketch_config
    }

    /// Encodes a single chunk against an existing base using their precomputed SpeedSketch hashes.
    /// The hashes must have been calculated from the supplied bytes with this encoder's masks.
    /// The result uses the format expected by `GdeltaDecoder` with the same zstd setting.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched mask configuration, for input lengths that exceed the
    /// delta format's length or offset limits, or when zstd compression fails.
    pub fn encode_chunk_against(
        &self,
        chunk_data: &[u8],
        chunk_hash: &SpeedSketchHash,
        base_data: &[u8],
        base_hash: &SpeedSketchHash,
    ) -> io::Result<Vec<u8>> {
        if chunk_data.len() >= 1 << 23 || base_data.len() > 1 << 24 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "chunk exceeds Gdelta limits"));
        }

        let config_id = Some(self.sketch_config.id());
        if chunk_hash.sketch_config_id() != config_id || base_hash.sketch_config_id() != config_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hashes must use the Gdelta encoder's SpeedSketch configuration",
            ));
        }

        let base = BaseChunk::new(base_data, base_hash.sketch(), &self.sketch_config);
        let delta = Self::delta_code(chunk_data, &base, chunk_hash.sketch().unwrap_or_default());
        if self.zstd_flag {
            stream::encode_all(delta.as_slice(), 0)
        } else {
            Ok(delta)
        }
    }

    /// Encodes `chunk_data` against `base` as a list of INSERT and COPY instructions.
    ///
    /// Uses `sketch_input` and `base.sketch` to filter fingerprint-table lookups. A differing
    /// class bit skips the lookup for that word. Unmatched bytes are encoded as INSERTs.
    fn delta_code(chunk_data: &[u8], base: &BaseChunk<'_>, sketch_input: u64) -> Vec<u8> {
        let parent_data = base.data;
        let word_size: usize = speedsketch::WORD_SIZE;
        let move_bts: usize = 64 / word_size;
        let mut delta_code = Vec::with_capacity(chunk_data.len());

        // A chunk shorter than a word has no fingerprint, nothing can be copied from it.
        if chunk_data.len() < word_size {
            encode_insert_instruction(chunk_data, &mut delta_code);
            return delta_code;
        }

        let mask_bts: usize = ((parent_data.len() as f64).log2() as usize).max(1);
        let mut anchor: usize = 0;
        let mut fp = 0u64;

        for &byte in &chunk_data[..word_size - 1] {
            fp = (fp << move_bts).wrapping_add(gear(byte));
        }
        let mut j = 0;
        while j < (chunk_data.len() - word_size + 1) {
            fp = (fp << move_bts).wrapping_add(gear(chunk_data[j + word_size - 1]));
            let word_hash: u64 = fp >> (64 - mask_bts);

            if speedsketch::class_bit_matches(fp, sketch_input, base.sketch) {
                if let Some(&offset) = base.word_hash_offsets.get(&word_hash) {
                    let mut equal_part_len: usize = 0;
                    for k in 0..min(parent_data.len() - offset, chunk_data.len() - j) {
                        if parent_data[offset + k] != chunk_data[j + k] {
                            break;
                        }
                        equal_part_len += 1;
                    }

                    if equal_part_len >= word_size {
                        //Insert instruction
                        let insert_data_len: usize = j - anchor;
                        if insert_data_len > 0 {
                            let insert_data = &chunk_data[anchor..(anchor + insert_data_len)];
                            let insert_instruction = &mut insert_data_len.to_ne_bytes()[..3];
                            insert_instruction[2] += 1 << 7;
                            delta_code.extend_from_slice(insert_instruction);
                            delta_code.extend_from_slice(insert_data);
                        }

                        // Copy instruction
                        let copy_instruction_len = &equal_part_len.to_ne_bytes()[..3];
                        let copy_instruction_offset = &offset.to_ne_bytes()[..3];
                        delta_code.extend_from_slice(copy_instruction_len);
                        delta_code.extend_from_slice(copy_instruction_offset);

                        anchor = j + equal_part_len;
                        j = anchor - 1; // Update j to skip the matched part
                        if j < chunk_data.len() - word_size {
                            for &byte in &chunk_data[anchor..anchor + word_size - 1] {
                                fp = (fp << move_bts).wrapping_add(gear(byte));
                            }
                        }
                    }
                }
            }

            if j >= chunk_data.len() - word_size {
                let insert_data_len: usize = chunk_data.len() - anchor;
                let insert_data = &chunk_data[anchor..(anchor + insert_data_len)];
                let insert_instruction = &mut insert_data_len.to_ne_bytes()[..3];
                insert_instruction[2] += 1 << 7;
                delta_code.extend_from_slice(insert_instruction);
                delta_code.extend_from_slice(insert_data);
            }
            j += 1
        }

        delta_code
    }

    fn encode_delta_chunk<D: Decoder, Hash: SBCHash>(
        &self,
        target_map: Arc<Mutex<&mut SBCMap<D, Hash>>>,
        chunk_data: &[u8],
        hash: Hash,
        base: &BaseChunk<'_>,
        base_hash: &Hash,
    ) -> (usize, usize, SBCKey<Hash>) {
        if let Some(id) = hash.sketch_config_id() {
            assert_eq!(
                id,
                self.sketch_config.id(),
                "chunk hash was produced with a different SpeedSketch configuration"
            );
        }
        if let Some(id) = base_hash.sketch_config_id() {
            assert_eq!(
                id,
                self.sketch_config.id(),
                "base chunk hash was produced with a different SpeedSketch configuration"
            );
        }

        // Sketch of the input chunk. Reused from the hashing stage when the hasher already
        // produced one, computed here otherwise.
        let sketch_input = hash
            .sketch()
            .unwrap_or_else(|| speedsketch::sketch_with(chunk_data, self.sketch_config.masks()));
        let mut delta_code = GdeltaEncoder::delta_code(chunk_data, base, sketch_input);

        let mut target_map_lock = target_map.lock().unwrap();
        let number_delta_chunk = count_delta_chunks_with_hash(&target_map_lock, &hash);
        let sbc_hash = SBCKey {
            hash,
            chunk_type: ChunkType::Delta {
                parent_hash: base_hash.clone(),
                number: number_delta_chunk,
            },
        };
        if self.zstd_flag {
            delta_code = stream::encode_all(delta_code.as_slice(), 0).unwrap();
        }
        let processed_data = delta_code.len();
        let _ = target_map_lock.insert(sbc_hash.clone(), delta_code);
        (0, processed_data, sbc_hash)
    }
}

impl Encoder for GdeltaEncoder {
    fn encode_cluster<D: Decoder, Hash: SBCHash>(
        &self,
        target_map: Arc<Mutex<&mut SBCMap<D, Hash>>>,
        cluster: &mut [ClusterPoint<Hash>],
        parent_hash: Hash,
    ) -> (usize, usize) {
        let mut processed_data = 0;
        let parent_chunk = get_parent_data(target_map.clone(), parent_hash.clone(), cluster);
        let mut data_left = parent_chunk.data_left;
        let parent_data = parent_chunk.parent_data;
        let parent_sbc_hash = parent_chunk.parent_hash;
        if let Some(id) = parent_sbc_hash.sketch_config_id() {
            assert_eq!(
                id,
                self.sketch_config.id(),
                "parent chunk hash was produced with a different SpeedSketch configuration"
            );
        }
        // Build the base sketch and fingerprint table in the same pass.
        let base = BaseChunk::new(&parent_data, None, &self.sketch_config);

        for (chunk_id, (hash, data_container)) in cluster.iter_mut().enumerate() {
            if parent_chunk.index > -1 && chunk_id == parent_chunk.index as usize {
                continue;
            }
            match data_container.extract() {
                Data::Chunk(data) => {
                    let (left, processed, sbc_hash) = self.encode_delta_chunk(
                        target_map.clone(),
                        data,
                        hash.clone(),
                        &base,
                        &parent_sbc_hash,
                    );
                    data_left += left;
                    processed_data += processed;
                    data_container.make_target(vec![sbc_hash]);
                }
                Data::TargetChunk(_) => {}
            }
        }
        (data_left, processed_data)
    }
}

/// Compute delta between `new_chunk` and `base_chunk` using gdelta algorithm.
/// Returns delta as byte vector (INSERT/COPY instructions).
pub fn gdelta_diff(new_chunk: &[u8], base_chunk: &[u8]) -> Vec<u8> {
    let word_size: usize = 16;
    if new_chunk.len() < word_size || base_chunk.len() < word_size {
        return new_chunk.to_vec();
    }
    let move_bts: usize = 64 / word_size;
    let mask_bts: usize = (base_chunk.len() as f64).log2() as usize;
    let mut word_hash_offsets: HashMap<u64, usize> = HashMap::with_capacity(base_chunk.len());
    let mut fp: u64 = 0;

    for &byte in &base_chunk[..word_size - 1] {
        fp = (fp << move_bts).wrapping_add(gear(byte));
    }

    for i in word_size..(base_chunk.len() - word_size + 1) {
        fp = (fp << move_bts).wrapping_add(gear(base_chunk[i + word_size - 1]));
        let word_hash: u64 = fp >> (64 - mask_bts);
        word_hash_offsets.insert(word_hash, i);
    }

    let mut delta_code = Vec::new();
    let mut anchor: usize = 0;
    let mut fp = 0u64;

    for &byte in &new_chunk[..word_size - 1] {
        fp = (fp << move_bts).wrapping_add(gear(byte));
    }

    let mut j = 0;
    while j + word_size <= new_chunk.len() {
        fp = (fp << move_bts).wrapping_add(gear(new_chunk[j + word_size - 1]));
        let word_hash: u64 = fp >> (64 - mask_bts);

        if let Some(&offset) = word_hash_offsets.get(&word_hash) {
            let mut equal_part_len: usize = 0;
            for k in 0..min(base_chunk.len() - offset, new_chunk.len() - j) {
                if base_chunk[offset + k] != new_chunk[j + k] {
                    break;
                }
                equal_part_len += 1;
            }

            if equal_part_len >= word_size {
                let insert_data_len = j - anchor;
                if insert_data_len > 0 {
                    let insert_data = &new_chunk[anchor..(anchor + insert_data_len)];
                    let mut insert_instruction = insert_data_len.to_ne_bytes();
                    insert_instruction[2] |= 1 << 7;
                    delta_code.extend_from_slice(&insert_instruction[..3]);
                    delta_code.extend_from_slice(insert_data);
                }

                let copy_instruction_len = &equal_part_len.to_ne_bytes()[..3];
                let copy_instruction_offset = &offset.to_ne_bytes()[..3];
                delta_code.extend_from_slice(copy_instruction_len);
                delta_code.extend_from_slice(copy_instruction_offset);

                anchor = j + equal_part_len;
                j = anchor - 1;
                if j < new_chunk.len() - word_size {
                    for &byte in &new_chunk[anchor..anchor + word_size - 1] {
                        fp = (fp << move_bts).wrapping_add(gear(byte));
                    }
                }
            }
        }

        if j >= new_chunk.len() - word_size {
            let insert_data_len = new_chunk.len() - anchor;
            let insert_data = &new_chunk[anchor..(anchor + insert_data_len)];
            let mut insert_instruction = insert_data_len.to_ne_bytes();
            insert_instruction[2] |= 1 << 7;
            delta_code.extend_from_slice(&insert_instruction[..3]);
            delta_code.extend_from_slice(insert_data);
        }

        j += 1;
    }

    delta_code
}

/// Compute delta between `new_chunk` and `base_chunk` using gdelta algorithm.
/// Returns delta as byte vector (INSERT/COPY instructions).
pub fn gdelta_diff_new(
    new_chunk: &[u8],
    base_chunk: &[u8],
    manifest: &HashMap<u64, u32>,
) -> Vec<u8> {
    let base_len = base_chunk.len();

    let new_len = new_chunk.len();
    let word_size: usize = 16;
    if new_len < word_size || base_len < word_size {
        return new_chunk.to_vec();
    }
    let move_bts: usize = 64 / word_size;
    let mask_bts: usize = (base_chunk.len() as f64).log2() as usize;

    let mut delta_code = Vec::new();
    let mut anchor: usize = 0;
    let mut fp = 0u64;

    for &byte in &new_chunk[..word_size - 1] {
        fp = (fp << move_bts).wrapping_add(gear(byte));
    }

    let mut j = 0;
    while j + word_size <= new_len {
        fp = (fp << move_bts).wrapping_add(gear(new_chunk[j + word_size - 1]));
        let word_hash: u64 = fp >> (64 - mask_bts);

        if let Some(&offset) = manifest.get(&(word_hash)) {
            let mut equal_part_len: usize = 0;
            for k in 0..min(base_len - offset as usize, new_len - j) {
                if base_chunk[offset as usize + k] != new_chunk[j + k] {
                    break;
                }
                equal_part_len += 1;
            }

            if equal_part_len >= word_size {
                let insert_data_len = j - anchor;
                if insert_data_len > 0 {
                    let insert_data = &new_chunk[anchor..(anchor + insert_data_len)];
                    let mut insert_instruction = insert_data_len.to_ne_bytes();
                    insert_instruction[2] |= 1 << 7;
                    delta_code.extend_from_slice(&insert_instruction[..3]);
                    delta_code.extend_from_slice(insert_data);
                }

                let copy_instruction_len = &equal_part_len.to_ne_bytes()[..3];
                let copy_instruction_offset = &offset.to_ne_bytes()[..3];
                delta_code.extend_from_slice(copy_instruction_len);
                delta_code.extend_from_slice(copy_instruction_offset);

                anchor = j + equal_part_len;
                j = anchor - 1;
                if j < new_len - word_size {
                    for &byte in &new_chunk[anchor..anchor + word_size - 1] {
                        fp = (fp << move_bts).wrapping_add(gear(byte));
                    }
                }
            }
        }

        if j >= new_len - word_size {
            let insert_data_len = new_len - anchor;
            let insert_data = &new_chunk[anchor..(anchor + insert_data_len)];
            let mut insert_instruction = insert_data_len.to_ne_bytes();
            insert_instruction[2] |= 1 << 7;
            delta_code.extend_from_slice(&insert_instruction[..3]);
            delta_code.extend_from_slice(insert_data);
        }

        j += 1;
    }

    delta_code
}

// Gdelta fingerprints and the SpeedSketch fingerprints must come out of the very same gear
// table, otherwise a word of the base chunk could miss the class bit in its sketch and the
// exclusion would drop a word that is really there. The table stays private to `marline_sketcher`
// and is exposed through its accessor, which is re-exported here so the other encoders can keep
// importing it from this module.
pub(crate) use marline_sketcher::gear;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::GdeltaDecoder;
    use crate::encoder::encode_simple_chunk;
    use marline_sketcher::{SBCHasher, SpeedSketchHasher};

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    fn encode(base: &[u8], new: &[u8]) -> Vec<u8> {
        let config = SpeedSketchConfig::default();
        let base_chunk = BaseChunk::new(base, None, &config);
        GdeltaEncoder::delta_code(new, &base_chunk, speedsketch::sketch_with(new, config.masks()))
    }

    fn decode(base: &[u8], delta: &[u8]) -> Vec<u8> {
        GdeltaDecoder::new(false).decode_chunk(base.to_vec(), delta)
    }

    /// Number of COPY instructions in a gdelta code, so a round-trip test cannot silently
    /// degenerate into a pure INSERT of the whole chunk.
    fn count_copies(delta: &[u8]) -> usize {
        let mut copies = 0;
        let mut i = 0;
        while i < delta.len() {
            let len = u32::from_ne_bytes([delta[i], delta[i + 1], delta[i + 2], 0]) as usize;
            if delta[i + 2] >= 128 {
                i += 3 + (len & 0x7f_ffff);
            } else {
                copies += 1;
                i += 6;
            }
        }
        copies
    }

    #[test]
    fn roundtrip_chunk_shorter_than_word() {
        let base = pattern(64, 0);
        let new = b"short".to_vec();
        let delta = encode(&base, &new);
        assert_eq!(count_copies(&delta), 0, "a sub-word chunk has no fingerprint to copy");
        assert_eq!(decode(&base, &delta), new);
    }

    #[test]
    fn roundtrip_word_sized_chunk() {
        let base = pattern(64, 0);
        let new = base[..speedsketch::WORD_SIZE].to_vec();
        let delta = encode(&base, &new);
        assert_eq!(count_copies(&delta), 1, "the identical word must be copied, not inserted");
        assert_eq!(decode(&base, &delta), new);
    }

    #[test]
    fn roundtrip_single_byte_changed() {
        let base = pattern(256, 0);
        let mut new = base.clone();
        new[100] ^= 0xff;
        let delta = encode(&base, &new);
        assert!(count_copies(&delta) > 0, "the untouched prefix must be copied");
        assert_eq!(decode(&base, &delta), new);
    }

    #[test]
    fn roundtrip_insert_tail_after_copy() {
        let base = pattern(256, 0);
        let mut new = base.clone();
        new.extend_from_slice(b"appended-tail-bytes");
        let delta = encode(&base, &new);
        assert!(count_copies(&delta) > 0, "the unchanged head must be copied");
        assert_eq!(decode(&base, &delta), new);
    }

    #[test]
    fn delta_code_skips_lookup_when_class_bit_differs() {
        let new = pattern(64, 7);
        let empty_base = BaseChunk { data: &[], word_hash_offsets: HashMap::new(), sketch: 0 };
        let delta = GdeltaEncoder::delta_code(&new, &empty_base, u64::MAX);

        assert_eq!(count_copies(&delta), 0, "a cleared class bit must skip every lookup");
        assert_eq!(delta[2] & 0x80, 0x80, "the word must fall through to an INSERT");
        let insert_len = u32::from_ne_bytes([delta[0], delta[1], delta[2] & 0x7f, 0]) as usize;
        assert_eq!(insert_len, new.len());
        assert_eq!(&delta[3..], new.as_slice());
        assert_eq!(decode(&[], &delta), new);
    }

    #[test]
    fn delta_references_parent_key_the_parent_is_stored_under() {
        let parent = pattern(128, 1);
        let mut child = parent.clone();
        child[40] ^= 0x55;

        let requested_parent_hash = SpeedSketchHash::new_with_u32(1000);
        let mut map: SBCMap<GdeltaDecoder, SpeedSketchHash> = SBCMap::new(GdeltaDecoder::default());
        map.insert(
            SBCKey { hash: requested_parent_hash.clone(), chunk_type: ChunkType::Simple },
            b"already-taken".to_vec(),
        )
        .unwrap();

        let stored_key = {
            let guard = Mutex::new(&mut map);
            let (_, key) = encode_simple_chunk(
                &mut guard.lock().unwrap(),
                parent.as_slice(),
                requested_parent_hash.clone(),
            );
            key
        };
        assert_ne!(stored_key.hash, requested_parent_hash, "an occupied key must be shifted");
        assert_eq!(stored_key.hash, requested_parent_hash.next_hash());

        let config = SpeedSketchConfig::default();
        let base = BaseChunk::new(&parent, None, &config);
        let delta = GdeltaEncoder::delta_code(
            child.as_slice(),
            &base,
            speedsketch::sketch_with(child.as_slice(), config.masks()),
        );

        let child_key = SBCKey {
            hash: SpeedSketchHash::new_with_u32(2000),
            chunk_type: ChunkType::Delta { parent_hash: stored_key.hash.clone(), number: 0 },
        };
        map.insert(child_key.clone(), delta).unwrap();
        assert_eq!(map.get(&child_key).unwrap(), child);
    }

    #[test]
    fn test_encode_chunk_against_rejects_mismatched_config() {
        let base = pattern(128, 0);
        let child = pattern(128, 1);
        let encoder = GdeltaEncoder::default();
        let base_hash =
            SpeedSketchHasher::with_config(encoder.sketch_config().clone()).calculate_hash(&base);
        let child_hash = SpeedSketchHasher::with_config(SpeedSketchConfig::uniform(8, 1).unwrap())
            .calculate_hash(&child);

        let result = encoder.encode_chunk_against(&child, &child_hash, &base, &base_hash);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_encode_chunk_against_with_zstd() {
        let base = pattern(128, 0);
        let mut child = base.clone();
        child[40] ^= 1;
        let encoder = GdeltaEncoder::new(true);
        let hasher = SpeedSketchHasher::with_config(encoder.sketch_config().clone());
        let delta = encoder
            .encode_chunk_against(
                &child,
                &hasher.calculate_hash(&child),
                &base,
                &hasher.calculate_hash(&base),
            )
            .unwrap();

        assert_eq!(GdeltaDecoder::new(true).decode_chunk(base, &delta), child);
    }
}
