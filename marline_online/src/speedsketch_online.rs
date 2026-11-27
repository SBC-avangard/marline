use chunkfs::chunkers::{FastChunker, SizeParams};
use chunkfs::Chunker;
use marline_palantir::error::PalantirError;
use marline_palantir::palantir_online::OnlineSBC;
use marline_scrub::decoder::{Decoder, GdeltaDecoder};
use marline_scrub::encoder::GdeltaEncoder;
use marline_sketcher::speedsketch::WORD_SIZE;
use marline_sketcher::{SBCHash, SBCHasher, SpeedSketchConfig, SpeedSketchHash, SpeedSketchHasher};
use std::collections::HashMap;

const MIN_CHUNK_SIZE: usize = 4 * 1024;
const AVG_CHUNK_SIZE: usize = 8 * 1024;
const MAX_CHUNK_SIZE: usize = 64 * 1024;

type Fingerprint = [u8; 32];

#[derive(Debug)]
enum StoredChunk {
    Full { data: Box<[u8]>, hash: SpeedSketchHash },
    Delta { base: Fingerprint, instructions: Box<[u8]> },
}

/// In-memory online SBC using FastCDC, SpeedSketch and Gdelta.
///
/// Each `write` chunks one complete buffer. The index and stored chunks are reused across writes.
#[derive(Debug)]
pub struct SpeedSketchOnline {
    chunker: FastChunker,
    hasher: SpeedSketchHasher,
    encoder: GdeltaEncoder,
    zstd_deltas: bool,
    chunks: HashMap<Fingerprint, StoredChunk>,
    bases: HashMap<u32, Fingerprint>,
    stored_bytes: usize,
}

impl Default for SpeedSketchOnline {
    fn default() -> Self {
        Self::new()
    }
}

impl SpeedSketchOnline {
    /// Creates an empty store with FastCDC sizes of 4/8/64 KiB and the default SpeedSketch masks
    /// (feature popcount 8, bloom popcount 5, seed 12345).
    /// Gdelta instructions are compressed with Zstd.
    pub fn new() -> Self {
        Self::with_config(SpeedSketchConfig::default())
    }

    /// Creates an empty store sharing `config` between similarity hashing and delta encoding.
    /// Gdelta instructions are compressed with Zstd.
    pub fn with_config(config: SpeedSketchConfig) -> Self {
        Self::with_config_and_zstd(config, true)
    }

    /// Creates an empty store with optional Zstd compression for Gdelta instructions.
    /// The same setting is used to recover deltas. Full chunks are stored as raw bytes.
    pub fn with_config_and_zstd(config: SpeedSketchConfig, zstd_deltas: bool) -> Self {
        Self {
            chunker: FastChunker::new(SizeParams::new(
                MIN_CHUNK_SIZE,
                AVG_CHUNK_SIZE,
                MAX_CHUNK_SIZE,
            )),
            hasher: SpeedSketchHasher::with_config(config.clone()),
            encoder: GdeltaEncoder::with_sketch_config(zstd_deltas, config),
            zstd_deltas,
            chunks: HashMap::new(),
            bases: HashMap::new(),
            stored_bytes: 0,
        }
    }

    /// Returns the original bytes of a stored chunk by its 32-byte BLAKE3 fingerprint.
    pub fn get_chunk(&self, fingerprint: &[u8; 32]) -> Option<Vec<u8>> {
        match self.chunks.get(fingerprint)? {
            StoredChunk::Full { data, .. } => Some(data.to_vec()),
            StoredChunk::Delta { base, instructions } => {
                let StoredChunk::Full { data, .. } = self.chunks.get(base)? else {
                    return None;
                };
                Some(GdeltaDecoder::new(self.zstd_deltas).decode_chunk(data.to_vec(), instructions))
            }
        }
    }

    fn store_chunk(&mut self, data: &[u8]) -> Result<(), PalantirError> {
        let fingerprint = *blake3::hash(data).as_bytes();
        if self.chunks.contains_key(&fingerprint) {
            return Ok(());
        }

        let hash = self.hasher.calculate_hash(data);
        let feature = hash.get_key_for_graph_clusterer();
        if data.len() >= WORD_SIZE {
            if let Some(&base) = self.bases.get(&feature) {
                let Some(StoredChunk::Full { data: base_data, hash: base_hash }) =
                    self.chunks.get(&base)
                else {
                    return Err(PalantirError::MetadataError("missing SpeedSketch base".into()));
                };
                let instructions = self
                    .encoder
                    .encode_chunk_against(data, &hash, base_data, base_hash)
                    .map_err(|err| PalantirError::MetadataError(err.to_string()))?;
                if instructions.len() < data.len() {
                    self.stored_bytes += instructions.len();
                    self.chunks.insert(
                        fingerprint,
                        StoredChunk::Delta { base, instructions: instructions.into_boxed_slice() },
                    );
                    return Ok(());
                }
            }
            self.bases.insert(feature, fingerprint);
        }

        self.chunks.insert(fingerprint, StoredChunk::Full { data: data.into(), hash });
        self.stored_bytes += data.len();
        Ok(())
    }
}

impl OnlineSBC<SpeedSketchHasher, Fingerprint, GdeltaEncoder, 1> for SpeedSketchOnline {
    /// Deduplicates and stores FastCDC chunks from a complete input buffer.
    fn write(&mut self, data: &[u8]) -> Result<(), PalantirError> {
        let offsets = Vec::with_capacity(self.chunker.estimate_chunk_count(data));
        for chunk in self.chunker.chunk_data(data, offsets) {
            self.store_chunk(&data[chunk.range()])?;
        }
        Ok(())
    }

    /// Returns the sum of stored chunk and delta payload sizes, excluding index metadata.
    fn bytes_stored(&self) -> usize {
        self.stored_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_zstd_delta_round_trips_and_counts_stored_bytes() {
        let mut online = SpeedSketchOnline::new();
        assert!(online.zstd_deltas);
        let base = [0; 1024];
        let mut child = base;
        child[512] = 1;

        online.write(&base).unwrap();
        assert_eq!(online.bytes_stored(), base.len());
        online.write(&child).unwrap();

        let fingerprint = blake3::hash(&child);
        let Some(StoredChunk::Delta { instructions, .. }) =
            online.chunks.get(fingerprint.as_bytes())
        else {
            panic!("expected a stored Zstd delta");
        };
        assert_eq!(online.bytes_stored(), base.len() + instructions.len());
        assert_eq!(online.get_chunk(fingerprint.as_bytes()).unwrap(), child);
    }

    #[test]
    fn test_replacing_a_base_keeps_previous_deltas_readable() {
        // Without Zstd, the unrelated replacement's literal-only delta is rejected.
        let mut online =
            SpeedSketchOnline::with_config_and_zstd(SpeedSketchConfig::default(), false);
        let base = [0; 1024];
        let mut child = base;
        child[512] = 1;
        let replacement = [2; 1024];
        let feature = online.hasher.calculate_hash(&base).get_key_for_graph_clusterer();
        assert_eq!(online.hasher.calculate_hash(&child).get_key_for_graph_clusterer(), feature);
        assert_eq!(
            online.hasher.calculate_hash(&replacement).get_key_for_graph_clusterer(),
            feature
        );

        online.write(&base).unwrap();
        online.write(&child).unwrap();
        let child_fingerprint = blake3::hash(&child);
        assert!(matches!(
            online.chunks.get(child_fingerprint.as_bytes()),
            Some(StoredChunk::Delta { .. })
        ));

        let stored = online.bytes_stored();
        online.write(&replacement).unwrap();
        assert_eq!(online.bytes_stored() - stored, replacement.len());
        assert_eq!(online.bases[&feature], *blake3::hash(&replacement).as_bytes());
        assert_eq!(online.get_chunk(child_fingerprint.as_bytes()).unwrap(), child);
    }
}
