use chunkfs::chunkers::{FastChunker, SizeParams};
use chunkfs::Chunker;
use marline_online::{OnlineSBC, SpeedSketchOnline};
use marline_sketcher::{SBCHash, SBCHasher, SpeedSketchConfig, SpeedSketchHasher};

fn sample_data(len: usize) -> Vec<u8> {
    let mut state = 1u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

#[test]
fn test_writes_fastcdc_chunks_and_skips_duplicates() {
    let mut online = SpeedSketchOnline::new();
    online.write(&[]).unwrap();
    assert_eq!(online.bytes_stored(), 0);

    let data = sample_data(256 * 1024 + 7);
    let mut reference = FastChunker::new(SizeParams::new(4 * 1024, 8 * 1024, 64 * 1024));
    let chunks = reference.chunk_data(&data, Vec::new());
    assert!(chunks.len() > 1);

    online.write(&data).unwrap();
    for chunk in chunks {
        let expected = &data[chunk.range()];
        assert_eq!(online.get_chunk(blake3::hash(expected).as_bytes()).unwrap(), expected);
    }

    let stored = online.bytes_stored();
    online.write(&data).unwrap();
    assert_eq!(online.bytes_stored(), stored);
}

#[test]
fn test_matching_feature_stores_a_smaller_lossless_delta() {
    let base = sample_data(4 * 1024);
    let mut target = base.clone();
    target[2048] ^= 1;
    assert_ne!(blake3::hash(&base), blake3::hash(&target));

    for config in [SpeedSketchConfig::default(), SpeedSketchConfig::new(8, 6, 99).unwrap()] {
        let hasher = SpeedSketchHasher::with_config(config.clone());
        assert_eq!(hasher.calculate_hash(&base), hasher.calculate_hash(&target));
        let mut online = SpeedSketchOnline::with_config(config);

        online.write(&base).unwrap();
        assert_eq!(online.bytes_stored(), base.len());
        online.write(&target).unwrap();
        let delta_size = online.bytes_stored() - base.len();
        assert!(delta_size > 0 && delta_size < target.len());
        assert_eq!(online.get_chunk(blake3::hash(&target).as_bytes()).unwrap(), target);

        online.write(&target).unwrap();
        assert_eq!(online.bytes_stored(), base.len() + delta_size);
    }
}

#[test]
fn test_distinct_short_chunks_with_the_same_empty_sketch_are_stored_in_full() {
    let mut online = SpeedSketchOnline::default();
    let hasher = SpeedSketchHasher::with_config(SpeedSketchConfig::default());
    for data in [b"one", b"two"] {
        assert_eq!(hasher.calculate_hash(data).sketch(), Some(0));
        online.write(data).unwrap();
        assert_eq!(online.get_chunk(blake3::hash(data).as_bytes()).unwrap(), data);
    }
    assert_eq!(online.bytes_stored(), 6);
}
