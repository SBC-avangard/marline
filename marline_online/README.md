# marline_online

`SpeedSketchOnline` implements `OnlineSBC` for in-memory deduplication. Each call to `write`
processes one complete buffer with FastCDC. The minimum, target and maximum chunk sizes are
4, 8 and 64 KiB. The default SpeedSketch masks use feature popcount 8, bloom popcount 5 and seed
12345. `SpeedSketchOnline::with_config` accepts a custom `SpeedSketchConfig`.

The store detects exact duplicates by BLAKE3 fingerprint. For new chunks at least one Gdelta word
long, the lower 32 bits of the SpeedSketch are used to look up the latest full base chunk with
the same feature. Gdelta uses both full sketches to encode a delta.

By default, Zstd compresses the Gdelta instructions. The store keeps the resulting delta when
it is strictly smaller than the original chunk. In other cases the full chunk is stored as raw
bytes. Full chunks at least one Gdelta word long can serve as bases.
Use `SpeedSketchOnline::with_config_and_zstd(config, false)` for uncompressed deltas.

```rust
use marline_online::{OnlineSBC, SpeedSketchOnline};

let mut store = SpeedSketchOnline::new();
let data = b"example input";
store.write(data).unwrap();
store.write(data).unwrap();
assert_eq!(store.bytes_stored(), data.len());
```

`bytes_stored` counts stored chunk and delta payloads. `get_chunk` reconstructs a chunk given its
32-byte BLAKE3 fingerprint.
