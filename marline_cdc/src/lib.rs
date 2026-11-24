//! Content-defined chunking (FastCDC v2020) with in-pass feature collection.

#[doc(hidden)]
pub mod fastcdc;

pub use fastcdc::{
    collect_raw_features, Chunk, ChunkData, Error as StreamError, FastCDC, StreamCDC,
};
