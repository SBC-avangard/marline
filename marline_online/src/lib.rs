//! Online similarity-based chunking with SpeedSketch.

pub use marline_palantir::palantir_online::OnlineSBC;
pub use speedsketch_online::SpeedSketchOnline;

/// The SpeedSketch implementation of [`OnlineSBC`].
pub mod speedsketch_online;
