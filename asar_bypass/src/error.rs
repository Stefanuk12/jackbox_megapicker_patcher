#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error(transparent)]
	IO(#[from] std::io::Error),
	#[error(transparent)]
	Goblin(#[from] goblin::error::Error),
	#[error(transparent)]
	Capstone(#[from] capstone::Error),

	#[error("file offset not found in any section")]
	RvaNotFound,
	#[error("could not find xref to data")]
	XrefNotFound,
	#[error("could not find section containing ref_va")]
	SectionNotFound,
	#[error("function start out of range")]
	InvalidFunctionStart,
	#[error("empty function found")]
	EmptyFunction,
	#[error("could not find the Electron fuse sentinel")]
	FuseSentinelNotFound,
	#[error("the Electron fuse wire is truncated")]
	FuseWireTruncated,
	#[error("unexpected Electron fuse state {0:#x}")]
	FuseUnexpected(u8)
}

pub type Result<T, E = Error> = core::result::Result<T, E>;