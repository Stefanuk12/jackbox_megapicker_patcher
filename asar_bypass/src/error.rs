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
	EmptyFunction
}

pub type Result<T, E = Error> = core::result::Result<T, E>;