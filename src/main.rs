pub mod input;
pub mod process;
pub mod error;
pub mod ui;

use input::{Args, Command::{Cypher, Decipher}};
use error::{Error, Result};
use process::{Processor, ProcessorBuilder};

fn main() {
	match app() {
		Ok(_) => (),
		Err(e) => {
			ui::print_error(e);
		},
	}
}

/// Runs the application.
fn app() -> Result<()> {
	let args: Args = structopt::StructOpt::from_args();
	let processor;

	let report = match args.cmd {
		Cypher { key, source, fill_letter, namespace } => {
			processor = ProcessorBuilder::default()
				.key(&key)
				.source(&source)
				.fill_letter(Some(fill_letter))
				.namespace(namespace.as_ref())
				.build()
				.unwrap()
			// processor.cipher()
		},
		Decipher { key, source, fill_letter, namespace } => {
			processor = ProcessorBuilder::default()
				.key(&key)
				.source(&source)
				.fill_letter(fill_letter)
				.namespace(namespace.as_ref())
				.build()
				.unwrap()
			// processor.decipher()
		},
	};

	Ok(())
}
