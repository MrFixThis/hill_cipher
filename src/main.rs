pub mod input;
pub mod process;
pub mod error;
pub mod ui;

use colored::Colorize as _;

use input::{Args, Command::{Cipher, Decipher}};
use error::Result;
use process::ProcessorBuilder;

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
		Cipher { key, source, fill_letter, namespace } => {
			processor = ProcessorBuilder::default()
				.key(key)
				.source(source)
				.fill_letter(Some(fill_letter))
				.namespace(namespace)
				.build()
				.unwrap();
			processor.cipher()?
		},
		Decipher { key, source, fill_letter, namespace } => {
			processor = ProcessorBuilder::default()
				.key(key)
				.source(source)
				.fill_letter(fill_letter)
				.namespace(namespace)
				.build()
				.unwrap();
			processor.decipher()?
		},
	};

	report_msg![
		"  {}: {}\n  {}: {}\n  {}: {}\n  {}: {}\n  {}: {}",
		"Used key".yellow(), report.used_key,
		"Source text".yellow(), report.source_txt,
		"Result text".blue(), report.result_txt,
		"Filled?".yellow(), report.filled,
		"Namespace".yellow(), match report.def_namespace {
			Some(ns) => ns,
			None => "Default namespace".to_owned()
		}
	];

	Ok(())
}
