use structopt::StructOpt;
use structopt::clap::AppSettings;

/// Cypher and decipher text using the Hill's Cypher method
#[derive(Debug, StructOpt)]
#[structopt(
	name = "hill_cipher",
	author = "Bryan Baron <MrFixThis>",
	rename_all = "kebab-case",
	setting = AppSettings::DeriveDisplayOrder,
	setting = AppSettings::ColoredHelp,
)]
pub struct Args {
	#[structopt(subcommand)]
	pub cmd: Command,
}

// This struct represents the application's available commands
#[derive(Debug, StructOpt)]
#[structopt(rename_all = "kebab-case")]
pub enum Command {
	/// Cypher a given source text
	Cypher {
		/// Key to cipher the source text
		#[structopt(short, long)]
		key: String,

		/// Source text to cipher
		#[structopt(short, long)]
		source: String,

		/// Source text's fill letter
		#[structopt(short, long)]
		fill_letter: char,

		/// Custom namespace for the base of the algorithm
		#[structopt(short, long)]
		namespace: Option<String>,
	},

	/// Decipher a given source text
	Decipher {
		/// Key to decipher the source text
		#[structopt(short, long)]
		key: String,

		/// Cyphered source text
		#[structopt(short, long)]
		source: String,

		/// Known key's and source text's fill letter
		#[structopt(short, long)]
		fill_letter: Option<char>,

		/// Known namespace used to cipher the ciphered source text
		#[structopt(short, long)]
		namespace: Option<String>
	}
}
