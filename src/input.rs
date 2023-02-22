use structopt::StructOpt;
use structopt::clap::AppSettings;

/// Cipher and decipher text using the Hill's cipher method
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
	/// Cipher a given source text
	Cipher {
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

		/// Cipher source text
		#[structopt(short, long)]
		source: String,

		/// Known source text's fill letter
		#[structopt(short, long)]
		fill_letter: Option<char>,

		/// Known namespace used to decipher source text
		#[structopt(short, long)]
		namespace: Option<String>
	}
}
