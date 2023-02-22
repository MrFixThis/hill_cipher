use std::error::Error;

/// Prints the results of the `cipher` or `decipher` processes.
#[macro_export]
macro_rules! report_msg {
    ($($fmt:tt)+) => {
		eprint!("{}", colored::Colorize::bold(
				colored::Colorize::green("Report result"))
		);
		eprint!("{}", colored::Colorize::bold(": "));
		eprintln!("{:>4}", colored::Colorize::bold(format!($($fmt)+)));
	};
}

/// Prints any possible error catched from the `cipher` or `decipher` processes.
pub fn print_error(err: impl Error) {
	use colored::Colorize as _;
	eprintln!("{}{}{}",
		"Error".red().bold(),
		": ".bold(),
		err.to_string().bold()
	);
}
