/// 
#[macro_export]
macro_rules! error_msg {
    ($msg:expr) => {
		let colorizer = colored::Colorize;
		eprint!("{}", colorizer::bold(colorizer::red("error")));
		eprint!("{}", colorizer::bold(": "));
		eprintln!("{}", colorizer::bold(&msg));
	};
}
