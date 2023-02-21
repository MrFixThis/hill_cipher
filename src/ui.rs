/// 
#[macro_export]
macro_rules! error_msg {
    ($msg:expr) => {
		eprint!("{}", colored::Colorize::bold(colored::Colorize::red("error")));
		eprint!("{}", colored::Colorize::bold(": "));
		eprintln!("{}", colored::Colorize::bold($msg));
	};
}
