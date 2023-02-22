use derive_builder::Builder;
use fancy_regex::Regex;
use rulinalg::matrix::{Matrix, BaseMatrix};
use modinverse;

use crate::error::Result;

/// Default namespace used by the `cipher` and `decipher` algorithms to do its
/// work. This value is obscured if a `custom namespace` is specified.
pub const DEFAULT_NAMESPACE: [char; 26] = [
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
];

/// `Cipher`/`Decipher` processes report.
///
/// A report that holds the results of the processes performed by a
/// [`Processor`] with the information provided to program.
#[derive(Debug, Default, Builder, PartialEq)]
pub struct Report {
	pub used_key: String,
	pub source_txt: String,
	pub fill_letter: Option<char>,
	pub result_txt: String,
	pub filled: bool,
	pub def_namespace: Option<String>
}

/// A `Cipher` and `Decipher` processor.
///
/// The processor exposes the application's cipher and decipher capabilities
/// based on the `Hill's Method` cipher.
#[derive(Debug, Default, Builder)]
pub struct Processor {
	key: String,
	source: String,
	fill_letter: Option<char>,
	namespace: Option<String>,
}

impl Processor {
	/// Ciphers the given `source text` based on the information passed
	/// to the program, like a `key`, a `fill letter` or a possibe
	/// `custom namespace`.
	pub fn cipher(self) -> Result<Report> {
		// definition of which namespace to use: either the user supplied
		// namespace or the default one
		let namespace = self.def_namespace()?;

		// Checking the validness of the user supplied info
		self.check_information(&namespace)?;

		// getting the checked key's length square root
		let dimension = (self.key.len() as f64).sqrt() as usize;

		// checking if the source text's length is divisible by the above dimension.
		// If it is not, the the text is filled
		let mut was_filled = false;
		let sl = self.source.len();
		let source = if !is_divisble(self.source.len(), &dimension) {
			was_filled = true;
			fill_txt(
				&self.source,
				self.fill_letter.unwrap(),
				turn_divisible(sl, &dimension), sl
			)
		} else {
			self.source.to_uppercase()
		};

		// getting the key's matrix representation and its determinant
		let key_mtrx_repr = txt_mtrx_repr(dimension, dimension, &self.key, &namespace)?;
		let key_mtrx_det = key_mtrx_repr.clone().det(); // it is clone because det() consumes
													  // the the receiver

		// checking if the supplied key's matrix representation is valid to
		// use for the cipher process
		Self::check_key_mtrx_validness(&key_mtrx_det, namespace.len())?;

		// spliting the source text into as many parts as the square root of
		// the key's matrix representation dimension, and turning its values
		// into its respective numeric representation inside the namespace
		let src_mtrx_repr = txt_mtrx_repr(
			source.len() / dimension,
			dimension,
			&source,
			&namespace
		)?;

		// turning the ciphertext parts into its textual representation
		let ciphered_txt = translate_txt_mtrx(
			&key_mtrx_repr,
			src_mtrx_repr,
			namespace
		);

		// building the report
		Ok(self.build_report(ciphered_txt, was_filled))
	}

	/// Deciphers the given `ciphertext` based on the information passed
	/// to the program, like the known `key`, or a possible known `fill letter`
	/// and a `custom namespace` used in the `cipher` process.
	pub fn decipher(self) -> Result<Report> {
		// definition of which namespace to use: either the user supplied
		// namespace or the default one
		let namespace = self.def_namespace()?;

		// Checking the validness of the user supplied info
		self.check_information(&namespace)?;

		// getting the passed key's length square root
		let dimension = (self.key.len() as f64).sqrt() as usize;

		// getting the key's matrix representation and its inverse
		let key_mtrx_repr = txt_mtrx_repr(dimension, dimension, &self.key, &namespace)?;
		let key_mtrx_inv = key_mtrx_repr.clone().inverse();

		// deciphering the given source text
		match key_mtrx_inv {
			Ok(inverse) => {
				let key_mtrx_det = key_mtrx_repr.det();
				
				// checking if the supplied key's matrix representation is valid to
				// use for the decipher process
				Self::check_key_mtrx_validness(&key_mtrx_det, namespace.len())?;

				// getting modular multiplicative inverse of the keys's
				// matrix representation determinant
				let mod_mul_inv = modinverse::modinverse(
					key_mtrx_det as i128,
					namespace.len() as i128
				).unwrap() as f64;
				
				// multipling the key's matrix representation inverse
				// by its modular multiplicative inverse
				let inverse = Matrix::new(
					inverse.rows(),
					inverse.cols(),
					inverse
						.into_vec()
						.into_iter()
						.map(|v| ((v * mod_mul_inv) * key_mtrx_det).round())
						.collect::<Vec<_>>()
				);

				// turning the ciphertext into its matrix representation
				let src_mtrx_repr = txt_mtrx_repr(
					self.source.len() / dimension,
					dimension,
					&self.source,
					&namespace
				)?;

				// turning the deciphertext parts into its textual representation
				let deciphered_txt = translate_txt_mtrx(
					&inverse,
					src_mtrx_repr,
					namespace,
				);

				// building the report
				Ok(self.build_report(deciphered_txt, false))
			},
			// if the passed key's matrix representation has no an inverse,
			// then the key length is not square
			Err(_) => Err(
				"invalid or malformed key. the key has no a square length".into()
			)
		}
	}

	/// Builds a final `Report` instance that hold the result of the `cipher`
	/// or `decipher` processes.
	pub fn build_report(self, res_text: String, filled: bool) -> Report {
		ReportBuilder::default()
		   .used_key(self.key)
		   .source_txt(self.source)
		   .result_txt(res_text)
		   .fill_letter(self.fill_letter)
		   .filled(filled)
		   .def_namespace(self.namespace)
		   .build()
		   .unwrap()
	}

	/// Defines the `namespace` to use in the `cipher` and `decipher` processes.
	/// If a custom namespace is not defined, the default one is used. In case
	/// that the user defined namespace has a length < 29, then
	/// (ProcessingError)[crate::error::Error] is returned.
	fn def_namespace(&self) -> Result<Vec<char>> {
		match &self.namespace {
			Some(ns) => {
				// cheking if the supplied namespace is malformed
				Self::check_namespace(&ns)?;

				if !is_square(ns.len()) {
					return Err(
						format!(
							"the supplied namespace must be square in length"
						).into()
					);
				}
				Ok(ns.chars().collect())
			},
			None => Ok(DEFAULT_NAMESPACE.to_vec())
		}
	}

	/// Checks if possible custom `defined` namespace is malformed, that is
	/// if it has duplicated values, if it is the case,
	/// (ProcessingError)[crate::error::Error] is returned.
	fn check_namespace(namespace: &String) -> Result<()> {
		let rgx = Regex::new(r"(.)\1{1,}").unwrap();
		if rgx.is_match(namespace).unwrap() {
			return Err("the supplied namespace has duplicated characters".into())
		}

		Ok(())
	}

	/// Checks the validness of the user supplied information. If something went
	/// wrong in the checking, (ProcessingError)[crate::error::Error] is returned.
	fn check_information(&self, namespace: &[char]) -> Result<()> {
		// checking if the supplied key has a square length
		if !is_square(self.key.len()) {
			return Err("the supplied key must be square in length".into())
		}

		// checking if the supplied fill character is inside the namespace
		if let Some(f) = self.fill_letter {
			Self::is_in_namespace(f, &namespace)?;
		}

		// checking if the supplied key and source text have an unkwnon character
		let mut target = &self.key;
		for _ in 0..2 {
			for c in target.chars() {
				Self::is_in_namespace(c, &namespace)?;
			}
			target = &self.source;
		}

		Ok(())
	}

	/// Checks if the supplied `key`'s matrix representation is valid to perform
	/// the `cipher` and `decipher` processes, if it is not,
	/// (ProcessingError)[crate::error::Error] is returned.
	fn check_key_mtrx_validness(det: &f64, ns_len: usize) -> Result<()> {
		let mod_mul_inv = modinverse::modinverse(*det as i128, ns_len as i128);
		if *det == 0.0 || mod_mul_inv.is_none() || has_any_factor(det.abs() as usize, ns_len) {
			return Err(
				format!(
					"the specified key cannot be used. [matrix's det 0 or has factors with {}]",
					ns_len
				 ).into()
			)
		}

		Ok(())
	}

	/// Checks if the supplied `character` is inside the given namespace; if it
	/// is not, (ProcessingError)[crate::error::Error] is returned.
	fn is_in_namespace(char: char, namespace: &[char]) -> Result<()> {
		if namespace.into_iter().find(|&c| *c == char) == None {
			return Err(
				format!(
					"the character '{char}' is not present in the namespace"
				).into()
			);
		}

		Ok(())
	}
}

/// Turns a given (Matrix)[rulinalg::matrix::Matrix] filled with the positions
/// of each character of any `text`, into its textual
/// representations inside the supplied namespace; all using another
/// (Matrix)[rulinalg::matrix::Matrix] as key for the process.
fn translate_txt_mtrx(
	key_mtrx: &Matrix<f64>,
	src_mtrx: Matrix<f64>,
	namespace: Vec<char>
) -> String {
	// ciphering the source text's matrix
	let mtrx_mul = (key_mtrx * src_mtrx).transpose();
	mtrx_mul
		.into_vec()
		.into_iter()
		.map(|v| namespace[euc_mod(v as i128, namespace.len() as u128) as usize])
		.collect()
}

/// Splits a given `text` into its numeric representations inside the namespace
/// specified, and stores it inside a (Matrix)[rulinalg::matrix::Matrix] with
/// `rows` x `cols` dimension.
fn txt_mtrx_repr(
	rows: usize,
	cols: usize,
	src: &str,
	namespace: &[char]
) -> Result<Matrix<f64>>
{
	let parts: Vec<_> = src
		.chars()
		.map(|c| char_pos(c, namespace) as f64)
		.collect();

	Ok(Matrix::new(rows, cols, parts).transpose())
}

/// Fills a given `text` with a specified character (a - b) times.
fn fill_txt(txt: &str, char: char, a: usize, b: usize) -> String {
	let reps = a - b;

	if reps != 0 {
		let append = char.to_string().repeat(reps);
		format!("{}{}", txt, append).to_uppercase()
	} else {
		txt.to_owned()
	}
}

/// Retrives the given character's `position` inside the namespace specified.
fn char_pos(char: char, namespace: &[char]) -> usize {
	namespace.iter().position(|&c| c == char.to_ascii_uppercase()).unwrap()
}

/// Checks if a `target number` has at least one factor against any number
/// specified.
fn has_any_factor(target: usize, number: usize) -> bool {
	for factor in target..number {
		if target % factor == 0 {
			return true
		}
	}
	false
}

/// Performs the modulus of a number in any other number specified,
/// following the `Euclid` algorithm.
fn euc_mod(a: i128, b: u128) -> u128 {
    if a >= 0 {
        (a as u128) % b
    } else {
        let r = (!a as u128) % b;
        b - r - 1
    }
}

/// Checks if the supplied number is square.
fn is_square(num: usize) -> bool {
	let sqrt = (num as f64).sqrt().floor();

	num == 0 || num == 1 || (sqrt.powi(2) == num as f64)
}

/// Checks if the supplied target number is divisible by another one.
fn is_divisble(target: usize, num: &usize) -> bool {
	target % num == 0
}

/// Turns a given target number divisible by another one.
fn turn_divisible(target: usize, dim: &usize) -> usize {
	let mut base = target;
	loop {
		if base % dim == 0 {
			return base;
		}
		base += 1;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn source_text_with_not_divisible_length_is_filled() {
		let key = "ABCDEFGHI";
		let key_dim = (key.len() as f64).sqrt() as usize;
		let src = "ABCD".to_owned();
		let sl = src.len();
		let fill_char = 'E';

		assert_eq!(
			fill_txt(&src, fill_char, turn_divisible(sl, &key_dim), sl),
			"ABCDEE"
		);
	}

	#[test]
	fn key_is_turned_into_matrix_representation() {
		let key = "ABCDEFGHI";
		let dim = (key.len() as f64).sqrt() as usize;

		assert_eq!(
			txt_mtrx_repr(dim, dim, &key, &DEFAULT_NAMESPACE).unwrap(),
			Matrix::new(dim, dim,
						vec![0.0, 3.0, 6.0,
							 1.0, 4.0, 7.0,
							 2.0, 5.0, 8.0]
						 )
		);
	}

	#[test]
	fn text_is_turned_into_matrix_representation() {
		let _key = "FJCRXLUDN";
		let src = "CODIGO".to_owned();
		let dim = (_key.len() as f64).sqrt() as usize;

		assert_eq!(
			txt_mtrx_repr(src.len() / dim, dim, &src, &DEFAULT_NAMESPACE).unwrap(),
			Matrix::new(dim, src.len()/dim,
						vec![2.0, 8.0,
							 14.0, 6.0,
							 3.0, 14.0]
						 )
		);
	}

	#[test]
	fn source_text_parts_are_turned_into_ciphertext() {
		let namespace = DEFAULT_NAMESPACE.to_vec();
		let key = "FJCRXLUDN";
		let src = "CODIGO".to_owned();
		let dim = (key.len() as f64).sqrt() as usize;
		let key_mtrx = txt_mtrx_repr(dim, dim, &key, &namespace).unwrap();
		let src_mtrx = txt_mtrx_repr(src.len()/dim, dim, &src, &namespace).unwrap();

		assert_eq!(
			translate_txt_mtrx(&key_mtrx, src_mtrx, namespace),
			String::from("WLPGSE")
		);
	}

	#[test]
	fn ciphertext_parts_are_turned_into_deciphertext() {
		let namespace = DEFAULT_NAMESPACE.to_vec();
		let key = "FJCRXLUDN";
		let src = "WLPGSE".to_owned();
		let dim = (key.len() as f64).sqrt() as usize;
		let key_mtrx = txt_mtrx_repr(dim, dim, &key, &namespace).unwrap();
		let src_mtrx = txt_mtrx_repr(src.len()/dim, dim, &src, &namespace).unwrap();

		let key_mtrx_inv = key_mtrx.clone().inverse().unwrap();
		let key_mtrx_det =  key_mtrx.det();
		let mod_mul_inv = modinverse::modinverse(
			key_mtrx_det as i64,
			namespace.len() as i64
		).unwrap() as f64;

		let key_mtrx_inv = Matrix::new(
			key_mtrx_inv.rows(),
			key_mtrx_inv.cols(),
			key_mtrx_inv
				.into_vec()
				.into_iter()
				.map(|v| ((v * mod_mul_inv) * key_mtrx_det).round())
				.collect::<Vec<_>>()
		);

		assert_eq!(
			translate_txt_mtrx(&key_mtrx_inv, src_mtrx, namespace),
			String::from("CODIGO")
		);
	}

	#[derive(Clone)]
	struct TestArgInfo {
		key: String,
		source: String,
		fill_letter: Option<char>,
		namespace: Option<String>,
	}

	#[test]
	fn cipher_operation_with_default_namespace_is_completed() {
		let info = TestArgInfo {
			key: "FJCRXLUDN".to_owned(),
			source: "CODIGO".to_owned(),
			fill_letter: Some('H'),
			namespace: None
		};
		let info_cl = info.clone();

		let processor = ProcessorBuilder::default()
			.key(info_cl.key)
			.source(info_cl.source)
			.fill_letter(info_cl.fill_letter)
			.namespace(info_cl.namespace)
			.build()
			.unwrap();

		let report = ReportBuilder::default()
			.used_key(info.key)
			.source_txt(info.source)
			.result_txt("WLPGSE".to_owned())
			.fill_letter(info.fill_letter)
			.filled(false)
			.def_namespace(info.namespace)
			.build()
			.unwrap();

		assert_eq!(processor.cipher().unwrap(), report);
	}

	#[test]
	fn decipher_operation_with_default_namespace_is_completed() {
		let info = TestArgInfo {
			key: "FJCRXLUDN".to_owned(),
			source: "WLPGSE".to_owned(),
			fill_letter: Some('H'),
			namespace: None
		};
		let info_cl = info.clone();

		let processor = ProcessorBuilder::default()
			.key(info_cl.key)
			.source(info_cl.source)
			.fill_letter(info_cl.fill_letter)
			.namespace(info_cl.namespace)
			.build()
			.unwrap();

		let report = ReportBuilder::default()
			.used_key(info.key)
			.source_txt(info.source)
			.result_txt("CODIGO".to_owned())
			.fill_letter(info.fill_letter)
			.filled(false)
			.def_namespace(info.namespace)
			.build()
			.unwrap();

		assert_eq!(processor.decipher().unwrap(), report);
	}

	#[test]
	fn cipher_operation_with_custom_namespace_is_completed() {
		let dns="ABCDEFGHIJKLMNOPQRSTUVWXYZ @$^&*/?.-".to_owned();
		let info = TestArgInfo {
			key: "AFJCRXLUDNLZ@$^?".to_owned(),
			source: "TEST CODIGO".to_owned(),
			fill_letter: Some('H'),
			namespace: Some(dns)
		};
		let info_cl = info.clone();

		let processor = ProcessorBuilder::default()
			.key(info_cl.key)
			.source(info_cl.source)
			.fill_letter(info_cl.fill_letter)
			.namespace(info_cl.namespace)
			.build()
			.unwrap();

		let report = ReportBuilder::default()
			.used_key(info.key)
			.source_txt(info.source)
			.result_txt("XR$HNK^BJQ@?".to_owned())
			.fill_letter(info.fill_letter)
			.filled(true)
			.def_namespace(info.namespace)
			.build()
			.unwrap();

		assert_eq!(processor.cipher().unwrap(), report);
	}

	#[test]
	fn decipher_operation_with_custom_namespace_is_completed() {
		let dns="ABCDEFGHIJKLMNOPQRSTUVWXYZ @$^&*/?.-".to_owned();
		let info = TestArgInfo {
			key: "AFJCRXLUDNLZ@$^?".to_owned(),
			source: "XR$HNK^BJQ@?".to_owned(),
			fill_letter: Some('H'),
			namespace: Some(dns)
		};
		let info_cl = info.clone();

		let processor = ProcessorBuilder::default()
			.key(info_cl.key)
			.source(info_cl.source)
			.fill_letter(info_cl.fill_letter)
			.namespace(info_cl.namespace)
			.build()
			.unwrap();

		let report = ReportBuilder::default()
			.used_key(info.key)
			.source_txt(info.source)
			.result_txt("TEST CODIGOH".to_owned())
			.fill_letter(info.fill_letter)
			.filled(false)
			.def_namespace(info.namespace)
			.build()
			.unwrap();

		assert_eq!(processor.decipher().unwrap(), report);
	}
}
