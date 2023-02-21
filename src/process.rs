use derive_builder::Builder;
use rulinalg::matrix::{Matrix, BaseMatrix};
use modinverse;

use crate::error::Result;

/// Default namespace used by the `cipher` and `decipher` algorithms to do its
/// work. This value is obscured if a `custom namespace` is specified.
pub const DEFAULT_NAMESPACE: [char; 26] = [
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
];

/// A `Cipher` and `Decipher` processor.
///
/// The processor exposes the application's cipher and decipher capabilities
/// based on the `Hill's Method` cipher.
#[derive(Debug, Default, Builder)]
pub struct Processor<'a> {
	key: &'a str,
	source: &'a str,
	fill_letter: Option<&'a char>,
	name_space: Option<&'a[char]>,
}

impl Processor<'_> {
	/// Ciphers the given `source text` based on the information passed
	/// to the program, like a `key`, a `fill letter` or a possibe
	/// `custom namespace`.
	pub fn cipher(&self) -> Result<String> {
		// definition of which namespace to use: either the user supplied
		// namespace or the default one
		let namespace = self.define_namespace()?;

		// Checking the validness of the user suplied info
		self.chek_information(namespace)?;

		// getting the checked key's length square root
		let dimension = (self.key.len() as f64).sqrt() as usize;

		// cheking if the source text's length is divisible by the above dimension.
		// If it is not, the the text is filled
		let sl = self.source.len();
		let source = if !is_divisble(self.source.len(), &dimension) {
			fill_txt(
				self.source,
				self.fill_letter.unwrap(),
				turn_divisible(sl, &dimension), sl)
		} else {
			self.source.to_uppercase()
		};

		// getting the key's matrix representation and its determinant
		let key_mtrx_repr = txt_mtrx_repr(dimension, dimension, self.key, namespace)?;
		let key_mtrx_det = key_mtrx_repr.clone().det(); // it is clone because det() consumes
											  // the the receiver
		// checking if the supplied key is valid to use for the cipher process
		if key_mtrx_det == 0.0 || has_any_factor(
			key_mtrx_det as usize, namespace.len() as usize
		) {
			return Err(
				format!(
					"the specified key cannot be used. [matrix's det 0 or has factors with {}]",
					namespace.len()
				 ).into()
			)
		}

		// spliting the source text into as many parts as the square root of
		// the key's matrix representation dimension, and turning its values
		// into its respective numeric representation inside the namespace
		let src_mtrx_repr = txt_mtrx_repr(
			source.len() / dimension,
			dimension,
			&source,
			namespace
		)?;

		// turning the ciphered parts into its textual representation
		Ok(translate_txt_mtrx(&key_mtrx_repr, src_mtrx_repr, namespace))
	}

	/// Deciphers the given `ciphered text` based on the information passed
	/// to the program, like the known `key`, or a possible known `fill letter`
	/// and a `custom namespace` used in the `cipher` process.
	pub fn decipher(&self) -> Result<String> {
		// definition of which namespace to use: either the user supplied
		// namespace or the default one
		let namespace = self.define_namespace()?;

		// Checking the validness of the user suplied info
		self.chek_information(&namespace)?;

		// getting the passed key's length square root
		let dimension = (self.key.len() as f64).sqrt() as usize;

		// getting the key's matrix representation and its inverse
		let key_mtrx_repr = txt_mtrx_repr(dimension, dimension, self.key, namespace)?;
		let key_mtrx_inv = key_mtrx_repr.clone().inverse();

		// deciphering the given source text
		match key_mtrx_inv {
			Ok(inverse) => {
				// getting modular multiplicative inverse of the keys's
				// matrix representation determinant
				let mod_mul_inv = modinverse::modinverse(
					key_mtrx_repr.det() as u64,
					dimension as u64
				).unwrap() as f64;

				// turning the ciphered text into its matrix representation
				// and multipling its values by the modular multiplicative
				// inverse of the keys's matrix representation
				let mut src_mtrx_repr = txt_mtrx_repr(
					self.source.len() / dimension,
					dimension,
					&self.source,
					namespace
				)?;
				for v in src_mtrx_repr.mut_data() { let _ = *v * mod_mul_inv; }

				// turning the deciphered parts into its textual representation
				Ok(translate_txt_mtrx(
						&inverse,
						src_mtrx_repr,
						namespace,
					)
				)
			},
			// if the passed key's matrix representation has no an inverse,
			// then the key length is not square
			Err(_) => Err(
				"invalid or malformed key. the key has no a square length".into()
			)
		}
	}

	/// Defines the `namespace` to use in the `cipher` and `decipher` processes.
	/// If a custom namespace is not defined, the default one is used. In case
	/// that the user defined namespace has a length < 29, then
	/// (ProcessingError)[crate::error::Error] is returned.
	fn define_namespace(&self) -> Result<&[char]> {
		match self.name_space {
			Some(ns) => {
				let ns_len = ns.len();
				if ns_len < DEFAULT_NAMESPACE.len() || !is_square(ns_len) {
					return Err(
						format!(
							"the supplied namespace must to has a square length"
						).into()
					);
				}
				Ok(ns)
			},
			None => Ok(&DEFAULT_NAMESPACE)
		}
	}

	/// Cheks the validness of the user supplied information. If something went
	/// wrong in the cheking, (ProcessingError)[crate::error::Error] is returned.
	fn chek_information(&self, namespace: &[char]) -> Result<()> {
		// checking if the suplied key has a square length
		if !is_square(self.key.len()) {
			return Err("the suplied key must has a square length".into())
		}

		// cheking if the supplied fill character is inside the namespace
		if let Some(f) = self.fill_letter {
			Self::is_in_namespace(f, &namespace)?;
		}

		// cheking if the supplied key and source text have an unkwnon character
		let mut target = self.key;
		for _ in 0..2 {
			for c in target.chars() {
				Self::is_in_namespace(&c, &namespace)?;
			}
			target = self.source;
		}

		Ok(())
	}

	/// Checks if the supplied `character` is inside the given namespace; if it
	/// is not, (ProcessingError)[crate::error::Error] is returned.
	fn is_in_namespace(char: &char, namespace: &[char]) -> Result<()> {
		if namespace.into_iter().find(|&c| *c == *char) == None {
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
	namespace: &[char]
) -> String {
	// ciphering the source text's matrix
	let mtrx_mul = (key_mtrx * src_mtrx).transpose();
	mtrx_mul
		.into_vec()
		.into_iter()
		.map(|v| namespace[(v % namespace.len() as f64) as usize])
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
		.map(|c| char_pos(&c, namespace) as f64)
		.collect();

	Ok(Matrix::new(rows, cols, parts).transpose())
}

/// Fills a given `text` with a specified character (a - b) times.
fn fill_txt(txt: &str, char: &char, a: usize, b: usize) -> String {
	let reps = a - b;

	if reps != 0 {
		let append = char.to_string().repeat(reps);
		format!("{}{}", txt, append).to_uppercase()
	} else {
		txt.to_owned()
	}
}

/// Retrives the given character's `position` inside the namespace specified.
fn char_pos(char: &char, namespace: &[char]) -> usize {
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

/// Checks if the supplied number is square.
fn is_square(num: usize) -> bool {
	let sqrt = (num as f64).sqrt();

	num == 0 || num == 1 || (sqrt * sqrt == num as f64)
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
			fill_txt(&src, &fill_char, turn_divisible(sl, &key_dim), sl),
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
	fn source_text_is_turned_into_matrix_representation() {
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
	fn source_text_parts_are_turned_into_ciphered_text() {
		let namespace = &DEFAULT_NAMESPACE;
		let key = "FJCRXLUDN";
		let src = "CODIGO".to_owned();
		let dim = (key.len() as f64).sqrt() as usize;
		let key_mtrx = txt_mtrx_repr(dim, dim, &key, namespace).unwrap();
		let src_mtrx = txt_mtrx_repr(src.len()/dim, dim, &src, namespace).unwrap();

		assert_eq!(
			translate_txt_mtrx(&key_mtrx, src_mtrx, namespace),
			String::from("WLPGSE")
		);
	}

	#[test]
	fn name() {
	    unimplemented!();
	}

	//TODO: Build the test for the whole cipher and decipher processes
	//checking the validness of the input info
}
