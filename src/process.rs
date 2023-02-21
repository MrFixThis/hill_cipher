use derive_builder::Builder;
use rulinalg::matrix::{Matrix, BaseMatrix};

use crate::error::Result;

/// Default namespace used by the `cypher` and `decypher` algorithms to do its
/// work. This value is obscured if a `custom namespace` is specified.
pub const DEFAULT_NAMESPACE: [char; 27] = [
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' '
];

/// A `Cypher` and `Decypher` processor.
///
/// The processor exposes the application's cypher and decypher capabilities
/// based on the `Hill's Method` cypher.
#[derive(Debug, Default, Builder)]
pub struct Processor<'a> {
	key: &'a str,
	source: &'a str,
	fill_letter: Option<&'a char>,
	name_space: Option<&'a[char]>,
}

impl Processor<'_> {
	/// Cyphers the given `source text` based on the information passed
	/// to the program, like a `key`, a `fill letter` or a possibe
	/// `custom namespace`.
	pub fn cypher(&self) -> Result<String> {
		// definition of which namespace to use: either the user supplied
		// namespace or the default one
		let namespace = self.define_namespace()?;

		// Checking the validness of the user suplied info
		self.chek_information(&namespace)?;

		// cheking if the key's length is square. If it is not, then the
		// key is filled
		let kl = self.key.len();
		let key = if !is_square(kl) {
			fill_txt(self.key, self.fill_letter.unwrap(), turn_perfect_sqrt(kl), kl)
		} else {
			self.key.to_uppercase()
		};

		// getting the checked key's length square root
		let dimension = (key.len() as f64).sqrt() as usize;

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
		let key_mtrx = txt_mtrx_repr(dimension, dimension, &key, &namespace)?;
		let key_det = key_mtrx.clone().det(); // it is clone because det() consumes
											  // the the receiver

		// checking if the supplied key is valid to use for the cypher process
		if key_det == 0.0 || has_any_factor(
			key_det as usize, namespace.len() as usize
		) {
			return Err(
				format!(
					"the specified key cannot be used. [det 0 or has factors with {}]",
					namespace.len()
				 ).into()
			)
		}

		// spliting the source text into as many parts as the dimension of
		// the key's matrix representation, and turning its values
		// into its respective numeric representation inside the namespace
		let src_mtrx = txt_mtrx_repr(
			source.len() / dimension,
			dimension,
			&source, &namespace)?;

		// turning the cyphered_parts into its textual representation
		Ok(translate_txt_mtrx(&key_mtrx, src_mtrx, &namespace))
	}

	/// Decyphers the given `cyphered text` based on the information passed
	/// to the program, like the known `key`, or a possible known `fill letter`
	/// and a `custom namespace` used in the `cypher` process.
	pub fn decypher(&self) -> Result<String> {
		// definition of which namespace to use: either the user supplied
		// namespace or the default one
		let namespace = self.define_namespace()?;

		// Checking the validness of the user suplied info
		self.chek_information(&namespace)?;

	}

	/// Defines the `namespace` to use in the `cypher` and `decypher` processes.
	/// If a custom namespace is not defined, the default one is used. In case
	/// that the user defined namespace has a length < 27, then
	/// (ProcessingError)[crate::error::Error] is returned.
	fn define_namespace(&self) -> Result<&[char]> {
		match self.name_space {
			Some(ns) => {
				let ns_len = ns.len();
				if ns_len < DEFAULT_NAMESPACE.len() || !is_square(ns_len) {
					return Err(
						format!(
							"the suplied namespace has to have a length >= 27",
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

// pub(crate) fn get_inverse_matrix<T>(source: &Matrix<T>) -> Matrix<T>
// where
// 	T: Ord + PartialOrd
// {
//
// }

/// Turns a given (Matrix)[rulinalg::matrix::Matrix] filled with the positions
/// of each character of a passed `text`, into its textual representations
/// inside the supplied namespace.
fn translate_txt_mtrx(
	key_mtrx: &Matrix<f64>,
	src_mtrx: Matrix<f64>,
	namespace: &[char]
) -> String {
	// cyphering the source text's matrix
	let mtrx_mul = (key_mtrx * src_mtrx).transpose();
	mtrx_mul
		.into_vec()
		.into_iter()
		.map(|v| namespace[(v % (namespace.len() - 1) as f64) as usize])
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

/// Turns a given number a perfect square upwards it own value.
fn turn_perfect_sqrt(dim: usize) -> usize {
	let mut base = dim as f64;
	let mut sqrt;
	loop {
		sqrt = base.sqrt();
		if sqrt * sqrt == base {
			return base as usize;
		}
		base += 1.0;
	}
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
	fn key_with_not_square_length_is_filled() {
		let key = "ABCDE".to_owned();
		let kl = key.len();
		let fill_char = 'L';

		assert_eq!(
			fill_txt(&key, &fill_char, turn_perfect_sqrt(kl), kl),
			"ABCDELLLL"
		);
	}

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
	fn source_text_is_turned_into_mtrx_repr() {
		let _key = "FJCRXLUDN";
		let src = "CODIGO".to_owned();
		let dim = (_key.len() as f64).sqrt() as usize;

		assert_eq!(
			txt_mtrx_repr(src.len()/dim, dim, &src, &DEFAULT_NAMESPACE).unwrap(),
			Matrix::new(dim, src.len()/dim,
						vec![2.0, 8.0,
							 14.0, 6.0,
							 3.0, 14.0]
						 )
		);
	}

	#[test]
	fn source_text_parts_are_turned_into_cyphered_parts() {
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

	//TODO: Build the test for the whole cypher and decypher processes
	//checking the validness of the input info
}
