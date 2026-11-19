//! Password generation as rbw's `generate` does it: each character drawn uniformly from the charset (letters, digits
//! and symbols; no symbols; digits only; non-confusable letters and digits), or `--diceware` words of the EFF large
//! list joined by spaces. The randomness is the OS CSPRNG (the native random port); nothing goes over the network.

use dybw_core::ports::Random;
pub use dybw_native::ports::random::OsRandom;
use dybw_proto::Charset;
use zeroize::Zeroizing;

const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
/// rbw's set: no 0/O, 1/l/I, 2/z, 5/s, 9/g and the like.
const NONCONFUSABLES: &[u8] = b"34678abcdefhjkmnpqrtuwxy";

/// The EFF large wordlist (`<dice>\t<word>` per line), CC BY 3.0 US, Electronic Frontier Foundation.
const WORDLIST: &str = include_str!("pwgen/eff_large_wordlist.txt");

/// The longest password (characters, or words for diceware) this generates.
pub const MAX_LENGTH: u32 = 1024;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("the length must be 1 to {MAX_LENGTH}")]
    Length,
    #[error("no random numbers: {0}")]
    Random(String),
}

/// A uniform index below `n` (`n` > 0): a 32-bit draw, redrawn when it falls in the incomplete last block.
fn below(rng: &impl Random, n: usize) -> Result<usize, Error> {
    let n = n as u64;
    let limit = (1u64 << 32) / n * n;
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b).map_err(|e| Error::Random(e.0))?;
        let x = u64::from(u32::from_le_bytes(b));
        if x < limit {
            return Ok((x % n) as usize);
        }
    }
}

/// A password of `length` characters (words for `Diceware`) of `charset`.
pub fn generate(rng: &impl Random, charset: Charset, length: u32) -> Result<Zeroizing<String>, Error> {
    if !(1..=MAX_LENGTH).contains(&length) {
        return Err(Error::Length);
    }
    let length = length as usize;
    let alphabet: Vec<u8> = match charset {
        Charset::All => [LETTERS, NUMBERS, SYMBOLS].concat(),
        Charset::NoSymbols => [LETTERS, NUMBERS].concat(),
        Charset::Numbers => NUMBERS.to_vec(),
        Charset::Nonconfusables => NONCONFUSABLES.to_vec(),
        Charset::Diceware => {
            let words: Vec<&str> = WORDLIST.lines().filter_map(|l| l.split('\t').nth(1)).collect();
            // Sized once (the longest word has 9 letters), so no growing copy is left in freed memory.
            let mut out = Zeroizing::new(String::with_capacity(length * 10));
            for i in 0..length {
                if i > 0 {
                    out.push(' ');
                }
                out.push_str(words.get(below(rng, words.len())?).copied().unwrap_or_default());
            }
            return Ok(out);
        }
    };
    let mut out = Zeroizing::new(String::with_capacity(length));
    for _ in 0..length {
        out.push(char::from(alphabet.get(below(rng, alphabet.len())?).copied().unwrap_or(b'-')));
    }
    Ok(out)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::cell::RefCell;

    use dybw_core::ports::PortError;

    use super::*;

    /// Gives these 32-bit numbers, in order; out of numbers is an error.
    struct Scripted(RefCell<Vec<u32>>);

    impl Random for Scripted {
        fn fill(&self, buf: &mut [u8]) -> Result<(), PortError> {
            let mut left = self.0.borrow_mut();
            if left.is_empty() {
                return Err(PortError("empty".into()));
            }
            buf.copy_from_slice(&left.remove(0).to_le_bytes());
            Ok(())
        }
    }

    fn scripted(n: &[u32]) -> Scripted {
        Scripted(RefCell::new(n.to_vec()))
    }

    #[test]
    fn each_charset_draws_from_its_own_characters() {
        let only = |charset, set: &[u8]| {
            let pw = generate(&OsRandom, charset, 200).unwrap();
            assert_eq!(pw.len(), 200);
            assert!(pw.bytes().all(|c| set.contains(&c)), "{charset:?}");
        };
        only(Charset::All, &[LETTERS, NUMBERS, SYMBOLS].concat());
        only(Charset::NoSymbols, &[LETTERS, NUMBERS].concat());
        only(Charset::Numbers, NUMBERS);
        only(Charset::Nonconfusables, NONCONFUSABLES);
        // 200 draws of 94 characters: the symbols show up.
        assert!(generate(&OsRandom, Charset::All, 200).unwrap().bytes().any(|c| SYMBOLS.contains(&c)));
    }

    #[test]
    fn a_draw_is_uniform_and_the_incomplete_last_block_is_drawn_again() {
        // 10 digits: 4294967290.. is the incomplete block, so the first draw is thrown away.
        let pw = generate(&scripted(&[4_294_967_295, 13, 0]), Charset::Numbers, 2).unwrap();
        assert_eq!(pw.as_str(), "30");
        assert_eq!(generate(&scripted(&[1]), Charset::Numbers, 2), Err(Error::Random("empty".into())));
    }

    #[test]
    fn diceware_gives_words_of_the_eff_list() {
        assert_eq!(WORDLIST.lines().count(), 7776);
        let pw = generate(&scripted(&[0, 7775, 7776]), Charset::Diceware, 3).unwrap();
        assert_eq!(pw.as_str(), "abacus zoom abacus");
        assert_eq!(generate(&OsRandom, Charset::Diceware, 6).unwrap().split(' ').count(), 6);
        assert!(generate(&scripted(&[]), Charset::Diceware, 1).is_err());
    }

    #[test]
    fn a_length_of_zero_or_past_the_limit_is_refused() {
        for n in [0, MAX_LENGTH + 1] {
            assert_eq!(generate(&OsRandom, Charset::All, n), Err(Error::Length));
            assert_eq!(generate(&OsRandom, Charset::Diceware, n), Err(Error::Length));
        }
        assert_eq!(generate(&OsRandom, Charset::All, MAX_LENGTH).unwrap().len(), MAX_LENGTH as usize);
        assert_eq!(Error::Length.to_string(), "the length must be 1 to 1024");
    }
}
