use secrecy::SecretString;
use zeroize::Zeroizing;

pub const DEFAULT_PASSWORD_LENGTH: usize = 24;
pub const MAX_PASSWORD_LENGTH: usize = 4096;
pub const DEFAULT_SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CharacterClass {
    Lowercase,
    Uppercase,
    Digit,
    Symbol,
}

pub const ALL_CLASSES: [CharacterClass; 4] = [
    CharacterClass::Lowercase,
    CharacterClass::Uppercase,
    CharacterClass::Digit,
    CharacterClass::Symbol,
];

/// Explicit constraints for a runtime-generated password. Every listed required class appears at
/// least once; an impossible combination is an error and is never silently weakened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordPolicy {
    pub length: usize,
    pub allowed: Vec<CharacterClass>,
    pub required: Vec<CharacterClass>,
    pub symbols: String,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: DEFAULT_PASSWORD_LENGTH,
            allowed: ALL_CLASSES.to_vec(),
            required: ALL_CLASSES.to_vec(),
            symbols: DEFAULT_SYMBOLS.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PasswordPolicyError {
    #[error("the password policy cannot be satisfied")]
    Unsatisfiable,
    #[error("secure random generation failed")]
    RandomGenerationFailed,
}

impl PasswordPolicy {
    /// Validates the complete policy before any random byte is drawn.
    pub fn validate(&self) -> Result<(), PasswordPolicyError> {
        let symbols_valid = !self.symbols.is_empty()
            && self
                .symbols
                .chars()
                .all(|symbol| symbol.is_ascii_punctuation())
            && self
                .symbols
                .chars()
                .enumerate()
                .all(|(index, symbol)| !self.symbols[..index].contains(symbol));
        let allows_symbols = self.allowed.contains(&CharacterClass::Symbol);
        if self.length == 0
            || self.length > MAX_PASSWORD_LENGTH
            || self.allowed.is_empty()
            || self.required.len() > self.length
            || self
                .required
                .iter()
                .any(|class| !self.allowed.contains(class))
            || (allows_symbols && !symbols_valid)
            || has_duplicates(&self.allowed)
            || has_duplicates(&self.required)
        {
            return Err(PasswordPolicyError::Unsatisfiable);
        }
        Ok(())
    }

    fn alphabet(&self, class: CharacterClass) -> &str {
        match class {
            CharacterClass::Lowercase => LOWERCASE,
            CharacterClass::Uppercase => UPPERCASE,
            CharacterClass::Digit => DIGITS,
            CharacterClass::Symbol => &self.symbols,
        }
    }
}

/// Generates a password with the operating-system CSPRNG and unbiased rejection sampling.
pub fn generate_password(policy: &PasswordPolicy) -> Result<SecretString, PasswordPolicyError> {
    policy.validate()?;
    let mut pool = Zeroizing::new(Vec::<u8>::new());
    for class in &policy.allowed {
        pool.extend_from_slice(policy.alphabet(*class).as_bytes());
    }
    let mut password = Zeroizing::new(Vec::<u8>::with_capacity(policy.length));
    for class in &policy.required {
        password.push(pick(policy.alphabet(*class).as_bytes())?);
    }
    while password.len() < policy.length {
        password.push(pick(&pool)?);
    }
    for index in (1..password.len()).rev() {
        let other = uniform_index(index + 1)?;
        password.swap(index, other);
    }
    let text = String::from_utf8(std::mem::take(&mut *password))
        .map_err(|_| PasswordPolicyError::Unsatisfiable)?;
    Ok(SecretString::from(text))
}

fn pick(alphabet: &[u8]) -> Result<u8, PasswordPolicyError> {
    Ok(alphabet[uniform_index(alphabet.len())?])
}

fn uniform_index(bound: usize) -> Result<usize, PasswordPolicyError> {
    let bound = u32::try_from(bound).map_err(|_| PasswordPolicyError::Unsatisfiable)?;
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| PasswordPolicyError::RandomGenerationFailed)?;
        let value = u32::from_le_bytes(bytes);
        if value < zone {
            return usize::try_from(value % bound).map_err(|_| PasswordPolicyError::Unsatisfiable);
        }
    }
}

fn has_duplicates(classes: &[CharacterClass]) -> bool {
    let mut sorted = classes.to_vec();
    sorted.sort();
    sorted.windows(2).any(|pair| pair[0] == pair[1])
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use secrecy::ExposeSecret;

    use super::*;

    fn class_of(character: char, policy: &PasswordPolicy) -> Option<CharacterClass> {
        ALL_CLASSES
            .into_iter()
            .find(|class| policy.alphabet(*class).contains(character))
    }

    #[test]
    fn generated_passwords_honor_length_alphabet_and_required_classes() {
        let policies = [
            PasswordPolicy::default(),
            PasswordPolicy {
                length: 4,
                ..PasswordPolicy::default()
            },
            PasswordPolicy {
                length: 12,
                allowed: vec![CharacterClass::Digit, CharacterClass::Symbol],
                required: vec![CharacterClass::Symbol],
                symbols: "-_".to_owned(),
            },
            PasswordPolicy {
                length: MAX_PASSWORD_LENGTH,
                ..PasswordPolicy::default()
            },
        ];
        for policy in policies {
            for _ in 0..200 {
                let password = generate_password(&policy).expect("satisfiable policy");
                let password = password.expose_secret();
                assert_eq!(password.chars().count(), policy.length);
                let classes = password
                    .chars()
                    .map(|character| class_of(character, &policy).expect("known class"))
                    .collect::<BTreeSet<_>>();
                assert!(classes.iter().all(|class| policy.allowed.contains(class)));
                assert!(policy.required.iter().all(|class| classes.contains(class)));
            }
        }
    }

    #[test]
    fn unsatisfiable_or_invalid_policies_are_rejected_before_generation() {
        let default = PasswordPolicy::default();
        let cases = [
            PasswordPolicy {
                length: 3,
                ..default.clone()
            },
            PasswordPolicy {
                length: 0,
                required: Vec::new(),
                ..default.clone()
            },
            PasswordPolicy {
                length: MAX_PASSWORD_LENGTH + 1,
                ..default.clone()
            },
            PasswordPolicy {
                allowed: vec![CharacterClass::Lowercase],
                ..default.clone()
            },
            PasswordPolicy {
                allowed: Vec::new(),
                required: Vec::new(),
                ..default.clone()
            },
            PasswordPolicy {
                symbols: String::new(),
                ..default.clone()
            },
            PasswordPolicy {
                symbols: "a!".to_owned(),
                ..default.clone()
            },
            PasswordPolicy {
                symbols: " !".to_owned(),
                ..default.clone()
            },
            PasswordPolicy {
                symbols: "!!".to_owned(),
                ..default.clone()
            },
            PasswordPolicy {
                symbols: "€".to_owned(),
                ..default.clone()
            },
            PasswordPolicy {
                required: vec![CharacterClass::Digit, CharacterClass::Digit],
                ..default.clone()
            },
        ];
        for policy in cases {
            assert_eq!(
                generate_password(&policy).map(|_| ()),
                Err(PasswordPolicyError::Unsatisfiable),
                "{policy:?}"
            );
        }
        assert!(
            PasswordPolicy {
                allowed: vec![CharacterClass::Lowercase],
                required: Vec::new(),
                symbols: String::new(),
                length: 8,
            }
            .validate()
            .is_ok(),
            "an unused symbol set is irrelevant when symbols are not allowed"
        );
    }

    #[test]
    fn characters_are_uniform_across_the_allowed_alphabet() {
        let policy = PasswordPolicy {
            length: 64,
            required: Vec::new(),
            ..PasswordPolicy::default()
        };
        let alphabet_size = 26 + 26 + 10 + policy.symbols.len();
        let samples = 1_500;
        let mut counts = BTreeMap::<char, u64>::new();
        for _ in 0..samples {
            for character in generate_password(&policy).unwrap().expose_secret().chars() {
                *counts.entry(character).or_default() += 1;
            }
        }
        assert_eq!(
            counts.len(),
            alphabet_size,
            "every allowed character occurs"
        );
        let total = (samples * policy.length) as f64;
        let expected = total / alphabet_size as f64;
        let chi_square = counts
            .values()
            .map(|count| {
                let delta = *count as f64 - expected;
                delta * delta / expected
            })
            .sum::<f64>();
        // 89 degrees of freedom: the 99.999th percentile is about 160.
        assert!(chi_square < 160.0, "chi-square {chi_square}");
    }

    #[test]
    fn generated_passwords_do_not_repeat() {
        let policy = PasswordPolicy::default();
        let passwords = (0..2_000)
            .map(|_| {
                generate_password(&policy)
                    .unwrap()
                    .expose_secret()
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(passwords.len(), 2_000);
    }

    #[test]
    fn required_characters_are_not_fixed_to_leading_positions() {
        let policy = PasswordPolicy {
            length: 8,
            allowed: vec![CharacterClass::Lowercase, CharacterClass::Digit],
            required: vec![CharacterClass::Digit],
            symbols: String::new(),
        };
        let first_is_digit = (0..2_000)
            .filter(|_| {
                generate_password(&policy)
                    .unwrap()
                    .expose_secret()
                    .starts_with(|character: char| character.is_ascii_digit())
            })
            .count();
        // A fixed placement would make every first character a digit.
        assert!((150..1_000).contains(&first_is_digit), "{first_is_digit}");
    }
}
