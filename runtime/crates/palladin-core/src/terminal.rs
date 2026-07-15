#[must_use]
pub fn shorten_identifier(value: &str) -> String {
    if value.chars().any(is_unsafe_terminal_character) {
        return "[invalid-id]".to_owned();
    }
    if value.chars().count() <= 16 {
        return value.to_owned();
    }
    let prefix = value.chars().take(8).collect::<String>();
    let suffix = value
        .chars()
        .rev()
        .take(6)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{prefix}…{suffix}")
}

#[must_use]
pub fn safe_terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if is_unsafe_terminal_character(character) {
                '�'
            } else {
                character
            }
        })
        .collect()
}

#[must_use]
pub fn is_safe_terminal_text(value: &str) -> bool {
    !value.chars().any(is_unsafe_terminal_character)
}

const fn is_unsafe_terminal_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
        )
}

#[cfg(test)]
mod tests {
    use super::{is_safe_terminal_text, safe_terminal_text, shorten_identifier};

    #[test]
    fn identifiers_use_the_shared_prefix_and_suffix_contract() {
        assert_eq!(shorten_identifier("1234567890123456"), "1234567890123456");
        assert_eq!(shorten_identifier("12345678901234567"), "12345678…234567");
        assert_eq!(
            shorten_identifier("12345678\u{202e}spoofed"),
            "[invalid-id]"
        );
    }

    #[test]
    fn terminal_text_neutralizes_lines_ansi_and_bidi_controls() {
        assert_eq!(
            safe_terminal_text("first\n\u{1b}[31m\u{202e}second"),
            "first��[31m�second"
        );
        assert!(!is_safe_terminal_text("line\nsecond"));
        assert!(!is_safe_terminal_text("spoof\u{202e}name"));
        assert!(is_safe_terminal_text("Zażółć gęślą jaźń"));
    }
}
