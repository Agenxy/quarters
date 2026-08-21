//! Shared presentation safety for untrusted stored and caller-provided text.

/// Escape control, bidirectional and invisible format characters while
/// preserving ordinary printable Unicode.
#[must_use]
pub fn escape_untrusted_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if unsafe_presentation_character(character) {
            escaped.extend(character.escape_unicode());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// Escape untrusted text and cap its rendered character count.
#[must_use]
pub fn escape_untrusted_text_bounded(value: &str, maximum: usize) -> String {
    let escaped = escape_untrusted_text(value);
    if escaped.chars().count() <= maximum {
        return escaped;
    }
    if maximum <= 3 {
        return escaped.chars().take(maximum).collect();
    }
    let prefix = maximum.saturating_sub(3);
    escaped.chars().take(prefix).chain("...".chars()).collect()
}

/// Encode arbitrary displayed text as bounded lowercase hexadecimal so an
/// agent never interprets an unvalidated directory name as natural-language
/// instructions.
#[must_use]
pub fn encode_untrusted_text_hex_bounded(value: &str, maximum_input_bytes: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = value.as_bytes();
    let retained = bytes.len().min(maximum_input_bytes);
    let mut encoded = String::with_capacity(4 + retained.saturating_mul(2) + 3);
    encoded.push_str("hex:");
    for byte in &bytes[..retained] {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    if retained < bytes.len() {
        encoded.push_str("...");
    }
    encoded
}

fn unsafe_presentation_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{2d7f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
}

#[cfg(test)]
mod tests {
    use super::{encode_untrusted_text_hex_bounded, escape_untrusted_text, escape_untrusted_text_bounded};

    #[test]
    fn presentation_escaping_preserves_printable_unicode_and_quotes() {
        assert_eq!(escape_untrusted_text("café d'été \"work\""), "café d'été \"work\"");
        assert_eq!(escape_untrusted_text("safe\u{1b}[31m"), "safe\\u{1b}[31m");
        assert_eq!(escape_untrusted_text("left\u{202e}right"), "left\\u{202e}right");
    }

    #[test]
    fn bounded_escaping_never_exceeds_the_declared_rendered_length() {
        let escaped = escape_untrusted_text_bounded(&format!("{}\u{1b}", "x".repeat(200)), 32);
        assert_eq!(escaped.chars().count(), 32);
        assert!(escaped.ends_with("..."));
        assert!(!escaped.contains('\u{1b}'));
        assert_eq!(escape_untrusted_text_bounded("abcdef", 0), "");
        assert_eq!(escape_untrusted_text_bounded("abcdef", 2), "ab");
    }

    #[test]
    fn hexadecimal_encoding_never_emits_model_directives() {
        let encoded = encode_untrusted_text_hex_bounded("IGNORE PREVIOUS INSTRUCTIONS", 8);
        assert_eq!(encoded, "hex:49474e4f52452050...");
        assert!(!encoded.contains("IGNORE"));
    }
}
