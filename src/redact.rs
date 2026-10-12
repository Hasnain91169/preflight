//! PII redaction.
//!
//! Each rule is a regex plus an optional checksum validator. Validators
//! cut false positives: a 16-digit number is only treated as a card if it
//! passes Luhn, an IBAN only if it passes mod-97, a PPSN only if its check
//! letter is correct.
//!
//! The same value always maps to the same token (`[EMAIL_1]` everywhere it
//! appears), so an LLM can still reason about "the same person" without
//! seeing who they are. Original values never appear in the report.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiKind {
    Email,
    PaymentCard,
    Iban,
    UkNino,
    IrishPpsn,
    Phone,
}

impl PiiKind {
    pub fn label(self) -> &'static str {
        match self {
            PiiKind::Email => "EMAIL",
            PiiKind::PaymentCard => "CARD",
            PiiKind::Iban => "IBAN",
            PiiKind::UkNino => "NINO",
            PiiKind::IrishPpsn => "PPSN",
            PiiKind::Phone => "PHONE",
        }
    }
}

struct Rule {
    kind: PiiKind,
    re: Regex,
    validate: Option<fn(&str) -> bool>,
}

/// Rules run in order. Long digit patterns (cards, IBANs) go before phone
/// numbers so the phone rule cannot swallow part of a card number.
static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    // These patterns are fixed at compile time, so a failure here is a
    // programming bug, not a runtime condition. `expect` is acceptable.
    let rule = |kind, pattern: &str, validate| Rule {
        kind,
        re: Regex::new(pattern).expect("built-in PII regex must compile"),
        validate,
    };
    vec![
        rule(
            PiiKind::Email,
            r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b",
            None,
        ),
        rule(
            PiiKind::PaymentCard,
            r"\b(?:\d[ -]?){12,18}\d\b",
            Some(luhn_valid),
        ),
        rule(
            PiiKind::Iban,
            r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b",
            Some(iban_valid),
        ),
        rule(
            PiiKind::UkNino,
            r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b",
            None,
        ),
        rule(
            PiiKind::IrishPpsn,
            r"\b\d{7}[A-W][A-IW]?\b",
            Some(ppsn_valid),
        ),
        rule(
            PiiKind::Phone,
            r"(?:\+(?:44|353)\s?(?:\(0\)\s?)?|\b0)\d{1,4}[\s-]?\d{3,4}[\s-]?\d{3,4}\b",
            None,
        ),
    ]
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PiiFinding {
    pub kind: PiiKind,
    /// Distinct values of this kind found.
    pub distinct: usize,
    /// Total occurrences, including repeats of the same value.
    pub occurrences: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Redaction {
    pub text: String,
    pub findings: Vec<PiiFinding>,
}

#[derive(Default)]
struct TokenState {
    /// (kind, normalised value) -> token number for that kind
    tokens: HashMap<(PiiKind, String), usize>,
    distinct: HashMap<PiiKind, usize>,
    occurrences: HashMap<PiiKind, usize>,
}

impl TokenState {
    fn token_for(&mut self, kind: PiiKind, value: &str) -> String {
        let key = (kind, normalise(value));
        let next = self.distinct.get(&kind).copied().unwrap_or(0) + 1;
        let n = *self.tokens.entry(key).or_insert_with(|| {
            self.distinct.insert(kind, next);
            next
        });
        *self.occurrences.entry(kind).or_insert(0) += 1;
        format!("[{}_{}]", kind.label(), n)
    }

    fn into_findings(self) -> Vec<PiiFinding> {
        let mut findings: Vec<PiiFinding> = self
            .occurrences
            .into_iter()
            .map(|(kind, occurrences)| PiiFinding {
                kind,
                distinct: self.distinct.get(&kind).copied().unwrap_or(0),
                occurrences,
            })
            .collect();
        findings.sort_by_key(|f| f.kind);
        findings
    }
}

/// Strip spaces and dashes and lowercase, so "07700 900123" and
/// "07700900123" get the same token.
fn normalise(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Redact all PII in `input`.
///
/// Takes a borrowed `&str`, so the caller keeps ownership of the original.
/// Internally the working text is a `Cow`: while no rule has matched it
/// stays borrowed and nothing is copied; the first match allocates.
pub fn redact(input: &str) -> Redaction {
    let mut state = TokenState::default();
    let mut current: Cow<'_, str> = Cow::Borrowed(input);

    for rule in RULES.iter() {
        let replaced = rule.re.replace_all(&current, |caps: &Captures| {
            let matched = &caps[0];
            let is_real = rule.validate.map_or(true, |check| check(matched));
            if is_real {
                state.token_for(rule.kind, matched)
            } else {
                matched.to_string()
            }
        });
        // `replace_all` returns Cow::Borrowed when nothing changed.
        // Only swap in the new String when something actually did.
        let changed = match replaced {
            Cow::Owned(s) => Some(s),
            Cow::Borrowed(_) => None,
        };
        if let Some(s) = changed {
            current = Cow::Owned(s);
        }
    }

    Redaction {
        text: current.into_owned(),
        findings: state.into_findings(),
    }
}

fn digits(value: &str) -> Vec<u32> {
    value.chars().filter_map(|c| c.to_digit(10)).collect()
}

/// Luhn checksum used by payment cards.
pub fn luhn_valid(value: &str) -> bool {
    let ds = digits(value);
    if !(13..=19).contains(&ds.len()) {
        return false;
    }
    let sum: u32 = ds
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// ISO 13616 mod-97 check. Done digit by digit so it never overflows.
pub fn iban_valid(value: &str) -> bool {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    let (head, tail) = compact.split_at(4);
    let mut remainder: u32 = 0;
    for c in tail.chars().chain(head.chars()) {
        let n = match c {
            '0'..='9' => c as u32 - '0' as u32,
            'A'..='Z' => c as u32 - 'A' as u32 + 10,
            _ => return false,
        };
        let width = if n >= 10 { 100 } else { 10 };
        remainder = (remainder * width + n) % 97;
    }
    remainder == 1
}

/// Irish PPS number: 7 digits, a check letter, optional second letter.
pub fn ppsn_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(8..=9).contains(&bytes.len()) {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &b) in bytes[..7].iter().enumerate() {
        if !b.is_ascii_digit() {
            return false;
        }
        sum += u32::from(b - b'0') * (8 - i as u32);
    }
    if let Some(&second) = bytes.get(8) {
        let v = if second == b'W' {
            0
        } else {
            u32::from(second - b'A') + 1
        };
        sum += v * 9;
    }
    let remainder = sum % 23;
    let expected = if remainder == 0 {
        b'W'
    } else {
        b'A' + (remainder as u8) - 1
    };
    bytes[7] == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_email_with_stable_tokens() {
        let r = redact("Mail a@b.com, then a@b.com again, then c@d.ie");
        assert_eq!(
            r.text,
            "Mail [EMAIL_1], then [EMAIL_1] again, then [EMAIL_2]"
        );
        assert_eq!(
            r.findings,
            vec![PiiFinding {
                kind: PiiKind::Email,
                distinct: 2,
                occurrences: 3
            }]
        );
    }

    #[test]
    fn untouched_text_is_unchanged() {
        let input = "Nothing sensitive here.";
        let r = redact(input);
        assert_eq!(r.text, input);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn card_requires_luhn() {
        assert!(luhn_valid("4111 1111 1111 1111"));
        assert!(!luhn_valid("4111 1111 1111 1112"));
        let r = redact("Card 4111-1111-1111-1111 and order 4111111111111112");
        assert_eq!(r.text, "Card [CARD_1] and order 4111111111111112");
    }

    #[test]
    fn iban_requires_mod97() {
        assert!(iban_valid("IE29 AIBK 9311 5212 3456 78"));
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(!iban_valid("GB82WEST12345698765433"));
        let r = redact("Pay IE29 AIBK 9311 5212 3456 78 today");
        assert_eq!(r.text, "Pay [IBAN_1] today");
    }

    #[test]
    fn ppsn_requires_check_letter() {
        assert!(ppsn_valid("1234567T"));
        assert!(ppsn_valid("1234567FA"));
        assert!(!ppsn_valid("1234567A"));
        let r = redact("PPSN 1234567T, ref 1234567A");
        assert_eq!(r.text, "PPSN [PPSN_1], ref 1234567A");
    }

    #[test]
    fn uk_and_irish_phones() {
        let r = redact("Call +44 7700 900123, 07700900123 or +353 87 123 4567 or 01 234 5678");
        assert_eq!(
            r.text,
            "Call [PHONE_1], [PHONE_2] or [PHONE_3] or [PHONE_4]"
        );
    }

    #[test]
    fn uk_nino() {
        let r = redact("NI number JG 10 37 59 A on file");
        assert_eq!(r.text, "NI number [NINO_1] on file");
        // QQ is HMRC's dummy prefix and is never issued, so it is left alone.
        let r = redact("Example QQ 12 34 56 C");
        assert_eq!(r.text, "Example QQ 12 34 56 C");
    }
}
