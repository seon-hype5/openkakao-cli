//! Exact-and-unique matching shared by every desktop backend.

/// The result of matching a secret target label against observed labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactMatch {
    Found(usize),
    NotFound,
    Ambiguous(usize),
}

/// Match case-sensitively and byte-for-byte, refusing duplicate candidates.
///
/// `None` represents a label the platform could not read. It is never treated
/// as a match and indices always refer to the original candidate sequence.
pub fn exact_unique_match<'a, I>(candidates: I, target: &str) -> ExactMatch
where
    I: IntoIterator<Item = Option<&'a str>>,
{
    let mut found_index = None;
    let mut count = 0;

    for (index, candidate) in candidates.into_iter().enumerate() {
        if candidate == Some(target) {
            found_index.get_or_insert(index);
            count += 1;
        }
    }

    match (found_index, count) {
        (None, _) => ExactMatch::NotFound,
        (Some(index), 1) => ExactMatch::Found(index),
        (Some(_), count) => ExactMatch::Ambiguous(count),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_exact_case_sensitive_text() {
        let labels = [Some("Alice"), Some("Alice and Bob"), Some("alice")];
        assert_eq!(exact_unique_match(labels, "Alice"), ExactMatch::Found(0));
        assert_eq!(exact_unique_match(labels, "Ali"), ExactMatch::NotFound);
    }

    #[test]
    fn preserves_original_index_while_ignoring_unreadable_labels() {
        let labels = [None, Some("Self"), None];
        assert_eq!(exact_unique_match(labels, "Self"), ExactMatch::Found(1));
    }

    #[test]
    fn refuses_duplicate_exact_labels() {
        let labels = [Some("Self"), Some("Self")];
        assert_eq!(exact_unique_match(labels, "Self"), ExactMatch::Ambiguous(2));
    }

    #[test]
    fn does_not_normalize_whitespace_or_unicode() {
        let labels = [Some("Self"), Some("Self "), Some("Ｓｅｌｆ")];
        assert_eq!(exact_unique_match(labels, "Self"), ExactMatch::Found(0));
        assert_eq!(exact_unique_match(labels, " Self"), ExactMatch::NotFound);
    }
}
