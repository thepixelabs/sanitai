//! Aho-Corasick keyword pre-filter for the regex detector.
//!
//! Before running expensive regex matching, we ask whether any of a rule's
//! keywords appear in the haystack. If none do, the rule is skipped entirely.
//! This provides O(n) linear scan over the haystack per chunk instead of
//! running O(k) regex passes.
//!
//! The filter returns a [u64; 4] bitmask (256 rule slots). Bit N is set iff
//! rule N has at least one keyword match in the haystack.
//! Rules with no keywords (keywords: None) are always considered to have
//! matched — their bits are pre-set in `always_fire_mask`.

use aho_corasick::AhoCorasick;

/// Maximum number of rules supported by the bitmask. 256 slots = [u64; 4].
pub const MAX_RULES: usize = 256;

pub struct KeywordFilter {
    ac: AhoCorasick,
    /// Maps AC pattern index → rule index (u16 supports 65535 rules).
    pattern_to_rule: Vec<u16>,
    /// Bitmask of rules that fire unconditionally (no keyword gate).
    always_fire_mask: [u64; 4],
    pub rule_count: usize,
}

impl KeywordFilter {
    /// Build from a slice of (rule_index, keywords) pairs.
    /// `keywords` is `None` for rules with no keyword gate.
    pub fn build(rules: &[(usize, Option<&'static [&'static str]>)]) -> Self {
        let mut patterns: Vec<&'static str> = Vec::new();
        let mut pattern_to_rule: Vec<u16> = Vec::new();
        let mut always_fire_mask = [0u64; 4];

        for (rule_idx, keywords) in rules {
            assert!(*rule_idx < MAX_RULES, "rule index exceeds MAX_RULES=256");
            match keywords {
                None => {
                    // No keyword gate — always fires.
                    let bucket = rule_idx / 64;
                    let bit = rule_idx % 64;
                    always_fire_mask[bucket] |= 1u64 << bit;
                }
                Some(kws) => {
                    for kw in kws.iter() {
                        patterns.push(kw);
                        pattern_to_rule.push(*rule_idx as u16);
                    }
                }
            }
        }

        let ac = AhoCorasick::new(&patterns).expect("AhoCorasick build must succeed");

        Self {
            ac,
            pattern_to_rule,
            always_fire_mask,
            rule_count: rules.len(),
        }
    }

    /// Scan `hay` and return a bitmask where bit N is set iff rule N can fire.
    /// Zero heap allocation per call.
    #[inline]
    pub fn scan(&self, hay: &str) -> [u64; 4] {
        let mut mask = self.always_fire_mask;
        for mat in self.ac.find_iter(hay) {
            let rule_idx = self.pattern_to_rule[mat.pattern().as_usize()] as usize;
            let bucket = rule_idx / 64;
            let bit = rule_idx % 64;
            mask[bucket] |= 1u64 << bit;
        }
        mask
    }

    /// Check if rule `idx` fires given the mask.
    #[inline]
    pub fn rule_fires(mask: &[u64; 4], idx: usize) -> bool {
        mask[idx / 64] & (1u64 << (idx % 64)) != 0
    }
}
