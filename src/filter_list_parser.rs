//! ABP / EasyList filter list line parser.
//!
//! Supports 4 rule types that map to the privacy engine's capabilities:
//!   - Domain blocks (`||domain^`)
//!   - URL patterns (`||domain/path`)
//!   - Cosmetic selectors (`##selector` or `domain##selector`)
//!   - Exception rules (`@@||domain^`)
//!
//! Everything else (regex rules, options, extended CSS) is silently skipped.

/// A single parsed filter list rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedRule {
    /// `||domain^`  →  dns_block + tracker_set_cookie
    DomainBlock { domain: String },
    /// `||domain/path`  →  tracker_script_patterns
    UrlPattern { domain: String, path: String },
    /// `##selector`  →  body_rewrite.remove_selectors (global)
    CosmeticGlobal { selector: String },
    /// `domain##selector`  →  domain-scoped cosmetic
    CosmeticDomainScoped { domain: String, selector: String },
    /// `@@||domain^`  →  exception (overrides filter-list blocks, not manual config)
    Exception { domain: String },
}

/// Aggregate statistics from parsing a filter list.
#[derive(Debug, Clone, Default)]
pub struct ParseStats {
    pub total_lines: usize,
    pub domain_blocks: usize,
    pub url_patterns: usize,
    pub cosmetic_global: usize,
    pub cosmetic_domain_scoped: usize,
    pub exceptions: usize,
    pub skipped_comments: usize,
    pub skipped_unsupported: usize,
}

/// Parse a single ABP filter list line into a rule (or None if skipped).
pub fn parse_line(line: &str) -> Option<ParsedRule> {
    let line = line.trim();

    // Skip empty lines
    if line.is_empty() {
        return None;
    }

    // Skip comments and header lines
    if line.starts_with('!') || line.starts_with('[') {
        return None;
    }

    // Exception rules: @@||domain^
    if let Some(rest) = line.strip_prefix("@@||") {
        return parse_exception(rest);
    }

    // Cosmetic rules: ##selector or domain##selector
    if let Some(idx) = line.find("##") {
        return parse_cosmetic(line, idx);
    }

    // Domain/URL block rules: ||domain^  or ||domain/path
    if let Some(rest) = line.strip_prefix("||") {
        return parse_domain_or_url(rest);
    }

    // Everything else is unsupported (regex, option-heavy rules, etc.)
    None
}

/// Parse the full text of a filter list into rules + stats.
pub fn parse_filter_list(text: &str) -> (Vec<ParsedRule>, ParseStats) {
    let mut rules = Vec::new();
    let mut stats = ParseStats::default();

    for line in text.lines() {
        stats.total_lines += 1;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('!') || trimmed.starts_with('[') {
            stats.skipped_comments += 1;
            continue;
        }

        match parse_line(trimmed) {
            Some(rule) => {
                match &rule {
                    ParsedRule::DomainBlock { .. } => stats.domain_blocks += 1,
                    ParsedRule::UrlPattern { .. } => stats.url_patterns += 1,
                    ParsedRule::CosmeticGlobal { .. } => stats.cosmetic_global += 1,
                    ParsedRule::CosmeticDomainScoped { .. } => stats.cosmetic_domain_scoped += 1,
                    ParsedRule::Exception { .. } => stats.exceptions += 1,
                }
                rules.push(rule);
            }
            None => {
                stats.skipped_unsupported += 1;
            }
        }
    }

    (rules, stats)
}

fn parse_exception(rest: &str) -> Option<ParsedRule> {
    // @@||domain^  or @@||domain^$options
    // We only handle simple domain exceptions.
    let domain_part = rest.split('$').next()?;
    let domain_part = domain_part.strip_suffix('^').unwrap_or(domain_part);
    let domain = normalize_filter_domain(domain_part)?;
    // Reject if it contains path separators — those are URL-level exceptions we skip
    if domain.contains('/') {
        return None;
    }
    Some(ParsedRule::Exception { domain })
}

fn parse_cosmetic(line: &str, separator_idx: usize) -> Option<ParsedRule> {
    let domain_part = &line[..separator_idx];
    let selector = &line[separator_idx + 2..];

    if selector.is_empty() {
        return None;
    }

    // Skip ABP extended CSS pseudo-classes we can't handle
    // (e.g. :has(), :has-text(), :matches-css(), :-abp-has(), etc.)
    if contains_extended_css(selector) {
        tracing::debug!(selector, "skipping extended CSS selector");
        return None;
    }

    // Validate CSS selector at parse time
    if selector.parse::<lol_html::Selector>().is_err() {
        tracing::debug!(selector, "skipping invalid CSS selector");
        return None;
    }

    if domain_part.is_empty() {
        Some(ParsedRule::CosmeticGlobal {
            selector: selector.to_string(),
        })
    } else {
        // domain_part may contain commas for multi-domain rules.
        // We only support single-domain scoped rules for simplicity.
        // For multi-domain, take the first domain.
        let first_domain = domain_part.split(',').next()?;
        let domain = normalize_filter_domain(first_domain)?;
        Some(ParsedRule::CosmeticDomainScoped {
            domain,
            selector: selector.to_string(),
        })
    }
}

fn parse_domain_or_url(rest: &str) -> Option<ParsedRule> {
    // Strip trailing options ($third-party, $script, etc.)
    let without_options = rest.split('$').next()?;

    // Check for path component: ||domain/path^
    if let Some(slash_idx) = without_options.find('/') {
        let domain_part = &without_options[..slash_idx];
        let path_part = without_options[slash_idx..].trim_end_matches('^');
        let domain = normalize_filter_domain(domain_part)?;
        if path_part.is_empty() || path_part == "/" {
            // Just a trailing slash, treat as domain block
            return Some(ParsedRule::DomainBlock { domain });
        }
        Some(ParsedRule::UrlPattern {
            domain,
            path: path_part.to_string(),
        })
    } else {
        // Pure domain block: ||domain^
        let domain_part = without_options.trim_end_matches('^');
        let domain = normalize_filter_domain(domain_part)?;
        Some(ParsedRule::DomainBlock { domain })
    }
}

fn normalize_filter_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    // Reject wildcards and regex-like patterns
    if trimmed.contains('*') || trimmed.contains('?') || trimmed.contains('{') {
        return None;
    }
    // Must look like a domain (has at least one dot or is a known TLD)
    // We accept single-label for flexibility but skip clearly invalid entries
    if trimmed.contains(' ') {
        return None;
    }
    Some(trimmed)
}

fn contains_extended_css(selector: &str) -> bool {
    // ABP/uBO extended CSS pseudo-classes that lol_html can't parse
    let extended = [
        ":has(",
        ":has-text(",
        ":matches-css(",
        ":-abp-has(",
        ":-abp-contains(",
        ":contains(",
        ":xpath(",
        ":nth-ancestor(",
        ":upward(",
        ":remove(",
        ":style(",
        ":matches-path(",
    ];
    let lower = selector.to_ascii_lowercase();
    extended.iter().any(|ext| lower.contains(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain_block() {
        assert_eq!(
            parse_line("||doubleclick.net^"),
            Some(ParsedRule::DomainBlock {
                domain: "doubleclick.net".into()
            })
        );
    }

    #[test]
    fn parse_domain_block_with_options() {
        assert_eq!(
            parse_line("||ads.example.com^$third-party"),
            Some(ParsedRule::DomainBlock {
                domain: "ads.example.com".into()
            })
        );
    }

    #[test]
    fn parse_domain_block_no_caret() {
        assert_eq!(
            parse_line("||tracker.example.com"),
            Some(ParsedRule::DomainBlock {
                domain: "tracker.example.com".into()
            })
        );
    }

    #[test]
    fn parse_url_pattern() {
        assert_eq!(
            parse_line("||example.com/ads/banner.js^"),
            Some(ParsedRule::UrlPattern {
                domain: "example.com".into(),
                path: "/ads/banner.js".into()
            })
        );
    }

    #[test]
    fn parse_url_pattern_with_options() {
        assert_eq!(
            parse_line("||cdn.example.com/tracking.js$script"),
            Some(ParsedRule::UrlPattern {
                domain: "cdn.example.com".into(),
                path: "/tracking.js".into()
            })
        );
    }

    #[test]
    fn parse_exception_rule() {
        assert_eq!(
            parse_line("@@||example.com^"),
            Some(ParsedRule::Exception {
                domain: "example.com".into()
            })
        );
    }

    #[test]
    fn parse_exception_with_options() {
        assert_eq!(
            parse_line("@@||allowed.example.com^$document"),
            Some(ParsedRule::Exception {
                domain: "allowed.example.com".into()
            })
        );
    }

    #[test]
    fn parse_cosmetic_global() {
        assert_eq!(
            parse_line("##.ad-banner"),
            Some(ParsedRule::CosmeticGlobal {
                selector: ".ad-banner".into()
            })
        );
    }

    #[test]
    fn parse_cosmetic_domain_scoped() {
        assert_eq!(
            parse_line("example.com##.sidebar-ad"),
            Some(ParsedRule::CosmeticDomainScoped {
                domain: "example.com".into(),
                selector: ".sidebar-ad".into()
            })
        );
    }

    #[test]
    fn skip_comment_lines() {
        assert_eq!(parse_line("! This is a comment"), None);
        assert_eq!(parse_line("[Adblock Plus 2.0]"), None);
    }

    #[test]
    fn skip_empty_lines() {
        assert_eq!(parse_line(""), None);
        assert_eq!(parse_line("   "), None);
    }

    #[test]
    fn skip_extended_css() {
        assert_eq!(parse_line("##.ad:has(.tracker)"), None);
        assert_eq!(parse_line("##div:-abp-has(span)"), None);
        assert_eq!(parse_line("##p:has-text(sponsored)"), None);
    }

    #[test]
    fn skip_wildcard_domains() {
        assert_eq!(parse_line("||*.example.com^"), None);
    }

    #[test]
    fn skip_regex_rules() {
        // Pure regex rules don't start with || or ##
        assert_eq!(parse_line("/ads\\.js/"), None);
    }

    #[test]
    fn domain_normalization_case_insensitive() {
        assert_eq!(
            parse_line("||DoubleClick.NET^"),
            Some(ParsedRule::DomainBlock {
                domain: "doubleclick.net".into()
            })
        );
    }

    #[test]
    fn domain_block_trailing_slash_treated_as_domain() {
        assert_eq!(
            parse_line("||example.com/"),
            Some(ParsedRule::DomainBlock {
                domain: "example.com".into()
            })
        );
    }

    #[test]
    fn parse_filter_list_full() {
        let text = "\
[Adblock Plus 2.0]
! Title: Test List
! Last modified: 2026-01-01

||doubleclick.net^
||ads.example.com^$third-party
||cdn.example.com/tracking.js$script
@@||safe.example.com^
##.ad-banner
example.com##.sidebar-ad
/some-regex-rule/
||*.wildcard.example^
";
        let (rules, stats) = parse_filter_list(text);
        assert_eq!(stats.total_lines, 12);
        assert_eq!(stats.skipped_comments, 3);
        assert_eq!(stats.domain_blocks, 2);
        assert_eq!(stats.url_patterns, 1);
        assert_eq!(stats.exceptions, 1);
        assert_eq!(stats.cosmetic_global, 1);
        assert_eq!(stats.cosmetic_domain_scoped, 1);
        assert_eq!(stats.skipped_unsupported, 2); // regex + wildcard
        assert_eq!(rules.len(), 6);
    }

    #[test]
    fn parse_stats_empty_input() {
        let (rules, stats) = parse_filter_list("");
        assert_eq!(rules.len(), 0);
        assert_eq!(stats.total_lines, 0);
    }

    #[test]
    fn cosmetic_multi_domain_takes_first() {
        let result = parse_line("a.com,b.com##.ad");
        assert_eq!(
            result,
            Some(ParsedRule::CosmeticDomainScoped {
                domain: "a.com".into(),
                selector: ".ad".into()
            })
        );
    }

    #[test]
    fn exception_with_path_is_skipped() {
        // @@||example.com/path^ is a URL-level exception, we only do domain-level
        assert_eq!(parse_line("@@||example.com/some/path^"), None);
    }

    #[test]
    fn cosmetic_empty_selector_skipped() {
        assert_eq!(parse_line("##"), None);
        assert_eq!(parse_line("example.com##"), None);
    }

    #[test]
    fn parse_line_handles_whitespace() {
        assert_eq!(
            parse_line("  ||doubleclick.net^  "),
            Some(ParsedRule::DomainBlock {
                domain: "doubleclick.net".into()
            })
        );
    }

    #[test]
    fn complex_valid_selector() {
        // lol_html should accept standard CSS selectors
        let result = parse_line("##div[class*=\"ad-\"]");
        assert!(result.is_some());
        if let Some(ParsedRule::CosmeticGlobal { selector }) = result {
            assert_eq!(selector, "div[class*=\"ad-\"]");
        } else {
            panic!("expected CosmeticGlobal");
        }
    }

    #[test]
    fn domain_block_trailing_dot_stripped() {
        assert_eq!(
            parse_line("||example.com.^"),
            Some(ParsedRule::DomainBlock {
                domain: "example.com".into()
            })
        );
    }
}
