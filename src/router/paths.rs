use std::collections::HashMap;

/// A compiled path pattern with support for `:param` segments and `?` suffix (list).
#[derive(Debug, Clone)]
pub struct PathPattern {
    segments: Vec<Segment>,
}

#[derive(Debug, Clone)]
enum Segment {
    Literal(String),
    Param(String),
    /// Trailing `?` marker means this pattern handles LIST operations
    ListMarker,
}

impl PathPattern {
    pub fn new(pattern: &str) -> Self {
        let trimmed = pattern.trim_matches('/');
        let segments = trimmed
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| {
                if s == "?" {
                    Segment::ListMarker
                } else if let Some(name) = s.strip_prefix(':') {
                    Segment::Param(name.to_string())
                } else {
                    Segment::Literal(s.to_string())
                }
            })
            .collect();

        Self { segments }
    }

    /// Try to match a path against this pattern, returning extracted parameters.
    pub fn match_path(&self, path: &str) -> Option<HashMap<String, String>> {
        let trimmed = path.trim_matches('/');
        let parts: Vec<&str> = if trimmed.is_empty() {
            vec![]
        } else {
            trimmed.split('/').collect()
        };

        // Filter out the list marker for length comparison
        let non_marker_segments: Vec<_> = self
            .segments
            .iter()
            .filter(|s| !matches!(s, Segment::ListMarker))
            .collect();

        if parts.len() != non_marker_segments.len() {
            return None;
        }

        let mut params = HashMap::new();
        for (part, segment) in parts.iter().zip(non_marker_segments.iter()) {
            match segment {
                Segment::Literal(lit) => {
                    if *part != lit.as_str() {
                        return None;
                    }
                }
                Segment::Param(name) => {
                    params.insert(name.clone(), part.to_string());
                }
                Segment::ListMarker => unreachable!(),
            }
        }

        Some(params)
    }

    /// Whether this pattern ends with a list marker.
    pub fn is_list_pattern(&self) -> bool {
        self.segments
            .last()
            .map(|s| matches!(s, Segment::ListMarker))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_match() {
        let p = PathPattern::new("config");
        assert!(p.match_path("config").is_some());
        assert!(p.match_path("config/").is_some());
        assert!(p.match_path("other").is_none());
    }

    #[test]
    fn test_param_match() {
        let p = PathPattern::new("wallets/:name");
        let m = p.match_path("wallets/my-wallet").unwrap();
        assert_eq!(m.get("name").unwrap(), "my-wallet");
        assert!(p.match_path("wallets/").is_none());
        assert!(p.match_path("wallets/a/b").is_none());
    }

    #[test]
    fn test_nested_param() {
        let p = PathPattern::new("wallets/:name/addresses/new");
        let m = p.match_path("wallets/test/addresses/new").unwrap();
        assert_eq!(m.get("name").unwrap(), "test");
    }

    #[test]
    fn test_list_pattern() {
        let p = PathPattern::new("wallets/?");
        assert!(p.is_list_pattern());
        let m = p.match_path("wallets").unwrap();
        assert!(m.is_empty());
    }
}
