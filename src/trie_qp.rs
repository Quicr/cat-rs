// Note: qp-trie doesn't support Serialize/Deserialize, so we can't derive them
use std::collections::HashMap;
use qp_trie::Trie;

#[derive(Debug, Clone, PartialEq)]
pub struct PrefixTrie {
    trie: Trie<Vec<u8>, String>,
    size: usize,
}

impl Default for PrefixTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefixTrie {
    pub fn new() -> Self {
        Self {
            trie: Trie::new(),
            size: 0,
        }
    }

    pub fn insert(&mut self, pattern: &str, value: String) {
        let key = pattern.as_bytes().to_vec();
        if !self.trie.contains_key(&key) {
            self.size += 1;
        }
        self.trie.insert(key, value);
    }

    pub fn search_prefix(&self, text: &str) -> Vec<&str> {
        let mut matches = Vec::new();
        let text_bytes = text.as_bytes();
        
        // Get all entries that are prefixes of the text
        for (key, value) in self.trie.iter() {
            if text_bytes.starts_with(key) {
                matches.push(value.as_str());
            }
        }
        
        matches
    }

    pub fn contains_prefix(&self, text: &str) -> bool {
        let text_bytes = text.as_bytes();
        
        // Check if any key in the trie is a prefix of the text
        for (key, _) in self.trie.iter() {
            if text_bytes.starts_with(key) {
                return true;
            }
        }
        
        false
    }

    pub fn get_all_patterns(&self) -> Vec<String> {
        self.trie.keys().map(|k| String::from_utf8_lossy(k).into_owned()).collect()
    }

    pub fn remove(&mut self, pattern: &str) -> bool {
        let key = pattern.as_bytes().to_vec();
        if self.trie.remove(&key).is_some() {
            self.size -= 1;
            true
        } else {
            false
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SuffixTrie {
    trie: Trie<Vec<u8>, String>,
    size: usize,
}

impl Default for SuffixTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl SuffixTrie {
    pub fn new() -> Self {
        Self {
            trie: Trie::new(),
            size: 0,
        }
    }

    pub fn insert(&mut self, pattern: &str, value: String) {
        // Store the pattern as-is, we'll reverse during search
        let key = pattern.as_bytes().to_vec();
        if !self.trie.contains_key(&key) {
            self.size += 1;
        }
        self.trie.insert(key, value);
    }

    pub fn search_suffix(&self, text: &str) -> Vec<&str> {
        let mut matches = Vec::new();
        
        // Check if text ends with any of our stored patterns
        for (key, value) in self.trie.iter() {
            let pattern = std::str::from_utf8(key).unwrap();
            if text.ends_with(pattern) {
                matches.push(value.as_str());
            }
        }
        
        matches
    }

    pub fn contains_suffix(&self, text: &str) -> bool {
        // Check if text ends with any of our stored patterns
        for (key, _) in self.trie.iter() {
            let pattern = std::str::from_utf8(key).unwrap();
            if text.ends_with(pattern) {
                return true;
            }
        }
        
        false
    }

    pub fn get_all_patterns(&self) -> Vec<String> {
        self.trie.keys().map(|k| String::from_utf8_lossy(k).into_owned()).collect()
    }

    pub fn remove(&mut self, pattern: &str) -> bool {
        let key = pattern.as_bytes().to_vec();
        if self.trie.remove(&key).is_some() {
            self.size -= 1;
            true
        } else {
            false
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

pub struct UriMatcher {
    prefix_trie: PrefixTrie,
    suffix_trie: SuffixTrie,
    exact_patterns: HashMap<String, String>,
    regex_patterns: Vec<(regex::Regex, String)>,
    hash_patterns: HashMap<String, String>,
}

impl Default for UriMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl UriMatcher {
    pub fn new() -> Self {
        Self {
            prefix_trie: PrefixTrie::new(),
            suffix_trie: SuffixTrie::new(),
            exact_patterns: HashMap::new(),
            regex_patterns: Vec::new(),
            hash_patterns: HashMap::new(),
        }
    }

    pub fn add_pattern(
        &mut self,
        pattern: crate::claims::UriPattern,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match pattern {
            crate::claims::UriPattern::Exact(uri) => {
                let key = uri.clone();
                self.exact_patterns.insert(key, uri);
            }
            crate::claims::UriPattern::Prefix(prefix) => {
                let value = prefix.clone();
                self.prefix_trie.insert(&prefix, value);
            }
            crate::claims::UriPattern::Suffix(suffix) => {
                let value = suffix.clone();
                self.suffix_trie.insert(&suffix, value);
            }
            crate::claims::UriPattern::Regex(pattern) => {
                let regex = regex::Regex::new(&pattern)?;
                self.regex_patterns.push((regex, pattern));
            }
            crate::claims::UriPattern::Hash(hash) => {
                self.hash_patterns.insert(hash.clone(), hash);
            }
        }
        Ok(())
    }

    pub fn matches(&self, uri: &str) -> bool {
        // Check exact match
        if self.exact_patterns.contains_key(uri) {
            return true;
        }

        // Check prefix match
        if self.prefix_trie.contains_prefix(uri) {
            return true;
        }

        // Check suffix match
        if self.suffix_trie.contains_suffix(uri) {
            return true;
        }

        // Check regex patterns
        for (regex, _) in &self.regex_patterns {
            if regex.is_match(uri) {
                return true;
            }
        }

        // Check hash match
        let uri_hash = crate::crypto::hash_sha256(uri.as_bytes());
        let uri_hash_hex = hex::encode(uri_hash);
        if self.hash_patterns.contains_key(&uri_hash_hex) {
            return true;
        }

        false
    }

    pub fn get_matching_patterns(&self, uri: &str) -> Vec<String> {
        let mut matches = Vec::new();

        // Check exact match
        if let Some(pattern) = self.exact_patterns.get(uri) {
            matches.push(format!("exact:{}", pattern));
        }

        // Check prefix matches
        for prefix_match in self.prefix_trie.search_prefix(uri) {
            matches.push(format!("prefix:{}", prefix_match));
        }

        // Check suffix matches
        for suffix_match in self.suffix_trie.search_suffix(uri) {
            matches.push(format!("suffix:{}", suffix_match));
        }

        // Check regex patterns
        for (regex, pattern) in &self.regex_patterns {
            if regex.is_match(uri) {
                matches.push(format!("regex:{}", pattern));
            }
        }

        // Check hash match
        let uri_hash = crate::crypto::hash_sha256(uri.as_bytes());
        let uri_hash_hex = hex::encode(uri_hash);
        if let Some(pattern) = self.hash_patterns.get(&uri_hash_hex) {
            matches.push(format!("hash:{}", pattern));
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_trie_basic_operations() {
        let mut trie = PrefixTrie::new();

        trie.insert("hello", "greeting".to_string());
        trie.insert("help", "assistance".to_string());
        trie.insert("world", "earth".to_string());

        assert!(trie.contains_prefix("hello"));
        assert!(trie.contains_prefix("help"));
        assert!(!trie.contains_prefix("he"));

        let matches = trie.search_prefix("hello world");
        assert!(matches.contains(&"greeting"));
    }

    #[test]
    fn test_suffix_trie_basic_operations() {
        let mut trie = SuffixTrie::new();

        trie.insert(".com", "commercial".to_string());
        trie.insert(".org", "organization".to_string());
        trie.insert("ing", "gerund".to_string());

        assert!(trie.contains_suffix("example.com"));
        assert!(trie.contains_suffix("running"));
        assert!(!trie.contains_suffix("example"));

        let matches = trie.search_suffix("programming");
        assert!(matches.contains(&"gerund"));
    }

    #[test]
    fn test_uri_matcher() {
        let mut matcher = UriMatcher::new();

        matcher
            .add_pattern(crate::claims::UriPattern::Exact(
                "https://example.com".to_string(),
            ))
            .unwrap();
        matcher
            .add_pattern(crate::claims::UriPattern::Prefix(
                "https://api.".to_string(),
            ))
            .unwrap();
        matcher
            .add_pattern(crate::claims::UriPattern::Suffix(".json".to_string()))
            .unwrap();

        assert!(matcher.matches("https://example.com"));
        assert!(matcher.matches("https://api.service.com"));
        assert!(matcher.matches("/data/users.json"));
        assert!(!matcher.matches("http://unknown.com"));
    }
}