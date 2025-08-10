use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrieNode {
    pub children: HashMap<char, Box<TrieNode>>,
    pub is_terminal: bool,
    pub value: Option<String>,
}

impl TrieNode {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            is_terminal: false,
            value: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrefixTrie {
    pub root: TrieNode,
    pub size: usize,
}

impl PrefixTrie {
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
            size: 0,
        }
    }

    pub fn insert(&mut self, pattern: &str, value: String) {
        let mut current = &mut self.root;

        for ch in pattern.chars() {
            current = current
                .children
                .entry(ch)
                .or_insert_with(|| Box::new(TrieNode::new()));
        }

        if !current.is_terminal {
            self.size += 1;
        }

        current.is_terminal = true;
        current.value = Some(value);
    }

    pub fn search_prefix(&self, text: &str) -> Vec<&str> {
        let mut matches = Vec::new();
        let mut current = &self.root;
        let chars: Vec<char> = text.chars().collect();

        for (_i, &ch) in chars.iter().enumerate() {
            if let Some(next_node) = current.children.get(&ch) {
                current = next_node;

                if current.is_terminal {
                    if let Some(ref value) = current.value {
                        matches.push(value.as_str());
                    }
                }
            } else {
                break;
            }
        }

        matches
    }

    pub fn contains_prefix(&self, text: &str) -> bool {
        let mut current = &self.root;

        for ch in text.chars() {
            if let Some(next_node) = current.children.get(&ch) {
                current = next_node;
                if current.is_terminal {
                    return true;
                }
            } else {
                return false;
            }
        }

        current.is_terminal
    }

    pub fn get_all_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        self.collect_patterns(&self.root, String::new(), &mut patterns);
        patterns
    }

    fn collect_patterns(&self, node: &TrieNode, prefix: String, patterns: &mut Vec<String>) {
        if node.is_terminal {
            patterns.push(prefix.clone());
        }

        for (ch, child) in &node.children {
            let mut new_prefix = prefix.clone();
            new_prefix.push(*ch);
            self.collect_patterns(child, new_prefix, patterns);
        }
    }

    pub fn remove(&mut self, pattern: &str) -> bool {
        let removed = Self::remove_recursive_static(&mut self.root, pattern, 0);
        if removed {
            self.size -= 1;
        }
        removed
    }

    fn remove_recursive_static(node: &mut TrieNode, pattern: &str, index: usize) -> bool {
        if index == pattern.len() {
            if node.is_terminal {
                node.is_terminal = false;
                node.value = None;
                return true;
            }
            return false;
        }

        let ch = pattern.chars().nth(index).unwrap();

        if let Some(mut child) = node.children.remove(&ch) {
            let child_removed = Self::remove_recursive_static(&mut child, pattern, index + 1);

            if child_removed {
                if !child.is_terminal && child.children.is_empty() {
                    // Don't reinsert the child, it should be deleted
                    // Return true to indicate successful removal, let parent handle its own cleanup
                    return true;
                } else {
                    // Reinsert the child since it still has value or other children
                    node.children.insert(ch, child);
                    return true;
                }
            } else {
                // No removal occurred, reinsert the child
                node.children.insert(ch, child);
            }
        }

        false
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuffixTrie {
    pub root: TrieNode,
    pub size: usize,
}

impl SuffixTrie {
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
            size: 0,
        }
    }

    pub fn insert(&mut self, pattern: &str, value: String) {
        let reversed: String = pattern.chars().rev().collect();
        let mut current = &mut self.root;

        for ch in reversed.chars() {
            current = current
                .children
                .entry(ch)
                .or_insert_with(|| Box::new(TrieNode::new()));
        }

        if !current.is_terminal {
            self.size += 1;
        }

        current.is_terminal = true;
        current.value = Some(value);
    }

    pub fn search_suffix(&self, text: &str) -> Vec<&str> {
        let mut matches = Vec::new();
        let reversed: String = text.chars().rev().collect();
        let mut current = &self.root;

        for ch in reversed.chars() {
            if let Some(next_node) = current.children.get(&ch) {
                current = next_node;

                if current.is_terminal {
                    if let Some(ref value) = current.value {
                        matches.push(value.as_str());
                    }
                }
            } else {
                break;
            }
        }

        matches
    }

    pub fn contains_suffix(&self, text: &str) -> bool {
        let reversed: String = text.chars().rev().collect();
        let mut current = &self.root;

        for ch in reversed.chars() {
            if let Some(next_node) = current.children.get(&ch) {
                current = next_node;
                if current.is_terminal {
                    return true;
                }
            } else {
                return false;
            }
        }

        current.is_terminal
    }

    pub fn get_all_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        self.collect_patterns(&self.root, String::new(), &mut patterns);
        patterns
            .into_iter()
            .map(|p| p.chars().rev().collect())
            .collect()
    }

    fn collect_patterns(&self, node: &TrieNode, prefix: String, patterns: &mut Vec<String>) {
        if node.is_terminal {
            patterns.push(prefix.clone());
        }

        for (ch, child) in &node.children {
            let mut new_prefix = prefix.clone();
            new_prefix.push(*ch);
            self.collect_patterns(child, new_prefix, patterns);
        }
    }

    pub fn remove(&mut self, pattern: &str) -> bool {
        let reversed: String = pattern.chars().rev().collect();
        let removed = Self::remove_recursive_static(&mut self.root, &reversed, 0);
        if removed {
            self.size -= 1;
        }
        removed
    }

    fn remove_recursive_static(node: &mut TrieNode, pattern: &str, index: usize) -> bool {
        if index == pattern.len() {
            if node.is_terminal {
                node.is_terminal = false;
                node.value = None;
                return true;
            }
            return false;
        }

        let ch = pattern.chars().nth(index).unwrap();

        if let Some(mut child) = node.children.remove(&ch) {
            let child_removed = Self::remove_recursive_static(&mut child, pattern, index + 1);

            if child_removed {
                if !child.is_terminal && child.children.is_empty() {
                    // Don't reinsert the child, it should be deleted
                    // Return true to indicate successful removal, let parent handle its own cleanup
                    return true;
                } else {
                    // Reinsert the child since it still has value or other children
                    node.children.insert(ch, child);
                    return true;
                }
            } else {
                // No removal occurred, reinsert the child
                node.children.insert(ch, child);
            }
        }

        false
    }
}

pub struct UriMatcher {
    prefix_trie: PrefixTrie,
    suffix_trie: SuffixTrie,
    exact_patterns: HashMap<String, String>,
    regex_patterns: Vec<(regex::Regex, String)>,
    hash_patterns: HashMap<String, String>,
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
        if !self.prefix_trie.search_prefix(uri).is_empty() {
            return true;
        }

        // Check suffix match
        if !self.suffix_trie.search_suffix(uri).is_empty() {
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
