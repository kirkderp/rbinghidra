use std::collections::HashMap;

use serde::Serialize;
use thiserror::Error;

use crate::ProjectManager;
use crate::code_index::{CodeIndexError, read_code_index};
use crate::project::cache_key;

pub const SEARCH_CODE_SCHEMA: &str = "rbm.ghidra.search_code.v0";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CodeSearchResult {
    pub function_name: String,
    pub address: String,
    pub signature: String,
    pub code: String,
    pub similarity: f64,
    pub search_mode: String,
    pub callers: Vec<String>,
    pub callees: Vec<String>,
    pub decompile_error: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CodeSearchResults {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub results: Vec<CodeSearchResult>,
    pub query: String,
    pub search_mode: String,
    pub returned_count: usize,
    pub offset: usize,
    pub limit: usize,
    pub literal_total: usize,
    pub total_functions: usize,
}

#[derive(Debug, Error)]
pub enum SearchCodeError {
    #[error("query must not be empty")]
    EmptyQuery,
    #[error(
        "code index is missing for {binary_query}; build it first with ghidra_build_code_index ({path})"
    )]
    IndexMissing {
        binary_query: String,
        path: std::path::PathBuf,
    },
    #[error(transparent)]
    CodeIndex(#[from] CodeIndexError),
}

#[derive(Debug, Clone)]
pub struct SearchCodeContext {
    pub manager: std::sync::Arc<ProjectManager>,
    pub preview_length: usize,
}

/// Tokenize text into lowercase alphabetic tokens (length >= 3).
fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut buf = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            buf.push(ch.to_ascii_lowercase());
        } else {
            if buf.len() >= 3 {
                tokens.push(buf.clone());
            }
            buf.clear();
        }
    }
    if buf.len() >= 3 {
        tokens.push(buf);
    }
    tokens
}

/// Build an inverted index and compute TF-IDF scores for the query against all documents.
/// Returns (`doc_index`, score) pairs sorted by score descending.
fn tfidf_scores(documents: &[(usize, &[String])], query_tokens: &[String]) -> Vec<(usize, f64)> {
    if query_tokens.is_empty() || documents.is_empty() {
        return Vec::new();
    }
    let n = usize_to_f64(documents.len());

    // Document frequency: how many docs contain each term
    let mut df: HashMap<&str, usize> = HashMap::new();
    for (_, doc_tokens) in documents {
        let mut seen: HashMap<&str, bool> = HashMap::new();
        for t in *doc_tokens {
            if !seen.contains_key(t.as_str()) {
                seen.insert(t.as_str(), true);
                *df.entry(t.as_str()).or_insert(0) += 1;
            }
        }
    }

    // Score each document
    let mut scores: Vec<(usize, f64)> = Vec::with_capacity(documents.len());
    for (doc_idx, doc_tokens) in documents {
        // Term frequency in this document
        let mut tf: HashMap<&str, usize> = HashMap::new();
        for t in *doc_tokens {
            *tf.entry(t.as_str()).or_insert(0) += 1;
        }

        // Cosine similarity between query vector and document vector
        // query vector: tfidf_q = 1 * idf (binary term presence in query)
        // doc vector: tfidf_d = tf * idf
        let mut dot = 0.0f64;
        let mut query_norm_sq = 0.0f64;
        let mut doc_norm_sq = 0.0f64;

        // All terms in query or document
        let all_terms: std::collections::HashSet<&str> = query_tokens
            .iter()
            .map(std::string::String::as_str)
            .chain(doc_tokens.iter().map(std::string::String::as_str))
            .collect();

        for term in all_terms {
            let idf = (n / usize_to_f64(df.get(term).copied().unwrap_or(0).max(1))).ln() + 1.0;
            let in_query = query_tokens.iter().any(|t| t == term);
            let doc_tf = usize_to_f64(tf.get(term).copied().unwrap_or(0));

            if in_query {
                query_norm_sq += idf * idf;
                doc_norm_sq += doc_tf * doc_tf * idf * idf;
                dot += idf * doc_tf * idf;
            }
        }

        let score = if query_norm_sq > 0.0 && doc_norm_sq > 0.0 {
            dot / (query_norm_sq.sqrt() * doc_norm_sq.sqrt())
        } else {
            0.0
        };

        if score > 0.0 {
            scores.push((*doc_idx, score));
        }
    }

    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scores
}

fn usize_to_f64(value: usize) -> f64 {
    value.to_string().parse::<f64>().unwrap_or(f64::MAX)
}

/// Search options for `search_code`.
pub struct SearchCodeOptions {
    pub search_mode: String,
    pub limit: usize,
    pub offset: usize,
    pub include_full_code: bool,
    pub preview_length: usize,
}

/// Search cached decompiler code.
///
/// # Errors
///
/// Returns an error if the query is empty, the binary cannot be resolved, the
/// code index cannot be read, or rebuilding the index fails.
pub async fn search_code(
    ctx: &SearchCodeContext,
    binary_query: &str,
    query: &str,
    opts: &SearchCodeOptions,
) -> Result<CodeSearchResults, SearchCodeError> {
    if query.trim().is_empty() {
        return Err(SearchCodeError::EmptyQuery);
    }

    let clamped_limit = opts.limit.clamp(1, 100);
    let offset = opts.offset;
    let (cached, envelope) = match read_code_index(ctx.manager.as_ref(), binary_query).await {
        Ok(result) => result,
        Err(CodeIndexError::IndexMissing { binary_query, path }) => {
            return Err(SearchCodeError::IndexMissing { binary_query, path });
        }
        Err(other) => return Err(SearchCodeError::CodeIndex(other)),
    };
    let total_functions = envelope.functions.len();

    // Prepare documents for indexing
    let documents: Vec<(usize, Vec<String>)> = envelope
        .functions
        .iter()
        .enumerate()
        .map(|(i, f)| (i, tokenize(&f.pseudocode)))
        .collect();

    let doc_slices: Vec<(usize, &[String])> = documents
        .iter()
        .map(|(i, tokens)| (*i, tokens.as_slice()))
        .collect();

    let query_tokens = tokenize(query);

    // Literal (substring) search
    let query_lower = query.to_lowercase();
    let mut literal_matches: Vec<usize> = Vec::new();
    for (i, f) in envelope.functions.iter().enumerate() {
        if f.pseudocode.to_lowercase().contains(&query_lower) {
            literal_matches.push(i);
        }
    }
    let literal_total = literal_matches.len();

    // TF-IDF semantic search
    let semantic_scores = if opts.search_mode == "semantic" {
        tfidf_scores(&doc_slices, &query_tokens)
    } else {
        Vec::new()
    };

    // Combine results
    let mut results: Vec<(usize, f64, &str)> = Vec::new(); // (idx, score, mode)

    if opts.search_mode == "semantic" {
        // Semantic mode: TF-IDF results, with literal_total reported
        for (idx, score) in &semantic_scores {
            results.push((*idx, *score, "semantic"));
        }
    } else {
        // Literal mode: substring match only
        for &idx in &literal_matches {
            results.push((idx, 1.0, "literal"));
        }
    }

    // Apply pagination
    let returned_count = results.len();
    let search_results: Vec<CodeSearchResult> = results
        .into_iter()
        .skip(offset)
        .take(clamped_limit)
        .map(|(idx, score, mode)| {
            let f = &envelope.functions[idx];
            let preview_length = opts.preview_length.min(ctx.preview_length);
            let code = if opts.include_full_code || f.pseudocode.len() <= preview_length {
                f.pseudocode.clone()
            } else {
                let preview = f.pseudocode[..preview_length].to_string();
                format!("{preview}...")
            };

            CodeSearchResult {
                function_name: f.name.clone(),
                address: f.address.clone(),
                signature: f.signature.clone(),
                code,
                similarity: (score * 1000.0).round() / 1000.0,
                search_mode: mode.to_string(),
                callers: f.callers.clone(),
                callees: f.callees.clone(),
                decompile_error: f.decompile_error.clone(),
            }
        })
        .collect();

    Ok(CodeSearchResults {
        schema: SEARCH_CODE_SCHEMA.to_string(),
        cache_key: cache_key(&cached.sha256),
        sha256: cached.sha256,
        program_name: cached.program_name,
        results: search_results,
        query: query.to_string(),
        search_mode: opts.search_mode.clone(),
        returned_count,
        offset,
        limit: clamped_limit,
        literal_total,
        total_functions,
    })
}
