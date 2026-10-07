#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

//! Stable-toolchain byte-input entry point for the bounded sitemap parser.

use std::io::{self, Read};

use endpoint_validator::sitemap::{parse, SitemapDocument, MAX_DOCUMENT_BYTES, MAX_URLS};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = Vec::new();
    io::stdin()
        .take(u64::try_from(MAX_DOCUMENT_BYTES + 1)?)
        .read_to_end(&mut data)?;
    if let Ok(SitemapDocument::UrlSet(urls) | SitemapDocument::Index(urls)) = parse(&data) {
        assert!(urls.len() <= MAX_URLS);
        assert!(urls
            .iter()
            .all(|url| !url.is_empty() && url.chars().count() <= 2048));
    }
    Ok(())
}
