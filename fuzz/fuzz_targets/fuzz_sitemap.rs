#![no_main]
#![forbid(unsafe_code)]

use endpoint_validator::sitemap::{parse, SitemapDocument, MAX_URLS};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(SitemapDocument::UrlSet(urls) | SitemapDocument::Index(urls)) = parse(data) {
        assert!(urls.len() <= MAX_URLS);
        assert!(urls
            .iter()
            .all(|url| !url.is_empty() && url.chars().count() <= 2048));
    }
});
