//! Bounded sitemap XML parsing; no DTD or external entity resolution.

use roxmltree::{Document, Node, ParsingOptions};
use thiserror::Error;

/// Maximum decoded bytes accepted from one discovery document.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
/// Maximum URLs accepted from one sitemap document.
pub const MAX_URLS: usize = 4096;
const MAX_URL_CHARACTERS: usize = 2048;
const MAX_URL_BYTES: usize = MAX_URL_CHARACTERS * 4;
const MAX_DEPTH: usize = 32;
const MAX_TAG_BYTES: usize = 4096;
const MAX_ATTRIBUTES: usize = 32;
const MAX_RAW_OPEN_MARKERS: usize = 32_768;
const MAX_RAW_ATTRIBUTE_MARKERS: usize = 16_384;
const MAX_NODES: u32 = 32_768;
const SITEMAP_NAMESPACE: &str = "http://www.sitemaps.org/schemas/sitemap/0.9";

/// Validated URL records or same-origin index candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SitemapDocument {
    UrlSet(Vec<String>),
    Index(Vec<String>),
}

/// Malformed or over-budget documents never yield partial URL lists.
#[derive(Debug, Error)]
pub enum SitemapError {
    #[error("sitemap resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("sitemap must be UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("invalid sitemap XML: {0}")]
    InvalidXml(#[from] roxmltree::Error),
    #[error("invalid sitemap structure: {0}")]
    InvalidStructure(&'static str),
}

fn terminated(bytes: &[u8], start: usize, marker: &[u8]) -> Result<usize, SitemapError> {
    bytes[start..]
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|offset| start + offset + marker.len())
        .ok_or(SitemapError::InvalidStructure("unterminated markup"))
}

/// Resource preflight only; the XML library performs all grammar/namespace checks.
fn preflight(bytes: &[u8]) -> Result<(), SitemapError> {
    // The library reserves arrays from raw '<'/'=' counts, including comments
    // and CDATA. Bound those counts before allowing its initial allocations.
    let mut open_markers = 0;
    let mut attribute_markers = 0;
    for &byte in bytes {
        match byte {
            b'<' => open_markers += 1,
            b'=' => attribute_markers += 1,
            _ => {}
        }
        if open_markers > MAX_RAW_OPEN_MARKERS || attribute_markers > MAX_RAW_ATTRIBUTE_MARKERS {
            return Err(SitemapError::ResourceLimit("raw allocation markers"));
        }
    }
    let mut cursor = 0;
    let mut depth: usize = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'<' {
            cursor += 1;
            continue;
        }
        let remaining = &bytes[cursor..];
        if remaining.starts_with(b"<!--") {
            cursor = terminated(bytes, cursor + 4, b"-->")?;
            continue;
        }
        if remaining.starts_with(b"<![CDATA[") {
            cursor = terminated(bytes, cursor + 9, b"]]>")?;
            continue;
        }
        if remaining.starts_with(b"<?") {
            cursor = terminated(bytes, cursor + 2, b"?>")?;
            continue;
        }
        if remaining.starts_with(b"<!") {
            return Err(SitemapError::InvalidStructure(
                "DTD/declarations are forbidden",
            ));
        }
        let closing = remaining.starts_with(b"</");
        let start = cursor;
        cursor += 1;
        let mut quote = None;
        let mut attributes = 0;
        while cursor < bytes.len() {
            if cursor - start >= MAX_TAG_BYTES {
                return Err(SitemapError::ResourceLimit("tag bytes"));
            }
            let byte = bytes[cursor];
            if let Some(delimiter) = quote {
                if byte == delimiter {
                    quote = None;
                }
            } else {
                match byte {
                    b'\'' | b'"' => quote = Some(byte),
                    b'=' => {
                        attributes += 1;
                        if attributes > MAX_ATTRIBUTES {
                            return Err(SitemapError::ResourceLimit("attributes per element"));
                        }
                    }
                    b'>' => break,
                    _ => {}
                }
            }
            cursor += 1;
        }
        if cursor == bytes.len() {
            return Err(SitemapError::InvalidStructure("unterminated element"));
        }
        if closing {
            depth = depth
                .checked_sub(1)
                .ok_or(SitemapError::InvalidStructure("unmatched closing tag"))?;
        } else {
            if depth >= MAX_DEPTH {
                return Err(SitemapError::ResourceLimit("element nesting"));
            }
            if bytes[cursor - 1] != b'/' {
                depth += 1;
            }
        }
        cursor += 1;
    }
    if depth != 0 {
        return Err(SitemapError::InvalidStructure("unclosed elements"));
    }
    Ok(())
}

fn matches(node: Node<'_, '_>, name: &str, namespace: Option<&str>) -> bool {
    node.is_element() && node.tag_name().name() == name && node.tag_name().namespace() == namespace
}

fn location(item: Node<'_, '_>, namespace: Option<&str>) -> Result<String, SitemapError> {
    let mut locations = item
        .children()
        .filter(|node| matches(*node, "loc", namespace));
    let loc = locations
        .next()
        .ok_or(SitemapError::InvalidStructure("missing loc"))?;
    if locations.next().is_some() || loc.children().any(|child| child.is_element()) {
        return Err(SitemapError::InvalidStructure(
            "loc is duplicated or contains elements",
        ));
    }
    let mut value = String::new();
    for node in loc.children().filter(Node::is_text) {
        let text = node.text().unwrap_or_default();
        if text.len() > MAX_URL_BYTES - value.len() {
            return Err(SitemapError::ResourceLimit("URL bytes"));
        }
        value.push_str(text);
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SitemapError::InvalidStructure("loc is empty"));
    }
    if trimmed.chars().count() > MAX_URL_CHARACTERS {
        return Err(SitemapError::ResourceLimit("URL characters"));
    }
    Ok(trimmed.to_owned())
}

/// Parse a bounded UTF-8 sitemap, preserving escaped/CDATA URL text.
///
/// Index URLs are candidates only: callers must enforce origin and traversal
/// budgets before requesting them. This function performs no network access.
///
/// # Errors
///
/// Returns [`SitemapError`] for malformed XML, unsupported roots/namespaces,
/// DTDs, invalid locations or resource budgets. Never returns partial results.
pub fn parse(bytes: &[u8]) -> Result<SitemapDocument, SitemapError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(SitemapError::ResourceLimit("document bytes"));
    }
    preflight(bytes)?;
    let text = std::str::from_utf8(bytes)?;
    let document = Document::parse_with_options(
        text,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: MAX_NODES,
            entity_resolver: None,
        },
    )?;
    let root = document.root_element();
    let namespace = root.tag_name().namespace();
    if namespace.is_some_and(|value| value != SITEMAP_NAMESPACE) {
        return Err(SitemapError::InvalidStructure("unsupported root namespace"));
    }
    let (item_name, index) = match root.tag_name().name() {
        "urlset" => ("url", false),
        "sitemapindex" => ("sitemap", true),
        _ => return Err(SitemapError::InvalidStructure("unsupported root element")),
    };
    let mut urls = Vec::new();
    for item in root
        .children()
        .filter(|node| matches(*node, item_name, namespace))
    {
        if urls.len() == MAX_URLS {
            return Err(SitemapError::ResourceLimit("URL count"));
        }
        urls.push(location(item, namespace)?);
    }
    Ok(if index {
        SitemapDocument::Index(urls)
    } else {
        SitemapDocument::UrlSet(urls)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn namespaces_escaped_urls_cdata_and_comments_preserve_locations() {
        let xml = br#"<?xml version="1.0"?><s:urlset xmlns:s="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:x="urn:metadata" ignored="greater > sign">
            <s:url><s:loc> https://service.test/api?q=1&amp;b=2<![CDATA[&c=3]]><!--ignore--> </s:loc></s:url>
            <x:url><x:loc>https://other.test/ignored</x:loc></x:url>
            <s:url><s:loc>/two</s:loc><s:lastmod>2026-10-07</s:lastmod></s:url>
        </s:urlset>"#;
        assert_eq!(
            parse(xml).unwrap(),
            SitemapDocument::UrlSet(vec![
                "https://service.test/api?q=1&b=2&c=3".to_owned(),
                "/two".to_owned()
            ])
        );
    }

    #[test]
    fn default_namespace_and_index_are_supported() {
        let xml = br#"<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>/child.xml</loc></sitemap></sitemapindex>"#;
        assert_eq!(
            parse(xml).unwrap(),
            SitemapDocument::Index(vec!["/child.xml".to_owned()])
        );
        assert_eq!(
            parse(b"<urlset />").unwrap(),
            SitemapDocument::UrlSet(vec![])
        );
    }

    #[test]
    fn malformed_ambiguous_and_foreign_locations_are_rejected() {
        for xml in [
            "<urlset><url></url></urlset>",
            "<urlset><url><loc/></url></urlset>",
            "<urlset><url><loc>/a</loc><loc>/b</loc></url></urlset>",
            "<urlset><url><loc><b>/a</b></loc></url></urlset>",
            "<urlset><url><x:loc xmlns:x='urn:other'>/a</x:loc></url></urlset>",
            "<urlset xmlns='urn:other'/>",
            "<other/>",
            "<urlset><url></urlset>",
            "<urlset/><urlset/>",
            "</urlset>",
            "<urlset>",
            "<?xml",
            "<!--",
            "<![CDATA[",
            "<urlset><url a='1' a='2'/></urlset>",
        ] {
            assert!(parse(xml.as_bytes()).is_err(), "accepted {xml}");
        }
        assert!(parse(b"<urlset>\xff</urlset>").is_err());
    }

    #[test]
    fn dtd_external_entities_and_entity_bombs_never_resolve() {
        for xml in [
            "<!DOCTYPE urlset><urlset/>",
            "<!DOCTYPE urlset SYSTEM 'https://outside.test/entity'><urlset/>",
            "<!DOCTYPE urlset [<!ENTITY x 'expanded'>]><urlset><url><loc>&x;</loc></url></urlset>",
            "<!DOCTYPE urlset [<!ENTITY x '&x;&x;'>]><urlset>&x;</urlset>",
        ] {
            assert!(matches!(
                parse(xml.as_bytes()),
                Err(SitemapError::InvalidStructure(_))
            ));
        }
        assert!(parse(b"<urlset><url><loc>&unknown;</loc></url></urlset>").is_err());
    }

    #[test]
    fn resource_budgets_reject_before_returning_partial_results() {
        assert!(parse(&vec![b' '; MAX_DOCUMENT_BYTES + 1]).is_err());
        let deep = format!(
            "{}{}",
            "<x>".repeat(MAX_DEPTH + 1),
            "</x>".repeat(MAX_DEPTH + 1)
        );
        assert!(matches!(
            parse(deep.as_bytes()),
            Err(SitemapError::ResourceLimit("element nesting"))
        ));
        let mut attributes = String::new();
        for index in 0..=MAX_ATTRIBUTES {
            write!(attributes, " a{index}='x'").unwrap();
        }
        assert!(matches!(
            parse(format!("<urlset{attributes}/>").as_bytes()),
            Err(SitemapError::ResourceLimit("attributes per element"))
        ));
        let long_tag = format!("<urlset ignored='{}'/>", "x".repeat(MAX_TAG_BYTES));
        assert!(matches!(
            parse(long_tag.as_bytes()),
            Err(SitemapError::ResourceLimit("tag bytes"))
        ));
        let many_urls = format!(
            "<urlset>{}</urlset>",
            "<url><loc>/x</loc></url>".repeat(MAX_URLS + 1)
        );
        assert!(matches!(
            parse(many_urls.as_bytes()),
            Err(SitemapError::ResourceLimit("URL count"))
        ));
        let long_url = format!(
            "<urlset><url><loc>{}</loc></url></urlset>",
            "x".repeat(MAX_URL_CHARACTERS + 1)
        );
        assert!(matches!(
            parse(long_url.as_bytes()),
            Err(SitemapError::ResourceLimit("URL characters"))
        ));
        let prefix = "<urlset ignored='";
        let suffix = "'/>";
        let exact = format!(
            "{prefix}{}{suffix}",
            "x".repeat(MAX_TAG_BYTES - prefix.len() - suffix.len())
        );
        assert!(parse(exact.as_bytes()).is_ok());
        let over = format!(
            "{prefix}{}{suffix}",
            "x".repeat(MAX_TAG_BYTES + 1 - prefix.len() - suffix.len())
        );
        assert!(matches!(
            parse(over.as_bytes()),
            Err(SitemapError::ResourceLimit("tag bytes"))
        ));
        let exact_depth = format!(
            "<urlset>{}<leaf/>{}</urlset>",
            "<meta>".repeat(MAX_DEPTH - 2),
            "</meta>".repeat(MAX_DEPTH - 2)
        );
        assert!(parse(exact_depth.as_bytes()).is_ok());
        let excessive_depth = format!(
            "<urlset>{}<leaf/>{}</urlset>",
            "<meta>".repeat(MAX_DEPTH - 1),
            "</meta>".repeat(MAX_DEPTH - 1)
        );
        assert!(matches!(
            parse(excessive_depth.as_bytes()),
            Err(SitemapError::ResourceLimit("element nesting"))
        ));
    }

    #[test]
    fn raw_marker_reservations_and_document_nodes_are_bounded() {
        for repeated in [
            "<".repeat(MAX_RAW_OPEN_MARKERS + 1),
            "=".repeat(MAX_RAW_ATTRIBUTE_MARKERS + 1),
        ] {
            let xml = format!("<urlset><![CDATA[{repeated}]]></urlset>");
            assert!(matches!(
                parse(xml.as_bytes()),
                Err(SitemapError::ResourceLimit("raw allocation markers"))
            ));
        }
        let xml = format!("<urlset>{}</urlset>", "<!--comment-->text".repeat(16_384));
        assert!(matches!(
            parse(xml.as_bytes()),
            Err(SitemapError::InvalidXml(
                roxmltree::Error::NodesLimitReached
            ))
        ));
    }

    #[test]
    fn deterministic_byte_mutations_only_return_valid_documents_or_errors() {
        let seed = b"<urlset><url><loc>/health?a=1&amp;b=2</loc></url></urlset>";
        for index in 0..seed.len() {
            for bit in 0..8 {
                let mut mutated = seed.to_vec();
                mutated[index] ^= 1 << bit;
                if let Ok(SitemapDocument::UrlSet(urls) | SitemapDocument::Index(urls)) =
                    parse(&mutated)
                {
                    assert!(urls.len() <= MAX_URLS);
                    assert!(urls
                        .iter()
                        .all(|value| !value.is_empty()
                            && value.chars().count() <= MAX_URL_CHARACTERS));
                }
            }
        }
    }
}
