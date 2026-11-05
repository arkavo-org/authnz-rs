//! The home page and site icons of identity.arkavo.net (#138).
//!
//! Apple Passwords shows a site's icon beside its passkeys, and every Arkavo
//! passkey's site is the WebAuthn RP ID, `identity.arkavo.net`. Without these
//! routes the host answered 404 for `/` and every icon, so Passwords drew a
//! gray letter tile and "Open website" landed on a 404.
//!
//! `/` is a page on this host, never a redirect off it: an icon fetcher that
//! follows a redirect lands on a host with no touch icon.
//!
//! The files are built into the binary from `assets/site/`. The PNGs are the
//! sailboat mark (`AppLogo.png`, 1800×1800, in the app repo) flattened onto
//! white, so they are opaque.

use axum::Router;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::get;

const HOME_PAGE: &str = include_str!("../assets/site/index.html");
/// 180×180, opaque.
const APPLE_TOUCH_ICON: &[u8] = include_bytes!("../assets/site/apple-touch-icon.png");
/// 32×32, opaque.
const FAVICON_32: &[u8] = include_bytes!("../assets/site/favicon-32x32.png");
/// 16, 32 and 48 px.
const FAVICON_ICO: &[u8] = include_bytes!("../assets/site/favicon.ico");

const CACHE_CONTROL: &str = "public, max-age=86400";

/// The routes this module serves. Merged into the main router ahead of its
/// layers and fallback.
pub fn routes() -> Router {
    Router::new()
        .route("/", get(home_page))
        .route("/apple-touch-icon.png", get(apple_touch_icon))
        // Older iOS fetchers ask for this name first.
        .route("/apple-touch-icon-precomposed.png", get(apple_touch_icon))
        .route("/favicon-32x32.png", get(favicon_32))
        .route("/favicon.ico", get(favicon_ico))
}

async fn home_page() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, CACHE_CONTROL)], Html(HOME_PAGE))
}

async fn apple_touch_icon() -> impl IntoResponse {
    image("image/png", APPLE_TOUCH_ICON)
}

async fn favicon_32() -> impl IntoResponse {
    image("image/png", FAVICON_32)
}

async fn favicon_ico() -> impl IntoResponse {
    image("image/x-icon", FAVICON_ICO)
}

fn image(content_type: &'static str, bytes: &'static [u8]) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, CACHE_CONTROL),
        ],
        bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt;

    async fn fetch(method: Method, path: &str) -> (StatusCode, String, Vec<u8>) {
        let res = routes()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let content_type = res
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let body = to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, content_type, body)
    }

    /// Width, height and PNG color type from the IHDR chunk.
    fn png_header(bytes: &[u8]) -> (u32, u32, u8) {
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "not a PNG");
        assert_eq!(&bytes[12..16], b"IHDR");
        let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        (width, height, bytes[25])
    }

    /// PNG color types 2 (truecolor) and 0 (grayscale) carry no alpha.
    fn is_opaque(color_type: u8) -> bool {
        color_type == 2 || color_type == 0
    }

    #[tokio::test]
    async fn apple_touch_icon_is_an_opaque_180_png() {
        for path in ["/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"] {
            let (status, content_type, body) = fetch(Method::GET, path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(content_type, "image/png", "{path}");
            let (w, h, color) = png_header(&body);
            assert_eq!((w, h), (180, 180), "{path}");
            assert!(is_opaque(color), "{path}: color type {color} has alpha");
        }
    }

    #[tokio::test]
    async fn favicon_png_is_an_opaque_32_png() {
        let (status, content_type, body) = fetch(Method::GET, "/favicon-32x32.png").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "image/png");
        let (w, h, color) = png_header(&body);
        assert_eq!((w, h), (32, 32));
        assert!(is_opaque(color), "color type {color} has alpha");
    }

    #[tokio::test]
    async fn favicon_ico_is_an_icon() {
        let (status, content_type, body) = fetch(Method::GET, "/favicon.ico").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "image/x-icon");
        // ICONDIR: reserved 0, type 1 (icon), at least one image.
        assert_eq!(&body[..4], &[0, 0, 1, 0]);
        assert!(u16::from_le_bytes([body[4], body[5]]) >= 1);
    }

    #[tokio::test]
    async fn home_page_is_titled_and_links_what_this_host_serves() {
        let (status, content_type, body) = fetch(Method::GET, "/").await;
        assert_eq!(status, StatusCode::OK);
        assert!(content_type.starts_with("text/html"), "{content_type}");
        let page = String::from_utf8(body).unwrap();
        assert!(page.contains("<title>Arkavo</title>"));
        assert!(page.contains(r#"<meta name="apple-mobile-web-app-title" content="Arkavo">"#));
        assert!(page.contains(r#"<a href="https://arkavo.com">"#));
        for href in [
            r#"<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">"#,
            r#"<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">"#,
            r#"<link rel="icon" href="/favicon.ico">"#,
        ] {
            assert!(page.contains(href), "missing {href}");
        }
        // Every icon the page links is served by this host.
        for path in [
            "/apple-touch-icon.png",
            "/favicon-32x32.png",
            "/favicon.ico",
        ] {
            assert_eq!(fetch(Method::GET, path).await.0, StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn head_answers_200_without_a_body() {
        for path in [
            "/",
            "/apple-touch-icon.png",
            "/favicon-32x32.png",
            "/favicon.ico",
        ] {
            let (status, _, body) = fetch(Method::HEAD, path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(body.is_empty(), "{path}");
        }
    }
}
