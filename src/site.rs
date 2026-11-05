//! The operator's home page and site icons (#138).
//!
//! Apple Passwords shows a site's icon beside its passkeys, and every passkey's
//! site is the WebAuthn RP ID. A host that answers 404 for `/` and every icon
//! gets a gray letter tile, and "Open website" lands on a 404.
//!
//! authnz-rs carries no branding: any organization can deploy it. The operator
//! puts its files in a directory and names it in `SITE_ASSETS_DIR`; they are
//! read once at boot. Each file present is served at a fixed path ([`FILES`]);
//! a file absent, or the variable unset, leaves that path to the 404 fallback,
//! as before. Only these names are ever read, so nothing else in the directory
//! is exposed.
//!
//! The page should not redirect off-domain: an icon fetcher that follows the
//! redirect lands on a host that may have no touch icon.

use std::path::Path;

use axum::Router;
use axum::body::Bytes;
use axum::http::header;
use axum::routing::get;

pub const SITE_ASSETS_DIR_ENV: &str = "SITE_ASSETS_DIR";

/// Served path, file name in the directory, content type.
/// `/apple-touch-icon-precomposed.png` (asked for first by older iOS
/// fetchers) serves the same file as `/apple-touch-icon.png`.
pub const FILES: &[(&str, &str, &str)] = &[
    ("/", "index.html", "text/html; charset=utf-8"),
    ("/apple-touch-icon.png", "apple-touch-icon.png", "image/png"),
    (
        "/apple-touch-icon-precomposed.png",
        "apple-touch-icon.png",
        "image/png",
    ),
    ("/favicon-32x32.png", "favicon-32x32.png", "image/png"),
    ("/favicon.ico", "favicon.ico", "image/x-icon"),
];

const CACHE_CONTROL: &str = "public, max-age=86400";

/// The files read from `SITE_ASSETS_DIR`: served path, content type, bytes.
pub struct SiteAssets {
    files: Vec<(&'static str, &'static str, Bytes)>,
}

impl SiteAssets {
    /// Reads `SITE_ASSETS_DIR`. Unset or blank ⇒ `None` (no site routes). Set
    /// to a directory that cannot be read, or that holds none of the files ⇒
    /// an error, so a misconfigured deployment fails at boot.
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_setting(std::env::var(SITE_ASSETS_DIR_ENV).ok().as_deref())
    }

    fn from_setting(value: Option<&str>) -> Result<Option<Self>, String> {
        match value.map(str::trim) {
            None | Some("") => Ok(None),
            Some(dir) => Self::load(Path::new(dir)).map(Some),
        }
    }

    pub fn load(dir: &Path) -> Result<Self, String> {
        if !dir.is_dir() {
            return Err(format!(
                "{SITE_ASSETS_DIR_ENV}={} is not a directory",
                dir.display()
            ));
        }
        let mut files = Vec::new();
        for &(path, name, content_type) in FILES {
            let file = dir.join(name);
            match std::fs::read(&file) {
                Ok(bytes) => files.push((path, content_type, Bytes::from(bytes))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{SITE_ASSETS_DIR_ENV}: {}: {e}", file.display())),
            }
        }
        if files.is_empty() {
            let mut names: Vec<&str> = FILES.iter().map(|&(_, name, _)| name).collect();
            names.dedup();
            return Err(format!(
                "{SITE_ASSETS_DIR_ENV}={} holds none of {}",
                dir.display(),
                names.join(", ")
            ));
        }
        Ok(Self { files })
    }

    /// The paths served, for the startup log.
    pub fn served_paths(&self) -> Vec<&'static str> {
        self.files.iter().map(|&(path, _, _)| path).collect()
    }
}

/// A route for each file present. Merged into the main router ahead of its
/// layers and fallback.
pub fn routes(assets: Option<&SiteAssets>) -> Router {
    let mut router = Router::new();
    for (path, content_type, body) in assets.map(|a| a.files.as_slice()).unwrap_or_default() {
        let (content_type, body) = (*content_type, body.clone());
        router = router.route(
            path,
            get(move || {
                let body = body.clone();
                async move {
                    (
                        [
                            (header::CONTENT_TYPE, content_type),
                            (header::CACHE_CONTROL, CACHE_CONTROL),
                        ],
                        body,
                    )
                }
            }),
        );
    }
    router
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, StatusCode};
    use std::path::PathBuf;
    use tower::ServiceExt;

    /// A fresh directory holding `files`, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn with(files: &[(&str, &[u8])]) -> Self {
            let dir = std::env::temp_dir().join(format!("authnz-site-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            for (name, bytes) in files {
                std::fs::write(dir.join(name), bytes).unwrap();
            }
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const PAGE: &[u8] = b"<!DOCTYPE html><title>Example</title>";
    const TOUCH: &[u8] = b"touch-icon-bytes";
    const PNG32: &[u8] = b"png-32-bytes";
    const ICO: &[u8] = b"ico-bytes";

    fn all_files() -> TempDir {
        TempDir::with(&[
            ("index.html", PAGE),
            ("apple-touch-icon.png", TOUCH),
            ("favicon-32x32.png", PNG32),
            ("favicon.ico", ICO),
        ])
    }

    async fn fetch(router: Router, method: Method, path: &str) -> (StatusCode, String, Vec<u8>) {
        let res = router
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

    #[tokio::test]
    async fn serves_each_file_at_its_path() {
        let dir = all_files();
        let assets = SiteAssets::load(&dir.0).unwrap();
        for (path, content_type, body) in [
            ("/", "text/html; charset=utf-8", PAGE),
            ("/apple-touch-icon.png", "image/png", TOUCH),
            ("/apple-touch-icon-precomposed.png", "image/png", TOUCH),
            ("/favicon-32x32.png", "image/png", PNG32),
            ("/favicon.ico", "image/x-icon", ICO),
        ] {
            let got = fetch(routes(Some(&assets)), Method::GET, path).await;
            assert_eq!(
                got,
                (StatusCode::OK, content_type.to_string(), body.to_vec()),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn head_answers_200_without_a_body() {
        let dir = all_files();
        let assets = SiteAssets::load(&dir.0).unwrap();
        for &(path, _, _) in FILES {
            let (status, _, body) = fetch(routes(Some(&assets)), Method::HEAD, path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(body.is_empty(), "{path}");
        }
    }

    #[tokio::test]
    async fn unset_serves_nothing() {
        assert!(SiteAssets::from_setting(None).unwrap().is_none());
        assert!(SiteAssets::from_setting(Some("  ")).unwrap().is_none());
        for &(path, _, _) in FILES {
            let (status, _, _) = fetch(routes(None), Method::GET, path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn an_absent_file_is_not_served() {
        let dir = TempDir::with(&[("favicon.ico", ICO)]);
        let assets = SiteAssets::load(&dir.0).unwrap();
        assert_eq!(assets.served_paths(), vec!["/favicon.ico"]);
        let router = routes(Some(&assets));
        assert_eq!(
            fetch(router.clone(), Method::GET, "/favicon.ico").await.0,
            StatusCode::OK
        );
        for path in ["/", "/apple-touch-icon.png", "/favicon-32x32.png"] {
            assert_eq!(
                fetch(router.clone(), Method::GET, path).await.0,
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
    }

    #[test]
    fn only_the_listed_names_are_read() {
        let dir = TempDir::with(&[("favicon.ico", ICO), ("secret.pem", b"key")]);
        let assets = SiteAssets::load(&dir.0).unwrap();
        assert_eq!(assets.served_paths(), vec!["/favicon.ico"]);
    }

    #[test]
    fn a_misconfigured_directory_fails_boot() {
        let missing = std::env::temp_dir().join(format!("authnz-site-{}", uuid::Uuid::new_v4()));
        assert!(SiteAssets::from_setting(missing.to_str()).is_err());

        let empty = TempDir::with(&[]);
        let err = SiteAssets::load(&empty.0).err().unwrap();
        assert!(err.contains("holds none of"), "{err}");

        let file = TempDir::with(&[("index.html", PAGE)]);
        assert!(SiteAssets::load(&file.0.join("index.html")).is_err());
    }
}
