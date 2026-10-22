mod config;
mod guard;

use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use config::Settings;
use guard::{Guard, Verdict};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error, path::Path, sync::Arc, time::Duration};
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct PluginRequest {
    version: String,
    op: String,
    content: ConnectionInfo,
}

#[derive(Deserialize)]
struct ConnectionInfo {
    proxy_name: String,
    proxy_type: String,
    remote_addr: String,
}

#[derive(Serialize)]
struct PluginResponse {
    reject: bool,
    unchange: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reject_reason: Option<&'static str>,
}

async fn handle(
    State(guard): State<Arc<Guard>>,
    Query(query): Query<HashMap<String, String>>,
    Json(request): Json<PluginRequest>,
) -> Result<Json<PluginResponse>, (StatusCode, &'static str)> {
    if request.version != "0.1.0"
        || query.get("version").map(String::as_str) != Some("0.1.0")
        || query.get("op").map(String::as_str) != Some("NewUserConn")
        || request.op != "NewUserConn"
    {
        return Err((StatusCode::BAD_REQUEST, "unsupported frp plugin operation"));
    }

    let verdict = guard.inspect(
        &request.content.proxy_name,
        &request.content.proxy_type,
        &request.content.remote_addr,
    );
    let response = match verdict {
        Verdict::Allow => PluginResponse {
            reject: false,
            unchange: true,
            reject_reason: None,
        },
        Verdict::Reject(reason) => PluginResponse {
            reject: true,
            unchange: true,
            reject_reason: Some(reason),
        },
    };
    Ok(Json(response))
}

fn app(guard: Arc<Guard>) -> Router {
    Router::new()
        .route(&guard.config.server.path, post(handle))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(guard.config.server.max_body_bytes))
        .with_state(guard)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config/guard.toml".to_owned());
    let config = Settings::read(Path::new(&path))?;
    let listen = config.server.listen.clone();
    let cleanup_interval = config.limits.cleanup_interval_secs;
    let guard = Arc::new(Guard::new(config)?);

    let cleaner = Arc::clone(&guard);
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(cleanup_interval));
        timer.tick().await;
        loop {
            timer.tick().await;
            cleaner.cleanup();
        }
    });

    let listener = TcpListener::bind(&listen).await?;
    println!("frp-connection-guard listening on {listen}");
    axum::serve(listener, app(guard)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use serde_json::{json, Value};
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn setup() -> (TempDir, Router) {
        let temp = TempDir::new().unwrap();
        let mut settings = Settings::default();
        settings.storage.sqlite_path = temp.path().join("bans.db").display().to_string();
        settings.limits.short_max_connections = 2;
        settings.limits.rapid_retry_max = 100;
        (temp, app(Arc::new(Guard::new(settings).unwrap())))
    }

    async fn send(router: Router, op: &str, address: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri("/handler?version=0.1.0&op=NewUserConn")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "version":"0.1.0",
                    "op":op,
                    "content": {
                        "proxy_name":"ssh-access",
                        "proxy_type":"tcp",
                        "remote_addr":address
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let reply = router.oneshot(request).await.unwrap();
        let status = reply.status();
        let bytes = to_bytes(reply.into_body(), 65536).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn rpc_rejects_bursts_and_preserves_response_format() {
        let (_temp, router) = setup();
        let (_, a) = send(router.clone(), "NewUserConn", "192.0.2.10:3000").await;
        let (_, b) = send(router.clone(), "NewUserConn", "192.0.2.10:3001").await;
        let (status, c) = send(router.clone(), "NewUserConn", "192.0.2.10:3002").await;
        assert_eq!(a["reject"], false);
        assert_eq!(a["unchange"], true);
        assert_eq!(b["reject"], false);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c["reject"], true);
        assert_eq!(
            c["reject_reason"],
            "connection frequency exceeded; IP banned"
        );
    }

    #[tokio::test]
    async fn rpc_rejects_unconfigured_operation() {
        let (_temp, router) = setup();
        let (status, _) = send(router, "Login", "192.0.2.10:3000").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn payload_limit_rejects_large_requests() {
        let (_temp, router) = setup();
        let payload = "x".repeat(20_000);
        let req = Request::builder()
            .method("POST")
            .uri("/handler?version=0.1.0&op=NewUserConn")
            .header("content-type", "application/json")
            .body(Body::from(payload))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
