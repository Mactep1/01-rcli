use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}
pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("Serving {:?} on port {}", path, addr);
    let state = HttpServeState { path: path.clone() };
    let dir_service = ServeDir::new(path)
        .append_index_html_on_directories(true)
        .precompressed_gzip()
        .precompressed_br()
        .precompressed_deflate()
        .precompressed_zstd();
    // axum router
    let router = Router::new()
        .nest_service("/tower", dir_service)
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, String) {
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading file {:?}", p);
    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            format!("File {} not found", p.display()),
        )
    } else {
        match tokio::fs::read_to_string(p).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                (StatusCode::OK, content)
            }
            Err(e) => {
                warn!("Error reading file: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Error reading file: {}", e),
                )
            }
        }
    }
}
