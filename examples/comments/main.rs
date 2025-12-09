use bot_tariff::nonce::{RollingWindow, VerifiableNonce};
use bot_tariff::verify::verify_proof;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, StatusCode, http::response::Builder};
use hyper_util::rt::TokioIo;
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use serde::Serialize;
use std::fmt::{Formatter, LowerHex};
use std::sync::{LazyLock, RwLock};
use std::time::UNIX_EPOCH;
use tokio::net::TcpListener;

const INDEX_HTML: &[u8] = include_bytes!("index.html");
const POW_WASM: &[u8] = include_bytes!("../../pow.wasm");
const POW_MODULE: &[u8] = include_bytes!("../../pow.mjs");
const POW_WORKER_MODULE: &[u8] = include_bytes!("../../pow_worker_script.mjs");

static COMMENTS: LazyLock<RwLock<Vec<Comment>>> = LazyLock::new(|| {
    RwLock::new(vec![
        Comment {
            timestamp: 1755003600,
            author: "John D.".to_string(),
            content: "First!".to_string(),
        },
        Comment {
            timestamp: 1757840580,
            author: "Mike T.".to_string(),
            content: "Great project! I hate CAPTCHAs.".to_string(),
        },
    ])
});

#[derive(Serialize)]
struct Comment {
    timestamp: u32,
    author: String,
    content: String,
}

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;
type Response = hyper::Response<Either<Full<Bytes>, Empty<Bytes>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 8080)).await?;
    loop {
        let (stream, _remote_address) = listener.accept().await?;
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(io, service_fn(handler))
                .await;
        });
    }
}

struct Hex<'a>(&'a [u8]);

impl LowerHex for Hex<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for &it in self.0 {
            write!(f, "{:02x}", it)?;
        }
        Ok(())
    }
}

static NONCE_ROLLING_WINDOW: LazyLock<RollingWindow> =
    LazyLock::new(|| RollingWindow::from_seed(b"comments_example_seed_of_64bytes"));

async fn handler(req: Request<hyper::body::Incoming>) -> Result<Response> {
    let builder = Builder::new();
    Ok(match req.uri().path() {
        "/" => match req.method() {
            &hyper::Method::GET => builder
                .header(CONTENT_TYPE, HeaderValue::from_static("text/html"))
                .body(Either::Left(Full::new(Bytes::from_static(INDEX_HTML))))?,
            _ => builder
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::default()))?,
        },
        "/pow.wasm" => match req.method() {
            &hyper::Method::GET => builder
                .header(CONTENT_TYPE, HeaderValue::from_static("application/wasm"))
                .body(Either::Left(Full::new(Bytes::from_static(POW_WASM))))?,
            _ => builder
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::default()))?,
        },
        "/pow.mjs" => match req.method() {
            &hyper::Method::GET => builder
                .header(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/javascript"),
                )
                .body(Either::Left(Full::new(Bytes::from_static(POW_MODULE))))?,
            _ => builder
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::default()))?,
        },
        "/pow_worker_script.mjs" => match req.method() {
            &hyper::Method::GET => builder
                .header(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/javascript"),
                )
                .body(Either::Left(Full::new(Bytes::from_static(
                    POW_WORKER_MODULE,
                ))))?,
            _ => builder
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::default()))?,
        },
        "/comments" => match req.method() {
            &hyper::Method::GET => {
                let str = serde_json::to_string(&*COMMENTS.read().unwrap())?;
                builder
                    .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                    .body(Either::Left(Full::new(Bytes::from_owner(str.into_bytes()))))?
            }
            _ => builder
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::default()))?,
        },
        "/nonce" => match req.method() {
            &hyper::Method::GET => match NONCE_ROLLING_WINDOW.nonce() {
                Some(VerifiableNonce {
                    generation,
                    counter,
                    nonce,
                }) => builder
                    .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                    .body(Either::Left(Full::new(Bytes::from_owner(format!(
                        "{{\"generation\":{generation},\"counter\":{counter},\"nonce\":\"{:x}\"}}",
                        Hex(&nonce)
                    )))))?,
                None => builder
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Either::Right(Empty::default()))?,
            },
            _ => builder
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::default()))?,
        },
        "/comment" => match req.method() {
            &hyper::Method::POST => {
                if let Some(boundary) = req
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|it| it.to_str().ok())
                    .and_then(|it| parse_boundary(it).ok())
                {
                    let mut multipart = Multipart::with_constraints(
                        req.into_body().into_data_stream(),
                        boundary,
                        Constraints::new().size_limit(SizeLimit::new().whole_stream(16_384)),
                    );
                    let mut content = None;
                    let mut author = None;
                    let mut generation = None;
                    let mut counter = None;
                    let mut nonce = None;
                    let mut proof = None;
                    while let Ok(Some(field)) = multipart.next_field().await {
                        match field.name() {
                            Some("content") => {
                                if let Ok(it) = field.text().await {
                                    content = Some(it);
                                }
                            }
                            Some("author") => {
                                if let Ok(it) = field.text().await {
                                    author = Some(it);
                                }
                            }
                            Some("generation") => {
                                if let Ok(it) = field.text().await {
                                    generation = it.parse::<u16>().ok();
                                }
                            }
                            Some("counter") => {
                                if let Ok(it) = field.text().await {
                                    counter = it.parse::<usize>().ok();
                                }
                            }
                            Some("nonce") => {
                                if let Ok(it) = field.bytes().await {
                                    nonce = it.as_ref().try_into().ok();
                                }
                            }
                            Some("proof") => {
                                if let Ok(it) = field.bytes().await {
                                    proof = Some(it.to_vec());
                                }
                            }
                            _ => {}
                        }
                    }
                    if let Some(content) = content
                        && let Some(author) = author
                        && let Some(generation) = generation
                        && let Some(counter) = counter
                        && let Some(nonce) = nonce
                        && let Some(proof) = proof
                    {
                        if NONCE_ROLLING_WINDOW
                            .verify(&VerifiableNonce {
                                generation,
                                counter,
                                nonce,
                            })
                            .is_some()
                            && verify_proof(&nonce, &proof).is_some()
                        {
                            COMMENTS.write().unwrap().push(Comment {
                                timestamp: UNIX_EPOCH.elapsed()?.as_secs() as u32,
                                author,
                                content,
                            });
                            builder
                                .status(StatusCode::CREATED)
                                .body(Either::Right(Empty::default()))?
                        } else {
                            builder
                                .status(StatusCode::BAD_REQUEST)
                                .body(Either::Right(Empty::default()))?
                        }
                    } else {
                        builder
                            .status(StatusCode::BAD_REQUEST)
                            .body(Either::Right(Empty::default()))?
                    }
                } else {
                    builder
                        .status(StatusCode::BAD_REQUEST)
                        .body(Either::Right(Empty::default()))?
                }
            }
            _ => builder
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::default()))?,
        },
        _ => builder.body(Either::Right(Empty::default()))?,
    })
}
