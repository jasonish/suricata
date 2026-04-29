use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

const DEFAULT_SOCKET: &str = "/tmp/suricata-flowtop.sock";
const DEFAULT_LISTEN: &str = "127.0.0.1:9876";
const INDEX_HTML: &str = include_str!("../static/index.html");

fn main() -> io::Result<()> {
    let mut socket_path = env::var("SURICATA_FLOWTOP_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string());
    let mut listen_addr = DEFAULT_LISTEN.to_string();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" | "-s" => {
                if let Some(value) = args.next() {
                    socket_path = value;
                }
            }
            "--listen" | "-l" => {
                if let Some(value) = args.next() {
                    listen_addr = value;
                }
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            value => socket_path = value.to_string(),
        }
    }

    let listener = TcpListener::bind(&listen_addr)?;
    eprintln!("flowtop web listening on http://{listen_addr}");
    eprintln!("reading flow snapshots from {socket_path}");

    for stream in listener.incoming() {
        let socket_path = socket_path.clone();
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream, &socket_path) {
                        eprintln!("client error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }

    Ok(())
}

fn print_help() {
    println!("suricata-flowtop-web [--socket PATH] [--listen ADDR]");
    println!("  --socket PATH   flowtop Unix socket (default: {DEFAULT_SOCKET})");
    println!("  --listen ADDR   HTTP listen address (default: {DEFAULT_LISTEN})");
}

fn handle_client(mut stream: TcpStream, socket_path: &str) -> io::Result<()> {
    let mut request = [0u8; 2048];
    let n = stream.read(&mut request)?;
    let request = String::from_utf8_lossy(&request[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    match path {
        "/" | "/index.html" => serve_index(stream),
        "/events" => serve_events(stream, socket_path),
        "/health" => serve_text(stream, "ok\n"),
        _ => serve_not_found(stream),
    }
}

fn serve_index(mut stream: TcpStream) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n{}",
        INDEX_HTML.len(),
        INDEX_HTML
    )
}

fn serve_text(mut stream: TcpStream, body: &str) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n{}",
        body.len(),
        body
    )
}

fn serve_not_found(mut stream: TcpStream) -> io::Result<()> {
    let body = "not found\n";
    write!(
        stream,
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
}

fn serve_events(mut stream: TcpStream, socket_path: &str) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n"
    )?;

    loop {
        match UnixStream::connect(socket_path) {
            Ok(unix) => {
                writeln!(stream, "event: status")?;
                writeln!(stream, "data: {{\"status\":\"connected\"}}\n")?;
                stream.flush()?;

                let mut reader = BufReader::new(unix);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => {
                            write!(stream, "data: {}\n\n", line.trim_end())?;
                            stream.flush()?;
                        }
                        Err(_) => break,
                    }
                }
            }
            Err(err) => {
                writeln!(stream, "event: status")?;
                writeln!(
                    stream,
                    "data: {{\"status\":\"connect failed: {}; retrying\"}}\n",
                    json_escape(&err.to_string())
                )?;
                stream.flush()?;
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
