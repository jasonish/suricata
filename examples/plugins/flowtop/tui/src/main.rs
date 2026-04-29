use std::cmp::Ordering;
use std::env;
use std::io::{self, BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event as CEvent, KeyCode};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table};
use ratatui::{Frame, Terminal};
use serde::Deserialize;

const DEFAULT_SOCKET: &str = "/tmp/suricata-flowtop.sock";

#[derive(Debug, Clone, Default, Deserialize)]
struct Snapshot {
    #[serde(default)]
    active_flows: u64,
    #[serde(default)]
    total_flows: u64,
    #[serde(default)]
    closed_flows: u64,
    #[serde(default)]
    total_bytes: u64,
    #[serde(default)]
    total_bps: u64,
    #[serde(default)]
    flows: Vec<Flow>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Flow {
    #[serde(default)]
    src_ip: String,
    #[serde(default)]
    dest_ip: String,
    #[serde(default)]
    src_port: u16,
    #[serde(default)]
    dest_port: u16,
    #[serde(default)]
    proto: String,
    #[serde(default)]
    app_proto: String,
    #[serde(default)]
    packets: u64,
    #[serde(default)]
    bytes: u64,
    #[serde(default)]
    bps: u64,
    #[serde(default)]
    age_ms: u64,
}

#[derive(Debug)]
enum AppEvent {
    Snapshot(Snapshot),
    Status(String),
}

struct App {
    socket_path: String,
    snapshot: Snapshot,
    status: String,
    sort_column: SortColumn,
    sort_order: SortOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Proto,
    App,
    Tuple,
    Packets,
    Bytes,
    Rate,
    Age,
}

impl SortColumn {
    const ALL: [SortColumn; 7] = [
        SortColumn::Proto,
        SortColumn::App,
        SortColumn::Tuple,
        SortColumn::Packets,
        SortColumn::Bytes,
        SortColumn::Rate,
        SortColumn::Age,
    ];

    fn label(self) -> &'static str {
        match self {
            SortColumn::Proto => "proto",
            SortColumn::App => "app",
            SortColumn::Tuple => "5-tuple",
            SortColumn::Packets => "packets",
            SortColumn::Bytes => "bytes",
            SortColumn::Rate => "rate",
            SortColumn::Age => "age",
        }
    }

    fn previous(self) -> Self {
        let idx = Self::ALL.iter().position(|column| *column == self).unwrap_or(0);
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|column| *column == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    fn from_digit(digit: char) -> Option<Self> {
        digit.to_digit(10).and_then(|value| {
            let idx = value.checked_sub(1)? as usize;
            Self::ALL.get(idx).copied()
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortOrder {
    Ascending,
    Descending,
}

impl SortOrder {
    fn toggle(self) -> Self {
        match self {
            SortOrder::Ascending => SortOrder::Descending,
            SortOrder::Descending => SortOrder::Ascending,
        }
    }

    fn label(self) -> &'static str {
        match self {
            SortOrder::Ascending => "ascending",
            SortOrder::Descending => "descending",
        }
    }

    fn marker(self) -> &'static str {
        match self {
            SortOrder::Ascending => "▲",
            SortOrder::Descending => "▼",
        }
    }
}

fn main() -> io::Result<()> {
    let socket_path = env::args()
        .nth(1)
        .or_else(|| env::var("SURICATA_FLOWTOP_SOCKET").ok())
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string());

    let (tx, rx) = mpsc::channel();
    spawn_reader(socket_path.clone(), tx);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App {
        socket_path,
        snapshot: Snapshot::default(),
        status: "connecting".to_string(),
        sort_column: SortColumn::Rate,
        sort_order: SortOrder::Descending,
    };

    let result = run(&mut terminal, &mut app, rx);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn spawn_reader(socket_path: String, tx: mpsc::Sender<AppEvent>) {
    thread::spawn(move || loop {
        match UnixStream::connect(&socket_path) {
            Ok(stream) => {
                let _ = tx.send(AppEvent::Status(format!("connected to {socket_path}")));
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => match serde_json::from_str::<Snapshot>(&line) {
                            Ok(snapshot) => {
                                let _ = tx.send(AppEvent::Snapshot(snapshot));
                            }
                            Err(err) => {
                                let _ = tx.send(AppEvent::Status(format!("bad snapshot: {err}")));
                            }
                        },
                        Err(err) => {
                            let _ = tx.send(AppEvent::Status(format!("read error: {err}")));
                            break;
                        }
                    }
                }
                let _ = tx.send(AppEvent::Status("disconnected; retrying".to_string()));
            }
            Err(err) => {
                let _ = tx.send(AppEvent::Status(format!("connect failed: {err}; retrying")));
            }
        }
        thread::sleep(Duration::from_secs(1));
    });
}

fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    rx: Receiver<AppEvent>,
) -> io::Result<()> {
    loop {
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::Snapshot(snapshot) => {
                    app.snapshot = snapshot;
                    app.status = "receiving snapshots".to_string();
                }
                AppEvent::Status(status) => app.status = status,
            }
        }

        terminal.draw(|frame| draw(frame, app))?;

        if event::poll(Duration::from_millis(250))? {
            if let CEvent::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Left | KeyCode::Char('<') | KeyCode::Char('h') => {
                        app.sort_column = app.sort_column.previous();
                    }
                    KeyCode::Right | KeyCode::Char('>') | KeyCode::Char('l') | KeyCode::F(6) => {
                        app.sort_column = app.sort_column.next();
                    }
                    KeyCode::Char(' ') | KeyCode::Char('r') | KeyCode::Enter => {
                        app.sort_order = app.sort_order.toggle();
                    }
                    KeyCode::Char(digit) => {
                        if let Some(column) = SortColumn::from_digit(digit) {
                            app.sort_column = column;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(0), Constraint::Length(1)])
        .split(frame.area());

    let header_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Length(3)])
        .split(chunks[0]);

    let header = vec![
        Line::from(vec![
            Span::styled("Suricata flowtop", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("  live flow monitor"),
        ]),
        Line::from(vec![
            Span::styled("socket ", Style::default().fg(Color::DarkGray)),
            Span::styled(app.socket_path.as_str(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("active ", Style::default().fg(Color::DarkGray)),
            Span::styled(app.snapshot.active_flows.to_string(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw("   "),
            Span::styled("total ", Style::default().fg(Color::DarkGray)),
            Span::styled(app.snapshot.total_flows.to_string(), Style::default().fg(Color::Blue)),
            Span::raw("   "),
            Span::styled("closed ", Style::default().fg(Color::DarkGray)),
            Span::styled(app.snapshot.closed_flows.to_string(), Style::default().fg(Color::Magenta)),
            Span::raw("   "),
            Span::styled("bytes ", Style::default().fg(Color::DarkGray)),
            Span::styled(human_bytes(app.snapshot.total_bytes), Style::default().fg(Color::Yellow)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(header)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Blue))),
        header_chunks[0],
    );

    let gauge = Gauge::default()
        .block(Block::default().title(" aggregate rate ").borders(Borders::ALL).border_style(Style::default().fg(Color::Blue)))
        .gauge_style(rate_style(app.snapshot.total_bps).bg(Color::Black).add_modifier(Modifier::BOLD))
        .label(format!("{}/s", human_bits(app.snapshot.total_bps)))
        .ratio(rate_gauge_ratio(app.snapshot.total_bps));
    frame.render_widget(gauge, header_chunks[1]);

    let mut flows = app.snapshot.flows.clone();
    sort_flows(&mut flows, app.sort_column, app.sort_order);

    let rows = flows.into_iter().enumerate().map(|(idx, flow)| {
        let rate = flow.bps;
        Row::new(vec![
            Cell::from(flow.proto.clone()).style(Style::default().fg(Color::Magenta)),
            Cell::from(display_app_proto(&flow.app_proto)).style(Style::default().fg(Color::Cyan)),
            Cell::from(flow_tuple(&flow)).style(Style::default().fg(Color::White)),
            Cell::from(flow.packets.to_string()).style(Style::default().fg(Color::Blue)),
            Cell::from(human_bytes(flow.bytes)).style(Style::default().fg(Color::Yellow)),
            Cell::from(format!("{}/s", human_bits(rate))).style(rate_style(rate).add_modifier(Modifier::BOLD)),
            Cell::from(human_duration(flow.age_ms)).style(Style::default().fg(Color::DarkGray)),
        ])
        .style(row_style(idx))
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Percentage(48),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(header_cells(app))
            .style(Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(table_title(app)).borders(Borders::ALL).border_style(Style::default().fg(Color::Blue)));

    frame.render_widget(table, chunks[1]);
    frame.render_widget(
        Paragraph::new(status_line(app))
            .style(status_style(&app.status))
            .alignment(Alignment::Center),
        chunks[2],
    );
}

fn sort_flows(flows: &mut [Flow], column: SortColumn, order: SortOrder) {
    flows.sort_by(|left, right| {
        let ordered = match order {
            SortOrder::Ascending => compare_flows(left, right, column),
            SortOrder::Descending => compare_flows(right, left, column),
        };

        ordered
            .then_with(|| right.bps.cmp(&left.bps))
            .then_with(|| right.bytes.cmp(&left.bytes))
            .then_with(|| flow_tuple(left).cmp(&flow_tuple(right)))
    });
}

fn compare_flows(left: &Flow, right: &Flow, column: SortColumn) -> Ordering {
    match column {
        SortColumn::Proto => left.proto.cmp(&right.proto),
        SortColumn::App => display_app_proto(&left.app_proto).cmp(&display_app_proto(&right.app_proto)),
        SortColumn::Tuple => flow_tuple(left).cmp(&flow_tuple(right)),
        SortColumn::Packets => left.packets.cmp(&right.packets),
        SortColumn::Bytes => left.bytes.cmp(&right.bytes),
        SortColumn::Rate => left.bps.cmp(&right.bps),
        SortColumn::Age => left.age_ms.cmp(&right.age_ms),
    }
}

fn header_cells(app: &App) -> Vec<Cell<'static>> {
    SortColumn::ALL
        .iter()
        .map(|column| {
            let label = if *column == app.sort_column {
                format!("{}{}", column.label(), app.sort_order.marker())
            } else {
                column.label().to_string()
            };
            Cell::from(label)
        })
        .collect()
}

fn table_title(app: &App) -> String {
    format!(
        " active flows | sort: {} {} ",
        app.sort_column.label(),
        app.sort_order.label()
    )
}

fn status_line(app: &App) -> String {
    format!(
        "{}   sort: ←/→, </>, h/l, F6 or 1-7; reverse: Space/r/Enter; quit: q",
        app.status
    )
}

fn row_style(idx: usize) -> Style {
    if idx % 2 == 0 {
        Style::default().bg(Color::Rgb(12, 16, 24))
    } else {
        Style::default().bg(Color::Rgb(18, 24, 34))
    }
}

fn rate_style(bps: u64) -> Style {
    match bps {
        0 => Style::default().fg(Color::DarkGray),
        1..=999_999 => Style::default().fg(Color::Green),
        1_000_000..=99_999_999 => Style::default().fg(Color::Yellow),
        _ => Style::default().fg(Color::Red),
    }
}

fn status_style(status: &str) -> Style {
    if status.contains("failed") || status.contains("error") || status.contains("bad") {
        Style::default().fg(Color::Red)
    } else if status.contains("retrying") || status.contains("disconnected") {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Green)
    }
}

fn rate_gauge_ratio(bps: u64) -> f64 {
    if bps == 0 {
        0.0
    } else {
        ((bps as f64).log10() / 10.0).clamp(0.03, 1.0)
    }
}

fn display_app_proto(app_proto: &str) -> String {
    if app_proto.is_empty() || app_proto == "unknown" {
        "-".to_string()
    } else {
        app_proto.to_string()
    }
}

fn flow_tuple(flow: &Flow) -> String {
    format!(
        "{} -> {}",
        endpoint(&flow.src_ip, flow.src_port),
        endpoint(&flow.dest_ip, flow.dest_port)
    )
}

fn endpoint(ip: &str, port: u16) -> String {
    if port == 0 {
        ip.to_string()
    } else if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn human_bytes(value: u64) -> String {
    human_scaled(value as f64, &["B", "KiB", "MiB", "GiB", "TiB"])
}

fn human_bits(value: u64) -> String {
    human_scaled(value as f64, &["bps", "Kbps", "Mbps", "Gbps", "Tbps"])
}

fn human_scaled(mut value: f64, units: &[&str]) -> String {
    let mut unit = units[0];
    for next in &units[1..] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    if value >= 100.0 {
        format!("{value:.0} {unit}")
    } else if value >= 10.0 {
        format!("{value:.1} {unit}")
    } else {
        format!("{value:.2} {unit}")
    }
}

fn human_duration(ms: u64) -> String {
    let seconds = ms / 1000;
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h{:02}m", seconds / 3600, (seconds % 3600) / 60)
    }
}
