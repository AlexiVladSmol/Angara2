//! Render synthetic M11 TUI frames to JSON for screenshot generation.
//!
//! This example is not part of the product surface. It exists so wide and
//! narrow acceptance screenshots can be reproduced without a live terminal:
//!
//! `cargo run --example m11_screenshot -- target/m11-wide.json 120 32 users`
//! `cargo run --example m11_screenshot -- target/m11-narrow.json 80 24 access`

use std::io;

use angara::connections::{ConnectionRow, ConnectionState};
use angara::control::{AccessSummary, BlockStatus, Lifecycle, ReloadOutcome, StatusSnapshot};
use angara::control_protocol::{
    AccessPage, AccessRuleView, ApiLimits, ConfigState, Event, EventKind, ProxySnapshot, Snapshot,
    UserStatus,
};
use angara::tui::view;
use angara::tui::viewmodel::{Screen, ViewModel};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::style::Color;

fn main() -> io::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "target/m11-wide.json".to_owned());
    let width = args
        .get(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(120);
    let height = args
        .get(3)
        .and_then(|value| value.parse().ok())
        .unwrap_or(32);
    let screen = args.get(4).map(String::as_str).unwrap_or("users");
    let mut model = synthetic();
    match screen {
        "access" => model.screen = Screen::Access,
        "overview" => model.screen = Screen::Overview,
        "config" => model.screen = Screen::Config,
        _ => model.screen = Screen::Users,
    }
    model.selected[model.screen.index()] = 1;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| view::draw(frame, &model))
        .expect("draw frame");
    let buffer = terminal.backend().buffer();
    let mut rows = Vec::new();
    for y in 0..height {
        let mut row = Vec::new();
        for x in 0..width {
            let cell = &buffer[(x, y)];
            let (fg, bold) = if cell.fg == Color::Reset {
                ((214, 214, 214), false)
            } else {
                color(cell.fg)
            };
            let bg = if cell.bg == Color::Reset {
                (18, 20, 24)
            } else {
                color(cell.bg).0
            };
            row.push(serde_json::json!({
                "s": cell.symbol(),
                "fg": fg,
                "bg": bg,
                "b": bold,
            }));
        }
        rows.push(row);
    }
    let document = serde_json::json!({
        "width": width,
        "height": height,
        "rows": rows,
    });
    std::fs::write(path, serde_json::to_vec(&document)?)
}

fn color(color: Color) -> ((u8, u8, u8), bool) {
    let value = match color {
        Color::Black => (0, 0, 0),
        Color::Red => (180, 40, 40),
        Color::Green => (40, 160, 80),
        Color::Yellow => (190, 150, 20),
        Color::Blue => (50, 80, 180),
        Color::Magenta => (170, 60, 150),
        Color::Cyan => (30, 180, 190),
        Color::Gray => (170, 170, 170),
        Color::DarkGray => (100, 100, 100),
        Color::LightRed => (240, 100, 100),
        Color::LightGreen => (100, 220, 130),
        Color::LightYellow => (240, 210, 90),
        Color::LightBlue => (100, 140, 240),
        Color::LightMagenta => (230, 120, 210),
        Color::LightCyan => (100, 230, 240),
        Color::White => (235, 235, 235),
        Color::Rgb(r, g, b) => (r, g, b),
        _ => (214, 214, 214),
    };
    (value, false)
}

fn synthetic() -> ViewModel {
    let status = StatusSnapshot {
        lifecycle: Lifecycle::Running,
        generation: 42,
        config_version: "sha256:7de41d113960e6fe006955a8d78976681116014e8bd0a5210287bdf9df8af047"
            .to_owned(),
        users_version: Some(
            "sha256:a8429444399efd8447830d759f70b4c2d69894090598d9c811189e01915f4acb".to_owned(),
        ),
        live_generations: 1,
        uptime_ms: 8_640_000,
        worker_threads: 4,
        listeners: vec![
            angara::control::ListenerStatus {
                id: "proxy-loopback".to_owned(),
                bind: "127.0.0.1:3128".to_owned(),
                transport: "http".to_owned(),
                auth: "none".to_owned(),
            },
            angara::control::ListenerStatus {
                id: "proxy-tls".to_owned(),
                bind: "0.0.0.0:8443".to_owned(),
                transport: "https".to_owned(),
                auth: "basic".to_owned(),
            },
        ],
        egress: vec![
            angara::control::EgressStatus {
                id: "system".to_owned(),
                mode: "system".to_owned(),
                bind_ip: None,
            },
            angara::control::EgressStatus {
                id: "lan".to_owned(),
                mode: "bind_ip".to_owned(),
                bind_ip: Some("192.0.2.10".to_owned()),
            },
        ],
        max_client_connections: 128,
        max_connections: 256,
        client_active: 3,
        outbound_active: 2,
        tls_active: 0,
        connect_active: 1,
        auth_active: 0,
        dns_active: 0,
        pool_idle: 2,
        pool_leased: 1,
        reload_busy: false,
        last_reload: Some(ReloadOutcome::Applied { generation: 42 }),
    };
    let proxy = ProxySnapshot {
        api_version: 1,
        instance_id: "a1b2c3d4".to_owned(),
        generation: 42,
        config_version: status.config_version.clone(),
        users_version: status.users_version.clone(),
        config_path: "/etc/angara/angara.toml".to_owned(),
        users_path: Some("/etc/angara/users.toml".to_owned()),
        status: status.clone(),
        access: AccessSummary {
            source_allow: vec!["127.0.0.0/8".to_owned(), "::1/128".to_owned()],
            rule_count: 3,
            ip_rule_count: 1,
            ip_default: "deny".to_owned(),
        },
        routing: angara::control_protocol::RoutingSummary {
            default_egress: "system".to_owned(),
            default_parent: None,
            rule_count: 0,
        },
        counters: angara::control_protocol::CounterSummary {
            tcp_accepted: 128,
            tcp_rejected: 2,
            http_completed: 96,
            http_cancelled: 1,
            http_4xx: 7,
            http_5xx: 1,
            connect_completed: 4,
            connect_error: 0,
            auth_ok: 90,
            auth_invalid: 6,
            dns_error: 0,
            reload_applied: 4,
            reload_rejected: 0,
            cache_hit: 22,
            cache_miss: 31,
            log_dropped: 0,
        },
        user_count: 3,
        block_count: 1,
        connection_count: 3,
        limits: ApiLimits::default(),
    };
    let mut model = ViewModel::new();
    model.connected = true;
    model.writable = true;
    model.status_message = "на связи · изменения синхронизированы".to_owned();
    model.event_cursor = 128;
    model.snapshot = Some(Snapshot {
        proxy: proxy.clone(),
        event_cursor: 128,
        writable: true,
    });
    model.status = Some(status);
    model.users = vec![
        UserStatus {
            username: "alice".to_owned(),
            block: "active".to_owned(),
            blocked_until: None,
            remaining_seconds: None,
        },
        UserStatus {
            username: "bob".to_owned(),
            block: "temporary".to_owned(),
            blocked_until: Some("2026-11-27T18:30:00Z".to_owned()),
            remaining_seconds: Some(1_620),
        },
        UserStatus {
            username: "carol".to_owned(),
            block: "permanent".to_owned(),
            blocked_until: None,
            remaining_seconds: None,
        },
    ];
    model.users_total = 3;
    model.blocks = vec![BlockStatus {
        username: "bob".to_owned(),
        kind: "temporary".to_owned(),
        blocked_until: Some("2026-11-27T18:30:00Z".to_owned()),
        remaining_seconds: Some(1_620),
    }];
    model.blocks_total = 2;
    model.connections = vec![
        ConnectionRow {
            id: 101,
            listener: "proxy-loopback".to_owned(),
            transport: "http".to_owned(),
            state: ConnectionState::Http,
            duration_ms: 14_500,
            requests: 7,
        },
        ConnectionRow {
            id: 102,
            listener: "proxy-tls".to_owned(),
            transport: "https".to_owned(),
            state: ConnectionState::Connect,
            duration_ms: 62_000,
            requests: 1,
        },
        ConnectionRow {
            id: 103,
            listener: "proxy-loopback".to_owned(),
            transport: "http".to_owned(),
            state: ConnectionState::Http,
            duration_ms: 800,
            requests: 2,
        },
    ];
    model.connections_total = 3;
    model.access = Some(AccessPage {
        section: angara::control_protocol::AccessSection::Rules,
        source_allow: vec!["127.0.0.0/8".to_owned(), "::1/128".to_owned()],
        rules: vec![
            AccessRuleView {
                id: "deny-metadata".to_owned(),
                action: "deny".to_owned(),
                listeners: None,
                sources: None,
                methods: None,
                ports: None,
                users: None,
                host_exact: Some(vec!["metadata.example".to_owned()]),
                host_suffix: None,
            },
            AccessRuleView {
                id: "allow-ops".to_owned(),
                action: "allow".to_owned(),
                listeners: Some(vec!["proxy-loopback".to_owned()]),
                sources: Some(vec!["127.0.0.0/8".to_owned()]),
                methods: Some(vec!["GET".to_owned(), "POST".to_owned()]),
                ports: Some(vec![80, 443]),
                users: Some(vec!["alice".to_owned(), "bob".to_owned()]),
                host_exact: None,
                host_suffix: None,
            },
            AccessRuleView {
                id: "allow-lab".to_owned(),
                action: "allow".to_owned(),
                listeners: None,
                sources: Some(vec!["10.20.0.0/16".to_owned()]),
                methods: None,
                ports: None,
                users: None,
                host_exact: None,
                host_suffix: Some(vec!["lab.example".to_owned()]),
            },
        ],
        ip_rules: vec![angara::control_protocol::IpRuleView {
            id: "loopback".to_owned(),
            action: "allow".to_owned(),
            networks: vec!["127.0.0.0/8".to_owned()],
            allow_special: true,
        }],
        ip_default: "deny".to_owned(),
        offset: 0,
        total: 3,
    });
    model.config = Some(ConfigState {
        config_path: "/etc/angara/angara.toml".to_owned(),
        users_path: Some("/etc/angara/users.toml".to_owned()),
        active_config_version: proxy.config_version.clone(),
        disk_config_version: Some(proxy.config_version.clone()),
        active_users_version: proxy.users_version.clone(),
        disk_users_version: proxy.users_version.clone(),
        generation: 42,
        last_reload: Some(ReloadOutcome::Applied { generation: 42 }),
        writable: true,
        valid: true,
        detail: None,
    });
    model.events = vec![
        Event {
            cursor: 125,
            kind: EventKind::UsersSaved,
            at: "2026-11-27T18:01:10Z".to_owned(),
            generation: 41,
            config_version: None,
            users_version: proxy.users_version.clone(),
            username: Some("bob".to_owned()),
            detail: Some("блокировка сохранена: bob".to_owned()),
        },
        Event {
            cursor: 126,
            kind: EventKind::ConfigApplied,
            at: "2026-11-27T18:01:11Z".to_owned(),
            generation: 42,
            config_version: Some(proxy.config_version.clone()),
            users_version: proxy.users_version.clone(),
            username: None,
            detail: Some("активное поколение обновлено".to_owned()),
        },
        Event {
            cursor: 127,
            kind: EventKind::BlockExpired,
            at: "2026-11-27T18:02:00Z".to_owned(),
            generation: 42,
            config_version: None,
            users_version: None,
            username: Some("dave".to_owned()),
            detail: Some("срок блокировки истёк".to_owned()),
        },
        Event {
            cursor: 128,
            kind: EventKind::ConfigSaved,
            at: "2026-11-27T18:02:04Z".to_owned(),
            generation: 42,
            config_version: Some(proxy.config_version.clone()),
            users_version: None,
            username: None,
            detail: Some("файл конфигурации изменён на диске".to_owned()),
        },
    ];
    model
}
