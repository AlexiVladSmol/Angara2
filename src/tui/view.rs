//! Ratatui rendering for [`ViewModel`].

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};

use crate::tui::viewmodel::{FormKind, Screen, ViewModel};

const ACCENT: Color = Color::Cyan;
const ERROR: Color = Color::Red;
const MUTED: Color = Color::DarkGray;

pub fn draw(frame: &mut Frame<'_>, model: &ViewModel) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(4),
            Constraint::Length(2),
        ])
        .split(area);
    draw_header(frame, chunks[0], model);
    draw_screen(frame, chunks[1], model);
    draw_footer(frame, chunks[2], model);
    if model.palette {
        draw_palette(frame, area);
    } else if model.help {
        draw_help(frame, area);
    } else if let Some(confirm) = &model.confirm {
        draw_confirm(frame, area, confirm);
    } else if let Some(preview) = &model.preview {
        draw_preview(frame, area, preview);
    } else if let Some(form) = &model.form {
        draw_form(frame, area, form);
    }
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    let generation = model
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.proxy.generation)
        .or_else(|| model.status.as_ref().map(|status| status.generation))
        .unwrap_or(0);
    let connection = if model.connected {
        Span::styled("● на связи", Style::default().fg(ACCENT))
    } else {
        Span::styled("○ нет связи", Style::default().fg(ERROR))
    };
    let title = Line::from(vec![
        Span::styled(
            " Angara ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::raw("· терминальное управление  "),
        connection,
        Span::raw(format!(
            "  поколение {generation}  события {}  {}",
            model.event_cursor,
            if model.writable {
                "запись разрешена"
            } else {
                "только чтение"
            }
        )),
    ]);
    let tabs = Line::from(
        [
            "1 Обзор",
            "2 Входы",
            "3 Соединения",
            "4 Пользователи",
            "5 Блокировки",
            "6 Доступ",
            "7 Конфигурация",
            "8 События",
        ]
        .into_iter()
        .enumerate()
        .flat_map(|(index, label)| {
            let active = index == screen_index(model.screen);
            let style = if active {
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(MUTED)
            };
            [Span::styled(format!(" {label} "), style), Span::raw(" ")]
        })
        .collect::<Vec<_>>(),
    );
    frame.render_widget(
        Paragraph::new(vec![title, tabs])
            .block(Block::bordered().border_style(Style::default().fg(MUTED))),
        area,
    );
}

fn screen_index(screen: Screen) -> usize {
    match screen {
        Screen::Overview => 0,
        Screen::Routes => 1,
        Screen::Connections => 2,
        Screen::Users => 3,
        Screen::Blocks => 4,
        Screen::Access => 5,
        Screen::Config => 6,
        Screen::Events => 7,
    }
}

fn draw_screen(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    match model.screen {
        Screen::Overview => draw_overview(frame, area, model),
        Screen::Routes => draw_routes(frame, area, model),
        Screen::Connections => draw_connections(frame, area, model),
        Screen::Users => draw_users(frame, area, model),
        Screen::Blocks => draw_blocks(frame, area, model),
        Screen::Access => draw_access(frame, area, model),
        Screen::Config => draw_config(frame, area, model),
        Screen::Events => draw_events(frame, area, model),
    }
}

fn draw_overview(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    let Some(status) = &model.status else {
        frame.render_widget(empty("Обзор", "снимок ещё не получен"), area);
        return;
    };
    let Some(snapshot) = &model.snapshot else {
        frame.render_widget(empty("Обзор", "снимок ещё не получен"), area);
        return;
    };
    let last = snapshot
        .proxy
        .status
        .last_reload
        .as_ref()
        .map(describe_reload)
        .unwrap_or_else(|| "нет данных".to_owned());
    let lines = vec![
        Line::from(vec![
            Span::styled("Состояние  ", Style::default().fg(MUTED)),
            Span::raw(format!("{:?}", status.lifecycle)),
        ]),
        Line::from(vec![
            Span::styled("Поколение  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "{} · живых {}",
                status.generation, status.live_generations
            )),
        ]),
        Line::from(vec![
            Span::styled("Последнее применение  ", Style::default().fg(MUTED)),
            Span::raw(last),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Клиенты  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "{} / {}",
                status.client_active, status.max_client_connections
            )),
            Span::raw("    "),
            Span::styled("Исходящие  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "{} / {}",
                status.outbound_active, status.max_connections
            )),
        ]),
        Line::from(vec![
            Span::styled("CONNECT  ", Style::default().fg(MUTED)),
            Span::raw(status.connect_active.to_string()),
            Span::raw("    "),
            Span::styled("TLS  ", Style::default().fg(MUTED)),
            Span::raw(status.tls_active.to_string()),
            Span::raw("    "),
            Span::styled("Auth  ", Style::default().fg(MUTED)),
            Span::raw(status.auth_active.to_string()),
            Span::raw("    "),
            Span::styled("DNS  ", Style::default().fg(MUTED)),
            Span::raw(status.dns_active.to_string()),
        ]),
        Line::from(vec![
            Span::styled("HTTP  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "ok {} · cancel {} · 4xx {} · 5xx {}",
                snapshot.proxy.counters.http_completed,
                snapshot.proxy.counters.http_cancelled,
                snapshot.proxy.counters.http_4xx,
                snapshot.proxy.counters.http_5xx
            )),
        ]),
        Line::from(vec![
            Span::styled("CONNECT  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "ok {} · error {}",
                snapshot.proxy.counters.connect_completed, snapshot.proxy.counters.connect_error
            )),
            Span::raw("    "),
            Span::styled("Auth  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "ok {} · invalid {}",
                snapshot.proxy.counters.auth_ok, snapshot.proxy.counters.auth_invalid
            )),
        ]),
        Line::from(vec![
            Span::styled("Кеш  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "hit {} · miss {}",
                snapshot.proxy.counters.cache_hit, snapshot.proxy.counters.cache_miss
            )),
            Span::raw("    "),
            Span::styled("Reload  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "applied {} · rejected {}",
                snapshot.proxy.counters.reload_applied, snapshot.proxy.counters.reload_rejected
            )),
        ]),
        Line::from(vec![
            Span::styled("Пул  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "idle {} · leased {}",
                status.pool_idle, status.pool_leased
            )),
            Span::raw("    "),
            Span::styled("Соединения в API  ", Style::default().fg(MUTED)),
            Span::raw(snapshot.proxy.connection_count.to_string()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Конфигурация  ", Style::default().fg(MUTED)),
            Span::raw(short_version(&snapshot.proxy.config_version)),
        ]),
        Line::from(vec![
            Span::styled("Пользователи  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "{} · блокировок {}",
                snapshot.proxy.user_count, snapshot.proxy.block_count
            )),
        ]),
        Line::from(vec![
            Span::styled("Uptime  ", Style::default().fg(MUTED)),
            Span::raw(format_duration(status.uptime_ms)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .title(" Обзор и ресурсы ")
                .border_style(Style::default().fg(MUTED)),
        ),
        area,
    );
}

fn draw_routes(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    let Some(snapshot) = &model.snapshot else {
        frame.render_widget(empty("Входы и маршруты", "снимок ещё не получен"), area);
        return;
    };
    let mut lines = vec![Line::from(Span::styled(
        "Входы",
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    ))];
    for listener in &snapshot.proxy.status.listeners {
        lines.push(Line::from(format!(
            "  {}  {}  {}  auth={}",
            listener.id, listener.bind, listener.transport, listener.auth
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Исходящие маршруты",
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    )));
    for egress in &snapshot.proxy.status.egress {
        lines.push(Line::from(format!(
            "  {}  {}{}",
            egress.id,
            egress.mode,
            egress
                .bind_ip
                .as_ref()
                .map(|ip| format!(" · {ip}"))
                .unwrap_or_default()
        )));
    }
    let routing = &snapshot.proxy.routing;
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Маршрутизация",
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(format!(
        "  default_egress={} · default_parent={} · правил {}",
        routing.default_egress,
        routing.default_parent.as_deref().unwrap_or("—"),
        routing.rule_count
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Диагностический экран. Маршруты меняются только через конфигурацию.",
    ));
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .title(" Входы и исходящие маршруты ")
                .border_style(Style::default().fg(MUTED)),
        ),
        area,
    );
}

fn draw_connections(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    let items = model
        .connections
        .iter()
        .map(|row| {
            let marker = match row.state {
                crate::connections::ConnectionState::Connect => "T",
                crate::connections::ConnectionState::TlsHandshake => "H",
                crate::connections::ConnectionState::Http => "H",
            };
            format!(
                "{marker} #{:<6} {:<16} {:<10} {:>8}  req {}",
                row.id,
                truncate(&row.listener, 16),
                row.transport,
                format_duration(row.duration_ms),
                row.requests
            )
        })
        .collect::<Vec<_>>();
    let detail = model.connections.get(model.selected_index()).map(|row| {
        vec![
            format!("ID: {}", row.id),
            format!("Listener: {}", row.listener),
            format!("Transport: {}", row.transport),
            format!("State: {:?}", row.state),
            format!("Duration: {}", format_duration(row.duration_ms)),
            format!("Requests: {}", row.requests),
        ]
    });
    draw_list_detail(
        frame,
        area,
        " Активные соединения ",
        &items,
        model.selected_index(),
        detail,
        model.page_label(model.connections.len(), model.connections_total),
    );
}

fn draw_users(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    let items = model
        .users
        .iter()
        .map(|user| {
            let (marker, suffix) = match user.block.as_str() {
                "permanent" => ("■", "бессрочная блокировка".to_owned()),
                "temporary" => (
                    "◐",
                    format!(
                        "до {} ({} с)",
                        local_time(user.blocked_until.as_deref().unwrap_or("?")),
                        user.remaining_seconds.unwrap_or(0)
                    ),
                ),
                _ => ("●", "активен".to_owned()),
            };
            format!("{marker} {:<32} {suffix}", user.username)
        })
        .collect::<Vec<_>>();
    let detail = model.users.get(model.selected_index()).map(|user| {
        vec![
            format!("Логин: {}", user.username),
            format!("Состояние: {}", user.block),
            format!(
                "До: {}",
                user.blocked_until
                    .as_deref()
                    .map(local_time)
                    .unwrap_or_else(|| "—".to_owned())
            ),
            format!(
                "Осталось: {}",
                user.remaining_seconds
                    .map(|seconds| format!("{seconds} с"))
                    .unwrap_or_else(|| "—".to_owned())
            ),
            String::new(),
            "a — добавить · p/e — сменить пароль · b — блокировка".to_owned(),
        ]
    });
    draw_list_detail(
        frame,
        area,
        " Пользователи ",
        &items,
        model.selected_index(),
        detail,
        format!(
            "{} · поиск / · [ ] страницы",
            model.page_label(model.users.len(), model.users_total)
        ),
    );
}

fn draw_blocks(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    let items = model
        .blocks
        .iter()
        .map(|block| {
            format!(
                "{:<32} {:<10} {}",
                block.username,
                block.kind,
                block
                    .blocked_until
                    .as_deref()
                    .map(|until| format!("{until} · {} с", block.remaining_seconds.unwrap_or(0)))
                    .unwrap_or_else(|| "до снятия".to_owned())
            )
        })
        .collect::<Vec<_>>();
    let detail = model.blocks.get(model.selected_index()).map(|block| {
        vec![
            format!("Логин: {}", block.username),
            format!("Вид: {}", block.kind),
            format!(
                "До: {}",
                block
                    .blocked_until
                    .as_deref()
                    .map(local_time)
                    .unwrap_or_else(|| "—".to_owned())
            ),
            String::new(),
            "a — добавить · e — изменить · x — снять".to_owned(),
        ]
    });
    draw_list_detail(
        frame,
        area,
        " Блокировки ",
        &items,
        model.selected_index(),
        detail,
        format!(
            "{} из {} · истечение не пишет TOML",
            model.blocks.len(),
            model.blocks_total
        ),
    );
}

fn draw_access(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    let Some(page) = &model.access else {
        frame.render_widget(empty("Доступ", "правила ещё не загружены"), area);
        return;
    };
    let mut items = Vec::new();
    let detail;
    let section_title;
    match model.access_section {
        "source" => {
            section_title = " Разрешённые источники ";
            for (index, source) in page.source_allow.iter().enumerate() {
                items.push(format!("{index:>3}  {source}"));
            }
            detail = page.source_allow.get(model.selected_index()).map(|source| {
                vec![
                    format!("Источник: {source}"),
                    String::new(),
                    "a — добавить · d/x — удалить · v — другой раздел".to_owned(),
                ]
            });
        }
        "ip_rules" => {
            section_title = " IP-политика ";
            for rule in &page.ip_rules {
                items.push(format!(
                    "{:<20} {:<5} {}",
                    truncate(&rule.id, 20),
                    rule.action,
                    truncate(&rule.networks.join(","), 36)
                ));
            }
            detail = page.ip_rules.get(model.selected_index()).map(|rule| {
                vec![
                    format!("ID: {}", rule.id),
                    format!("Действие: {}", rule.action),
                    format!("Сети: {}", rule.networks.join(", ")),
                    format!("allow_special: {}", rule.allow_special),
                    String::new(),
                    "a — создать · e — изменить · d — удалить · J/K — порядок".to_owned(),
                ]
            });
        }
        _ => {
            section_title = " Упорядоченные правила ";
            for rule in &page.rules {
                let hosts = rule
                    .host_exact
                    .as_ref()
                    .or(rule.host_suffix.as_ref())
                    .map(|hosts| hosts.join(","))
                    .unwrap_or_else(|| "any".to_owned());
                let users = rule
                    .users
                    .as_ref()
                    .map(|users| format!(" · users {}", users.join(",")))
                    .unwrap_or_default();
                items.push(format!(
                    "{:<20} {:<5} {}{}",
                    truncate(&rule.id, 20),
                    rule.action,
                    truncate(&hosts, 32),
                    users
                ));
            }
            detail = page.rules.get(model.selected_index()).map(|rule| {
                vec![
                    format!("ID: {}", rule.id),
                    format!("Действие: {}", rule.action),
                    format!(
                        "Хосты: {}",
                        rule.host_exact
                            .as_ref()
                            .or(rule.host_suffix.as_ref())
                            .map(|hosts| hosts.join(", "))
                            .unwrap_or_else(|| "any".to_owned())
                    ),
                    format!(
                        "Users: {}",
                        rule.users
                            .as_ref()
                            .map(|users| users.join(", "))
                            .unwrap_or_else(|| "any".to_owned())
                    ),
                    String::new(),
                    "a — создать · e — изменить · d — удалить · J/K — порядок".to_owned(),
                ]
            });
        }
    }
    let shown = page
        .source_allow
        .iter()
        .take(8)
        .cloned()
        .collect::<Vec<_>>();
    let extra = page.source_allow.len().saturating_sub(shown.len());
    let header = format!(
        "Источники: {}{} · правил {} · IP-правил {} · ip_default {}\n\n",
        shown.join(", "),
        if extra == 0 {
            String::new()
        } else {
            format!(" … +{extra}")
        },
        page.rules.len(),
        page.ip_rules.len(),
        page.ip_default
    );
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(2)])
        .split(area);
    frame.render_widget(
        Paragraph::new(header).block(
            Block::bordered()
                .title(" Правила доступа ")
                .border_style(Style::default().fg(MUTED)),
        ),
        chunks[0],
    );
    draw_list_detail(
        frame,
        chunks[1],
        section_title,
        &items,
        model.selected_index(),
        detail,
        format!(
            "{} · v — раздел · a/e/d · J/K",
            model.page_label(items.len(), page.total.max(items.len()))
        ),
    );
}

fn draw_config(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    let mut lines = Vec::new();
    if let Some(state) = &model.config {
        lines.push(Line::from(format!("Файл: {}", state.config_path)));
        lines.push(Line::from(format!(
            "Users: {}",
            state
                .users_path
                .as_deref()
                .unwrap_or("локальная аутентификация не настроена")
        )));
        lines.push(Line::from(format!(
            "Активная версия: {}",
            short_version(&state.active_config_version)
        )));
        lines.push(Line::from(format!(
            "Версия на диске: {}",
            state
                .disk_config_version
                .as_deref()
                .map(short_version)
                .unwrap_or_else(|| "недоступна".to_owned())
        )));
        lines.push(Line::from(format!(
            "Users active/disk: {} / {}",
            state
                .active_users_version
                .as_deref()
                .map(short_version)
                .unwrap_or_else(|| "—".to_owned()),
            state
                .disk_users_version
                .as_deref()
                .map(short_version)
                .unwrap_or_else(|| "—".to_owned())
        )));
        lines.push(Line::from(format!("Поколение: {}", state.generation)));
        lines.push(Line::from(format!(
            "Последний reload: {}",
            state
                .last_reload
                .as_ref()
                .map(describe_reload)
                .unwrap_or_else(|| "нет".to_owned())
        )));
        if !state.valid {
            lines.push(Line::from(Span::styled(
                format!(
                    "Файл на диске невалиден: {}",
                    state.detail.as_deref().unwrap_or("")
                ),
                Style::default().fg(ERROR),
            )));
        }
        if state.active_config_version != state.disk_config_version.clone().unwrap_or_default() {
            lines.push(Line::from(Span::styled(
                "Внимание: диск и активное поколение различаются",
                Style::default().fg(Color::Yellow),
            )));
        }
    } else {
        lines.push(Line::from("состояние конфигурации ещё не загружено"));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("c — проверить · A — применить · r — обновить"));
    lines.push(Line::from(
        "Проверено ≠ сохранено ≠ применено. После сохранения интерфейс сверяет версии.",
    ));
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .title(" Конфигурация ")
                .border_style(Style::default().fg(MUTED)),
        ),
        area,
    );
}

fn draw_events(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    let items = model
        .events
        .iter()
        .filter(|event| model.event_filter.is_none_or(|kind| kind == event.kind))
        .map(|event| {
            format!(
                "{:>5} {:<17} {} {}",
                event.cursor,
                format_kind(&event.kind),
                local_clock(&event.at),
                event
                    .username
                    .as_deref()
                    .map(|username| format!("· {username}"))
                    .or_else(|| event.detail.clone())
                    .unwrap_or_default()
            )
        })
        .collect::<Vec<_>>();
    let detail = model.events.get(model.selected_index()).map(|event| {
        vec![
            format!("Курсор: {}", event.cursor),
            format!("Категория: {:?}", event.kind),
            format!("Время: {}", event.at),
            format!("Поколение: {}", event.generation),
            format!("Логин: {}", event.username.as_deref().unwrap_or("—")),
            format!("Детали: {}", event.detail.as_deref().unwrap_or("—")),
        ]
    });
    draw_list_detail(
        frame,
        area,
        " События ",
        &items,
        model.selected_index(),
        detail,
        format!(
            "фильтр: {} · f — сменить · история ограничена",
            model
                .event_filter
                .map(|kind| format!("{kind:?}"))
                .unwrap_or_else(|| "все".to_owned())
        ),
    );
}

fn draw_list_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    items: &[String],
    selected: usize,
    detail: Option<Vec<String>>,
    footer: String,
) {
    let (list_area, detail_area) = if area.width >= 100 {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(area);
        (chunks[0], Some(chunks[1]))
    } else if area.height >= 10 {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(4), Constraint::Length(6)])
            .split(area);
        (chunks[0], Some(chunks[1]))
    } else {
        (area, None)
    };
    let list_items = if items.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "  пусто",
            Style::default().fg(MUTED),
        )))]
    } else {
        items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let style = if index == selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(ACCENT)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(format!(" {item}"), style)))
            })
            .collect()
    };
    frame.render_widget(
        List::new(list_items)
            .block(
                Block::bordered()
                    .title(format!(" {title}"))
                    .border_style(Style::default().fg(MUTED)),
            )
            .highlight_style(Style::default()),
        list_area,
    );
    if let Some(detail_area) = detail_area {
        let lines = detail
            .map(|lines| lines.into_iter().map(Line::from).collect())
            .unwrap_or_else(|| vec![Line::from("строка не выбрана")]);
        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                Block::bordered()
                    .title(" Карточка ")
                    .border_style(Style::default().fg(MUTED)),
            ),
            detail_area,
        );
        let _ = footer;
    }
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, model: &ViewModel) {
    let search = if model.search_active {
        format!("/{}", model.filter)
    } else if model.filter.is_empty() {
        "/ поиск".to_owned()
    } else {
        format!("фильтр: {}", model.filter)
    };
    let line = Line::from(vec![
        Span::styled(
            format!(" {} ", model.status_message),
            Style::default().fg(if model.error.is_some() { ERROR } else { MUTED }),
        ),
        Span::raw("  "),
        Span::styled(search, Style::default().fg(ACCENT)),
        Span::raw("  ·  Ctrl+P палитра · ? справка · q выход"),
    ]);
    let error = model
        .error
        .as_ref()
        .map(|error| {
            Line::from(Span::styled(
                format!(" ! {error}"),
                Style::default().fg(ERROR),
            ))
        })
        .unwrap_or_else(|| Line::from(""));
    frame.render_widget(Paragraph::new(vec![line, error]), area);
}

fn draw_palette(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(" 1  Обзор и ресурсы"),
        Line::from(" 2  Входы и маршруты"),
        Line::from(" 3  Активные соединения"),
        Line::from(" 4  Пользователи"),
        Line::from(" 5  Блокировки"),
        Line::from(" 6  Правила доступа"),
        Line::from(" 7  Конфигурация"),
        Line::from(" 8  События и ошибки"),
        Line::from(""),
        Line::from(" ?  Справка      q  Выход"),
        Line::from(""),
        Line::from(Span::styled("Esc — закрыть", Style::default().fg(MUTED))),
    ];
    draw_centered(frame, area, 46, 16, " Палитра действий ", lines);
}

fn draw_help(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from("Навигация"),
        Line::from("  /        поиск по текущему списку"),
        Line::from("  [ ]      предыдущая/следующая страница"),
        Line::from("  j/k ↑/↓  выбор строки"),
        Line::from("  PgUp/PgDn быстрый переход"),
        Line::from("  1..8     экраны, Ctrl+P палитра, q выход"),
        Line::from(""),
        Line::from("Действия"),
        Line::from("  a добавить · e изменить · d удалить"),
        Line::from("  J/K переместить правило · v раздел ACL · i ip_default"),
        Line::from("  c проверить · A применить · f фильтр событий"),
        Line::from("  Enter открыть/проверить · Esc отмена"),
        Line::from(""),
        Line::from("Пароль вводится скрыто и не попадает в argv, env или журнал."),
        Line::from("Сохранение и применение — разные состояния: проверяйте поколение."),
    ];
    draw_centered(frame, area, 74, 18, " Справка ", lines);
}

fn draw_confirm(frame: &mut Frame<'_>, area: Rect, confirm: &crate::tui::viewmodel::Confirm) {
    let lines = vec![
        Line::from(confirm.detail.clone()),
        Line::from(""),
        Line::from(Span::styled(
            "Enter — подтвердить · Esc — отмена",
            Style::default().fg(ACCENT),
        )),
    ];
    draw_centered(frame, area, 72, 10, &format!(" {} ", confirm.title), lines);
}

fn draw_preview(frame: &mut Frame<'_>, area: Rect, preview: &crate::tui::viewmodel::Preview) {
    let mut lines = vec![Line::from(preview.summary.clone()), Line::from("")];
    if let Some(before) = &preview.before {
        lines.push(Line::from(Span::styled(
            "Было:",
            Style::default().fg(MUTED),
        )));
        for line in before.lines().take(5) {
            lines.push(Line::from(truncate(line, 68)));
        }
    }
    if let Some(after) = &preview.after {
        lines.push(Line::from(Span::styled(
            "Станет:",
            Style::default().fg(MUTED),
        )));
        for line in after.lines().take(5) {
            lines.push(Line::from(truncate(line, 68)));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Enter — применить · Esc — отмена",
        Style::default().fg(ACCENT),
    )));
    draw_centered(frame, area, 74, 18, " Предпросмотр ", lines);
}

fn draw_form(frame: &mut Frame<'_>, area: Rect, form: &crate::tui::viewmodel::Form) {
    let mut lines = Vec::new();
    for (index, field) in form.fields.iter().enumerate() {
        let value = if field.secret {
            "•".repeat(field.value.chars().count().min(32))
        } else {
            field.value.as_str().to_owned()
        };
        let marker = if index == form.focus { ">" } else { " " };
        lines.push(Line::from(format!("{marker} {:<28} {value}", field.label)));
    }
    lines.push(Line::from(""));
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(ERROR),
        )));
    }
    lines.push(Line::from(Span::styled(
        form.hint.clone(),
        Style::default().fg(MUTED),
    )));
    let height = (lines.len() as u16 + 4).max(10);
    draw_centered(frame, area, 76, height, &format!(" {} ", form.title), lines);
    let _ = FormKind::AddUser;
}

fn draw_centered(
    frame: &mut Frame<'_>,
    area: Rect,
    width: u16,
    height: u16,
    title: &str,
    lines: Vec<Line<'_>>,
) {
    let width = width.min(area.width.saturating_sub(2)).max(20);
    let height = height.min(area.height.saturating_sub(2)).max(4);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let popup = Rect::new(x, y, width, height);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: false })
            .block(
                Block::bordered()
                    .title(title.to_owned())
                    .border_style(Style::default().fg(ACCENT)),
            ),
        popup,
    );
}

fn empty<'a>(title: &'a str, message: &'a str) -> Paragraph<'a> {
    Paragraph::new(Line::from(Span::styled(
        message.to_owned(),
        Style::default().fg(MUTED),
    )))
    .block(
        Block::bordered()
            .title(format!(" {title} "))
            .border_style(Style::default().fg(MUTED)),
    )
}

fn describe_reload(outcome: &crate::control::ReloadOutcome) -> String {
    use crate::control::ReloadOutcome;
    match outcome {
        ReloadOutcome::Applied { generation } => format!("применено · поколение {generation}"),
        ReloadOutcome::Valid { generation } => format!("проверено · поколение {generation}"),
        ReloadOutcome::Invalid { fields, .. } => format!("отклонено · {}", fields.join(",")),
        ReloadOutcome::RestartRequired { fields, .. } => {
            format!("нужен перезапуск · {}", fields.join(","))
        }
        ReloadOutcome::Conflict { current } => format!("конфликт · {current}"),
        ReloadOutcome::Busy => "занято".to_owned(),
        ReloadOutcome::GenerationBusy => "предел поколений".to_owned(),
        ReloadOutcome::TimedOut => "таймаут".to_owned(),
        ReloadOutcome::Cancelled => "отменено".to_owned(),
        ReloadOutcome::ShuttingDown => "остановка".to_owned(),
        ReloadOutcome::Internal => "ошибка".to_owned(),
    }
}

fn local_time(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %:z")
                .to_string()
        })
        .unwrap_or_else(|_| value.to_owned())
}

fn local_clock(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%H:%M:%S %:z")
                .to_string()
        })
        .unwrap_or_else(|_| value.to_owned())
}

fn short_version(version: &str) -> String {
    version.chars().take(19).collect()
}

fn format_duration(milliseconds: u64) -> String {
    if milliseconds >= 60_000 {
        format!(
            "{}.{}m",
            milliseconds / 60_000,
            (milliseconds % 60_000) / 10_000
        )
    } else if milliseconds >= 1_000 {
        format!("{}.{}s", milliseconds / 1_000, (milliseconds % 1_000) / 100)
    } else {
        format!("{milliseconds}ms")
    }
}

fn format_kind(kind: &crate::control_protocol::EventKind) -> String {
    use crate::control_protocol::EventKind;
    match kind {
        EventKind::ConfigSaved => "config.saved",
        EventKind::ConfigApplied => "config.applied",
        EventKind::ConfigRejected => "config.rejected",
        EventKind::UsersSaved => "users.saved",
        EventKind::BlockExpired => "block.expired",
        EventKind::Resync => "resync",
    }
    .to_owned()
}

fn truncate(value: &str, width: usize) -> String {
    let mut output: String = value.chars().take(width).collect();
    if value.chars().count() > width {
        output.pop();
        output.push('…');
    }
    output
}
