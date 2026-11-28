//! Terminal control panel (Ratatui + Crossterm).
//!
//! The terminal layer only renders a [`viewmodel::ViewModel`] and turns input
//! into actions. Network/protocol work lives in [`client`].

pub mod client;
pub mod view;
pub mod viewmodel;

use std::io;

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::control::ReloadOutcome;
use crate::control_protocol::{
    AccessChange, ApiError, Event as ControlEvent, EventEnvelope, Response, WriteOutcome,
};
use client::{Client, Command, Update};
use viewmodel::{FormKind, Pending, Screen, ViewModel};

/// Runs the TUI until the operator quits or the terminal is lost.
pub fn run(socket: &std::path::Path) -> io::Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tui requires an interactive terminal",
        ));
    }
    let mut terminal = ratatui::init();
    let result = run_terminal(&mut terminal, socket);
    ratatui::restore();
    result
}

use std::io::IsTerminal;

fn run_terminal(terminal: &mut DefaultTerminal, socket: &std::path::Path) -> io::Result<()> {
    let client = Client::start(socket.to_path_buf());
    let mut model = ViewModel::new();
    model.set_connected(false);
    client.send(model.refresh_all_command());
    loop {
        while let Some(update) = client.try_update() {
            apply_update(&mut model, update, &client);
        }
        if model.should_quit {
            return Ok(());
        }
        terminal.draw(|frame| view::draw(frame, &model))?;
        if event::poll(std::time::Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    handle_key(&mut model, key, &client);
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}

fn apply_update(model: &mut ViewModel, update: Update, client: &Client) {
    match update {
        Update::Connected => model.set_connected(true),
        Update::Disconnected(message) => model.set_connected_error(message),
        Update::Snapshot(snapshot) => {
            model.apply_snapshot(snapshot);
            client.send(model.refresh_all_command());
        }
        Update::Status(status) => model.apply_status(status),
        Update::Connections(page) => model.apply_connections(page),
        Update::Users(page) => model.apply_users(page),
        Update::Blocks(page) => model.apply_blocks(page),
        Update::Access(page) => model.apply_access(page),
        Update::Config(state) => model.apply_config(state),
        Update::Events(page) => model.apply_events(page),
        Update::Event(event) => {
            let kind = event.kind;
            model.apply_event(event);
            match kind {
                crate::control_protocol::EventKind::UsersSaved
                | crate::control_protocol::EventKind::BlockExpired => {
                    client.send(Command::RefreshUsers {
                        query: model.filter.clone(),
                        offset: model.offset_for(Screen::Users),
                    });
                    client.send(Command::RefreshBlocks {
                        query: model.filter.clone(),
                        offset: model.offset_for(Screen::Blocks),
                    });
                }
                crate::control_protocol::EventKind::ConfigSaved
                | crate::control_protocol::EventKind::ConfigApplied
                | crate::control_protocol::EventKind::ConfigRejected => {
                    client.send(model.refresh_all_command());
                }
                crate::control_protocol::EventKind::Resync => {
                    client.send(model.refresh_all_command());
                }
            }
        }
        Update::Resync => {
            model.status_message = "пропущены события · обновляю снимок".to_owned();
            client.send(model.refresh_all_command());
        }
        Update::Write(outcome) => {
            model.apply_write(outcome);
            client.send(model.refresh_all_command());
        }
        Update::Reload(outcome) => {
            model.apply_reload(outcome);
            client.send(model.refresh_all_command());
        }
        Update::Preview(preview) => model.apply_preview(preview),
        Update::Error(error) => {
            model.apply_error(error);
            client.send(Command::RefreshConfig);
        }
    }
}

fn handle_key(model: &mut ViewModel, key: KeyEvent, client: &Client) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        model.should_quit = true;
        return;
    }
    if model.confirm.is_some() {
        match key.code {
            KeyCode::Enter => confirm(model, client),
            KeyCode::Esc | KeyCode::Char('n') => model.confirm = None,
            _ => {}
        }
        return;
    }
    if model.form.is_some() {
        handle_form_key(model, key, client);
        return;
    }
    if model.preview.is_some() {
        match key.code {
            KeyCode::Enter => confirm_preview(model, client),
            KeyCode::Esc => model.preview = None,
            _ => {}
        }
        return;
    }
    if model.palette {
        match key.code {
            KeyCode::Esc => model.palette = false,
            KeyCode::Char('q') => model.should_quit = true,
            KeyCode::Char('?') => {
                model.palette = false;
                model.help = true;
            }
            KeyCode::Char('1') => {
                model.switch_screen(Screen::Overview);
                client.send(model.search_command());
            }
            KeyCode::Char('2') => {
                model.switch_screen(Screen::Routes);
                client.send(model.search_command());
            }
            KeyCode::Char('3') => {
                model.switch_screen(Screen::Connections);
                client.send(model.search_command());
            }
            KeyCode::Char('4') => {
                model.switch_screen(Screen::Users);
                client.send(model.search_command());
            }
            KeyCode::Char('5') => {
                model.switch_screen(Screen::Blocks);
                client.send(model.search_command());
            }
            KeyCode::Char('6') => {
                model.switch_screen(Screen::Access);
                client.send(model.search_command());
            }
            KeyCode::Char('7') => {
                model.switch_screen(Screen::Config);
                client.send(model.search_command());
            }
            KeyCode::Char('8') => {
                model.switch_screen(Screen::Events);
                client.send(model.search_command());
            }
            _ => {}
        }
        return;
    }
    if model.help {
        if matches!(
            key.code,
            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
        ) {
            model.help = false;
        }
        return;
    }
    if model.search_active {
        match key.code {
            KeyCode::Enter => {
                model.search_active = false;
                client.send(model.search_command());
            }
            KeyCode::Esc => {
                model.search_active = false;
                model.filter.clear();
                client.send(model.search_command());
            }
            KeyCode::Backspace => {
                model.filter.pop();
            }
            KeyCode::Char(character) if model.filter.len() < 64 && !character.is_control() => {
                model.filter.push(character);
            }
            _ => {}
        }
        return;
    }
    match key.code {
        KeyCode::Char('q') => model.should_quit = true,
        KeyCode::Char('?') => model.help = true,
        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.palette = true;
        }
        KeyCode::Char('/') => model.search_active = true,
        KeyCode::Char('1') => {
            model.switch_screen(Screen::Overview);
            client.send(model.search_command());
        }
        KeyCode::Char('2') => {
            model.switch_screen(Screen::Routes);
            client.send(model.search_command());
        }
        KeyCode::Char('3') => {
            model.switch_screen(Screen::Connections);
            client.send(model.search_command());
        }
        KeyCode::Char('4') => {
            model.switch_screen(Screen::Users);
            client.send(model.search_command());
        }
        KeyCode::Char('5') => {
            model.switch_screen(Screen::Blocks);
            client.send(model.search_command());
        }
        KeyCode::Char('6') => {
            model.switch_screen(Screen::Access);
            client.send(model.search_command());
        }
        KeyCode::Char('7') => {
            model.switch_screen(Screen::Config);
            client.send(model.search_command());
        }
        KeyCode::Char('8') => {
            model.switch_screen(Screen::Events);
            client.send(model.search_command());
        }
        KeyCode::Down | KeyCode::Char('j') => model.select_next(),
        KeyCode::Up | KeyCode::Char('k') => model.select_previous(),
        KeyCode::PageDown => model.select_page(1),
        KeyCode::PageUp => model.select_page(-1),
        KeyCode::Esc => {
            model.clear_transient();
            client.send(model.search_command());
        }
        KeyCode::Char('r') => client.send(model.search_command()),
        KeyCode::Char('f') if model.screen == Screen::Events => model.cycle_event_filter(),
        KeyCode::Char(']') => {
            model.next_page();
            client.send(model.search_command());
        }
        KeyCode::Char('[') => {
            model.previous_page();
            client.send(model.search_command());
        }
        KeyCode::Char('c') if model.screen == Screen::Config => {
            client.send(Command::ConfigValidate);
        }
        KeyCode::Char('A') if model.screen == Screen::Config => {
            if let Some(version) = model.disk_config_version() {
                model.confirm = Some(viewmodel::Confirm {
                    title: "Применить конфигурацию".to_owned(),
                    detail: "Проверить и применить файл с диска? Активное поколение изменится только после успешного reload."
                        .to_owned(),
                    pending: Pending::ConfigApply {
                        expected_version: version,
                    },
                });
            }
        }
        KeyCode::Char('a') => action_add(model, client),
        KeyCode::Char('e') | KeyCode::Char('p') if model.screen == Screen::Users => {
            action_edit(model);
        }
        KeyCode::Char('e') => action_edit(model),
        KeyCode::Char('d') => action_delete(model),
        KeyCode::Char('x') if model.screen == Screen::Blocks => action_delete(model),
        KeyCode::Char('J') => action_move(model, true, client),
        KeyCode::Char('K') => action_move(model, false, client),
        KeyCode::Char('v') if model.screen == Screen::Access => {
            model.cycle_access_section();
            client.send(model.search_command());
        }
        KeyCode::Char('i') if model.screen == Screen::Access => {
            model.start_ip_default_form();
        }
        KeyCode::Char('s') if model.screen == Screen::Access => {
            model.start_source_form();
        }
        KeyCode::Char('x') if model.screen == Screen::Access => {
            model.start_source_remove();
        }
        KeyCode::Enter => action_enter(model, client),
        _ => {}
    }
}

fn action_add(model: &mut ViewModel, _client: &Client) {
    match model.screen {
        Screen::Users => model.start_add_user(),
        Screen::Blocks => model.start_block_form(),
        Screen::Access => model.start_access_form(None),
        _ => {}
    }
}

fn action_edit(model: &mut ViewModel) {
    match model.screen {
        Screen::Users => model.start_password_form(),
        Screen::Blocks => model.start_block_edit(),
        Screen::Access => model.start_access_form(Some(model.selected_index())),
        _ => {}
    }
}

fn action_delete(model: &mut ViewModel) {
    if let Some(pending) = model.delete_pending() {
        model.confirm = Some(viewmodel::Confirm {
            title: "Подтверждение".to_owned(),
            detail: model.delete_detail(),
            pending,
        });
    }
}

fn action_move(model: &mut ViewModel, down: bool, _client: &Client) {
    if model.screen != Screen::Access {
        return;
    }
    model.move_rule(down);
}

fn action_enter(model: &mut ViewModel, client: &Client) {
    match model.screen {
        Screen::Config => {
            client.send(Command::ConfigValidate);
        }
        Screen::Users => model.start_password_form(),
        Screen::Blocks => model.start_block_edit(),
        Screen::Access => model.start_access_form(Some(model.selected_index())),
        _ => {}
    }
}

fn handle_form_key(model: &mut ViewModel, key: KeyEvent, client: &Client) {
    let Some(form) = model.form.as_mut() else {
        return;
    };
    match key.code {
        KeyCode::Esc => {
            if model.form_is_dirty() {
                let subject = model
                    .form
                    .as_ref()
                    .and_then(|form| {
                        form.subject.clone().or_else(|| {
                            form.fields
                                .first()
                                .map(|field| field.value.as_str().to_owned())
                                .filter(|value| !value.is_empty())
                        })
                    })
                    .unwrap_or_else(|| "форма".to_owned());
                model.confirm = Some(viewmodel::Confirm {
                    title: "Отменить изменения?".to_owned(),
                    detail: format!("Несохранённые данные формы «{subject}» будут потеряны."),
                    pending: Pending::DiscardForm,
                });
            } else {
                model.discard_form();
            }
        }
        KeyCode::Tab => form.focus_next(false),
        KeyCode::BackTab => form.focus_next(true),
        KeyCode::Enter => {
            if let Some((kind, username)) = model.take_submission() {
                submit(model, client, kind, username);
            }
        }
        KeyCode::Backspace => form.backspace(),
        KeyCode::Char(character) if !character.is_control() => form.push(character),
        _ => {}
    }
}

fn submit(model: &mut ViewModel, client: &Client, kind: FormKind, username: Option<String>) {
    let operation_id = next_operation_id();
    let command = match kind {
        FormKind::AddUser => {
            let Some((password, confirmation, expected)) = model.take_password_fields() else {
                return;
            };
            Command::UserAdd {
                username: username.unwrap_or_default(),
                password,
                password_confirm: confirmation,
                operation_id,
                expected_version: expected,
            }
        }
        FormKind::ChangePassword => {
            let Some((password, confirmation, expected)) = model.take_password_fields() else {
                return;
            };
            Command::UserPassword {
                username: username.unwrap_or_default(),
                password,
                password_confirm: confirmation,
                operation_id,
                expected_version: expected,
            }
        }
        FormKind::SetBlock { permanent: _ } => {
            let Some((until, expected)) = model.take_block_fields() else {
                return;
            };
            Command::BlockSet {
                username: username.unwrap_or_default(),
                permanent: until.is_none(),
                until,
                expected_version: expected,
            }
        }
        FormKind::Source { remove } => {
            let Some((value, index, expected)) = model.take_source_fields() else {
                return;
            };
            let change = if remove {
                AccessChange::SourceRemove {
                    index: index.unwrap_or(0),
                }
            } else {
                AccessChange::SourceAdd {
                    value: value.unwrap_or_default(),
                    index: None,
                }
            };
            model.preview_change = Some(change.clone());
            Command::AccessPreview {
                change,
                expected_version: expected,
            }
        }
        FormKind::Rule { index } => {
            let Some((draft, expected)) = model.take_rule_fields() else {
                return;
            };
            let change = match index {
                Some(index) => AccessChange::RuleUpdate { index, rule: draft },
                None => AccessChange::RuleCreate {
                    index: None,
                    rule: draft,
                },
            };
            model.preview_change = Some(change.clone());
            Command::AccessPreview {
                change,
                expected_version: expected,
            }
        }
        FormKind::IpRule { index } => {
            let Some((draft, expected)) = model.take_ip_rule_fields() else {
                return;
            };
            let change = match index {
                Some(index) => AccessChange::IpUpdate { index, rule: draft },
                None => AccessChange::IpCreate {
                    index: None,
                    rule: draft,
                },
            };
            model.preview_change = Some(change.clone());
            Command::AccessPreview {
                change,
                expected_version: expected,
            }
        }
        FormKind::IpDefault => {
            let Some((value, expected)) = model.take_default_fields() else {
                return;
            };
            let change = AccessChange::IpDefault { value };
            model.preview_change = Some(change.clone());
            Command::AccessPreview {
                change,
                expected_version: expected,
            }
        }
    };
    model.pending = true;
    client.send(command);
}

fn confirm(model: &mut ViewModel, client: &Client) {
    let Some(confirm) = model.confirm.clone() else {
        return;
    };
    model.confirm = None;
    match confirm.pending {
        Pending::ClearBlock {
            username,
            expected_version,
        } => {
            model.pending = true;
            client.send(Command::BlockClear {
                username,
                expected_version,
            });
        }
        Pending::DeleteRule { change } => {
            model.pending = true;
            client.send(Command::AccessApply {
                change,
                expected_version: model.config_version().unwrap_or_default(),
            });
        }
        Pending::MoveRule { change } => {
            model.pending = true;
            client.send(Command::AccessApply {
                change,
                expected_version: model.config_version().unwrap_or_default(),
            });
        }
        Pending::ConfigApply { expected_version } => {
            model.pending = true;
            client.send(Command::ConfigApply { expected_version });
        }
        Pending::DiscardForm => model.discard_form(),
    }
}

fn confirm_preview(model: &mut ViewModel, client: &Client) {
    let Some(preview) = model.preview.take() else {
        return;
    };
    model.pending = true;
    client.send(Command::AccessApply {
        change: preview.change,
        expected_version: model.config_version().unwrap_or_default(),
    });
}

fn next_operation_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!(
        "tui-{}-{}-{}",
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Re-exported so the terminal module can keep one small error rendering path.
pub fn describe_error(error: &ApiError) -> String {
    match error.code {
        crate::control_protocol::ErrorCode::Conflict => "конфликт версии",
        crate::control_protocol::ErrorCode::Unauthorized => "нет права изменения",
        crate::control_protocol::ErrorCode::InvalidCandidate => "кандидат отклонён",
        crate::control_protocol::ErrorCode::RestartRequired => "требуется перезапуск",
        crate::control_protocol::ErrorCode::UnknownResult => "результат неизвестен",
        crate::control_protocol::ErrorCode::ResyncRequired => "нужен новый снимок",
        _ => "ошибка",
    }
    .to_owned()
}

// Keep these imports used by the protocol-facing helpers above.
#[allow(dead_code)]
fn _protocol_types(
    _: &ControlEvent,
    _: &EventEnvelope,
    _: &Response,
    _: &WriteOutcome,
    _: &ReloadOutcome,
) {
}
