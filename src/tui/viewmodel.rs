//! Screen state and input-independent transitions for the TUI.
//!
//! This module deliberately has no Ratatui or Crossterm imports. Tests drive
//! the same transitions the terminal uses.

use zeroize::Zeroizing;

use crate::connections::ConnectionRow;
use crate::control::ReloadOutcome;
use crate::control_protocol::{
    AccessChange, AccessPage, AccessPreview, AccessRuleDraft, AccessRuleView, ApiError, BlocksPage,
    ConfigState, ConnectionsPage, Event, EventKind, EventsPage, Snapshot, StatusSnapshot,
    UserStatus, UsersPage, WriteOutcome,
};

/// Top-level screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Screen {
    Overview,
    Routes,
    Connections,
    Users,
    Blocks,
    Access,
    Config,
    Events,
}

impl Screen {
    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Обзор",
            Self::Routes => "Входы и маршруты",
            Self::Connections => "Соединения",
            Self::Users => "Пользователи",
            Self::Blocks => "Блокировки",
            Self::Access => "Доступ",
            Self::Config => "Конфигурация",
            Self::Events => "События",
        }
    }

    pub fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Routes => 1,
            Self::Connections => 2,
            Self::Users => 3,
            Self::Blocks => 4,
            Self::Access => 5,
            Self::Config => 6,
            Self::Events => 7,
        }
    }
}

/// Pending destructive operation.
#[derive(Clone, Debug)]
pub enum Pending {
    ClearBlock {
        username: String,
        expected_version: String,
    },
    DeleteRule {
        change: AccessChange,
    },
    MoveRule {
        change: AccessChange,
    },
    ConfigApply {
        expected_version: String,
    },
}

/// One explicit confirmation.
#[derive(Clone, Debug)]
pub struct Confirm {
    pub title: String,
    pub detail: String,
    pub pending: Pending,
}

/// Form kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormKind {
    AddUser,
    ChangePassword,
    SetBlock { permanent: bool },
    Source { remove: bool },
    Rule { index: Option<usize> },
    IpRule { index: Option<usize> },
    IpDefault,
}

/// One editable field.
pub struct Field {
    pub label: &'static str,
    pub value: Zeroizing<String>,
    pub secret: bool,
}

/// Active form.
pub struct Form {
    pub kind: FormKind,
    pub title: String,
    pub subject: Option<String>,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub error: Option<String>,
    pub hint: String,
    pub rule_base: Option<AccessRuleView>,
}

impl Form {
    fn new(kind: FormKind, title: impl Into<String>) -> Self {
        Self {
            kind,
            title: title.into(),
            subject: None,
            fields: Vec::new(),
            focus: 0,
            error: None,
            hint: String::new(),
            rule_base: None,
        }
    }

    fn field(mut self, label: &'static str, value: impl Into<String>, secret: bool) -> Self {
        self.fields.push(Field {
            label,
            value: Zeroizing::new(value.into()),
            secret,
        });
        self
    }

    fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = hint.into();
        self
    }

    pub fn focus_next(&mut self, reverse: bool) {
        if self.fields.is_empty() {
            return;
        }
        if reverse {
            self.focus = if self.focus == 0 {
                self.fields.len() - 1
            } else {
                self.focus - 1
            };
        } else {
            self.focus = (self.focus + 1) % self.fields.len();
        }
    }

    pub fn push(&mut self, character: char) {
        if let Some(field) = self.fields.get_mut(self.focus)
            && field.value.len() < 512
        {
            field.value.push(character);
            self.error = None;
        }
    }

    pub fn backspace(&mut self) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            field.value.pop();
        }
    }

    fn value(&self, index: usize) -> String {
        self.fields
            .get(index)
            .map(|field| field.value.as_str().to_owned())
            .unwrap_or_default()
    }
}

/// Local preview awaiting explicit apply.
pub struct Preview {
    pub change: AccessChange,
    pub summary: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

/// Complete view model.
pub struct ViewModel {
    pub screen: Screen,
    pub selected: [usize; 8],
    pub page: [usize; 8],
    pub filter: String,
    pub search_active: bool,
    pub palette: bool,
    pub help: bool,
    pub should_quit: bool,
    pub connected: bool,
    pub connection_error: Option<String>,
    pub status_message: String,
    pub error: Option<String>,
    pub pending: bool,
    pub writable: bool,
    pub snapshot: Option<Snapshot>,
    pub status: Option<StatusSnapshot>,
    pub connections: Vec<ConnectionRow>,
    pub connections_total: usize,
    pub users: Vec<UserStatus>,
    pub users_total: usize,
    pub blocks: Vec<crate::control::BlockStatus>,
    pub blocks_total: usize,
    pub access: Option<AccessPage>,
    pub config: Option<ConfigState>,
    pub events: Vec<Event>,
    pub event_cursor: u64,
    pub form: Option<Form>,
    pub confirm: Option<Confirm>,
    pub preview: Option<Preview>,
    pub preview_change: Option<AccessChange>,
    pub access_section: &'static str,
    pub event_filter: Option<EventKind>,
}

impl Default for ViewModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewModel {
    pub fn new() -> Self {
        Self {
            screen: Screen::Overview,
            selected: [0; 8],
            page: [0; 8],
            filter: String::new(),
            search_active: false,
            palette: false,
            help: false,
            should_quit: false,
            connected: false,
            connection_error: None,
            status_message: "подключение…".to_owned(),
            error: None,
            pending: false,
            writable: false,
            snapshot: None,
            status: None,
            connections: Vec::new(),
            connections_total: 0,
            users: Vec::new(),
            users_total: 0,
            blocks: Vec::new(),
            blocks_total: 0,
            access: None,
            config: None,
            events: Vec::new(),
            event_cursor: 0,
            form: None,
            confirm: None,
            preview: None,
            preview_change: None,
            access_section: "rules",
            event_filter: None,
        }
    }

    pub fn cycle_access_section(&mut self) {
        self.access_section = match self.access_section {
            "rules" => "source",
            "source" => "ip_rules",
            _ => "rules",
        };
        self.selected[Screen::Access.index()] = 0;
    }

    pub fn cycle_event_filter(&mut self) {
        use EventKind::*;
        self.event_filter = match self.event_filter {
            None => Some(ConfigSaved),
            Some(ConfigSaved) => Some(ConfigApplied),
            Some(ConfigApplied) => Some(ConfigRejected),
            Some(ConfigRejected) => Some(UsersSaved),
            Some(UsersSaved) => Some(BlockExpired),
            Some(BlockExpired) | Some(Resync) => None,
        };
        self.selected[Screen::Events.index()] = 0;
    }

    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
        if connected {
            self.connection_error = None;
            self.status_message = "на связи".to_owned();
        }
    }

    pub fn set_connected_error(&mut self, message: String) {
        self.connected = false;
        self.connection_error = Some(message.clone());
        self.status_message = message;
    }

    pub fn switch_screen(&mut self, screen: Screen) {
        self.screen = screen;
        self.page[screen.index()] = 0;
        self.selected[screen.index()] = 0;
        self.palette = false;
        self.help = false;
        self.search_active = false;
        self.confirm = None;
        self.preview = None;
        self.status_message = screen.title().to_owned();
    }

    pub fn select_next(&mut self) {
        let length = self.row_count();
        if length == 0 {
            return;
        }
        let index = &mut self.selected[self.screen.index()];
        *index = (*index + 1).min(length - 1);
    }

    pub fn select_previous(&mut self) {
        let index = &mut self.selected[self.screen.index()];
        *index = index.saturating_sub(1);
    }

    pub fn select_page(&mut self, direction: i32) {
        let length = self.row_count();
        if length == 0 {
            return;
        }
        let index = &mut self.selected[self.screen.index()];
        if direction > 0 {
            *index = (*index + 10).min(length - 1);
        } else {
            *index = index.saturating_sub(10);
        }
    }

    pub fn selected_index(&self) -> usize {
        self.selected[self.screen.index()]
    }

    fn row_count(&self) -> usize {
        match self.screen {
            Screen::Connections => self.connections.len(),
            Screen::Users => self.users.len(),
            Screen::Blocks => self.blocks.len(),
            Screen::Access => self
                .access
                .as_ref()
                .map(|page| match self.access_section {
                    "source" => page.source_allow.len(),
                    "ip_rules" => page.ip_rules.len(),
                    _ => page.rules.len(),
                })
                .unwrap_or(0),
            Screen::Events => self.events.len(),
            Screen::Overview | Screen::Routes | Screen::Config => 0,
        }
    }

    pub fn clear_transient(&mut self) {
        self.error = None;
        self.search_active = false;
        self.filter.clear();
        self.preview = None;
    }

    pub fn search_command(&self) -> crate::tui::client::Command {
        use crate::tui::client::Command;
        let offset = self.page_offset();
        match self.screen {
            Screen::Users => Command::RefreshUsers {
                query: self.filter.clone(),
                offset,
            },
            Screen::Blocks => Command::RefreshBlocks {
                query: self.filter.clone(),
                offset,
            },
            Screen::Access => Command::RefreshAccess {
                section: self.access_section.to_owned(),
            },
            Screen::Connections => Command::RefreshConnections { offset },
            Screen::Events => Command::RefreshEvents,
            Screen::Config => Command::RefreshConfig,
            Screen::Overview | Screen::Routes => Command::RefreshAll,
        }
    }

    pub fn page_offset(&self) -> usize {
        self.page[self.screen.index()] * 100
    }

    pub fn offset_for(&self, screen: Screen) -> usize {
        self.page[screen.index()] * 100
    }

    pub fn next_page(&mut self) {
        let total = match self.screen {
            Screen::Connections => self.connections_total,
            Screen::Users => self.users_total,
            Screen::Blocks => self.blocks_total,
            _ => return,
        };
        if (self.page[self.screen.index()] + 1) * 100 < total {
            self.page[self.screen.index()] += 1;
            self.selected[self.screen.index()] = 0;
        }
    }

    pub fn previous_page(&mut self) {
        if self.page[self.screen.index()] > 0 {
            self.page[self.screen.index()] -= 1;
            self.selected[self.screen.index()] = 0;
        }
    }

    pub fn page_label(&self, loaded: usize, total: usize) -> String {
        let page = self.page[self.screen.index()] + 1;
        format!("стр. {page} · загружено {loaded} из {total}")
    }

    pub fn apply_snapshot(&mut self, snapshot: Snapshot) {
        self.event_cursor = snapshot.event_cursor;
        self.writable = snapshot.writable;
        self.status = Some(snapshot.proxy.status.clone());
        self.snapshot = Some(snapshot);
        self.connected = true;
        self.connection_error = None;
        self.status_message = "снимок получен".to_owned();
    }

    pub fn apply_status(&mut self, status: StatusSnapshot) {
        self.status = Some(status);
    }

    pub fn apply_connections(&mut self, page: ConnectionsPage) {
        let selected = self
            .connections
            .get(self.selected_index())
            .map(|row| row.id);
        self.connections_total = page.total;
        self.connections = page.connections;
        if let Some(id) = selected
            && let Some(index) = self.connections.iter().position(|row| row.id == id)
        {
            self.selected[Screen::Connections.index()] = index;
        }
        self.clamp_selection();
    }

    pub fn apply_users(&mut self, page: UsersPage) {
        let selected = self
            .users
            .get(self.selected_index())
            .map(|user| user.username.clone());
        self.users_total = page.total;
        self.users = page.users;
        if let Some(username) = selected
            && let Some(index) = self.users.iter().position(|user| user.username == username)
        {
            self.selected[Screen::Users.index()] = index;
        }
        self.clamp_selection();
    }

    pub fn apply_blocks(&mut self, page: BlocksPage) {
        let selected = self
            .blocks
            .get(self.selected_index())
            .map(|block| block.username.clone());
        self.blocks_total = page.total;
        self.blocks = page.blocks;
        if let Some(username) = selected
            && let Some(index) = self
                .blocks
                .iter()
                .position(|block| block.username == username)
        {
            self.selected[Screen::Blocks.index()] = index;
        }
        self.clamp_selection();
    }

    pub fn apply_access(&mut self, page: AccessPage) {
        let selected = self
            .access
            .as_ref()
            .and_then(|page| page.rules.get(self.selected_index()))
            .map(|rule| rule.id.clone());
        self.access = Some(page);
        if let Some(id) = selected
            && let Some(index) = self
                .access
                .as_ref()
                .and_then(|page| page.rules.iter().position(|rule| rule.id == id))
        {
            self.selected[Screen::Access.index()] = index;
        }
        self.clamp_selection();
    }

    pub fn apply_config(&mut self, state: ConfigState) {
        self.config = Some(state);
    }

    pub fn apply_events(&mut self, page: EventsPage) {
        self.events = page.events;
        self.event_cursor = self.event_cursor.max(page.next_cursor);
        if page.resync_required {
            self.status_message = "история событий усечена, нужен снимок".to_owned();
        }
        self.clamp_selection();
    }

    pub fn apply_event(&mut self, event: Event) {
        self.event_cursor = self.event_cursor.max(event.cursor);
        self.events.push(event);
        if self.events.len() > 256 {
            self.events.remove(0);
        }
        self.clamp_selection();
    }

    pub fn apply_write(&mut self, outcome: WriteOutcome) {
        self.pending = false;
        if outcome.applied
            || self.form.as_ref().is_some_and(|form| {
                matches!(form.kind, FormKind::AddUser | FormKind::ChangePassword)
            })
        {
            self.form = None;
        } else if let Some(form) = self.form.as_mut() {
            form.error = outcome.detail.clone();
        }
        self.status_message = format!(
            "{} · {} · поколение {}",
            match outcome.state.as_str() {
                "applied" => "применено",
                "saved" => "сохранено на диске",
                "checked" => "проверено",
                "rejected" => "отклонено",
                "restart_required" => "требуется перезапуск",
                "conflict" => "конфликт",
                _ => "результат неизвестен",
            },
            if outcome.applied {
                "активная политика совпадает"
            } else {
                "активная политика прежняя"
            },
            outcome.generation
        );
        if outcome.state == "unknown" {
            self.status_message
                .push_str(" · сверьте версию и повторите только после явной проверки");
        }
    }

    pub fn apply_reload(&mut self, outcome: ReloadOutcome) {
        self.pending = false;
        self.status_message = match outcome {
            ReloadOutcome::Valid { generation } => {
                format!("проверено · поколение {generation}")
            }
            ReloadOutcome::Applied { generation } => {
                format!("применено · поколение {generation}")
            }
            ReloadOutcome::Invalid { fields, .. } => {
                format!("отклонено · {}", fields.join(", "))
            }
            ReloadOutcome::RestartRequired { fields, .. } => {
                format!("требуется перезапуск · {}", fields.join(", "))
            }
            ReloadOutcome::Conflict { current } => format!("конфликт · поколение {current}"),
            ReloadOutcome::Busy => "проверка уже выполняется".to_owned(),
            ReloadOutcome::GenerationBusy => "достигнут предел живых поколений".to_owned(),
            ReloadOutcome::TimedOut => "истёк срок проверки".to_owned(),
            ReloadOutcome::Cancelled => "проверка отменена".to_owned(),
            ReloadOutcome::ShuttingDown => "сервис завершает работу".to_owned(),
            ReloadOutcome::Internal => "внутренняя ошибка".to_owned(),
        };
    }

    pub fn apply_preview(&mut self, preview: AccessPreview) {
        self.pending = false;
        let change = self
            .preview_change
            .take()
            .unwrap_or(AccessChange::SourceReplace { values: Vec::new() });
        self.preview = Some(Preview {
            change,
            summary: preview.summary,
            before: preview.before,
            after: preview.after,
        });
    }

    pub fn apply_error(&mut self, error: ApiError) {
        self.pending = false;
        self.error = Some(error.message.clone());
        self.status_message = format!(
            "{}: {}{}",
            crate::tui::describe_error(&error),
            error.message,
            if error.fields.is_empty() {
                String::new()
            } else {
                format!(" [{}]", error.fields.join(", "))
            }
        );
        if let Some(form) = self.form.as_mut() {
            form.error = Some(error.message);
            if error.code == crate::control_protocol::ErrorCode::Conflict
                && matches!(form.kind, FormKind::AddUser | FormKind::ChangePassword)
            {
                self.status_message = "результат неизвестен: проверьте пользователя и вход новым паролем, затем повторите с актуальной версией".to_owned();
            }
        }
    }

    fn clamp_selection(&mut self) {
        let length = self.row_count();
        let index = &mut self.selected[self.screen.index()];
        if length == 0 {
            *index = 0;
        } else if *index >= length {
            *index = length - 1;
        }
    }

    pub fn disk_config_version(&self) -> Option<String> {
        self.config
            .as_ref()
            .and_then(|state| state.disk_config_version.clone())
            .or_else(|| {
                self.snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.proxy.config_version.clone())
            })
    }

    pub fn config_version(&self) -> Option<String> {
        self.disk_config_version()
    }

    pub fn users_version(&self) -> Option<String> {
        self.config
            .as_ref()
            .and_then(|state| state.disk_users_version.clone())
            .or_else(|| {
                self.snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.proxy.users_version.clone())
            })
    }

    pub fn start_add_user(&mut self) {
        self.form = Some(
            Form::new(FormKind::AddUser, "Новый пользователь")
                .field("Логин", "", false)
                .field("Пароль", "", true)
                .field("Повтор пароля", "", true)
                .hint("Tab — следующее поле · Enter — сохранить · Esc — отмена"),
        );
    }

    pub fn start_password_form(&mut self) {
        let Some(user) = self.users.get(self.selected_index()) else {
            self.status_message = "сначала выберите пользователя".to_owned();
            return;
        };
        let mut form = Form::new(FormKind::ChangePassword, "Смена пароля")
            .field("Пароль", "", true)
            .field("Повтор пароля", "", true)
            .hint("Пароль не отображается и не попадает в журнал");
        form.subject = Some(user.username.clone());
        self.form = Some(form);
    }

    pub fn start_block_form(&mut self) {
        let username = self
            .users
            .get(self.selected_index())
            .or_else(|| {
                self.blocks.get(self.selected_index()).and_then(|block| {
                    self.users
                        .iter()
                        .find(|user| user.username == block.username)
                })
            })
            .map(|user| user.username.clone())
            .unwrap_or_default();
        self.form = Some(
            Form::new(FormKind::SetBlock { permanent: false }, "Блокировка")
                .field("Логин", username, false)
                .field("До (RFC 3339, пусто = бессрочно)", "", false)
                .hint("Пример: 2026-11-27T18:00:00Z или 2026-11-27T21:00:00+03:00"),
        );
    }

    pub fn start_block_edit(&mut self) {
        let Some(block) = self.blocks.get(self.selected_index()).cloned() else {
            self.start_block_form();
            self.status_message = "выберите блокировку или добавьте новую".to_owned();
            return;
        };
        let until = block.blocked_until.unwrap_or_default();
        let permanent = block.kind == "permanent";
        let mut form = Form::new(FormKind::SetBlock { permanent }, "Изменить блокировку")
            .field("Логин", block.username.clone(), false)
            .field("До (RFC 3339, пусто = бессрочно)", until, false)
            .hint("Пустое поле делает блокировку бессрочной");
        form.subject = Some(block.username);
        self.form = Some(form);
    }

    pub fn start_access_form(&mut self, index: Option<usize>) {
        match self.access_section {
            "source" => self.start_source_form(),
            "ip_rules" => self.start_ip_rule_form(index),
            _ => self.start_rule_form(index),
        }
    }

    pub fn start_ip_rule_form(&mut self, index: Option<usize>) {
        let Some(page) = &self.access else {
            self.status_message = "IP-правила ещё не загружены".to_owned();
            return;
        };
        let (mut form, base) = match index.and_then(|index| page.ip_rules.get(index).cloned()) {
            Some(rule) => (
                Form::new(FormKind::IpRule { index }, "Изменить IP-правило")
                    .field("ID", rule.id.clone(), false)
                    .field("Действие (allow/deny)", rule.action.clone(), false)
                    .field("Сети через запятую", rule.networks.join(","), false)
                    .field(
                        "allow_special (true/false)",
                        rule.allow_special.to_string(),
                        false,
                    ),
                Some(rule),
            ),
            None => (
                Form::new(FormKind::IpRule { index: None }, "Новое IP-правило")
                    .field("ID", "", false)
                    .field("Действие (allow/deny)", "deny", false)
                    .field("Сети через запятую", "", false)
                    .field("allow_special (true/false)", "false", false),
                None,
            ),
        };
        form.rule_base = None;
        form.hint = "Enter — предпросмотр · Esc — отмена".to_owned();
        let _ = base;
        self.form = Some(form);
    }

    pub fn start_ip_default_form(&mut self) {
        let value = self
            .access
            .as_ref()
            .map(|page| page.ip_default.clone())
            .unwrap_or_else(|| "deny".to_owned());
        self.form = Some(
            Form::new(FormKind::IpDefault, "ip_default")
                .field("Значение (public_only/deny)", value, false)
                .hint("Enter — предпросмотр · Esc — отмена"),
        );
    }

    pub fn start_rule_form(&mut self, index: Option<usize>) {
        let Some(page) = &self.access else {
            self.status_message = "правила ещё не загружены".to_owned();
            return;
        };
        let (mut form, base) = match index.and_then(|index| page.rules.get(index).cloned()) {
            Some(rule) => (
                Form::new(FormKind::Rule { index }, "Изменить правило")
                    .field("ID", rule.id.clone(), false)
                    .field("Действие (allow/deny)", rule.action.clone(), false)
                    .field(
                        "Точные хосты через запятую",
                        rule.host_exact.clone().unwrap_or_default().join(","),
                        false,
                    )
                    .field(
                        "Суффиксы хостов через запятую",
                        rule.host_suffix.clone().unwrap_or_default().join(","),
                        false,
                    )
                    .field(
                        "Пользователи через запятую",
                        rule.users.clone().unwrap_or_default().join(","),
                        false,
                    ),
                Some(rule),
            ),
            None => (
                Form::new(FormKind::Rule { index: None }, "Новое правило")
                    .field("ID", "", false)
                    .field("Действие (allow/deny)", "deny", false)
                    .field("Точные хосты через запятую", "", false)
                    .field("Суффиксы хостов через запятую", "", false)
                    .field("Пользователи через запятую", "", false),
                None,
            ),
        };
        form.rule_base = base;
        form.hint =
            "Пустой список хостов означает any · Enter — предпросмотр · Esc — отмена".to_owned();
        self.form = Some(form);
    }

    pub fn start_source_form(&mut self) {
        self.form = Some(
            Form::new(FormKind::Source { remove: false }, "Добавить источник")
                .field("CIDR", "", false)
                .hint("Например 10.0.0.0/8 · Enter — предпросмотр"),
        );
    }

    pub fn start_source_remove(&mut self) {
        self.form = Some(
            Form::new(FormKind::Source { remove: true }, "Удалить источник")
                .field("Индекс (с нуля)", "0", false)
                .hint("Enter — предпросмотр · Esc — отмена"),
        );
    }

    pub fn delete_pending(&self) -> Option<Pending> {
        match self.screen {
            Screen::Blocks => {
                self.blocks
                    .get(self.selected_index())
                    .map(|block| Pending::ClearBlock {
                        username: block.username.clone(),
                        expected_version: self.users_version().unwrap_or_default(),
                    })
            }
            Screen::Access => {
                let index = self.selected_index();
                match self.access_section {
                    "source" => self
                        .access
                        .as_ref()
                        .and_then(|page| page.source_allow.get(index))
                        .map(|_| Pending::DeleteRule {
                            change: AccessChange::SourceRemove { index },
                        }),
                    "ip_rules" => self
                        .access
                        .as_ref()
                        .and_then(|page| page.ip_rules.get(index))
                        .map(|_| Pending::DeleteRule {
                            change: AccessChange::IpDelete { index },
                        }),
                    _ => self
                        .access
                        .as_ref()
                        .and_then(|page| page.rules.get(index))
                        .map(|_| Pending::DeleteRule {
                            change: AccessChange::RuleDelete { index },
                        }),
                }
            }
            _ => None,
        }
    }

    pub fn delete_detail(&self) -> String {
        match self.screen {
            Screen::Blocks => self
                .blocks
                .get(self.selected_index())
                .map(|block| {
                    format!(
                        "Снять блокировку с {}? Пароль и ACL сохраняются.",
                        block.username
                    )
                })
                .unwrap_or_default(),
            Screen::Access => match self.access_section {
                "source" => self
                    .access
                    .as_ref()
                    .and_then(|page| page.source_allow.get(self.selected_index()))
                    .map(|source| format!("Удалить источник {source}?"))
                    .unwrap_or_default(),
                "ip_rules" => self
                    .access
                    .as_ref()
                    .and_then(|page| page.ip_rules.get(self.selected_index()))
                    .map(|rule| format!("Удалить IP-правило {}?", rule.id))
                    .unwrap_or_default(),
                _ => self
                    .access
                    .as_ref()
                    .and_then(|page| page.rules.get(self.selected_index()))
                    .map(|rule| format!("Удалить правило {}?", rule.id))
                    .unwrap_or_default(),
            },
            _ => String::new(),
        }
    }

    pub fn move_rule(&mut self, down: bool) {
        let Some(page) = &self.access else {
            return;
        };
        let from = self.selected_index();
        if from >= page.rules.len() {
            return;
        }
        let to = if down {
            from + 1
        } else {
            from.saturating_sub(1)
        };
        if to >= page.rules.len() || to == from {
            return;
        }
        let rule = &page.rules[from];
        let neighbor = page
            .rules
            .get(if down { to + 1 } else { to.saturating_sub(1) })
            .map(|rule| rule.id.clone())
            .unwrap_or_else(|| "край списка".to_owned());
        self.confirm = Some(Confirm {
            title: "Перемещение правила".to_owned(),
            detail: format!(
                "Правило {}: позиция {} → {}. Сосед: {}. Применение проверит конфигурацию и изменит first-match.",
                rule.id, from, to, neighbor
            ),
            pending: Pending::MoveRule {
                change: AccessChange::RuleMove { from, to },
            },
        });
    }

    pub fn take_submission(&mut self) -> Option<(FormKind, Option<String>)> {
        let form = self.form.as_ref()?;
        let username = match form.kind {
            FormKind::AddUser => Some(form.value(0)),
            FormKind::ChangePassword => form.subject.clone(),
            FormKind::SetBlock { .. } => Some(form.value(0)),
            _ => None,
        };
        Some((form.kind, username))
    }

    pub fn take_password_fields(
        &mut self,
    ) -> Option<(Zeroizing<String>, Zeroizing<String>, String)> {
        let form = self.form.take()?;
        let (first, second) = match form.kind {
            FormKind::AddUser => (1, 2),
            FormKind::ChangePassword => (0, 1),
            _ => {
                self.form = Some(form);
                return None;
            }
        };
        let password = form.fields.get(first).map(|field| field.value.clone())?;
        let confirmation = form.fields.get(second).map(|field| field.value.clone())?;
        if password.is_empty() {
            self.restore_form(form, "пароль не может быть пустым");
            return None;
        }
        if password.as_str() != confirmation.as_str() {
            self.restore_form(form, "пароли не совпадают");
            return None;
        }
        let expected = self.users_version()?;
        Some((password, confirmation, expected))
    }

    pub fn take_block_fields(&mut self) -> Option<(Option<String>, String)> {
        let form = self.form.take()?;
        if !matches!(form.kind, FormKind::SetBlock { .. }) {
            self.form = Some(form);
            return None;
        }
        let username = form.value(0);
        if username.is_empty() {
            self.restore_form(form, "логин не может быть пустым");
            return None;
        }
        let until = form.value(1);
        let expected = self.users_version()?;
        Some(((!until.is_empty()).then_some(until), expected))
    }

    pub fn take_source_fields(&mut self) -> Option<(Option<String>, Option<usize>, String)> {
        let form = self.form.take()?;
        let FormKind::Source { remove } = form.kind else {
            self.form = Some(form);
            return None;
        };
        let value = form.value(0);
        let expected = self.config_version()?;
        if remove {
            let index = value.trim().parse::<usize>().ok();
            if index.is_none() {
                self.restore_form(form, "индекс должен быть целым числом");
                return None;
            }
            Some((None, index, expected))
        } else {
            if value.is_empty() {
                self.restore_form(form, "CIDR не может быть пустым");
                return None;
            }
            Some((Some(value), None, expected))
        }
    }

    pub fn take_rule_fields(&mut self) -> Option<(AccessRuleDraft, String)> {
        let form = self.form.take()?;
        let FormKind::Rule { .. } = form.kind else {
            self.form = Some(form);
            return None;
        };
        let id = form.value(0);
        let action = form.value(1);
        let hosts = split_list(&form.value(2));
        let suffixes = split_list(&form.value(3));
        let users = split_list(&form.value(4));
        if id.is_empty() {
            self.restore_form(form, "ID правила не может быть пустым");
            return None;
        }
        if !hosts.is_empty() && !suffixes.is_empty() {
            self.restore_form(form, "точные хосты и суффиксы взаимоисключающие");
            return None;
        }
        let base = form.rule_base.clone();
        let expected = self.config_version()?;
        let draft = AccessRuleDraft {
            id,
            action,
            listeners: base.as_ref().and_then(|rule| rule.listeners.clone()),
            sources: base.as_ref().and_then(|rule| rule.sources.clone()),
            methods: base.as_ref().and_then(|rule| rule.methods.clone()),
            ports: base.as_ref().and_then(|rule| rule.ports.clone()),
            users: if users.is_empty() {
                base.as_ref().and_then(|rule| rule.users.clone())
            } else {
                Some(users)
            },
            host_exact: (!hosts.is_empty()).then_some(hosts),
            host_suffix: (!suffixes.is_empty()).then_some(suffixes),
        };
        Some((draft, expected))
    }

    pub fn take_ip_rule_fields(
        &mut self,
    ) -> Option<(crate::control_protocol::IpRuleDraft, String)> {
        let form = self.form.take()?;
        let FormKind::IpRule { .. } = form.kind else {
            self.form = Some(form);
            return None;
        };
        let id = form.value(0);
        let action = form.value(1);
        let networks = split_list(&form.value(2));
        let allow_special = form.value(3).trim().eq_ignore_ascii_case("true");
        if id.is_empty() {
            self.restore_form(form, "ID правила не может быть пустым");
            return None;
        }
        if networks.is_empty() {
            self.restore_form(form, "список сетей не может быть пустым");
            return None;
        }
        let expected = self.config_version()?;
        Some((
            crate::control_protocol::IpRuleDraft {
                id,
                action,
                networks,
                allow_special,
            },
            expected,
        ))
    }

    pub fn take_default_fields(&mut self) -> Option<(String, String)> {
        let form = self.form.take()?;
        let FormKind::IpDefault = form.kind else {
            self.form = Some(form);
            return None;
        };
        let value = form.value(0);
        let expected = self.config_version()?;
        Some((value, expected))
    }

    fn restore_form(&mut self, form: Form, message: &str) {
        let mut form = form;
        form.error = Some(message.to_owned());
        self.status_message = message.to_owned();
        self.form = Some(form);
    }

    /// The Access preview must apply the exact edit that was previewed.
    pub fn set_preview_change(&mut self, change: AccessChange) {
        if let Some(preview) = self.preview.as_mut() {
            preview.change = change;
        }
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ReloadOutcome;

    fn user(name: &str, block: &str) -> UserStatus {
        UserStatus {
            username: name.to_owned(),
            block: block.to_owned(),
            blocked_until: None,
            remaining_seconds: None,
        }
    }

    #[test]
    fn navigation_keeps_selection_inside_the_current_page() {
        let mut model = ViewModel::new();
        model.switch_screen(Screen::Users);
        model.apply_users(UsersPage {
            users: vec![user("a", "active"), user("b", "active")],
            offset: 0,
            total: 2,
        });
        model.select_next();
        model.select_next();
        assert_eq!(model.selected_index(), 1);
        model.select_page(1);
        assert_eq!(model.selected_index(), 1);
        model.select_previous();
        assert_eq!(model.selected_index(), 0);
    }

    #[test]
    fn access_sections_cycle_and_ip_rules_are_edited_without_secrets() {
        let mut model = ViewModel::new();
        model.switch_screen(Screen::Access);
        model.access = Some(AccessPage {
            section: crate::control_protocol::AccessSection::Rules,
            source_allow: vec!["127.0.0.0/8".to_owned()],
            rules: Vec::new(),
            ip_rules: Vec::new(),
            ip_default: "deny".to_owned(),
            offset: 0,
            total: 0,
        });
        model.config = Some(ConfigState {
            config_path: "/etc/angara/angara.toml".to_owned(),
            users_path: None,
            active_config_version: "sha256:00".to_owned(),
            disk_config_version: Some("sha256:00".to_owned()),
            active_users_version: None,
            disk_users_version: None,
            generation: 1,
            last_reload: None,
            writable: true,
            valid: true,
            detail: None,
        });
        model.cycle_access_section();
        assert_eq!(model.access_section, "source");
        model.cycle_access_section();
        assert_eq!(model.access_section, "ip_rules");
        model.start_ip_rule_form(None);
        let form = model.form.as_mut().unwrap();
        form.fields[0].value = Zeroizing::new("lan".to_owned());
        form.fields[1].value = Zeroizing::new("allow".to_owned());
        form.fields[2].value = Zeroizing::new("10.0.0.0/8".to_owned());
        let (draft, _) = model.take_ip_rule_fields().expect("draft");
        assert_eq!(draft.id, "lan");
        assert_eq!(draft.networks, vec!["10.0.0.0/8"]);
        assert!(!draft.allow_special);
    }

    #[test]
    fn selection_follows_the_object_when_a_page_inserts_rows() {
        let mut model = ViewModel::new();
        model.switch_screen(Screen::Users);
        model.apply_users(UsersPage {
            users: vec![user("alice", "active"), user("bob", "active")],
            offset: 0,
            total: 2,
        });
        model.select_next();
        assert_eq!(model.selected_index(), 1);
        model.apply_users(UsersPage {
            users: vec![
                user("aaron", "active"),
                user("alice", "active"),
                user("bob", "active"),
            ],
            offset: 0,
            total: 3,
        });
        assert_eq!(model.users[model.selected_index()].username, "bob");
    }

    #[test]
    fn forms_validate_confirmation_without_leaking_the_password() {
        let mut model = ViewModel::new();
        model.snapshot = Some(Snapshot {
            proxy: crate::control_protocol::ProxySnapshot {
                api_version: 1,
                instance_id: "test".to_owned(),
                generation: 1,
                config_version: "sha256:00".to_owned(),
                users_version: Some("sha256:11".to_owned()),
                config_path: "/etc/angara/angara.toml".to_owned(),
                users_path: Some("/etc/angara/users.toml".to_owned()),
                status: crate::control::StatusSnapshot {
                    lifecycle: crate::control::Lifecycle::Running,
                    generation: 1,
                    config_version: "sha256:00".to_owned(),
                    users_version: Some("sha256:11".to_owned()),
                    live_generations: 1,
                    uptime_ms: 1,
                    worker_threads: 1,
                    listeners: Vec::new(),
                    egress: Vec::new(),
                    max_client_connections: 1,
                    max_connections: 1,
                    client_active: 0,
                    outbound_active: 0,
                    tls_active: 0,
                    connect_active: 0,
                    auth_active: 0,
                    dns_active: 0,
                    pool_idle: 0,
                    pool_leased: 0,
                    reload_busy: false,
                    last_reload: Some(ReloadOutcome::Applied { generation: 1 }),
                },
                access: crate::control::AccessSummary {
                    source_allow: Vec::new(),
                    rule_count: 0,
                    ip_rule_count: 0,
                    ip_default: "deny".to_owned(),
                },
                routing: crate::control_protocol::RoutingSummary {
                    default_egress: "system".to_owned(),
                    default_parent: None,
                    rule_count: 0,
                },
                counters: crate::control_protocol::CounterSummary::default(),
                user_count: 0,
                block_count: 0,
                connection_count: 0,
                limits: crate::control_protocol::ApiLimits::default(),
            },
            event_cursor: 1,
            writable: true,
        });
        model.start_add_user();
        let form = model.form.as_mut().unwrap();
        form.fields[0].value = Zeroizing::new("alice".to_owned());
        form.fields[1].value = Zeroizing::new("secret".to_owned());
        form.fields[2].value = Zeroizing::new("different".to_owned());
        assert!(model.take_password_fields().is_none());
        assert!(model.form.is_some());
        assert!(model.form.as_ref().unwrap().error.is_some());
        assert!(!format!("{:?}", model.form.as_ref().unwrap().title).contains("secret"));
    }

    #[test]
    fn write_state_is_rendered_unambiguously() {
        let mut model = ViewModel::new();
        model.apply_write(WriteOutcome {
            state: "unknown".to_owned(),
            saved: true,
            version: Some("sha256:00".to_owned()),
            generation: 3,
            applied: false,
            detail: None,
        });
        assert!(model.status_message.contains("неизвестен"));
        assert!(model.status_message.contains("поколение 3"));
    }
}
