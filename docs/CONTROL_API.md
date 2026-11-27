# Angara local control API v1

Статус: M11. Протокол локальный, Unix domain socket, без TCP. Публичный
сокет `/run/angara/control.sock` создаёт привилегированный
`angara control-write`; приватный `/run/angara/control-read.sock` создаёт
прокси.

## 1. Транспорт и версия

Один запрос — одна строка JSON, один ответ — одна строка JSON. Подписка:
ответ-снимок, затем поток событий. Кодировка UTF-8. Поле `v` обязательно и
равно `1`; другая версия получает `unsupported_version`. Неизвестные поля и
операции отклоняются. Строка запроса/ответа — не более 64 KiB.

```json
{"v":1,"id":17,"op":"snapshot"}
{"v":1,"id":17,"ok":true,"result":{},"event_cursor":42}
```

`id` выбирает клиент; ответ повторяет его. `event_cursor` — последний
доступный курсор событий на момент ответа.

## 2. Права

| Группа/UID | Чтение | Запись |
| --- | --- | --- |
| root | да | да |
| `angara-admin` | да (нужен также доступ к сокету) | да |
| `angara` | да | нет |
| прочие | нет доступа к сокету | нет |

Проверка записи выполняется writer-ом по peer UID/GID и `/etc/group`, а не
только режимом файла сокета. Служебный UID `angara` не является членом
`angara-admin`. Чтение не даёт права на `user.add`, `user.password`,
`block.set`, `block.clear`, `access.apply`, `config.apply`; такие запросы
получают `unauthorized`.

## 3. Операции чтения

| `op` | Аргументы | Результат |
| --- | --- | --- |
| `hello` | — | версия, роль, поколение |
| `snapshot` | — | `Snapshot` |
| `status` | — | `StatusSnapshot` |
| `connections` | `offset?`, `limit?` | `ConnectionsPage` |
| `users` | `query?`, `offset?`, `limit?` | `UsersPage` |
| `blocks` | `query?`, `offset?`, `limit?` | `BlocksPage` |
| `access` | `section?` (`summary`,`source`,`rules`,`ip_rules`), `offset?`, `limit?` | `AccessPage` |
| `config` | — | `ConfigState` |
| `events` | `cursor?`, `limit?` | `EventsPage` |
| `subscribe` | `cursor?` | снимок, затем `EventEnvelope` |

`limit` по умолчанию 50 и принудительно ограничен 100. `offset` — число
пропущенных строк. `query` — регистронезависимый поиск по логину.

### Snapshot

`Snapshot` содержит `api_version`, `instance_id` (идентификатор процесса
control-сервиса; меняется при каждом старте процесса, в отличие от стабильного
`runtime.instance_id` в `Via`), `generation`,
`config_version`, `users_version`, `config_path`, `users_path`, `status`,
`access`, `routing`, `counters`, `user_count`, `block_count`,
`connection_count`, `limits`, `event_cursor`, `writable`. Версии —
`sha256:<64 hex>` от точных байтов файла.

### Строки

- `UserStatus`: `username`, `block` (`active`/`permanent`/`temporary`),
  `blocked_until` (UTC RFC 3339), `remaining_seconds`.
- `BlockStatus`: `username`, `kind`, `blocked_until`, `remaining_seconds`.
- `ConnectionRow`: `id`, `listener`, `transport`, `state`
  (`http`/`tls_handshake`/`connect`), `duration_ms`, `requests`. Нет peer IP,
  URL, host и заголовков.
- `AccessRuleView` / `IpRuleView` / `AccessPage`: только ACL-поля, без
  секретов. `AccessPage.source_allow` содержит запрошенную страницу для
  `section=source`, иначе полный список.
- `ConfigState`: `active_config_version`, `disk_config_version`,
  `active_users_version`, `disk_users_version`, `generation`,
  `last_reload`, `writable`, `valid`, `detail`. Позволяет отличить диск от
  активного поколения.

## 4. Операции записи

Все операции записи требуют `expected_version` (кроме оговорённых) и
проверяют его под общим `<path>.lock`. `operation_id` обязателен для
`user.add` и `user.password`; повтор с тем же id и тем же логином в течение
10 минут возвращает сохранённый результат без повторной записи.

| `op` | Аргументы | Результат |
| --- | --- | --- |
| `user.add` | `username`, `password`, `password_confirm`, `operation_id`, `expected_version` | `WriteOutcome` |
| `user.password` | `username`, `password`, `password_confirm`, `operation_id`, `expected_version` | `WriteOutcome` |
| `block.set` | `username`, `expected_version`, `permanent?`, `until?` | `WriteOutcome` |
| `block.clear` | `username`, `expected_version` | `WriteOutcome` |
| `access.preview` | `change`, `expected_version?` | `AccessPreview` |
| `access.apply` | `change`, `expected_version` | `WriteOutcome` |
| `config.validate` | — | `ReloadOutcome` |
| `config.apply` | `expected_version?`, `expected_generation?` | `WriteOutcome` |

`block.set`: `permanent=true` — бессрочно, `until` запрещён. Иначе `until`
обязателен, RFC 3339 с явным смещением; writer нормализует в UTC.

`WriteOutcome`: `state` (`checked`, `saved`, `applied`, `rejected`,
`restart_required`, `conflict`, `unknown`), `saved`, `version`,
`generation`, `applied`, `detail`. `saved=true` означает замену файла;
`applied=true` — только совпадение поколения и версии после reload.

`access.preview` ничего не пишет и возвращает ограниченный фрагмент
`before`/`after` (затронутое правило и соседи), `valid` и `summary`.
`access.apply` принимает `change`:

```json
{"kind":"rule_create","index":0,"rule":{"id":"deny-get","action":"deny","methods":["GET"]}}
{"kind":"rule_update","index":2,"rule":{"id":"allow-ops","action":"allow","host_exact":["example.test"]}}
{"kind":"rule_delete","index":2}
{"kind":"rule_move","from":3,"to":0}
{"kind":"source_add","value":"10.0.0.0/8"}
{"kind":"source_remove","index":1}
{"kind":"source_replace","values":["127.0.0.0/8"]}
{"kind":"ip_create","rule":{"id":"lan","action":"allow","networks":["10.0.0.0/8"],"allow_special":true}}
{"kind":"ip_update","index":0,"rule":{"id":"lan","action":"deny","networks":["10.0.0.0/8"]}}
{"kind":"ip_delete","index":0}
{"kind":"ip_move","from":1,"to":0}
{"kind":"ip_default","value":"deny"}
```

`rule`/`ip_rule` update заменяет переданные поля; отсутствующие селекторы
удаляются. Создание/перемещение/удаление меняет только `access` и сохраняет
комментарии, порядок и прочие секции.

## 5. Ошибки

```json
{"v":1,"id":17,"ok":false,"error":{"code":"conflict","message":"file changed since the form was opened","current_version":"sha256:..."}}
```

| `code` | Значение |
| --- | --- |
| `invalid_request` | поля/операция/формат неверны |
| `unsupported_version` | `v` не 1 |
| `unauthorized` | нет права записи или операция недоступна на этом сокете |
| `not_found` | объект/файл отсутствует |
| `conflict` | `expected_version`/`expected_generation` устарели; запись не выполнена |
| `invalid_candidate` | кандидат не прошёл штатный validator; файл не заменён |
| `restart_required` | изменение требует перезапуска; активна прежняя политика |
| `busy` | занята дорогая операция или достигнут лимит подписчиков |
| `timeout` | истёк срок |
| `unavailable` | прокси/writer недоступен |
| `too_large` | строка/страница превышает лимит |
| `shutting_down` | сервис завершает работу |
| `unknown_result` | файл мог быть заменён, но применение не подтверждено; сверьте версии |
| `resync_required` | курсор событий вне кольца; запросите снимок |
| `internal` | локальная ошибка |

Сообщения не содержат пароль, PHC, `Authorization`, приватные ключи,
полные URL или тела запросов. `fields` — не более 16 безопасных путей.

## 6. События и подписка

События: `config_saved`, `config_applied`, `config_rejected`, `users_saved`,
`block_expired`, `resync`. Каждое имеет `cursor` (монотонный), `at` (UTC),
`generation`, версии, необязательный `username` и `detail`. Кольцо — 512
событий; при устаревшем курсоре возвращается `resync_required` или
`EventEnvelope` с `resync_cursor`. Подписчик имеет очередь 64; при
отставании writer отправляет `resync` и продолжает с актуального курсора.
Медленный подписчик не блокирует прокси и других клиентов.

```json
{"v":1,"event":{"cursor":43,"kind":"users_saved","at":"2026-11-27T18:01:10Z","generation":42,"username":"bob"}}
{"v":1,"resync_cursor":128}
```

## 7. Примеры

Успешное добавление:

```json
{"v":1,"id":3,"op":"user.add","username":"bob","password":"...","password_confirm":"...","operation_id":"tui-123","expected_version":"sha256:aa..."}
{"v":1,"id":3,"ok":true,"result":{"state":"applied","saved":true,"version":"sha256:bb...","generation":43,"applied":true},"event_cursor":44}
```

Конфликт версии (запись не выполнена):

```json
{"v":1,"id":4,"op":"user.add","username":"bob","password":"...","password_confirm":"...","operation_id":"tui-124","expected_version":"sha256:aa..."}
{"v":1,"id":4,"ok":false,"error":{"code":"conflict","message":"file changed since the form was opened","current_version":"sha256:cc..."}}
```

Отказ в правах (член группы `angara`, не `angara-admin`):

```json
{"v":1,"id":5,"op":"block.set","username":"bob","permanent":true,"expected_version":"sha256:cc..."}
{"v":1,"id":5,"ok":false,"error":{"code":"unauthorized","message":"this connection may read but not change users or ACL"}}
```

Потеря ответа после команды: клиент повторяет запрос с тем же
`operation_id`. В пределах 10 минут writer вернёт сохранённый результат.
После перезапуска writer распознавание теряется: клиент обязан сравнить
`users_version`/`config_version` и состояние объекта, показать «результат
неизвестен» и запросить явное решение оператора до повтора.
