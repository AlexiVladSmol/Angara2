# M07-r1 — эксплуатация: reload, control service, JSON-журналы и метрики

Статус: **READY, Issue #20**. Редакция от **13 ноября 2026 года**, пакет документов **0.8**. Постановка — Codex; реализация, тесты и CI — DeepSeek V4.1 Flash 1017. Это исполнимый контракт ближайшего этапа, а не отчёт о готовой реализации.

## 1. База, результат и порядок

- Ветка реализации: **`feat/20-m07-operations` от `main` @ `60aebdaec3240a8139a90c920589388f312e360c`**. PR направить в main с `Closes #20`.
- M06: PR #19 merged, Issue #17 completed; [ACCEPTED](https://github.com/AlexeiSmol/Angara/pull/19#issuecomment-6849197123) на `c1b9f1b00850b6b8bf8d83f89b4e657f12c63d85`. Tree принятой версии и merge совпадает. Post-merge [CI 43403004578](https://github.com/AlexeiSmol/Angara/actions/runs/43403004578) — success.
- Принятый Linux baseline: **357 основных тестов +3 отдельно запускаемые resource checks**. Повторные evidence-команды не прибавлять к числу основных тестов. Известная локальная нестабильность M04/RST не объявляется pass; её корректное устранение входит в §12.
- Документационный SHA этого задания закрепляется в Issue #20 независимо от базы кода. Прочитать весь документ, AGENTS, ARCHITECTURE, DECISIONS и TEST_STRATEGY на том SHA. Ждать merge документационного PR не требуется; другие PR не сливать.

Результат M07: уже работающий HTTP/HTTPS proxy безопасно применяет разрешённые изменения без restart, показывает статус через внутренний типизированный control service, выдаёт ограниченные JSON-журналы/метрики и завершается в один общий срок. Некорректный reload не меняет действующие правила. Это последняя функциональная эксплуатационная ступень перед M08, **не выпуск v0.1**.

Сначала оставить план в Issue: структура snapshot/shared services, момент публикации, auth identity/pool/budget lifetime, чтение файлов, отмена reload, logging ownership/Drop и порядок тестов. Обязательный узкий spike до полного рефакторинга:

1. Настоящий keep-alive HTTP и CONNECT поверх TLS: согласованная смена ACL/users/generation, без пересоздания общих permit pools.
2. Одна early transport write → stall и SIGTERM во время TLS flush/reload: сохранение сроков M05/M06.
3. Заполненная log queue и stderr pipe, который никто не читает: forwarding и выход CLI не получают неограниченное ожидание writer/Drop.

Схему ownership и фактические результаты spike приложить. При настоящей невозможности — воспроизведение и blocker, без молчаливого ослабления контракта. Самостоятельно принимать/сливать этап или запускать M08 нельзя.

## 2. Что входит и что остаётся следующим этапам

Входят атомарные runtime snapshots, reload с expected generation, SIGHUP, общий lifecycle/control service, совместимые live limits, pool invalidation, bounded logs/metrics, документация оператора и проверки. Не вводить новый HTTP/parser/framing backend, небезопасный код или собственную криптографию.

**Не входят:** сетевой admin server, Unix-socket RPC, HTTP `/metrics`, Prometheus exporter, TUI, web/порт7029, CRUD пользователей через сеть, автоматический file watcher, немедленный отзыв действующих CONNECT, reload TLS/egress/workers, ACME, parent/cache, bandwidth/per-user/per-source quotas. systemd unit, пакеты, release artifacts и длительный release soak — M08. Типизированный service подготавливает M11/M12; интерфейс управления сейчас не слушает никакой порт.

Сохранить один crate/процесс, Tokio/hyper/rustls, metadata-only hyper patch и прежнюю совместимость. Разрешены `arc-swap` **1.9.x, не ниже1.9.5**, и `serde_json` **1.x** с поддерживаемым patch, Cargo.lock, Rust1.97.1/MSRV и cargo-deny. Использовать готовый ArcSwap для публикации, не писать atomic raw-pointer алгоритм. `tracing`/`tracing-subscriber`/`tracing-appender` необязательны: добавлять только с обоснованием в плане и доказательством ограничений queue/Drop; название non-blocking само по себе ничего не доказывает. Другие существенные зависимости/архитектурные изменения сначала вынести отдельным вопросом.

## 3. Схема и точная совместимость reload

Сохраняется `schema_version=1`. Старые M01–M06 configs валидны при прежних безопасных файлах. Новые optional таблицы со строгим отказом на unknown fields:

```toml
[operations]
reload_timeout_ms = 5000

[observability]
log_level = "info"
log_queue_capacity = 1024
metrics_enabled = true
metrics_interval_ms = 30000
```

`reload_timeout_ms`:100..60000ms, default5000. `log_level`: ровно `off|error|warn|info`, default info. Queue capacity:64..8192 records, default1024. Один сериализованный record — **не больше4096bytes**. Metrics interval:1000..600000ms, default30000. Все эти параметры restart-required; включение/выключение logs не должно менять auth/proxy semantics. При log_level=off нет output worker/periodic JSON output; metrics_enabled=true по-прежнему разрешает внутренний metrics snapshot. При metrics_enabled=false структурные counters текущего resource accounting не исчезают: control status и budgets работают, а подробная telemetry не собирается/не публикуется.

Полный allow-list изменяемых полей, а не правило «всё кроме известных исключений»:

| Поля | M07 reload | Момент действия |
| --- | --- | --- |
| `access.*` | Да | Source/request/IP policy нового exchange; новый TCP early source gate |
| `routing.default_egress`, `routing.rules` | Да | Новый exchange; ссылки только на уже существующие egress IDs |
| `auth.users_file` и содержимое users-файла | Да | Новый exchange; наличие auth и её параметры фиксированы |
| `limits.max_connections`, `limits.max_client_connections` | Да | Новая глобальная admission, включая поздний dial старого request |
| `limits.shutdown_timeout_ms` | Да | Первый shutdown, начатый после публикации; уже начатый deadline не меняется |
| `transport.total_timeout_ms`, `connect_timeout_ms`, `max_connect_attempts` | Да | Новый exchange |
| `http.response_header_timeout_ms` | Да | Новый exchange |
| `connect.allowed_ports`, `connect.half_close_timeout_ms` | Да | Новый CONNECT; уже открытый tunnel сохраняет прежние параметры |
| Остальные поля `limits`, весь `runtime`, `listeners`, `tls`, `dns`, `egress` | **Restart** | Включая parser/header/idle settings и TLS admission |
| Остальной `transport`, HTTP pool/max_headers, `auth.max_verifying`, `auth.verify_timeout_ms`, наличие/отсутствие `auth` | **Restart** | Общие jobs/queues/pools и parser параметры не пересоздаются reload-ом |
| `operations`, `observability`, schema_version и любые будущие поля | **Restart либо invalid** | Unsupported/unknown не принимать молча |

Использовать существующие диапазоны/межполевую валидацию M01–M06; allow-list не разрешает значения вне них. Для Basic listener нельзя удалить auth table или оставить невалидный users snapshot. Disabled/empty users разрешаются только по прежней schema и deny semantics.

Сравнивать нормализованные значения, не TOML bytes: пробелы и комментарии не являются restart-изменением. Порядок ACL/routing rules значим; listener/egress идентифицируются по стабильным ID. Изменение хотя бы одного restart-required поля отклоняет **весь** reload, включая одновременно корректные новые ACL/users. Без частичного применения, rebind, пересоздания resolver или незаметного изменения crypto policy.

### Файлы, TLS и check

Основной TOML теперь ограничен **1MiB** и для `Config::parse*`, и для file-loading. На Linux main config читать из одного открытого regular-file FD: owner root/effective UID, mode без022, проверка metadata этого FD и read limit+1. Это включает check/startup/reload; TLS/users сохраняют более специальные прежние ограничения. Symlink на безопасный regular file допустим, FIFO/device/directory и превышение размера отвергать без зависания. Не вводить unsafe ради owner checks.

Сохранить абсолютный путь аргумента `--config` и его file context от startup; не привязывать reload к последующему cwd и не подменять путь финальной целью symlink так, чтобы атомарная замена ссылки перестала работать. Относительные users/TLS пути трактуются как раньше — относительно каталога основного TOML.

**Reload не перечитывает certificate/private-key файлы.** Сначала parse/semantic validation и сравнение restart-only полей; при прежних TLS paths переиспользуются исходные prepared TLS Arcs. Изменённые/удалённые/невалидные cert/key на диске не меняют работающий TLS и не мешают ACL/users reload. Новый TLS path — RestartRequired до его открытия. Полный `angara check --config` и новый startup по-прежнему читают и проверяют cert/key: они вправе отклонить такую плохую пару. Не ослаблять check ради reload и не выдавать их разную роль за cert reload.

При каждой подготовке полностью прочитать/проверить main TOML и выбранный users file; PHC parse/cost/mode/owner/size и безопасные diagnostics M05 сохраняются. **Hash verification jobs при reload/check/validate не запускаются.** Не создавать новый auth semaphore/dummy verifier на каждом поколении.

Атомарность публикации не обещает filesystem-транзакцию двух путей. Каждый файл читается один раз в ограниченный buffer/FD; затем готовится один согласованный candidate. Оператор пишет временные файлы с безопасными правами и делает atomic rename users, затем main, затем SIGHUP. При конкурентной внешней записи valid read-set не объявлять ACID snapshot файловой системы; malformed/incomplete input отвергается целиком. Не писать main/users config из control service M07.

## 4. Snapshot, generation и обмены

Один immutable `RuntimeSnapshot` логически содержит generation, validated config/policy/routing/users и references на прежние static TLS/egress/settings. Одна корневая Arc публикуется через ArcSwap. Нельзя независимо менять users, ACL и generation в разных atomic slots или читать новую policy посередине старой проверки.

Generation начинается с1. Каждый успешный reload, в том числе с эквивалентным содержимым, увеличивает её **ровно на1**; invalid/restart-required/busy/conflict/cancel/timeout не меняют generation. При u64 exhaustion — безопасный отказ без wrap. Epoch/attempt counters и root generation различаются.

Новый HTTP/CONNECT exchange получает один strong snapshot **после получения exchange gate, непосредственно перед source/auth/policy**. С ним выполняются auth identity, ACL, DNS/IP/routing, pool key, response и лог результата. Сам keep-alive/TCP listener не закрепляет старую reloadable policy на всю жизнь. Новый запрос того же клиента после Applied использует новый snapshot, даже если его bytes уже ждали в pipeline. Header/parser/idle transport settings остаются прежними restart-only параметрами.

Exchange, начатый до публикации, вправе завершиться на прежнем snapshot: нельзя смешать пароль поколенияG с ACL G+1. Проверенный identity привязан к users snapshot своего exchange; старый identity нельзя инъецировать в новый request/outbound context. Unknown/disabled users проходят прежний bounded dummy path. Изменение password/disabled действует на новые запросы, без auth cache.

После допустимого CONNECT200 tunnel сохраняет старую policy/half-close settings до закрытия/idle/shutdown. Новые CONNECT и requests проверяются заново. Немедленного отзыва старых tunnels нет; это явно сообщается оператору. HTTP response body и запрос в ходе auth/DNS до publish также не объявляются заново авторизованными новым snapshot. Исключение — текущие **глобальные admission caps** из §5, действующие при новой выдаче socket permit.

При accept кратко проверить source по текущему root до TLS и отпустить reloadable snapshot; handshake использует исходный TLS snapshot/общие slots. На каждом действительном HTTP exchange source проверяется снова до auth/DNS. Старый разрешённый accept не обходит ужесточение source policy на новом запросе.

### Ограничение старых поколений

Одновременно допускается **не более16 опубликованных живых поколений**, включая current; дополнительно максимум один bounded candidate §6. Активные bodies/tunnels могут держать старые snapshots, но reload не создаёт бесконечную историю Config/Users/OriginPool.

Хранить только ограниченный учёт реально удерживаемых поколений, освобождённые удалять. При исчерпании лимита — `GenerationBusy` до публикации, без автообрыва старых tunnels; после освобождения старого поколения повторная операция может пройти. Допустим консервативный отказ у границы лимита, но не превышение16. Registry, metrics, log records и returned status не должны сами удерживать все исторические roots. Не использовать бессрочные per-worker caches корневых snapshots.

## 5. Общие budgets и origin pool

Reload **не создаёт новый Proxy/runtime/resolver/AuthService budget/TaskTracker/OriginTasks/pool на поколение**. Разделить immutable настройки/identity snapshots и постоянные shared services. Допустимо внутреннее переустройство типов, но public test/library APIs и прежние инварианты сохранить либо совместимо адаптировать их тесты без ослабления.

Общность означает поколения/listeners одного сервиса. Независимые library HttpServer instances могут иметь раздельные ControlState/budgets, как в M06; они не должны неявно устанавливать process-global logger/subscriber или мешать друг другу.

Client/outbound/connecting/DNS/auth/handshake in-use учитываются через один process/server shared budget каждого вида для всех поколений/listeners. Начатый blocking DNS/Argon2 удерживает свой permit до фактического завершения, даже после timeout/disconnect/reload. Reload не сбрасывает in-use, blocking task accounting, counters, client permit или handshake deadline. Не переносить неограниченную очередь внутрь spawn_blocking.

Live max_client_connections/max_connections — **глобальные** caps. При понижении ниже текущего in-use старую работу не убивать; новые выдачи отвергать, пока счётчик не станет меньше нового cap. При повышении новые slots доступны без пересоздания старых permits. Освобождение старой работы корректно возвращает учёт. Поздний dial request поколенияG после Applied G+1 подчиняется текущему глобальному cap, хотя его policy/timers остаются G. Admission и публикация должны иметь определённый порядок: после Applied нельзя выдать новый socket по устаревшему повышенному cap. Предшествующие публикации выдачи считаются уже активными.

Pool остаётся общим и ограниченным. После успешной публикации idle origins прежних поколений закрываются/помечаются retired для запрета reuse; generation входит в key наряду с endpoint/egress/listener/user. Старые leases и открывающиеся позже старые requests не возвращают sockets в current pool. Возврат retired lease закрывает socket. Нельзя очистить действующий pool **до** успешного publish и потом откатить только config.

Новый request перед каждым pool hit проходит прежние source/auth/request ACL/DNS/IP/route checks. Invalid reload сохраняет текущий pool работоспособным. При успешном reload old pool hit не обходится повторной проверкой «только IP»: identity/rules/generation изолированы полностью. Старый request, уже допущенный до publish, вправе открыть отдельное соединение по своей policy, но не использовать retired idle socket и не обходить актуальный global cap.

Поддержать реальные изменения routing между существующими bind_ip профилями: origin наблюдает ожидаемый исходящий127.0.0.1/127.0.0.2. Состав/адреса egress и TLS не меняются reload-ом; физических NIC эти loopback тесты не доказывают.

## 6. Control service, подготовка и отмена

Нужен **внутренний Rust API**, а не сетевой endpoint. Названия типов допускается уточнить, минимальные операции/результаты фиксированы:

| Операция | Контракт |
| --- | --- |
| `status()` | Owned безопасная projection: lifecycle, generation, uptime, configured/resolved workers, bounded listeners/egress summary, configured caps/in-use, reload busy/live generations, последний безопасный reload outcome |
| `metrics()` | Owned ограниченный snapshot §9; без Config/Users/secret Arcs и без открытого доступа к mutable внутренностям |
| `validate_on_disk(expected_generation)` | Проверяет candidate/compatibility по startup config path, без публикации и hash jobs; возвращает safe report и observed generation |
| `reload(expected_generation)` | Повторно читает/проверяет файлы и применяет один candidate; не доверяет прежнему preview-флагу/другим bytes |
| `shutdown(reason)` | Идемпотентно начинает общий drain §7, без exit процесса из library API |

Результаты различают Applied(new_generation), Valid, Invalid, RestartRequired, Conflict, Busy, GenerationBusy, TimedOut, Cancelled, ShuttingDown и internal failure. Error содержит безопасный класс и структурные field paths, не input snippets/library dumps/секретные значения. Списки ошибок/полей максимум16, каждый path максимум160chars; при большем числе — явный truncated flag. Public status не возвращает PHC, PEM/DER, credentials, users map или raw config. Списков всех соединений/неограниченной истории M07 не требует.

Status может показывать настроенные локальные bind addresses listeners/egress для диагностики. Это не адреса пользователей/удалённых назначений; в обычные request logs их переносить не требуется.

Expected generation обязателен для validate/reload; stale value даёт Conflict. Между validate и reload файл может измениться, поэтому apply всегда перепроверяет заново. Два конкурирующих callers не могут опубликовать snapshots с одним predecessor. Published root, lifecycle fence и учёт операции меняются согласованно; generation не повышается до полного завершения preparation.

Максимум **один фактически выполняющийся preparation job**, очередь0. Второй validate/reload быстро возвращает Busy, не создаёт task/waiter. File read, TOML/PHC parsing/validation выполняются вне network async workers и вне publication lock, под persistent bounded permit. Не удерживать locks через await, disk I/O, hashing или передачу тела. Подготовка только возвращает candidate; background blocking closure **не публикует root**.

Deadline от начала операции — operations.reload_timeout_ms. Timeout/caller drop/cancel/shutdown снимает право на publish. Если blocking read ещё реально выполняется, его slot/handle остаются учтёнными до фактического конца; следующая операция не получает новый slot. Поздний candidate уничтожается без публикации. Тестом с управляемым preparer доказать отсутствие late publish после timeout и при shutdown; это не заменяется sleeps/объявлением spawn_blocking abortable.

Публикация — короткая согласованная секция: проверить expected generation, active operation token, deadline, Running lifecycle и generation cap; затем publish root. Failed/cancelled операции не имеют побочных rebind/TLS-read/pool-clear/частичного изменения caps. Если logger переполнен после commit, это не откатывает уже применённую конфигурацию. Status безопасно показывает outcome/счётчики.

Ни proxy headers, URL `/reload`/`/metrics`, ни proxy Basic identity не дают вызова control service. Не добавлять фиктивную отдельную CLI-команду reload/status без IPC. Для локального оператора M07 используются SIGHUP и JSON output, для in-process пользователя — typed API. Сетевой admin transport появится отдельной задачей M11/M12 с самостоятельной авторизацией.

## 7. SIGHUP и единый lifecycle

Linux/Ubuntu: SIGHUP запускает ту же reload operation с current expected generation. Callback только уведомляет async control loop; никакого чтения/сериализации/locks в raw signal handler. HUP во время подготовки coalesce/drop с bounded учётом: **не более одного pending notification**, без spawn на каждый signal и без неограниченных waiter-очередей. Не обещать один reload на каждый POSIX signal: ОС может объединять их. Способ coalescing явно описать; timeout/busy/invalid не останавливает proxy и не запускает бесконечный retry.

Lifecycle: Running → Draining → Stopped. SIGTERM/SIGINT и typed shutdown идут через один coordinator. Первый shutdown фиксирует **один absolute deadline** по текущему limits.shutdown_timeout_ms; последующие signals/calls его не продлевают. Допустимо ускоренное force при повторном interrupt, но не новое полное окно.

Draining прекращает новые accepts/exchanges/handshakes/auth jobs, запрещает reload publish, закрывает idle origins и даёт уже допущенной работе оставшееся время. TLS flush/close, CONNECT first-EOF drain, cleanup control/logging и runtime используют оставшийся срок; after-force sockets/async tasks действительно закрываются/reap-ятся. Не запускать admin/telemetry HTTP listener ради статуса.

Сохранить M05 shared server+runtime deadline и M06 cases: continuous partial encrypted progress; early-write→stall; TLS1.3 reverse drain; TLS1.2 closure; abrupt EOF; no application progress от control-only bytes. Config reload не сбрасывает clocks существующего body/tunnel и не даёт нового окна при закрытии.

Начатый native blocking DNS/Argon2/file read не обещается принудительно прерванным. Его количество/permit остаются ограниченными; shutdown runtime не ждёт новый полный timeout. Граница network-task cleanup и таких native jobs должна честно отражаться в отчёте. CLI exit ограничен исходным deadline с измеренным scheduler tolerance, без скрытого WorkerGuard/JoinHandle/Drop ожидания после него.

## 8. JSON-журналы и backpressure

После успешного startup `serve` выдаёт operational records в **stderr, JSON Lines**, по одному объекту на строку; stdout не превращается в protocol/admin channel. `check`, `users hash`, no-echo prompts и существующие exit codes сохраняются; PHC stdout users hash не смешивается с telemetry. Предстартовые CLI/config failures могут оставаться прежними безопасными diagnostics.

JSON сериализуется готовым serde_json из typed allow-list полей. Минимальные события: service_started, reload_applied/reload_rejected, shutdown_started/service_stopped, request_finished, tunnel_finished, metrics_summary. Поле event и outcome — конечные enums; timestamp UNIXms, schema_version=1; request/connection ID создаёт сервер, не клиентский header. Generation, listener_id/egress_id/matched rule ID, HTTP status при наличии, elapsed_ms и явно определённые body/tunnel byte counts — ограниченные поля. На admission/handshake/parser error без HTTP exchange допустимо connection outcome с connection_id вместо фиктивного request_finished.

Один HTTP exchange получает один terminal outcome после окончания/отмены streaming body, не сразу после заголовков. CONNECT200 не означает конец tunnel: tunnel_finished приходит при реальном завершении, idle/force/ошибке. Двойные terminal records и positive success при усечённом body запрещены. Закрытие/таймаут библиотечного будущего не считать успешной передачей. Wall clock для timestamp, monotonic clock для duration; saturating counters без wrap.

**В M07 не журналируются:** usernames, PHC/passwords, Proxy-Authorization/Authorization/Cookie, произвольные headers/trailers, URL/path/query, authority/domain, source/destination IP, TLS key/cert fragments/secrets и payload. Для базовой диагностики используются server IDs, configured IDs, outcome и safe reason class. Это выбранная privacy policy первого операционного этапа; richer sensitive audit — отдельное расширение. Public Debug/Error/status/metric labels защищены так же. Удалять секреты потом regex-ом из полного Debug dump нельзя: не сериализовать их изначально.

Каждый queued record — самостоятельные безопасные scalar/string значения, **без Arc RuntimeSnapshot/Users/Request**. Record максимум4096bytes; превышение даёт drop/counter, не некорректный усечённый JSON. Максимум log_queue_capacity records. `try_send`/аналог без ожидания; переполнение **drop newest + log_records_dropped_total**, forwarding продолжает работу. Sink errors учитываются без рекурсивного логирования и busy-spin; файловая ротация/retention не реализуются, stderr управляет supervisor в M08.

Logger worker не исполняет потенциально блокирующий stderr write на network Tokio workers или в общей spawn_blocking очереди DNS/auth/reload. Разрешён **один явно принадлежащий CLI process-lifetime output worker**, не новый worker на request/reload. Library HttpServer/control не создают скрытый stdout/stderr thread: принимают общий bounded sink либо no-op/test sink. Повторный bind/drop/reload не накапливает log threads/FD. Если старый process-owned writer ещё заблокирован, нельзя породить вместо него следующий writer.

Graceful log drain — best effort **внутри того же shutdown deadline**. Lossless logging при полном queue/зависшем sink не обещается; потеря наблюдаема counters. CLI обязан завершиться в срок даже при stderr pipe без reader; не ждать неограниченный join/Drop и не добавлять фиксированный таймаут после network/runtime cleanup. Единственный process-lifetime OS writer может быть завершён ОС при конечном exit процесса; это ограниченная особенность stderr, не разрешение detached/per-reload jobs. Для library lifecycle не маскировать остающийся worker как очищенный: shared sink принадлежит вызывающей стороне. В spike показать ownership/окончание процесса и поведение выбранной logging библиотеки, включая guard Drop.

## 9. Метрики и точные границы счётчиков

Внутренний `MetricsSnapshot` и periodic `metrics_summary` JSON дают базовые наблюдения без сетевого exporter. Summary — global scalars, чтобы вместиться в4096bytes; per-listener детализация доступна typed API. Счётчики живут весь lifetime сервиса (обычно один CLI process), reload не обнуляет их. Snapshot generation/настройки берутся из одного root; gauges конкурентны, не обещать идеально атомарную фотографию всех текущих задач.

Минимум: TCP accepted/rejected; client active; TLS handshakes active/success/error/timeout/busy; HTTP exchanges started/completed/cancelled и finite outcomes/status classes; CONNECT started/active/end reasons; auth actual jobs active/ok/invalid/busy/timeout; DNS actual jobs active/timeout/error; outbound sockets active/connecting; idle/leased pool sockets; reload attempts/applied/invalid/restart/conflict/busy/timeout; live generations/preparation busy; log queued/dropped/sink errors; shutdown/force counts. Фиксированные latency histograms для HTTP exchange, TLS handshake и auth verification; границы/units перечислить в README, без dynamic buckets.

Gauges отражают **реальное владение ресурсом**: timeout ответа auth/DNS/preparation не уменьшает actual-job gauge и не освобождает permit до конца native job. Outbound socket включает живой idle/leased Connected до фактического закрытия; client permit — от accept admission до завершения всех client I/O. Handshake slot освобождается по прежнему M06 контракту. Drop/error/cancel paths имеют RAII accounting, без double-decrement/отрицательных gauges.

Byte counts — **наблюдаемые application body/relay bytes**, а не обещание TCP ACK или чтения конечным приложением. Для HTTP считать DATA bytes проверенных Body frames на выбранных request/response adapter границах; HEAD/пустое body=0, headers/framing/trailers не body. Для CONNECT — положительные plaintext relay reads каждого направления, включая early payload ровно один раз; внутренний site TLS является opaque payload внешнего tunnel. Не включать outer TLS records/handshake/control. Место измерения точно описать; partial/abort лог может иметь observed bytes при incomplete outcome. Не переиспользовать/ломать M03 ConnectionOutput barrier ради статистики.

Кардинальность: global counters/finite enums/fixed histograms и не более64 configured listener IDs. В M07 не нужны per-user/domain/IP/request/generation/egress×outcome series или map произвольных labels. Общее число metric series **не больше2048** при максимальном допустимом config. Нет бесконечной event history, кэша чужих SNI/username/error strings. Status egress list ограничен существующим schema cap; он не является динамической labels map.

На трафиковом пути допустимы bounded atomics/локальные counters; нельзя сериализовать полный metrics snapshot, брать global publication lock или собирать JSON на каждый переданный chunk. Metrics summary task — одна общая, missed ticks Skip, никаких очередей просроченных ticks. При выключенной подробной telemetry proxy/control budgets всё равно корректны.

## 10. Положительные и отрицательные сценарии

Обязательные наблюдения через настоящий HTTP/HTTPS proxy и typed API:

- G1 разрешает Alice/routeA; G2 меняет password/disabled/ACL/routeB согласованно. Новый keep-alive/pipelined request видит только целый G1 либо G2, не смесь. До DNS/dial действительно отказывают source/auth/ACL; origin показывает нужный bind_ip. Есть NONE и Basic listeners.
- Slow response, blocked verifier/DNS и CONNECT проходят через публикацию. Старые bodies/tunnels продолжают старое поведение и сроки; новые requests получают новые правила. Старая identity не принимается новым snapshot; old leased socket после завершения не становится новым pool hit.
- Invalid TOML/UTF-8/users/PHC/mode/size/unknown field и mixed hot+restart change оставляют прежний generation и outbound поведение; stdout/stderr/origin/status не получают markers. Сохранить backtick/quote/dot/fake-array-index диагностику M05.
- Bad/deleted/replaced TLS files не меняют действующий сертификат и не читаются policy reload-ом; смена path отвергается. Новый startup/check такой bad pair отвергает. Отдельные proxy/site CAs и настоящий TLS-in-TLS остаются.
- Live cap2→1 при двух старых удерживаемых ресурсах запрещает новые, старые разрешено завершить; после освобождения допускается ровно новый cap. 1→2 сразу даёт новые slots. Бюджеты не умножаются reload-ами, включая незавершённый Argon2/DNS и pool leases.
- CAS race, busy admission, generation cap16, timeout/caller drop/shutdown preparation не дают late publish или неограниченного retaining roots. Signal storm не увеличивает число jobs/threads/queues.
- Заполненная/stalled log queue не задерживает независимый HTTP/tunnel; drops видимы. Stderr pipe без reader + SIGTERM укладывается в общий deadline. Логи valid JSON, finite schema, нет secrets/injection/частичных строк от конкурентных writers.
- Метрики сверяются с фактическими known requests/bodies/origin accepts/verifier calls и actual lifetime gates; HEAD0bytes, 1MiB stream equality, early CONNECT payload, abort и clear-to-baseline. Разнообразие тысячи ложных usernames/SNI/targets не создаёт новых series/history.

Не объявлять outer timeout успешным EOF/закрытием, любой SSL/OSError — certificate failure, или произвольный I/O error — допустимым force close. Expected clean closure и force RST различаются; тайм-аут наблюдения/неисполненный ignored test всегда failure/BLOCKED, не pass.

## 11. Матрица приёмки — 25 M07-ID

| ID | Обязательная проверка результата |
| --- | --- |
| M07-CFG-01 | Strict optional operations/observability, старые configs, ranges/unknown keys, main1MiB/regular FD/mode/owner/symlink; check без runtime/network/hash |
| M07-SNAP-01 | Полная preparation→один publish, invalid rollback без partial users/ACL/caps/pool mutation, successful generation+1 |
| M07-CAS-01 | Expected generation, validate/apply file race, stale/conflicting callers, Busy0queue; no concurrent commit |
| M07-REQ-01 | Keep-alive/pipeline snapshot после exchange gate; старое body/auth/DNS завершает G, новый request использует G+1 |
| M07-AUTH-01 | Password/disabled/users-file reload, real+dummy shared jobs, старый identity не проходит новый context, secret chars/NFC |
| M07-POL-01 | Live source/request/IP/domain/port/routing; fresh DNS/IP на pool hit; наблюдаемые два исходящих loopback IP |
| M07-POOL-01 | Idle old generation retired только после publish, old lease закрывается, listener/user/endpoint/egress/generation isolation |
| M07-LIMIT-01 | Shared global client/outbound caps lower/raise при старых holders; actual DNS/auth/connect/TLS budgets не сбрасываются |
| M07-STATIC-01 | Mixed hot+restart полностью отвергнут; workers/listeners/egress/DNS/parser/pool/auth/TLS static; TLS files на reload не открываются |
| M07-GEN-01 | Max16 опубликованных живых roots, bounded registry, GenerationBusy без мутации, освобождение старого root даёт продолжить |
| M07-CANCEL-01 | Один actual preparation, timeout/drop не освобождает работающий slot, controlled late completion не публикует root |
| M07-SIGNAL-01 | Реальный SIGHUP success/invalid/storm, bounded coalescing, no unbounded tasks; SIGTERM выигрывает у reload publish |
| M07-SHUT-01 | Один absolute срок server/control/logger/runtime, повторные signals не продлевают, stalled TLS flush/native work/log pipe |
| M07-LOG-01 | Valid bounded JSON Lines, typed fields, IDs, один terminal outcome на exchange/tunnel, observed bytes/duration, no fake success |
| M07-SECRET-01 | Credentials/PHC/key/query/header/trailer/source/user markers отсутствуют в telemetry/error/Debug/status; proxy credentials/PHC/key не попадают в origin; допустимые end-to-end query/headers/trailers передаются по прежнему HTTP контракту; safe typed paths |
| M07-LOG-02 | Queue capacity/record4096, drop-newest counters, sink error/no recursion, stalled stderr не тормозит data plane/CLI exit, max1 process writer |
| M07-MET-01 | Counters/gauges/histograms на фактических lifecycle gates; timeout jobs остаются active до actual completion; cancel не удваивает outcome |
| M07-MET-02 | Не больше2048 series, finite labels/arrays, нет роста от usernames/SNI/targets/generations; reset при reload отсутствует |
| M07-CTRL-01 | Owned safe status/metrics/validate/reload/shutdown API, без admin ports/IPC и без управления через proxy inputs |
| M07-CON-01 | Живой CONNECT сохраняет G и first-EOF/idle clocks; новый CONNECT проверяет G+1; TLS1.3 reverse drain/TLS1.2 closure сохранены |
| M07-CPU-01 | Workers1 и>=2, reload/log pressure не блокирует независимый разрешённый HTTP/tunnel, heartbeat/latency/actual workers evidence |
| M07-RES-01 | >=100 reload attempts плюс cancel/fail, bounded candidates/roots/jobs/queues; FD/RSS/tasks/threads до/пик/после и восстановление |
| M07-LOAD-01 | 10/20 logical clients,2 users, HTTP+HTTPS/CONNECT и>=20 successful reloads на cohort; controlled auth rate, все errors/busy/retries учтены |
| M07-REG-01 | Baseline357 +3 explicit resource tests и вся M01–M06/CLI/curl/TLS/raw-target/framing/typed-errors suite; fmt/clippy/build/deny/CI на head |
| M07-LEGACY-01 | M04 forced-shutdown RST/FIN проверка исправлена по §12; >=20 последовательных повторов без скрытых skips; graceful regressions не ослаблены |

## 12. Стенд, прежний M04 test и команды

Первый обязательный runner: Ubuntu24.04 x86_64, Rust1.97.1, динамические локальные порты, private tempdir/CA/users, без прав root/Интернета в protocol tests. Возможности других Linux описывать отдельно.10/20 clients — логические, а не20 физических устройств или подтверждение NIC.

Добавить полный `examples/m07-operations-local.toml` с HTTP+HTTPS/Basic и operations/observability, безопасную генерацию PKI/users, check/serve, atomic file replacement, `kill -HUP`/`kill -TERM`, JSON inspection и cleanup. Пароль вводится no-echo через users hash/curl prompt, без argv/env/private config interpolation; stderr redirect не прячет prompt. Wrong proxy/site CA/name/expiry остаются реальными certificate failures без insecure verifier.

В базовом `m04_srv01_forced_shutdown_reclaims_active_tunnel_tasks` origin иногда получает RST вместо FIN: это воспроизведено и на base M05, описано в [M06 ACCEPTED](https://github.com/AlexeiSmol/Angara/pull/19#issuecomment-6849197123). В M07 исправить **тестовую модель принудительного shutdown**, а не скрыть тест: force abort/drop может закрыть TCP EOF либо `ConnectionReset`/`ConnectionAborted`. Принимать только явно допустимые force-close исходы после действительного stop, обязательно проверяя исчезновение sockets/FD/tasks и прежний срок. `WouldBlock`, `TimedOut`, outer timeout, произвольная ошибка и ещё живой socket не являются успехом. Если проверяется graceful path, дочитать greeting/response и требовать соответствующего чистого EOF/close_notify. Не удалять и не ослаблять отдельные body/half-close/graceful проверки.

Приложить >=20 последовательных повторов этого regression на Linux, детерминированную синхронизацию fixture вместо увеличения sleep «до зелёного», и полные REG-01 результаты. M07 не наследует постоянный skip этого теста.

Обязательный минимум команд:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
cargo test --locked
cargo test --locked --test http_limits m03_res02 -- --ignored --test-threads=1 --nocapture
cargo test --locked --test m04_limits m04_res02 -- --ignored --test-threads=1 --nocapture
cargo test --locked --test m06_progress -- --nocapture
cargo deny check
```

M07 resource/load/signal/blocked-logger tests запускать явно и с документированными timeouts. Имена новых test targets исполнитель фиксирует в README/CI и PR; не оставлять обязательные сценарии неисполненными ignored. Сохранить все прежние example/check, Basic/HTTPS-proxy/site-TLS/curl, PTY, CPU/resource evidence. CI job timeout допускается обоснованно увеличить/разбить без выключения прежних checks.

Ресурсный отчёт: OS/kernel/Rust/CPU/RAM/workers, config/log cap/generation cap, attempts/applied/invalid/busy/conflict/timeouts/cancellations, successful HTTP/CONNECT/407/403/503/TLS failures и **все** retries; latency p50/p95/observed max с числом samples, FD/RSS/async tasks/OS threads и log drops до/пик/после. Не обещать неизменный RSS allocator или точные скорости на shared CI; задать разумный повторяемый верхний предел, измерить восстановление и отсутствие роста по истории attempts/stream length. Никаких тихих повторов неуспешных probes.

## 13. Отчёт и критерий готовности

В PR: base/head SHA, Ready Issue/документационный SHA, схема snapshot/shared ownership, hot/restart table и границы active tunnels, spike результаты, dependency/MSRV/deny, карта **25 M07-ID → tests/commands/evidence**, точные CI runs и реальные причины негативных исходов. Отдельно JSON schema/units/privacy/drop policy, logger shutdown ownership, resource/load measurements, M04 stabilisation и ограничения. Обновить README/help/архитектуру/текущее состояние, исторические M02–M06 task docs не переписывать.

Готовность: весь M07-r1 реализован, необходимые checks на актуальном head пройдены, нет открытых blocking findings, есть ACCEPTED Codex. Зелёный CI без осмысленных assertions и самоотчёт модели не заменяют ревью. Ошибка окружения/неисполненная обязательная проверка — BLOCKED, не pass. Слияние — только по отдельному поручению владельца; M08 не начинать самостоятельно.

## 14. Первичные источники для реализации

- [Tokio1.54 signal/unix](https://docs.rs/tokio/1.54.1/tokio/signal/unix/index.html) — signal notifications; бизнес-операции выполняются вне handler.
- [Tokio spawn_blocking](https://docs.rs/tokio/1.54.1/tokio/task/fn.spawn_blocking.html) — начатая native closure не становится abortable от Drop/timeout; отдельный admission обязателен.
- [arc-swap1.9.5](https://docs.rs/arc-swap/1.9.5/arc_swap/) — готовая публикация Arc; не использовать старые1.8.x ordering assumptions или бессрочный Cache для roots.
- [serde_json](https://docs.rs/serde_json/latest/serde_json/) — typed JSON serialization, не ручная конкатенация строк с пользовательскими значениями.
- [tracing-appender non_blocking](https://docs.rs/tracing-appender/latest/tracing_appender/non_blocking/index.html) — bounded/off-thread output и guard lifetime; выбранную конфигурацию/Drop проверять, defaults не считать политикой Angara.

Численные defaults, live allow-list,16 generations и privacy/logging contract — **SPECIFIED Codex** в рамках D01/D02/D08/D09/D12/D14 и поручения M07. Они не объявляются отдельными новыми решениями владельца.
