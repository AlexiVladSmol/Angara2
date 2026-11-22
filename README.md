# Angara

Прямой прокси-сервер для Linux с возможностями, которые будут развиваться поэтапно: HTTP, HTTPS через CONNECT, авторизация, правила доступа, управление ресурсами и кэширование HTTP.

**Статус: M00–M08 приняты и слиты.** M08 дал кандидат v0.1: архив с манифестом, установку, systemd, обновление и откат A→B→A, стендовые проверки. Ревизия документов: 1.0. Первый стенд — Ubuntu Server 24.04 x86_64, 10–20 устройств. Согласование требований, слияние PR, лицензия и публичный выпуск — отдельные действия владельца. [Задание M08](docs/tasks/M08_RELEASE_CANDIDATE.md) · [Issue #23](https://github.com/AlexiVladSmol/Angara/issues/23)

## Участники и работа

| Участник | Ответственность |
| --- | --- |
| Владелец проекта | Утверждение требований, архитектурных решений, приоритетов и выпусков |
| ChatGPT / Codex | Архитектура, планирование, задания, стратегия тестирования и код-ревью |
| DeepSeek V4.1 Flash 1017 | Реализация кода, тестов, CI и исправлений по согласованным заданиям |

Основной канал взаимодействия — Issues и Pull Requests этого репозитория. Решения из чата переносятся в репозиторий. GitHub хранит задания и результаты; запуск моделей выполняется в их рабочих средах.

## Согласованный первый выпуск

- Один сервис для Linux; Rust, Tokio, hyper и rustls; многопоточный runtime с настраиваемым числом рабочих потоков.
- HTTP/1.1 forward proxy и TCP-туннели CONNECT для HTTPS.
- Обычный и TLS-защищённый вход к прокси.
- Локальные пользователи, Basic proxy authentication, ACL по источнику, пользователю, домену, IP и порту назначения.
- Ограничения соединений и времени ожидания, потоковая передача, журналы, systemd.
- Несколько входных адресов и выбор исходящего адреса по правилам; сетевые профили не смешиваются при повторном использовании соединений.
- Parent proxy реализован в M09; кэширование HTTP — обязательный следующий этап M10.
- Далее — современный TUI через общий слой управления; локальная web-панель рассматривается отдельно, ориентир 127.0.0.1:7029.

HTTPS внутри CONNECT остаётся сквозным: TLS содержимого сайта завершается у клиента и сайта. TLS-вход к Angara защищает отдельно участок «клиент → прокси». Подмена сертификатов сайтов в первый выпуск не входит.

## Документы

| Документ | Содержание |
| --- | --- |
| [Описание продукта](docs/PROJECT_BRIEF.md) | Назначение, первый выпуск, ограничения и открытые вопросы |
| [Архитектура](docs/ARCHITECTURE.md) | Компоненты, обработка запроса, протоколы и ресурсы |
| [Этапы](docs/ROADMAP.md) | Зависимости, результаты и приёмка M00–M12 |
| [Стратегия тестирования](docs/TEST_STRATEGY.md) | Проверки протокола, безопасности, нагрузки и выпуска |
| [Процесс работы](docs/WORKFLOW.md) | Задания DeepSeek, PR, ревью и передача контекста |
| [Решения](docs/DECISIONS.md) | Предложения и журнал согласования |
| [Задание M01](docs/tasks/M01_BOOTSTRAP.md) | Каркас Rust, CLI, конфигурация, подготовка многопоточного runtime и CI |
| [Задание M07](docs/tasks/M07_OPERATIONS.md) | Контракт принятого этапа эксплуатации и наблюдаемости |
| [Задание M08](docs/tasks/M08_RELEASE_CANDIDATE.md) | Установка, systemd, Linux-артефакт, обновление, откат и измерения для кандидата v0.1 |
| [Инструкции участникам](AGENTS.md) | Роли и правила работы агентов |

## M01: сборка, CLI и конфигурация

M01 добавляет минимальную поддерживаемую основу. HTTP forwarding, CONNECT,
TLS, auth, ACL, egress, cache, TUI и admin API в неё не входят.

### Toolchain и сборка

- Rust 1.97.1, edition 2024; канал и компоненты закреплены в
  [`rust-toolchain.toml`](rust-toolchain.toml), точные версии зависимостей — в
  `Cargo.lock`.
- Целевая среда первой проверки: Ubuntu Server 24.04 x86_64.
- Сборка из чистой копии: `cargo build --locked`.

Обычные проверки (те же команды выполняет CI):

```console
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
cargo test --locked
cargo run --locked -- check --config examples/minimal.toml
cargo run --locked -- check --config examples/multi-listener.toml
cargo deny check
```

### CLI и коды завершения

| Команда | Поведение |
| --- | --- |
| `angara --version` | Печатает `angara 0.1.0`, код 0 |
| `angara check --config <path>` | Читает, разбирает и проверяет TOML; код 0 при успехе, без сети |
| `angara serve --config <path>` | Проверяет config, связывает все listeners, затем обслуживает HTTP/1.1 forward proxy; код 0 при штатной остановке по SIGINT/SIGTERM, 3 при ошибке bind/запуска |
| `angara users hash` | Читает пароль и подтверждение из TTY без echo и печатает один Argon2id PHC в stdout; без TTY требует явный `--password-stdin` |
| `angara users hash --password-stdin` | Читает одну ограниченную строку stdin, проверяет UTF-8/NFC и печатает один PHC; пароль не принимается через argv или env |
| `angara --help` | Печатает справку, код 0 |

Коды: `0` — успех, `1` — ошибка конфигурации, ввода пароля, хэширования или
локального users-файла, `2` — ошибка аргументов,
`3` — ошибка запуска сервера или неожиданное завершение. Ошибки печатаются в
stderr, не содержат значений config; семантические конфликты описываются
через пути полей и индексы, а управляющие символы в путях и именах полей
экранируются, чтобы диагностика оставалась одной записью журнала. По
возможности указываются поле, строка и столбец.

### Строгая схема TOML

```toml
schema_version = 1

[runtime]
worker_threads = "auto" # или целое 1..=64

[tls]
max_handshaking = 32
handshake_timeout_ms = 5000

[limits]
max_connections = 256
max_client_connections = 128
max_header_bytes = 32768
header_read_timeout_ms = 10000
idle_timeout_ms = 60000
shutdown_timeout_ms = 5000

[http]
max_headers = 100
response_header_timeout_ms = 30000
pool_max_idle = 16
pool_max_idle_per_key = 2
pool_idle_timeout_ms = 15000

[[listeners]]
id = "proxy-loopback"
bind = "127.0.0.1:3128"
transport = "http"
```

- Неизвестные ключи и будущие активные разделы (ACL вне `[access]`, cache,
  admin, parent и т. п.) отклоняются, а не игнорируются.
- `schema_version` поддерживается только `1`.
- `listeners`: от 1 до 64 определений; `id` уникален, состоит из 1–64 ASCII
  букв, цифр, `-`, `_`, `.`; `bind` — только числовой `IP:port` с портом
  1–65535; `transport` — `http` или `https`. Для `https` обязателен
  `[listeners.tls]`, для `http` он запрещён. `allow_insecure_basic` допустим
  только с `auth = "basic"` на HTTP listener и отвергается на HTTPS.
- Дубли `id`/адресов и пересечение wildcard-адреса с конкретным адресом того
  же семейства и порта отвергаются. IPv6 listener проектируется как IPv6-only:
  будущий bind выставит `IPV6_V6ONLY`, поэтому `0.0.0.0` и `[::]` на одном
  порту не конфликтуют. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) и scoped IPv6
  отклоняются.
- `[tls]` необязателен: `max_handshaking` 1–256 (default 32) — общий предел
  одновременных TLS handshake всех HTTPS listeners; `handshake_timeout_ms`
  100–60000 (default 5000) — абсолютный срок от TCP accept.
  `listeners[].tls.cert_chain_file` и `listeners[].tls.private_key_file`
  разрешаются относительно каталога config и читаются один раз при загрузке
  snapshot. Chain — 1–16 PEM `CERTIFICATE` (leaf-first), key — ровно один
  поддерживаемый unencrypted PKCS#1/PKCS#8/SEC1 ключ, файл до 1 MiB; rustls
  проверяет соответствие ключа leaf-сертификату. Весь PEM input проверяется
  строго: неизвестные/encrypted блоки, вложенные или незавершённые маркеры и
  непустой текст вне блоков отвергаются; допускаются обычные whitespace и
  CRLF. На Linux key не должен иметь
  group-write/world-битов (например `0600`/`0640`), chain — write для
  group/world (например `0600`/`0644`), владелец — effective UID сервиса или
  root. `[operations]` и `[observability]` — restart-required optional
  таблицы: `reload_timeout_ms` 100..60000 (5000), `log_level`
  `off|error|warn|info`, `log_queue_capacity` 64..8192 (1024),
  `metrics_enabled`, `metrics_interval_ms` 1000..600000 (30000).
- `limits`: `max_connections` 1–65535 — общий бюджет исходящих sockets
  (connecting, leased и idle); `max_client_connections` 1–65535 — отдельный
  входящий бюджет принятых клиентских sockets, включая keep-alive idle
  (по умолчанию равен `max_connections`); `max_header_bytes` 1 KiB–1 MiB, `header_read_timeout_ms` 100–300000,
  `idle_timeout_ms` 1000–3600000, `shutdown_timeout_ms` 1–300000. Ноль,
  отрицательные значения, переполнение и выход за границу — ошибка.
  Суммарный предел FD складывается из обоих бюджетов, listeners, DNS и
  служебных сокетов; `transport.max_connecting` дополнительно ограничивает
  одновременные connect attempts.
- `http`: `max_headers` 1–256 на каждую секцию request/response/interim/
  trailers; `response_header_timeout_ms` 100–300000 от начала отправки
  upstream headers до финальных response headers (1xx срок не перезапускают);
  `pool_max_idle` 0–min(1024, `max_connections`), по умолчанию
  min(16, `max_connections`); `pool_max_idle_per_key` 0 только при общем 0,
  иначе 1–`pool_max_idle`, по умолчанию min(2, `pool_max_idle`);
  `pool_idle_timeout_ms` 100–300000, по умолчанию 15000.
- `worker_threads`: `auto` использует доступный процессу параллелизм (минимум
  1, максимум 64); явное число задаёт multi-thread Tokio runtime. Число
  workers не ограничивает число клиентов или соединений.
- `check` не выполняет DNS, не открывает listener и не соединяется с
  upstream. На Linux отсутствие вызовов `socket`/`bind`/`connect`/
  `getaddrinfo`/`gethostbyname` для `check`, `help`, `version` и `serve` с
  невалидным config доказывает LD_PRELOAD-тест с положительным контролем;
  корректному `serve` сеть разрешена по контракту M03. На других ОС этот тест
  не исполняется.

Примеры: [`examples/minimal.toml`](examples/minimal.toml),
[`examples/multi-listener.toml`](examples/multi-listener.toml) и
[`examples/m03-http-local.toml`](examples/m03-http-local.toml).

Обоснование границ: 64 workers — верхняя граница выше типичного числа CPU на
первом сервере; она предотвращает случайное создание сотен потоков, а `auto`
использует доступный параллелизм, но не превышает её. 64 listeners с запасом
покрывают несколько интерфейсов и не позволяют конфигурации разрастись
незаметно. Числовые limits конечны, чтобы отвергать ноль, отрицательные
значения, переполнение и бесконтрольные очереди; значения в примерах —
безопасные стартовые, а не обещание производительности. `max_connections`
ограничивает соединения независимо от числа workers.

### Зависимости и лицензии

Базовые зависимости M01: `tokio` (`rt-multi-thread`), `serde`, `toml` и
`serde_path_to_error` для строгой схемы и безопасного пути поля в ошибках.
M02 добавляет `http`, `ipnet`, `idna` и Tokio `net`/`time`/`sync`/`io-util`.
M03 добавляет `hyper` 1.12 (`client`, `http1`, `server`), `hyper-util`
(`TokioIo`, таймер), `http-body`, `http-body-util`, `bytes`, `socket2` и
Tokio `macros`/`signal`. M06 добавляет `rustls` 0.23 (ring, `tls12`),
`tokio-rustls` 0.26, `rustls-pki-types` 1 (PEM parsing) и `x509-parser` 0.18.
M07 добавляет `arc-swap` 1.9.5 и `serde_json` 1. Hyper 1.12.0
закреплён с минимальным локальным patch для `OriginalRequestTarget`; см.
раздел M03 и
[`vendor/hyper-1.12.0/ANGARA_PATCH.md`](vendor/hyper-1.12.0/ANGARA_PATCH.md).
Политика
зависимостей проверяется
[`deny.toml`](deny.toml): RustSec advisories, allow-list MIT/Apache-2.0/
BSD-3-Clause/ISC/Unicode-3.0, только crates.io, запрет wildcard-версий. Лицензия самого Angara
не выбрана и `LICENSE` не создаётся; `[licenses.private]` исключает только
непубликуемый crate Angara, внешние зависимости проверяются полностью.

### CI

Workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) запускается на
`ubuntu-24.04` для PR и для push в `main`, `docs/m00-proposal`, `feat/**` и
`fix/**`:

| Job | Проверки |
| --- | --- |
| `rust` | install pinned toolchain, `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo build --locked`, `cargo test --locked`, M06 resource/load/CPU/TLS evidence, M07 reload/control/logging/metrics + resource/load/CPU evidence, `config_m07`/`cli_m07`/`m07_reload`/`m07_limits`, 20 повторов M04 forced-shutdown, проверка всех примеров через `angara check`, HTTPS-proxy curl smoke с двумя CA и отказом TLS1.0 |
| `release` | release-сборка B из head и A из `911266e...`, `manifest.json`, внешний `SHA256SUMS`, notices, artifact upload |
| `installer` | `tests/m08/install.sh`: манифест, SHA-256, private copy против TOCTOU, path traversal/symlink rejection, foreign unit/user/group conflicts, DESTDIR, повторная установка |
| `systemd` | реальный systemd: identity/capabilities/sandbox/limits, initial 403, reload accepted/rejected, restart-required, SIGHUP storm, завершаемый graceful-обмен, force stop без SIGKILL, crash restart, start limit, occupied port |
| `functional` | HTTP/HTTPS/Basic/ACL, 407/403, обе TLS-цепочки, TLS-in-TLS CONNECT, secret markers, stop under load; streaming 64 MiB/1 GiB; shipped `m08-operations-https-basic.toml` и backup/restore из ADMIN_GUIDE |
| `network` | установленный unit (не root foreground), два veth + netns, source IP у origin, реальный TCP accept counter, DNS/NSS и IPv6, удаление egress-адреса без fallback |
| `load` | 10/20 клиентов по 60 s, TLS+Basic, HTTP/HTTPS/CONNECT, upload/download/HEAD/Range, 1/2 workers (4 при наличии CPU), proxy-counter, warmed baseline, overload |
| `upgrade` | A→B→A с различимыми unit/helper/TLS, разрешённый запрос через origin, backup, `/proc/<pid>/exe`, config hashes, pre/post-switch failure, foreign-listener readiness, recover |
| `boot` | минимальный Ubuntu 24.04 rootfs, `systemctl enable`, systemd-nspawn boot, autostart, readiness 403 |
| `vm-boot` | одноразовая Ubuntu cloud VM: установка/enable на первом boot, второй boot и readiness после автозапуска |
| `soak` | 60-минутный 20-клиентный прогон; проверяет фактическую длительность и обязательные reload; запускается вручную через `workflow_dispatch` на итоговом SHA |
| `deny` | `cargo-deny check` (advisories, licenses, bans, sources) |

Права workflow — только `contents: read`; production secrets не используются.
Внешние actions закреплены commit SHA: `actions/checkout` v7.0.1
(`3d3c42e5aac5ba805825da76410c181273ba90b1`),
`actions/upload-artifact` v4 (`ea165f8d65b6e75b540449e92b4886f43607fa02`),
`actions/download-artifact` v4 (`d3f86a106a0bac45b974a628896c90dbdf5c8093`) и
`EmbarkStudios/cargo-deny-action` v2.1.1
(`3c6349835b2b7b196a839186cb8b78e02f7b5f25`). Фактические результаты для
конкретного head SHA указываются в PR.

## M02: исходящий путь, ACL, DNS и egress

M02 добавляет библиотечный `OutboundService`: доверенный `RequestContext`
(источник и listener) → каноническое назначение → source gate → ACL до DNS →
один egress-профиль → системный DNS → проверка каждого IP → TCP connect только
к разрешённому `SocketAddr`. Принимающего HTTP-сервера и forwarding ещё нет.

### Назначение и ACL

- HTTP принимается только в absolute-form со схемой `http`; CONNECT — только
  `host:port` или `[IPv6]:port`. Отклоняются userinfo, fragment, path/query у
  CONNECT, нестандартные числовые IPv4, scoped IPv6, управляющие символы,
  backslash и превышение лимитов 8192/1024 байт.
- Домены нормализуются IDNA/UTS #46 (`AsciiDenyList::URL`), ASCII lowercase и
  удалением одной завершающей точки; проверяются метки ≤63 и имя ≤253 байт.
  `host_exact` и `host_suffix` сравниваются по границе DNS-метки; IP literal
  не совпадает с доменным правилом.
- `access.source_allow` — CIDR реальных source; пустой/отсутствующий список
  запрещает всех. `access.rules` — first-match allow/deny с AND между полями и
  OR внутри списков: `listeners`, `sources`, `methods`, `ports`, `host_exact`
  или `host_suffix`. Нет совпадения — deny.
- `access.ip_rules` — отдельная first-match политика каждого DNS-кандидата;
  `access.ip_default = "public_only"` (default) или `"deny"`. Специальные адреса
  требуют `allow_special = true` в самом allow-правиле; unspecified, multicast
  и limited broadcast не разрешаются никогда.
- Консервативный снимок IANA special-purpose registries от 2026-11-09
  (включая Globally Reachable записи), private, loopback, link-local/metadata,
  CGNAT, документационные сети, multicast, IPv4 240.0.0.0/4 и IPv6 вне
  2000::/3 закрыт по умолчанию. IPv4-mapped IPv6 нормализуется до IPv4;
  IPv4-mapped CIDR в правилах также пересчитывается в IPv4 с сохранением
  семантики префикса, а CIDR с ненулевыми host bits отвергается.
  Прямой IP проходит ту же IP-политику без DNS.

### DNS, egress и transport

- `SystemResolver` использует системный resolver Ubuntu/Linux через
  `spawn_blocking`; permit `dns.max_in_flight` перемещается внутрь blocking
  closure и удерживается до фактического завершения lookup. Timeout или drop
  ожидающего future не освобождает бюджет начатой blocking-работы; новый запрос
  при исчерпании получает `DnsBusy` без очереди. Ответ дедуплицируется с
  сохранением порядка; пустой — `DnsNoAddresses`, превышение `max_answers` —
  `DnsTooManyAddresses`. Кэша DNS нет.
- Egress: `system` либо `bind_ip` (конкретный исходящий IP, bind к `IP:0`).
  Один профиль выбирается first-match `routing.rules` по
  listener/source/method/port/domain, иначе `routing.default_egress`; маршрут
  не расширяет ACL. Bind/connect failure не меняет профиль и не делает fallback.
- Dial выполняется через `TcpSocket::connect` только с проверенным
  `SocketAddr`; попытки последовательные, не более `max_connect_attempts` и
  `max_connecting`, с общим deadline. `Connected` удерживает outbound permit до
  закрытия и реализует `AsyncRead`/`AsyncWrite`; drop возвращает сокет и
  разрешения.
- `check` не создаёт сетевой runtime и не выполняет DNS или dial. `serve`
  после успешной проверки config строит runtime, связывает все listeners и
  обслуживает HTTP/1.1; отсутствие сети у `check`, `help`, `version` и
  невалидного `serve` отдельно проверяет Linux netguard.

Числовые defaults и диапазоны (все значения проверяются в config):
`dns.timeout_ms` 3000 (100..=30000), `dns.max_in_flight` 4 (1..=64),
`dns.max_answers` 16 (1..=64); `transport.total_timeout_ms` 10000
(100..=120000), `transport.connect_timeout_ms` 3000 (100..=30000 и не больше
total), `transport.max_connect_attempts` 3 (1..=8), `transport.max_connecting`
min(32, limits.max_connections) (1..=256 и не больше max_connections).

Примеры: [`examples/m02-policy.toml`](examples/m02-policy.toml) и
[`examples/m02-egress-local.toml`](examples/m02-egress-local.toml). Второй —
лабораторный: два egress bind_ip 127.0.0.1/127.0.0.2 и routing по listener;
проверка двух физических NIC остаётся M08.

### Зависимости M02

Добавлены `http` (URI/authority/method), `ipnet` (CIDR) и `idna` (UTS #46);
`tokio` получил `net`, `time`, `sync` и `io-util` для реального dial, deadlines
и бюджетов. M03 отдельно добавляет `hyper` 1.12, `hyper-util`, `http-body`,
`http-body-util`, `bytes` и `socket2`; `rustls` и собственный DNS/HTTP parser
не добавлены. Ограничение системного backend: уже выполняющийся `getaddrinfo`
нельзя принудительно прервать; его permit и учёт сохраняются до завершения, а
`SystemResolver::shutdown` ограниченно ждёт и сообщает, успели ли вернуться
разрешения.

## M03: потоковый HTTP/1.1 forward proxy

`angara serve --config <path>` связывает все настроенные HTTP listeners и
обслуживает absolute-form `http://authority/path?query`. Поддержаны
GET/HEAD/POST/PUT/DELETE/OPTIONS/PATCH, fixed Content-Length, chunked и
response-until-EOF тела, потоковая передача с backpressure, клиентский
keep-alive, `Expect: 100-continue`, упорядоченные 1xx (102/103), trailers,
Range/If-Range и SSE. CONNECT описан в разделе M04; TRACE, Upgrade/101,
HTTP/1.0 и HTTP/2 отвергаются без dial; `Host` обязателен, единственен и
должен совпадать с absolute URI.

- Для каждого запроса, включая keep-alive и pool hit, заново применяются
  source/request ACL, выбирается один egress и выполняется свежий DNS lookup;
  pool ищет соединение только среди разрешённых сейчас endpoint. Обмены на
  одном клиентском соединении сериализованы, поэтому interim/final разных
  pipelined-запросов не перепутываются. Барьер следующего обмена учитывает
  только байты hyper-потока в bridge; interim heads не создают кредит на
  неотправленный хвост предыдущего body.
- Origin pool ограничен `http.pool_*`; ключ включает canonical host/port,
  endpoint IP:port, egress и generation. Lease удерживается до завершения
  request body и response body/trailers; ошибка, drop, timeout или shutdown
  вытесняют соединение и возвращают permit. Idle sender вытесняется только
  при фактическом закрытии connection task, а не при временной
  неготовности `is_ready`; перед отправкой wrapper ждёт `ready()`, поэтому
  успешный keep-alive обмен не создаёт лишний origin accept и не даёт 502
  из-за ещё не опрошенного driver.
- `limits.max_client_connections` — общий входящий бюджет всех listeners;
  permit удерживается до закрытия клиентского socket, включая idle keep-alive.
- `limits.max_connections` — общий бюджет исходящих sockets, включая idle;
  `transport.max_connecting` ограничивает одновременные connect attempts.
- Остановка по SIGINT/SIGTERM сначала прекращает accept и новые обмены,
  закрывает idle pool, затем ждёт активные задачи в пределах
  `limits.shutdown_timeout_ms`; после общего deadline оставшиеся client/origin
  задачи отменяются, и shutdown ждёт их фактического завершения. Отдельных
  секундных окон на фазы нет; release barrier poll-ится внутри client task и
  не остаётся detached после abort. Порт освобождается до завершения процесса.
- Буфер bridge ограничен 64 KiB на направление; внутренний read/write buffer
  hyper ограничен `max(64 KiB, limits.max_header_bytes + 16 KiB)`, поэтому
  head до 1 MiB разбирается без неограниченного роста.
- `check` остаётся полностью сетевым no-op.

Ограничения текущего этапа: 1xx передаются узким bounded writer-adapter
(не более 16 heads/64 KiB на обмен); hyper 1.12 нормализует CL+TE до TE до
вызова service, поэтому такой запрос обслуживается по TE и клиентское
соединение принудительно закрывается после ответа. CONNECT реализован в M04;
TLS-listener — M06, локальная auth — M05, reload и control service — M07.

## M04: CONNECT и TCP-туннели

`CONNECT authority:port HTTP/1.1` проходит те же source/request ACL, выбор
egress, свежий DNS и IP-политику M02. Успешный ответ 200 отправляется только
после реального TCP connect и не содержит Content-Length, Transfer-Encoding,
Trailer, Upgrade, Connection или body. После 200 Angara передаёт
непрозрачные байты в обе стороны через существующий bounded bridge и один
writer; TLS/HTTPS, SNI и сертификат сайта остаются между клиентом и
origin. Пул HTTP-соединений для CONNECT не используется.

- `[connect]` необязателен. `allowed_ports` по умолчанию `[443]`; пустой
  список запрещает CONNECT, максимум 64 уникальных порта 1..=65535.
  `half_close_timeout_ms` по умолчанию 5000, диапазон 100..=300000.
  `[connect]` с неизвестным полем или неверным значением отклоняется
  `ConfigError`.
- CONNECT требует authority-form с явным портом. Path/query/fragment,
  userinfo, нулевой/переполненный порт, неверный Host, CL>0, TE, Trailer,
  Upgrade, Expect дают локальный отказ без dial; `Expect` — 417, Via-loop —
  508. Ранние байты после корректного head считаются началом туннеля и
  доставляются origin ровно один раз, включая один write с CONNECT.
- Исходящий бюджет общий с HTTP: `limits.max_connections`,
  `transport.max_connecting` и `limits.max_client_connections` учитывают
  живые туннели. Никакого отдельного неучтённого max_tunnels нет.
- Relay использует фиксированные буферы 16 KiB на направление (не более
  64 KiB) и общий byte-progress idle `limits.idle_timeout_ms`: активность
  только в одну сторону сохраняет туннель, отсутствие положительных
  read/write bytes закрывает его. После первого EOF уже прочитанные bytes
  дописываются, write half получателя закрывается, и один абсолютный
  `connect.half_close_timeout_ms` ограничивает drain второго направления;
  обратный progress этот срок не продлевает.
- Shutdown применяет тот же общий `shutdown_timeout_ms`, отменяет setup,
  upgrade, relay и blocked write, затем дожидается фактического завершения
  задач и освобождения клиентского/исходящего permit. После 200 ошибки и
  сбросы не превращаются в новый HTTP-ответ.

Ошибки до 200: неверный CONNECT → 400/close; Expect → 417/close; source,
port gate, request ACL или IP deny → 403/close; DNS/connect/outbound busy →
503/close; timeout → 504/close; DNS/connect failure → 502/close. Внутренние
адреса, raw target и payload в локальные тела ошибок не попадают.

### Локальный TLS/HTTPS стенд

Fixture `tests/fixtures/m04_tls_site.py` создаёт временную CA и сертификат
с SAN `localhost` только во временном каталоге (private key не коммитится),
запускает локальный TLS site и печатает `PORT=<n>`:

```console
tmp=$(mktemp -d)
python3 tests/fixtures/m04_tls_site.py --dir "$tmp"
# укажите напечатанный PORT в connect.allowed_ports примера
cargo run --locked -- serve --config examples/m04-connect-local.toml
curl --noproxy '' --proxy http://127.0.0.1:3128 \
  --cacert "$tmp/ca.pem" https://localhost:PORT/
```

`curl` без `-k` проверяет CA и hostname; запрос к `https://127.0.0.1:PORT/`
отвергается проверкой имени. Тест `tests/m04_tls.rs` дополнительно проверяет
wrong CA и cleanup. Сертификаты существуют только в `mktemp` и не попадают в
репозиторий или CI artifacts.

### Patch hyper 1.12 для исходного request-target

Hyper 1.12 удаляет fragment и нормализует пустой path при преобразовании в
`http::Uri` до вызова service. По отдельному решению владельца добавлен
минимальный patch: до нормализации сохраняются исходные байты request-target
и публикуются в `hyper::ext::OriginalRequestTarget` через
`Request::extensions`. Parser, CL/TE, chunked decoder, body и keep-alive не
изменены. Исходный target используется Angara для fragment → 400/close и для
различения `OPTIONS http://host` (→ `*`) от `OPTIONS http://host/` (→ `/`);
проверки выполняются на всех keep-alive/pipelined запросах, включая запросы
после CL/chunked body и trailers.

Патч закреплён на hyper 1.12.0 в `vendor/hyper-1.12.0`, подключается через
`[patch.crates-io]`, поэтому чистая сборка не зависит от локального Cargo
cache. Точный diff и границы изменения — в
[`vendor/hyper-1.12.0/ANGARA_PATCH.md`](vendor/hyper-1.12.0/ANGARA_PATCH.md).
При обновлении hyper патч нужно перенести и повторно проверить.

### Ручной локальный стенд

```console
# terminal 1: локальный origin только на loopback
python3 examples/m03-local-origin.py --port 18080

# terminal 2: прокси из примера
cargo run --locked -- serve --config examples/m03-http-local.toml

# terminal 3: запросы через прокси
curl --noproxy '' --proxy http://127.0.0.1:3128 http://127.0.0.1:18080/
curl --noproxy '' --proxy http://127.0.0.1:3128 -I http://127.0.0.1:18080/binary
head -c 65536 /dev/urandom > /tmp/angara-upload.bin
curl --noproxy '' --proxy http://127.0.0.1:3128 --data-binary @/tmp/angara-upload.bin \
  http://127.0.0.1:18080/echo
curl --noproxy '' --proxy http://127.0.0.1:3128 -H 'Transfer-Encoding: chunked' \
  --data-binary @/tmp/angara-upload.bin http://127.0.0.1:18080/echo
curl --noproxy '' --proxy http://127.0.0.1:3128 -H 'Range: bytes=0-15' \
  http://127.0.0.1:18080/range | wc -c
curl --noproxy '' --proxy http://127.0.0.1:3128 -N http://127.0.0.1:18080/sse
```

Ожидается `angara m03 local origin`, `received N bytes ...`, 16 байт Range,
последовательные `data: event ...` для SSE и штатная остановка прокси по
Ctrl-C с кодом 0. Пример разрешает только loopback-назначения и не требует
root, изменения маршрутов или firewall. В PowerShell пустой аргумент
`--noproxy ''` может быть потерян; используйте `curl.exe --proxy ...` с
`NO_PROXY=nohost.invalid` в окружении.

## M05: локальные пользователи и Basic

M05 добавляет строгий users TOML (`version = 1`, до 1 MiB/1024 записей),
Argon2id PHC с фиксированным профилем `m=19456,t=2,p=1`, соли 16 и выхода
32 байта, listener-local Basic и selectors `users` в ACL/routing. Проверка
пароля выполняется в `spawn_blocking` под общим `max_verifying`; локальный
407 закрывает соединение без DNS/dial/100 Continue, перегрузка и timeout
дают 503. Snapshot пользователей читается при `check`/`serve` и применяется
после restart; auth cache, reload и online CRUD не входят в M05.

На Linux users-файл должен быть regular file с правами без group write и
любых world-битов (например `0600`/`0640`) и принадлежать effective UID
сервиса либо root. Проверка выполняется по уже открытому handle; proxy не
меняет права автоматически. Доверенный административный каталог и сам
users-файл не должны быть доступны на запись другим пользователям.

Фиксированный профиль Argon2id требует около 19 MiB рабочей памяти на одну
проверку. При default `max_verifying = 2` одновременно занято около 38 MiB
плюс overhead; максимум `16` — до 304 MiB плюс overhead. Это настройка
памяти, а не обещание throughput. Уже начатая blocking-проверка не
отменяется при timeout/disconnect; она удерживает permit до фактического
завершения и не публикует поздний результат. Shutdown ограничен общим
deadline и не ждёт такие проверки отдельным окном.

### Безопасная подготовка users-файла

PHC считается чувствительным: не пишите его в фиксированное имя в `/tmp` и
не полагайтесь на `umask` для уже существующего файла. Используйте уникальный
приватный каталог, файл `0600` с момента создания и атомарную замену
финального файла рядом с ним.

```console
set -euo pipefail
umask 077
tmpdir=$(mktemp -d)
staging=""
cleanup() {
  rm -rf "$tmpdir"
  [ -z "$staging" ] || rm -f "$staging"
}
trap cleanup EXIT HUP INT TERM

angara users hash >"$tmpdir/alice.phc"   # интерактивный ввод и подтверждение
angara users hash >"$tmpdir/bob.phc"

staging=$(mktemp examples/.m05-users.local.XXXXXX)
{
  printf 'version = 1\n\n[[users]]\nusername = "alice"\npassword_hash = "'
  tr -d '\n' <"$tmpdir/alice.phc"
  printf '"\ndisabled = false\n\n[[users]]\nusername = "bob"\npassword_hash = "'
  tr -d '\n' <"$tmpdir/bob.phc"
  printf '"\ndisabled = false\n'
} >"$staging"
chmod 0600 "$staging"
mv -f "$staging" examples/m05-users.local.toml
```

`mktemp -d` создаёт приватный каталог; файлы PHC создаются с `0600` под
`umask 077`. Финальный файл готовится в том же каталоге `examples/`, получает
`0600` до публикации и заменяет старый путь одной атомарной операцией `mv`;
запись через существующий файл или симlink не выполняется. `trap` удаляет
временные файлы при ошибке и сигнале.

### Ручной сценарий: HTTP, CONNECT HTTPS, 407/403, disable + restart

Ниже используются только синтетические пользователи `alice` и `bob`.
Пароли вводятся интерактивно в `users hash`; в команды и history они не
попадают. Все временные файлы удаляются `trap`.

```console
# 1. Users-файл создан командами из предыдущего раздела; блоки выполняются
#    последовательно в одном shell.
set -euo pipefail
# 2. Локальный HTTP origin на 8080.
HTTP_PID=""
TLS_PID=""
PROXY_PID=""
tlsdir=""
cleanup_stand() {
  [ -z "$PROXY_PID" ] || kill -TERM "$PROXY_PID" 2>/dev/null || true
  [ -z "$HTTP_PID" ] || kill "$HTTP_PID" 2>/dev/null || true
  [ -z "$TLS_PID" ] || kill "$TLS_PID" 2>/dev/null || true
  [ -z "$tlsdir" ] || rm -rf "$tlsdir"
  rm -rf "$tmpdir"
}
trap cleanup_stand EXIT HUP INT TERM
python3 examples/m03-local-origin.py --port 8080 &
HTTP_PID=$!

# 3. Реальный локальный HTTPS site с временной CA.
tlsdir=$(mktemp -d)
python3 tests/fixtures/m04_tls_site.py --dir "$tlsdir" \
  >"$tlsdir/port.txt" 2>"$tlsdir/site.log" &
TLS_PID=$!
for _ in $(seq 1 100); do
  test -s "$tlsdir/port.txt" && break
  sleep 0.1
done
TLS_PORT=$(sed -n 's/^PORT=//p' "$tlsdir/port.txt")
test -n "$TLS_PORT"

# 4. Временная копия config: users-файл и TLS-порт.
install -m 0600 examples/m05-users.local.toml "$tmpdir/users.toml"
sed -e 's|m05-users.local.toml|users.toml|' \
    -e "s|ports = \[8080, 8443\]|ports = [8080, $TLS_PORT]|" \
    -e "s|allowed_ports = \[8443\]|allowed_ports = [$TLS_PORT]|" \
    examples/m05-auth-local.toml >"$tmpdir/proxy.toml"

angara serve --config "$tmpdir/proxy.toml" &
PROXY_PID=$!
for _ in $(seq 1 100); do
  curl -sS --noproxy '' --proxy http://127.0.0.1:3128 \
    -o /dev/null http://127.0.0.1:8080/ 2>/dev/null && break
  sleep 0.1
done

# 5. Пароли вводятся интерактивно для каждого curl; в argv/history/env
#    они не попадают. Интерактивный ввод сохраняет допустимые quote,
#    backslash, colon и spaces без экранирования в config.

# 6. HTTP: alice 200, без credentials 407, bob 403 по ACL.
test "$(curl --noproxy '' --proxy http://127.0.0.1:3128 \
  --proxy-user alice -o "$tmpdir/http.txt" \
  -w '%{http_code}' http://127.0.0.1:8080/)" = "200"
test "$(curl --noproxy '' --proxy http://127.0.0.1:3128 \
  -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/)" = "407"
test "$(curl --noproxy '' --proxy http://127.0.0.1:3128 \
  --proxy-user bob -o /dev/null -w '%{http_code}' \
  http://127.0.0.1:8080/)" = "403"

# 7. CONNECT HTTPS с проверкой CA и hostname; 1 MiB download.
curl --noproxy '' --proxy http://127.0.0.1:3128 --proxy-user alice \
  --cacert "$tlsdir/ca.pem" \
  "https://localhost:$TLS_PORT/download" -o "$tmpdir/download.bin"
test "$(wc -c <"$tmpdir/download.bin")" -eq 1048576

# 8. CONNECT HTTPS upload 1 MiB и сверка SHA-256 с ответом site.
head -c 1048576 /dev/urandom >"$tmpdir/upload.bin"
curl --noproxy '' --proxy http://127.0.0.1:3128 --proxy-user alice \
  --cacert "$tlsdir/ca.pem" \
  --data-binary @"$tmpdir/upload.bin" "https://localhost:$TLS_PORT/upload" \
  -o "$tmpdir/upload.txt"
test "$(cat "$tmpdir/upload.txt")" = \
  "upload:1048576:$(sha256sum "$tmpdir/upload.bin" | cut -d' ' -f1)"

# 9. Проверка name verification: ожидается exit 60, не 200.
set +e
curl --noproxy '' --proxy http://127.0.0.1:3128 --proxy-user alice \
  --cacert "$tlsdir/ca.pem" \
  "https://127.0.0.1:$TLS_PORT/" -o /dev/null 2>"$tmpdir/name.err"
NAME_CODE=$?
set -e
test "$NAME_CODE" -eq 60

# 10. Disable alice безопасной заменой и restart.
sed '0,/disabled = false/s//disabled = true/' "$tmpdir/users.toml" \
  >"$tmpdir/users.new"
chmod 0600 "$tmpdir/users.new"
mv -f "$tmpdir/users.new" "$tmpdir/users.toml"
kill -TERM "$PROXY_PID"
wait "$PROXY_PID"
angara serve --config "$tmpdir/proxy.toml" &
PROXY_PID=$!
for _ in $(seq 1 100); do
  curl --noproxy '' --proxy http://127.0.0.1:3128 \
    -o /dev/null http://127.0.0.1:8080/ 2>/dev/null && break
  sleep 0.1
done
test "$(curl --noproxy '' --proxy http://127.0.0.1:3128 \
  --proxy-user alice -o /dev/null -w '%{http_code}' \
  http://127.0.0.1:8080/)" = "407"

kill -TERM "$PROXY_PID"
wait "$PROXY_PID"
PROXY_PID=""
kill "$HTTP_PID" "$TLS_PID" 2>/dev/null || true
HTTP_PID=""
TLS_PID=""
trap - EXIT HUP INT TERM
rm -rf "$tmpdir" "$tlsdir"
```

Пароли и PHC не выводятся в терминал и не передаются через argv.
`curl --proxy-user alice` запрашивает пароль интерактивно; допустимые M05
символы `"`, `\`, `:`, пробелы и Unicode вводятся как есть и не проходят
через quoted curl config или shell history. Для неинтерактивного стенда
используйте безопасный механизм передачи секрета, который не помещает его
в argv/env/log. Этот сценарий проверяет HTTP, CONNECT HTTPS через настоящий
локальный TLS site, 407 без credentials, 403 для аутентифицированного
пользователя без ACL, а также disable + restart. TLS listener самого proxy
реализован в M06 и описан ниже.

`examples/m05-auth-local.toml` не содержит рабочих credentials. Подробный
контракт и матрица приёмки — [M05-r1, Issue #14](https://github.com/AlexeiSmol/Angara/issues/14).

Проверка `check` читает и структурно валидирует users-файл, но не запускает
runtime, сеть и Argon2 hashing. Plain Basic разрешён только на loopback bind
(`127.0.0.0/8`, `::1`) либо при явном `allow_insecure_basic = true`; это не
делает transport TLS. HTTPS listener к прокси реализован в M06 и допускает
Basic на non-loopback/wildcard bind без `allow_insecure_basic`; на HTTP это
исключение по-прежнему требуется. Unix-проверка прав и
owner реализована для Linux; другие ОС не объявляются поддержанными до
отдельных испытаний.

## M06: HTTPS listeners и TLS до прокси

M06 добавляет `transport = "https"`: клиент подключается к Angara как к HTTPS
proxy, проверяет сертификат самого proxy и передаёт HTTP/1.1 proxy
protocol/Basic внутри TLS. Обычный forwarding и `CONNECT` работают поверх
этого TLS без изменений; TLS сайта внутри CONNECT остаётся сквозным и
проверяется клиентом отдельно. Сертификат, SNI или факт HTTPS внутри CONNECT
не создают identity и не ослабляют auth/ACL.

```toml
[tls]
max_handshaking = 32
handshake_timeout_ms = 5000

[[listeners]]
id = "proxy-https"
bind = "127.0.0.1:3129"
transport = "https"
auth = "basic"

[listeners.tls]
cert_chain_file = "tls/proxy-chain.pem"
private_key_file = "tls/proxy-key.pem"
```

Полный стенд — [`examples/m06-https-local.toml`](examples/m06-https-local.toml):
HTTP listener 3128 без auth и HTTPS listener 3129 с Basic. `check` и `serve`
читают cert/key/users до bind; ошибка любого TLS listener или пары key/chain
отвергает весь startup, ранее подготовленные listeners не начинают accept.

- Политика rustls: explicit ring provider, TLS1.2 и TLS1.3, ALPN только
  `http/1.1` (отсутствие ALPN у клиента допустимо, `h2`-only отвергается).
  Сессии, tickets, early data/0-RTT, cert compression, secret extraction и
  key logging отключены; TLS1.0/1.1 не предлагаются.
- `max_handshaking` — общий semaphore всех HTTPS listeners. Client permit
  берётся с TCP accept и удерживается до конца TLS/HTTP/CONNECT; handshake
  permit освобождается после успешного handshake. Source gate проверяется до
  TLS bytes. Перегрузка handshake закрывает TCP без plaintext 503; абсолютный
  `handshake_timeout_ms` отсчитывается от accept и не продлевается chunks.
- Один plaintext writer обслуживает interim/final/CONNECT output. Реальный
  TLS flush учитывается output barrier; bounded transport observer считает
  положительные ciphertext-записи во время pending application output и
  передаёт их в HTTP idle/tunnel progress, не считая handshake/control-only
  трафик. 103/102, final body, CONNECT 200 и early tunnel bytes сохраняют
  порядок. Буфер приложения — 64 KiB, bridge — 64 KiB на направление.
- TLS1.3 корректный `close_notify` — EOF одного направления: принятые bytes
  дописываются, write side закрывается, reverse drain ограничен прежним
  first-EOF deadline M04. TLS1.2 использует полный closure exchange по
  RFC5246; независимый reverse half-close после `close_notify` не
  гарантируется. Abrupt TCP EOF без `close_notify` не считается успешным
  TLS-закрытием и не повторяет response.
- Сертификат/ключ читаются один раз в immutable snapshot. Замена файлов на
  диске не меняет работающий сервер; новый startup читает новую пару и
  отвергает несовпадающую до bind. Shutdown использует общий absolute
  deadline для handshake, HTTP, CONNECT, TLS flush/close и runtime.

### Локальный HTTPS-стенд

```console
set -euo pipefail
umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
python3 tests/fixtures/m06_pki.py --dir "$tmp/pki"
mkdir -p "$tmp/tls"
cp "$tmp/pki/proxy_chain.pem" "$tmp/tls/proxy-chain.pem"
cp "$tmp/pki/proxy_key.pem" "$tmp/tls/proxy-key.pem"
chmod 0600 "$tmp/tls/proxy-key.pem"

angara users hash >"$tmp/alice.phc"   # интерактивно, без echo
{
  printf 'version = 1\n\n[[users]]\nusername = "alice"\n'
  printf 'password_hash = "%s"\ndisabled = false\n' "$(cat "$tmp/alice.phc")"
} >"$tmp/m06-users.local.toml"
chmod 0600 "$tmp/m06-users.local.toml"
cp examples/m06-https-local.toml "$tmp/m06.toml"
```

Запустите локальный HTTP origin и TLS site, подставьте их порты в копию
config (`ports` правила и `connect.allowed_ports`), затем `angara serve
--config "$tmp/m06.toml"`. Пример использует две независимые CA: proxy CA и
site CA. Ручные проверки:

```console
# HTTP 200 через HTTPS listener; пароль вводится интерактивно.
curl --noproxy '' --proxy https://localhost:3129 \
  --proxy-cacert "$tmp/pki/proxy_ca.pem" --proxy-user alice \
  http://127.0.0.1:18080/

# Без credentials — 407; аутентифицированный пользователь без ACL — 403.
curl --noproxy '' --proxy https://localhost:3129 \
  --proxy-cacert "$tmp/pki/proxy_ca.pem" \
  -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/

# HTTPS сайта внутри CONNECT: отдельный --cacert для site CA.
curl --noproxy '' --proxy https://localhost:3129 \
  --proxy-cacert "$tmp/pki/proxy_ca.pem" --proxy-user alice \
  --cacert "$tmp/site/ca.pem" \
  "https://localhost:$TLS_PORT/download" -o "$tmp/download.bin"
```

Ожидаются 200, 407, 403 и 1 MiB download/upload через настоящий layered
TLS-in-TLS. Неверная proxy CA или имя дают curl exit 60 до auth/origin;
неверная site CA/имя — exit 60 после CONNECT. Не используйте `-k`,
`--proxy-insecure` или глобальную установку тестовой CA. `SSLKEYLOGFILE`
игнорируется: key log не создаётся. Автоматический эквивалент — CI шаг
«M06 HTTPS proxy curl smoke with two CAs», тесты `tests/m06_tls.rs`,
`tests/m06_extra.rs`, `tests/config_m06.rs`, `tests/cli_m06.rs`,
`tests/m06_progress.rs`, `tests/m06_limits.rs`.

Подробный контракт и матрица приёмки — [M06-r1, Issue #17](https://github.com/AlexeiSmol/Angara/issues/17).

## M07: эксплуатация, reload, control service и наблюдаемость

M07 добавляет атомарный runtime reload без restart. Один immutable
`RuntimeSnapshot` публикуется через `ArcSwap`; generation начинается с 1 и
увеличивается ровно на 1 после полного candidate preparation. Новый HTTP или
CONNECT exchange захватывает snapshot после exchange gate, поэтому старые
body/tunnel завершают своё поколение, а следующий keep-alive/pipelined request
видит новые ACL/users/routing. Одновременно живёт не более 16 опубликованных
roots; при исчерпании возвращается `GenerationBusy`. Registry хранит только
`Weak`-ссылки и удаляет освобождённые поколения; сам registry, metrics и
status не удерживают историю roots.

Подготовка и публикация разделены. Один admission guard допускает ровно один
blocking candidate (queue0) и удерживается до publish/уничтожения готового
результата, даже если native job уже завершился; caller drop/timeout не
освобождает слот работающего job. Файл читается один раз в ограниченный
buffer, TOML/PHC проверяются вне async workers. Публикация — короткая секция
под отдельным lifecycle-mutex: expected generation, deadline, `Running` и
generation cap проверяются вместе с CAS-заменой root. Поэтому `Draining`
не может быть обойдён поздним candidate, а `SIGTERM` отменяет ещё не
опубликованный reload.

Hot-reload разрешён только для `access.*`, `routing.*`, `auth.users_file` и
содержимого users-файла, глобальных `limits.max_connections`/
`max_client_connections`, `limits.shutdown_timeout_ms`, request-таймаутов
`transport.total_timeout_ms`/`connect_timeout_ms`/`max_connect_attempts`,
`http.response_header_timeout_ms`, `connect.allowed_ports`/
`half_close_timeout_ms`. Workers, listeners/TLS, DNS, egress definitions,
parser/idle/pool/auth-admission и `[operations]`/`[observability]` требуют
restart. Mixed hot+restart change отвергается целиком. Reload не открывает
cert/key: при прежних TLS paths используются prepared Arcs; изменённый путь —
`RestartRequired`. Startup/check продолжают полностью проверять файлы.

- `ControlState` — внутренний Rust API: `status()`, `metrics()`,
  `validate_on_disk(generation)`, `reload(expected_generation)`,
  `shutdown(reason)`. Сетевого admin listener, Unix RPC, `/metrics` и CLI
  reload без IPC нет. Один preparation job, queue0; чтение/TOML/PHC validation
  выполняются в `spawn_blocking` под permit, публикация — короткая CAS-секция
  с expected generation, deadline и lifecycle. Timeout/drop/shutdown не
  публикует поздний candidate; blocking slot живёт до фактического конца.
- SIGHUP запускает тот же reload. Во время выполнения максимум один
  pending-флаг взводится повторными HUP; после завершения выполняется ровно
  один дополнительный reload, без spawn на каждый signal и без очереди
  waiter-ов. SIGTERM/SIGINT прерывают незавершённый reload-task до publish.
  Shutdown выполняет один service-owned coordinator: первый absolute deadline
  и результат сохраняются, abort/timeout вызывающего future не отменяет
  force/reap, повторные вызовы ждут тот же результат. `HttpServer::shutdown`,
  `ControlState::shutdown` и CLI берут текущий hot `shutdown_timeout_ms` при
  первом запуске; уже начатый deadline не меняется. Lifecycle монотонен:
  `Stopped` не возвращается в `Draining`. Draining запрещает новый
  accept/exchange/reload publish, закрывает idle origins и даёт активной
  работе оставшееся время; native DNS/Argon2/file jobs не обещают
  принудительный abort, но их permits остаются ограниченными.
- Shared OutboundService/resolver/pool/auth permits/TaskTracker не
  пересоздаются. Client/outbound caps меняются глобально без убийства старых
  holders. Pool key содержит generation/listener/user/egress/endpoint; после
  publish idle origins старого поколения retire, старый lease при возврате
  закрывается.
- JSON Lines пишутся только в stderr `serve` из typed allow-list. События:
  `service_started` (с bounded списком listener bind), `reload_applied`/
  `reload_rejected`, `shutdown_started`/`service_stopped`, `request_finished`,
  `tunnel_finished`, `metrics_summary`. `request_finished` появляется после
  завершения или отмены streaming body, а не сразу после заголовков; HEAD и
  пустое body дают 0. Exactly-once guard создаётся при admission exchange и
  покрывает auth/DNS/ожидание headers/streaming/force: abort до тела пишет
  cancelled, а не оставляет `http_started` без outcome. CONNECT terminal
  создаётся сразу после exchange gate: отмена setup во время auth/DNS/dial
  пишет request cancellation с generation допущенного snapshot; отказ
  получает `request_finished` со status/reason rejected и не изображает
  открытый tunnel. `tunnel_finished` для CONNECT пишется только после
  фактического writer drain; потеря хвоста даёт failed/timeout, не success.
  Поля `request_body_bytes`/`response_body_bytes` считают только DATA-кадры
  соответствующих body, `tunnel_bytes` — положительные plaintext-чтения
  обоих направлений CONNECT (ранний payload один раз). Один terminal record
  на exchange/tunnel, record ≤4096 bytes, bounded queue drop-newest с
  counters. Username, PHC, credentials, URL/path/query, headers,
  source/destination IP, TLS material и payload не журналируются.
- Logging ownership: один CLI-owned stderr worker на процесс, очередь
  `log_queue_capacity`; producers используют `try_send` и не блокируют
  network workers. Library `HttpServer` по умолчанию имеет no-op sink и не
  создаёт thread. Worker намеренно detached: зависший stderr pipe не
  продлевает shutdown deadline; потеря записей видна в `log_dropped`/
  `log_sink_errors`. Файловая ротация — задача supervisor M08.
- `metrics()` и periodic summary дают global counters/gauges/fixed histograms
  (HTTP exchange, TLS handshake, auth), без user/domain/IP/generation labels;
  series ≤2048. Histogram bounds в миллисекундах:
  `1, 5, 10, 25, 50, 100, 500, 1000` плюс overflow bucket; units — ms.
  Reload не сбрасывает counters. `metrics_enabled=false` отключает
  histograms/summary, но structural counters, бюджеты и control status
  работают. `dns_active` привязан к фактическому blocking lookup: timeout/drop
  ожидающего future не уменьшает gauge, пока native job не завершится.
  `status()` дополнительно отдаёт configured listeners/egress, in-use gauges
  и последний safe reload outcome без Config/Users Arcs.

Полный стенд — [`examples/m07-operations-local.toml`](examples/m07-operations-local.toml)
(HTTP+HTTPS/Basic). Безопасный локальный сценарий:

```sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
umask 077
python3 tests/fixtures/m06_pki.py --dir "$TMP/pki"
mkdir "$TMP/tls"
cp "$TMP/pki/proxy_chain.pem" "$TMP/tls/proxy-chain.pem"
cp "$TMP/pki/proxy_key.pem" "$TMP/tls/proxy-key.pem"
# Пароль вводится no-echo в stdin; не передавайте его через argv/env.
PHC=$(printf '%s\n' 'synthetic-local-password' | \
  ./target/debug/angara users hash --password-stdin)
printf 'version = 1\n\n[[users]]\nusername = "alice"\npassword_hash = "%s"\ndisabled = false\n\n[[users]]\nusername = "bob"\npassword_hash = "%s"\ndisabled = false\n' \
  "$PHC" "$PHC" >"$TMP/users.local.toml"
chmod 0600 "$TMP/users.local.toml"
cp examples/m07-operations-local.toml "$TMP/proxy.toml"
./target/debug/angara check --config "$TMP/proxy.toml"
./target/debug/angara serve --config "$TMP/proxy.toml" 2>"$TMP/proxy.jsonl" &
PID=$!
# После проверки запросов: измените users/ACL и отправьте HUP.
kill -HUP "$PID"
# SIGTERM укладывается в общий deadline даже при нечитаемом stderr pipe.
kill -TERM "$PID"
wait "$PID"
jq -c 'select(.event == "request_finished")' "$TMP/proxy.jsonl"
```

Новые keep-alive запросы после HUP видят новое поколение; старые CONNECT
остаются на прежнем и не отзываются немедленно. JSON-строки можно смотреть
через `journalctl`/перенаправленный stderr; секреты в них не попадают.

M07 test targets: `m07_reload` (snapshot/CAS/static/auth/pool/limits/logging/
metrics/CONNECT/secret), `config_m07` (strict schema/files), `cli_m07` (real
SIGHUP/SIGTERM, stalled stderr, storm), `m07_limits` (RES/LOAD/CPU evidence,
Linux). Полный Linux baseline дополняется явными `http_limits`/`m04_limits`/
`m06_progress` проверками и 20 повторами M04 forced-shutdown; повторы CI не
прибавляются к числу основных тестов.

## M08: кандидат v0.1 для Ubuntu Server 24.04

M08 поставляет воспроизводимый архив `angara-0.1.0-linux-x86_64-<sha>.tar.gz`
с внешним `SHA256SUMS`, манифестом, unit, установщиком, `angaractl`,
безопасными примерами, руководством администратора и notices зависимостей.
Установка не требует Rust, Docker или исходников на целевой системе.

```sh
sha256sum -c SHA256SUMS
umask 077
tmp=$(mktemp -d)
tar -xzf angara-0.1.0-linux-x86_64-<sha>.tar.gz -C "$tmp" \
  --no-same-owner --no-same-permissions
sudo "$tmp"/angara-0.1.0-linux-x86_64-<sha>/install.sh \
  --archive "$PWD/angara-0.1.0-linux-x86_64-<sha>.tar.gz" \
  --sha256 <sha256> \
  --expected-source-sha <full-source-sha>
sudo systemctl enable --now angara.service
```

Раскладка: версия в `/opt/angara/releases/<candidate-id>`, активная ссылка
`/opt/angara/current`, CLI `/usr/local/bin/angara`, unit
`/etc/systemd/system/angara.service`, настройки `/etc/angara` с правами
`root:angara 0750`, основной TOML `root:angara 0640`. Начальный конфиг
слушает только loopback `127.0.0.1:3128` и запрещает все запросы: контрольный
запрос получает 403, origin не открывается. TLS, Basic, пользователи и ACL
включаются по [`docs/ADMIN_GUIDE.md`](docs/ADMIN_GUIDE.md).

`install.sh` читает архив один раз в приватную копию, проверяет SHA-256 этой
копии и использует её для tar/манифеста; повторная установка сверяется с
манифестом входящего архива, а не с оставшимся деревом. Он отклоняет path
traversal/ссылки, конфликты с чужими unit/helper/current/bin, проверяет, что
группа `angara` закрыта и у сервисного пользователя нет лишних групп, и умеет
непривилегированный `--destdir`. `angaractl upgrade --archive B --sha256 B
--confirm` проверяет B бинарником B от пользователя `angara`, делает
root-only резервную копию `/etc/angara`, останавливает A, атомарно
переключает `current`, устанавливает unit/helper B, запускает B и проверяет
запрос, привязанный к MainPID/listener выбранного release; `angaractl
rollback --confirm` возвращает A. Настройки, users и TLS не перезаписываются.
Полный пример TLS/Basic/ACL — `examples/m08-operations-https-basic.toml`.

Сборка и происхождение описаны в [`docs/RELEASE.md`](docs/RELEASE.md),
checklist — в [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md), карта
F01–F11/N01–N09 и 18 M08-ID — в
[`docs/M08_EVIDENCE.md`](docs/M08_EVIDENCE.md). CI собирает A и B, проверяет
архив без Rust на отдельном Ubuntu 24.04 runner, реальный systemd,
boot/enable в systemd-nspawn, одноразовую cloud VM, A→B→A с различимыми
метаданными, два veth/netns с DNS/IPv6, 1/2 workers (4 при наличии CPU),
10/20 клиентов с proxy-counter, 64 MiB и 1 GiB streaming, перегрузку и
60-минутный soak. Фактические результаты и SHA-256 испытанного архива
прикладываются к PR/CI run; они не заполняются заранее.

Нагрузочный профиль стенда использует `auth.max_verifying = 16` вместо
production default `2`, чтобы контролируемый поток 10/20 клиентов с Basic не
создавал искусственные 503 из-за очереди Argon2. Это изменение относится
только к `tests/m08/load_stand.sh`/`soak_stand.sh`; default и M05-контракт не
меняются. На 2-vCPU runner сравниваются 1 и 2 workers; конфигурация 4 workers
недоступна и отмечается ограничением, а не pass.

## M09: parent proxy (v0.2)

M09 добавляет именованные `[[parents]]` и выбор next hop в `routing`:

```toml
[runtime]
worker_threads = "auto"
instance_id = "edge-a"           # optional; unique in an Angara chain

[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"
transport = "http"               # "http" | "https"
credentials_file = "parent-credentials.toml"  # optional
ca_file = "parent-ca.pem"        # optional, https only

[routing]
default_egress = "system"
default_parent = "squid"

[[routing.rules]]
id = "direct-lab"
egress_id = "system"
next_hop = "direct"
ports = [18080]
```

Angara проверяет target ACL/DNS/IP до подключения к parent. Доменный HTTP и клиентский CONNECT уходят родителю как `CONNECT <проверенный-ip>:<порт>`; HTTP к IP-литералу — в absolute-form. Ошибка parent не даёт fallback в direct, parent 407/не-2xx CONNECT преобразуется в 502, timeout — в 504. Parent definitions/credentials/CA требуют restart; `routing` перезагружается атомарно. Parent-соединения в M09 не переиспользуются.

`runtime.instance_id` задаёт стабильный суффикс `Via`: запрос содержит `1.1 angara-<id>`, а отклоняется только возврат *собственного* идентификатора. По умолчанию используется `<hostname>-<port>`; для цепочки Angara задайте разные `instance_id` явно. Прокси, которые вырезают `Via`, ограничивают эту защиту. Полный пример — [examples/m09-parent-local.toml](examples/m09-parent-local.toml); эксплуатация и Squid — [ADMIN_GUIDE](docs/ADMIN_GUIDE.md#9-parent-proxy-m09). Локальные проверки: `cargo test --locked --test config_m09` и `--test m09_parent`.

## Текущее состояние

M00–M08 приняты и слиты. M09 (parent proxy) реализован и передан на ревью; слияние и выпуск v0.2 остаются решениями владельца. Кандидат v0.1 принят на `515365a` с архивом B
SHA-256 `e6fba6415f5d143d79d9c202a88a7c64abd9fe698ef186c672492bea1ed2dc8c`; полный
прогон CI вместе с часовым soak — [run 44315861684](https://github.com/AlexiVladSmol/Angara/actions/runs/44315861684).
M08 слит через PR #25 (`b1e82ef`). После слияния доработаны только тесты и CI
(#28, #30, #32, #34, #36, #38): устойчивость boot/VM-проверок, таймауты и очистка
`debootstrap`, нестабильные тесты; принятый архив не менялся. Linux CI сохраняет
полную регрессию M01–M08 и 20 повторов M04 forced-shutdown. Лицензия, первое
рабочее развёртывание и публичный выпуск v0.1 остаются решениями владельца.

Лицензия не выбрана. Совместимость с конфигурационным синтаксисом Squid не заявляется. Сроки и показатели производительности будут уточнены по параметрам первого сервера и результатам измерений.
