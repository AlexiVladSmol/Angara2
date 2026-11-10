# Angara

Прямой прокси-сервер для Linux с возможностями, которые будут развиваться поэтапно: HTTP, HTTPS через CONNECT, авторизация, правила доступа, управление ресурсами и кэширование HTTP.

**Статус: M02 принят и слит; M03 (HTTP/1.1 forward proxy) реализован в ветке `feat/9-m03-http-proxy` и передан на ревью.** Ревизия документов: 0.4. Первый стенд — Ubuntu Server 24.04 x86_64, 10–20 устройств. `angara serve` открывает настроенные HTTP listeners и выполняет forward-proxy для absolute-form HTTP/1.1; CONNECT-туннель, TLS, auth, cache и admin API появятся в следующих этапах. Согласование требований и слияние PR — отдельные действия владельца.

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
- Кэширование HTTP и parent proxy — обязательные последующие этапы M09/M10.
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
| `angara --help` | Печатает справку, код 0 |

Коды: `0` — успех, `1` — ошибка конфигурации, `2` — ошибка аргументов,
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

[limits]
max_connections = 256
max_client_connections = 128
max_header_bytes = 32768
header_read_timeout_ms = 10000
idle_timeout_ms = 60000
shutdown_timeout_ms = 10000

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

- Неизвестные ключи и будущие активные разделы (TLS, auth, ACL, egress,
  routing, cache, admin и т. п.) отклоняются, а не игнорируются.
- `schema_version` поддерживается только `1`.
- `listeners`: от 1 до 64 определений; `id` уникален, состоит из 1–64 ASCII
  букв, цифр, `-`, `_`, `.`; `bind` — только числовой `IP:port` с портом
  1–65535; `transport` в M01 — только `http`.
- Дубли `id`/адресов и пересечение wildcard-адреса с конкретным адресом того
  же семейства и порта отвергаются. IPv6 listener проектируется как IPv6-only:
  будущий bind выставит `IPV6_V6ONLY`, поэтому `0.0.0.0` и `[::]` на одном
  порту не конфликтуют. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) и scoped IPv6
  отклоняются.
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
Tokio `macros`/`signal`. Hyper 1.12.0 закреплён с минимальным локальным
patch для `OriginalRequestTarget`; см. раздел M03 и
[`vendor/hyper-1.12.0/ANGARA_PATCH.md`](vendor/hyper-1.12.0/ANGARA_PATCH.md).
`rustls`, CLI-фреймворк и dev-зависимости пока не подключены. Политика
зависимостей проверяется
[`deny.toml`](deny.toml): RustSec advisories, allow-list MIT/Apache-2.0/
Unicode-3.0, только crates.io, запрет wildcard-версий. Лицензия самого Angara
не выбрана и `LICENSE` не создаётся; `[licenses.private]` исключает только
непубликуемый crate Angara, внешние зависимости проверяются полностью.

### CI

Workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) запускается на
`ubuntu-24.04` для PR и для push в `main`, `docs/m00-proposal`, `feat/**` и
`fix/**`:

| Job | Проверки |
| --- | --- |
| `rust` | install pinned toolchain, `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo build --locked`, `cargo test --locked`, проверка четырёх примеров через `angara check` |
| `deny` | `cargo-deny check` (advisories, licenses, bans, sources) |

Права workflow — только `contents: read`; production secrets не используются.
Внешние actions закреплены commit SHA: `actions/checkout` v7.0.1
(`3d3c42e5aac5ba805825da76410c181273ba90b1`) и
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
Range/If-Range и SSE. CONNECT, TRACE, Upgrade/101, HTTP/1.0 и HTTP/2
отвергаются без dial; `Host` обязателен, единственен и должен совпадать с
absolute URI.

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
соединение принудительно закрывается после ответа. CONNECT и TLS — M04/M06,
локальная auth — M05, reload и control service — M07.

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

## Текущее состояние

M00, M01 и M02 приняты и слиты. M03 реализован в ветке
`feat/9-m03-http-proxy`; Linux CI выполняет baseline M02 (127 тестов) и новые
M03-проверки, включая CLI/raw/curl-совместимые и resource checks. Следующий
этап — CONNECT-туннель M04; слияние M03 выполняет владелец после ревью.

Лицензия не выбрана. Совместимость с конфигурационным синтаксисом Squid не заявляется. Сроки и показатели производительности будут уточнены по параметрам первого сервера и результатам измерений.
