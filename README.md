# Angara

Прямой прокси-сервер для Linux с возможностями, которые будут развиваться поэтапно: HTTP, HTTPS через CONNECT, авторизация, правила доступа, управление ресурсами и кэширование HTTP.

**Статус: M00–M04 приняты и слиты; M05 (локальные пользователи, Basic и ACL по identity) реализуется в ветке `feat/14-m05-auth`.** Ревизия документов: 0.6. Первый стенд — Ubuntu Server 24.04 x86_64, 10–20 устройств. `angara serve` открывает настроенные HTTP listeners, выполняет forward-proxy для absolute-form HTTP/1.1, принимает CONNECT и проверяет Basic credentials на listener с `auth = "basic"`; TLS-вход к прокси, cache и admin API появятся в следующих этапах. Согласование требований и слияние PR — отдельные действия владельца.

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
остаётся M06.

`examples/m05-auth-local.toml` не содержит рабочих credentials. Подробный
контракт и матрица приёмки — [M05-r1, Issue #14](https://github.com/AlexeiSmol/Angara/issues/14).

Проверка `check` читает и структурно валидирует users-файл, но не запускает
runtime, сеть и Argon2 hashing. Plain Basic разрешён только на loopback bind
(`127.0.0.0/8`, `::1`) либо при явном `allow_insecure_basic = true`; это не
делает transport TLS. TLS listener к прокси — M06. Unix-проверка прав и
owner реализована для Linux; другие ОС не объявляются поддержанными до
отдельных испытаний.

## Текущее состояние

M00–M04 приняты и слиты. M05 реализован в ветке `feat/14-m05-auth` и передан
на ревью; Linux CI выполняет прежние M01–M04 проверки, новые M05-тесты,
`cargo deny` и проверку auth-примера с временным users-файлом. Слияние
выполняет владелец после ревью.

Лицензия не выбрана. Совместимость с конфигурационным синтаксисом Squid не заявляется. Сроки и показатели производительности будут уточнены по параметрам первого сервера и результатам измерений.
