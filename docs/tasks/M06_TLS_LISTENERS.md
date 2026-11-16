# DeepSeek: M06 — TLS до прокси и HTTPS listeners

Статус: READY, редакция **M06-r1 от 12 ноября 2026 года**.
Постановка и ревью: Codex. Реализация, тесты и CI: DeepSeek V4.1 Flash 1017.
База реализации: `main` @ **`be548e5f613dfe8d83bc1c09d6f351be202789c6`**.
M05 принят [ревью ACCEPTED](https://github.com/AlexeiSmol/Angara/pull/16#issuecomment-6822181782) на `349a4e5c1153464779858a8b7a81c5c0b4af33dd` и слит в [PR #16](https://github.com/AlexeiSmol/Angara/pull/16); Issue #14 завершён. Baseline: 311 основных Linux-тестов + три отдельно запускаемые resource-проверки, CI `43198437631` успешен, M05-R1–R3 закрыты. Это результаты M05, не заранее заполненный отчёт M06.

## 1. Результат и границы

Клиент подключается к Angara как к **HTTPS proxy**, проверяет сертификат самого proxy и передаёт HTTP/1.1 proxy protocol/Basic внутри этого TLS. Обычный HTTP forwarding и CONNECT используют те же auth/ACL/DNS/egress/budgets M02–M05. Через CONNECT внутри внешнего TLS должен пройти отдельный настоящий TLS/HTTPS сеанс с сайтом, проверяемый клиентом независимо.

| Участок | Роль Angara | Кто проверяет доверие и имя |
| --- | --- | --- |
| Клиент → HTTPS listener Angara | TLS server; расшифровывает proxy protocol | Клиент проверяет сертификат proxy |
| HTTP proxy request к `http://origin/` | Прежний HTTP forward к origin | TLS сайта в этом запросе отсутствует |
| Клиент → HTTPS сайт внутри CONNECT | Непрозрачный relay после CONNECT200 | Клиент проверяет сертификат сайта; Angara его не подменяет |

В M06 входят rustls/tokio-rustls, загрузка cert/key, HTTPS listeners вместе с HTTP, ограниченный TLS handshake, безопасный рефакторинг client I/O, совместимость auth и CONNECT, тесты, CI и локальный стенд с CA. Первый стенд Ubuntu Server 24.04 x86_64, 10–20 логических клиентов. Это не подтверждение других ОС, физических устройств или нескольких NIC.

Не входят: MITM, расшифровка TLS сайта, TLS до parent, HTTPS absolute-form forwarding без CONNECT, HTTP/2 ingress/h2c/HTTP3/UDP, STARTTLS/автоопределение HTTP и TLS на одном порту, mTLS, SNI routing, ACME, online cert rotation/reload, новый auth backend/cache, TUI/web. Cert/key меняются restart по D08. Эксплуатация/reload/control/telemetry остаются M07, release — M08.

1. Прочитать AGENTS, ARCHITECTURE, DECISIONS, TEST_STRATEGY и этот документ на SHA постановки из Ready Issue. Создать `feat/<номер-Issue>-m06-tls` **от базы кода выше**, PR направить в main. Неслитый docs PR не блокирует реализацию по pinned Issue и не разрешает слияние других PR.
2. Оставить в Issue план: подготовка cert/key до bind, TLS admission/ownership, место TLS относительно SplitIo/writer, flush/barrier, EOF/drain/idle/shutdown, зависимости, порядок тестов.
3. Обязательный узкий spike: HTTP response/103 через TLS, CONNECT200+early bytes, TLS внутри CONNECT, client close_notify с обратным drain в TLS1.3 (TLS1.2 closure отдельно по §7) и stalled TLS flush под deadline. Использовать реальные rustls/tokio-rustls и действующий bridge. Spike входит в M06; результат/схему ownership приложить, не выдавать его за готовый этап.
4. Реализовать весь контракт и 22 группы приёмки. При настоящем blocker зафиксировать воспроизведение и решение; не ослаблять flush/EOF/auth требования молча. Не принимать/сливать этап самостоятельно и не начинать M07.

## 2. Архитектурный путь и зависимости

На базе M05 `HttpServer::serve_client`, `SplitIo` и `writer_loop` используют конкретные TcpStream/OwnedReadHalf/OwnedWriteHalf. Разрешён рефакторинг над `AsyncRead + AsyncWrite` либо эквивалентным внутренним transport type. Внешний TLS заканчивается **ниже** HTTP parser/bridge/CONNECT: TCP → TLS при transport=https → прежний plaintext HTTP ingress/single writer. Для http путь остаётся raw TCP. Не создавать вторую реализацию forwarding/CONNECT/auth под HTTPS.

Использовать совместимые поддерживаемые releases **rustls 0.23.x, tokio-rustls 0.26.x, rustls-pemfile 2.x**; актуальный безопасный patch выбрать при реализации, закрепить Cargo.lock и проверить Rust1.97/MSRV/deny. CryptoProvider — **ring**, явно переданный builder, с safe cipher suites и TLS1.2/1.3; отключить неиспользуемые default features/другой provider. Не полагаться на process-global `install_default()` и не создавать конфликт при двух server instances. Это разрешённая детализация D01/M06, не новая TLS архитектура. Нужный готовый X.509 DER parser для структурной проверки cert chain также допустим с обоснованием зависимости.

Своя crypto/ASN.1/TLS record/ClientHello/HTTP parser реализация, unsafe в Angara, расширение vendored hyper patch и external TLS terminator вместо реализации M06 не разрешены. Сохранить metadata-only hyper1.12.0 patch, OriginalRequestTarget, explicit sender.ready() перед pool reuse и отсутствие retry/replay. Зависимости/их лицензии добавлять точечно, без отключения advisories/deny или wildcard allow.

После успешного handshake нельзя получать read/write halves из исходного TcpStream и обходить TlsStream. Один общий TLS connection object/его корректные split halves владеют TCP до завершения. TLS-библиотека сериализует records, HTTP-приложение сохраняет одного writer plaintext. Все стадии входят в прежний TaskTracker и force shutdown.

## 3. Строгая конфигурация

`schema_version=1` и все семь прежних examples/их подготовки остаются валидны. Старые HTTP listeners по умолчанию не становятся TLS. Новые таблицы строгие, неизвестные поля/режимы/неправильные типы отвергаются.

| Поле | Контракт M06 |
| --- | --- |
| `listeners[].transport` | Только `"http"` / `"https"`; https означает TLS + HTTP/1.1 |
| `listeners[].tls.cert_chain_file` | Обязательный непустой путь для https |
| `listeners[].tls.private_key_file` | Обязательный непустой путь для https |
| `[tls].max_handshaking` | default 32, целое 1..=256; общий budget всех HTTPS listeners данного server instance |
| `[tls].handshake_timeout_ms` | default 5000, целое 100..=60000; один абсолютный срок от TCP accept |

Для http таблица `listeners[].tls` запрещена; для https обязательна. `[tls]` содержит только общие limits; при отсутствии HTTPS listener объявленные limits всё равно валидируются. Effective handshake concurrency ограничена также max_client_connections, меньший client cap допустим. Не добавлять конфигурацию arbitrary cipher suites/CA verifier/SNI/session cache/0-RTT.

```toml
# Фрагмент: остальные runtime/limits/access/egress/auth поля берутся из
# полного M06-примера, который должен реализовать DeepSeek.
[tls]
max_handshaking = 32
handshake_timeout_ms = 5000

[[listeners]]
id = "proxy-https-local"
bind = "127.0.0.1:3129"
transport = "https"
auth = "basic"

[listeners.tls]
cert_chain_file = "tls/proxy-chain.pem"
private_key_file = "tls/proxy-key.pem"
```

TLS/cert paths разрешаются от каталога основного TOML, абсолютные допустимы; cwd не определяет семантику относительного пути. Все внешние файлы/ServerConfig подготавливаются в одном валидированном immutable snapshot **до runtime/listen/DNS/dial**. `Config::load`/parse_with_base_dir дают тот же результат, что check. Чистая `Config::parse` без file context по-прежнему работает со старыми auth-free/http configs, а конфигурацию с cert/key отвергает, как users_file M05. Никакой публичный server constructor, включая ephemeral/test APIs, не принимает неподготовленный HTTPS config и не пропускает настоящий handshake.

`angara check` читает/структурно проверяет локальные файлы и соответствие ключа сертификату; для этого допустимы ограниченные синхронные операции crypto provider. Check не создаёт Tokio runtime, сокеты, handshake или password verification jobs. Ошибка любого TLS listener отвергает весь startup; ранее подготовленные listeners не начинают accept. Error codes сохраняются: config/check/invalid serve —1, usage —2, bind/unexpected server failure —3.

На **http** Basic вне loopback по-прежнему требует allow_insecure_basic. На **https** с подготовленным TLS Basic разрешён также при nonloopback/wildcard bind без этого исключения. `allow_insecure_basic=true` на https отвергать как бессмысленное; на http допустим только с basic, как M05. Защищённость задаёт действительный listener/завершённый TLS handshake, не peer loopback, X-Forwarded-Proto, SNI, сертификат клиента или факт HTTPS сайта внутри CONNECT. TLS с auth=none остаётся anonymous.

## 4. Cert/key snapshot и политика TLS

Для каждого https listener — одна chain/key pair на время жизни snapshot, без перечитывания на accept/request. Цепь PEM leaf-first, далее intermediates;1..=16 CERTIFICATE blocks, файл до 1 MiB. Root в цепи не нужен, но корректный дополнительный cert не запрещён. Синтаксис каждого X.509 DER проверять готовой библиотекой; мусорные/пустые/повреждённые blocks/DER отвергать. Это не построение собственного PKIX verifier: Angara check не удостоверяет клиентское доверие, hostname или срок действия server certificate; их проверяет клиент.

Ключ — отдельный PEM до 1 MiB, ровно один unencrypted private key PKCS#8, PKCS#1 RSA или SEC1 EC, поддержанный provider. Несовпадение с leaf public key, неподдержанный key, encrypted key, несколько keys, случайный PEM block — безопасная config error. Минимум positive coverage RSA2048 и ECDSA P-256. Для key matching использовать provider/rustls API; не сравнивать текст PEM, не подписывать/проверять самодельный challenge. Локальные self-signed/test CA certificates допустимы, клиент доверяет им только явно.

Читать каждый файл из одного открытого regular-file handle, проверяя metadata этого handle и читая не больше limit+1 bytes; одного stat до unbounded read недостаточно. Linux: owner cert/key — root либо effective UID; private key без group write и любых world permissions (`mode & 0o027 == 0`), cert chain без group/world write (`mode & 0o022 == 0`, публичный0644 допустим). Симлинк допустим к regular target, проверяемому по тому же handle. Нерегулярные/недоступные/oversize/небезопасные файлы отвергать без auto chmod/chown. Trusted parent directory задаёт администратор. Обычный запуск/порт3129 не требуют root.

Настроить явно:

- TLS1.2 и TLS1.3 включены, TLS1.0/1.1/SSL запрещены. Safe cipher suites выбранного provider, без insecure/custom verifier.
- ALPN — только `http/1.1`; отсутствие ALPN допустимо и означает HTTP/1.1. h2-only offer отклоняется, h2+h1 выбирает h1. Отсутствие ALPN не включает HTTP/2/h2c.
- mTLS выключен; TLS subject/SNI не создают VerifiedIdentity. Один cert используется независимо от SNI, дополнительного SNI routing/дискового поиска нет.
- 0-RTT/early application data, half-RTT sending, session resumption/cache/tickets в M06 **выключены явно**. Настроить отсутствие session storage/tickets, не оставить библиотечные defaults cache256/tickets2. HTTP per-request auth не зависит от TLS session state.
- TLS key logging/secret extraction выключены; SSLKEYLOGFILE не включает их. Certificate compression/cache features не включать; в M06 они не нужны.
- Для application write buffers каждой TLS connection — `set_buffer_limit(Some(64*1024))`, никогда None. Этот limit **не является** пределом всех handshake/control buffers: реальные library limits и размер certificate flight отдельно указать/проверить на закреплённой версии. Record size оставить безопасным библиотечным.

Каждый listener содержит bounded prepared config, число listeners по-прежнему<=64. Размер cert/key input, количество handshakes и TLS internal buffers учитываются в resource report вместе с bridge 64 KiB и M05 Argon2 budget; не утверждать, что весь TLS/RSS ограничен одним buffer 64 KiB.

## 5. Accept, handshake и HTTP admission

После TCP accept сохранить реальный peer и listener ID, взять **общий client permit** до создания TLS state. Для https применить ранний source gate по этому peer до дорогого handshake, затем `try_acquire_owned` общего handshake permit. Нет свободного client/handshake slot — закрыть TCP сразу, без очереди/jobs и **без plaintext HTTP503 на TLS port**. Source deny до TLS также закрывает transport без HTTP403/407; в уже установленном HTTP пути прежние source/ACL проверки остаются.

Handshake выполняется через tokio-rustls с одним deadline от accept. Ноль bytes, фрагментированный медленный ClientHello, повторные записи или handshake read/write progress не продлевают этот срок. На успех освободить handshake slot, сохранив client permit до конца HTTP/CONNECT и writer. На error/timeout/disconnect/cancel/drop — закрыть transport и вернуть оба permits. Pending handshake учитывается TaskTracker, не отдельной detached accept task.

При drain/SIGTERM прекратить accept/admission и отменить незавершённые handshakes; не тратить на них дополнительное grace window. Перед переходом в HTTP повторно проверить shutdown state. Новые HTTP exchanges после begin_shutdown не запускаются. После успешного TLS стартуют прежние HTTP header/idle clocks: время handshake не съедает срок первого HTTP header, а TLS records не продлевают его без HTTP progress.

Malformed TLS, raw HTTP на https port, unsupported versions/ALPN, fatal TLS alerts и oversized/неполный ClientHello получают TLS failure/close, а не fallback на http. Никаких auth/DNS/dial до успешного TLS и корректного request. HTTP на http port сохраняет прежнюю семантику.

TLS handshake использует стандартный async rustls path; его crypto primitives могут исполняться внутри poll библиотеки. Ограничивать одновременно принятые handshakes и измерять worker responsiveness; не обещать, что все внутренние crypto operations вынесены в spawn_blocking. Дорогой Argon2 M05 остаётся отдельно в bounded blocking pool. Нельзя выполнять blocking filesystem/OpenSSL process на accept/HTTP async workers.

## 6. HTTP, auth и CONNECT поверх TLS

После handshake HTTPS listener использует тот же HTTP/1.1 parser, original request-target, guard, policy/outbound и pool. Absolute-form остаётся `http://...`; доступ к HTTPS-сайту осуществляется CONNECT. Не добавлять `https://...` absolute-form forwarding как побочный эффект outer TLS.

Порядок внутри HTTP: source → auth текущего request → user/request ACL → routing → DNS/IP каждого кандидата → dial/reuse. Missing/wrong credentials дают **зашифрованный407** с прежним одним challenge и close; ACL deny403, auth overload/timeout503; до auth нет origin/DNS/100 Continue. Auth повторяется на keep-alive/pipeline, pool hit и CONNECT; anonymous/чужой snapshot token не обходят outbound guard. Proxy credentials не идут origin/trailers; site Authorization сохраняется.

Pool сохраняет host/endpoint/egress/generation/listener/user/snapshot isolation. TLS user не делит origin TCP с другим listener/user, один user в своём listener может reuse. Каждый request revalidates auth/policy/DNS/IP. Несколько HTTP/HTTPS listeners одновременно используют общие client/outbound/connecting/auth budgets; handshake budget только дополняет их. Реальный peer остаётся TCP peer; SNI/ALPN/headers не меняют ACL/routing identity.

CONNECT200 выдаётся после успешного auth/policy/DNS/IP/TCP connect. Затем внешний TLS несёт непрозрачный tunnel payload; внутри него допустимы второй TLS/HTTPS, HTTP/2 сайта или произвольные бинарные байты. Angara не завершает TLS сайта и не читает сертификат сайта для policy. Ранние CONNECT bytes, предыдущий HTTP response, полный200 и origin-first bytes сохраняют порядок/однократную передачу. После200 HTTP errors в tunnel не добавляются.

## 7. Plaintext writer, flush, EOF и сроки

Сохранить bridge 64 KiB, единственный application writer, bounded interim heads и ConnectionOutput/exchange barrier. Счётчики produced/consumed и границы HTTP response считают **plaintext HTTP bytes**, не ciphertext, TLS headers/alerts/handshake и не весь записанный interim. TLS не создаёт второго HTTP writer. Чтение TLS может отправлять protocol records через библиотеку — это не отдельный application response writer.

`TlsStream::poll_write` может принять bytes в свой buffer, не отправив их TCP. Поэтому старого условия «write принял все bytes» недостаточно: explicit flush должен довести boundary до underlying transport. До подтверждённого flush нельзя считать200/final response доставленным writer, отдавать bridge другому exchange или терять последнюю порцию тела. При backpressure flush ждёт только в пределах действующего idle/drain/shutdown срока. Не подменять flush drop-ом TLS stream или raw TCP shutdown.

Обычный Connection:close/407/завершение HTTP должно дописать уже сформированный response и послать close_notify в пределах общего срока. Клиент, переставший читать, не получает нового TLS-close timeout после истечения старого deadline. Успешный flush означает передачу underlying transport, не подтверждение чтения клиентским приложением.

Для CONNECT считать plaintext/application progress в обоих направлениях; pending/zero-byte polls не прогресс. Реальная частичная запись при TLS flush также не должна давать ложный idle: допустим bounded transport observer на время pending application output либо эквивалентная модель. Одни handshake/control records без application traffic не держат idle tunnel вечно. Не разбирать TLS records самостоятельно ради счётчиков. Описать измеримые границы progress в spike/PR.

В **TLS1.3** корректный outer close_notify означает EOF одного направления: принятые pending bytes дописываются, write side закрывается, обратный поток завершается в рамках **того же** first-EOF absolute half-close deadline M04. Отправка close_notify не должна сама потерять ещё допустимые reverse bytes. **TLS1.2** имеет прежнюю семантику полного closure exchange (RFC5246§7.2.1): независимый reverse half-close после close_notify не гарантируется. Следовать стандартному библиотечному closure, явно проверить/описать эту границу и ограниченное освобождение; не имитировать TLS1.3 half-close через raw socket. Это версия протокола, не послабление для raw TCP M04 или TLS1.3. TCP EOF без close_notify — abrupt TLS EOF/error, не фиктивное успешное TLS закрытие; уже доставленные допустимые bytes не дублируются, response не replay-ится. Для framing-complete response клиент может уже иметь весь body, но это не разрешает объявлять усечённый body успешным.

Один absolute shutdown deadline из M05-R1 охватывает handshakes, HTTP, CONNECT, writer/TLS flush/close и runtime. First-EOF deadline M04 также не обновляется на TLS стадиях. Network force cancel закрывает всё в рамках существующего ownership; начатый Argon2 по-прежнему удерживает permit до фактического окончания, без нового runtime wait window. Нет бесконечного ожидания peer close_notify или новых полных deadlines на каждую TLS запись.

## 8. Ошибки и секреты

Private key PEM/DER, passwords/PHC/Proxy-Authorization, TLS traffic secrets и certificate file fragments отсутствуют в обычных Debug/Display/errors/logs/response/CI artifacts. Ошибки config/TLS preparation — безопасный класс/структурный field/index/позиция без сырого library error dump. Сохранить typed-path/static-message защиту M05-R2, включая ключи с backtick, quote, dot, fake array index. Не вводить аналогичный leak при TLS config/PEM errors.

Own raw key buffers/временные DER copies очищаются secret wrapper/zeroization после подготовки; рабочий signing key хранится только нужное время в штатном provider. Не обещать удаления всех библиотечных/OS копий. Хэши и private keys не сохраняются в предсказуемые tmp names; private tempdir, secure creation 0600 и безопасная замена обязательны. Настоящие ключи/пароли не коммитить. Fixture CA/certs/keys генерируются локально во временном каталоге, без external ACME/network.

Не включать SSLKEYLOGFILE/KeyLogFile, insecure verifier, --proxy-insecure, -k/--insecure или глобальную установку тестовой CA ради успешного теста. Некорректные credentials/key не должны превращаться в secret-bearing panic. SNI/certificate subjects/full URLs не становятся неограниченными labels или maps; полноценная telemetry остаётся M07.

## 9. Обязательная матрица приёмки — 22 M06-ID

Каждый ID в PR связан с конкретным test/command, результатом и evidence на head SHA. Mock seams допустимы для детерминированного lifecycle/pressure, но не заменяют реальные TLS/crypto/HTTP/CONNECT. Негативный тест доказывает причину отказа и отсутствие запретного действия, а не просто любую SSL/OSError.

| ID | Проверяемый результат |
| --- | --- |
| M06-CFG-01 | Старые7 examples валидны; http/https и строгие поля/ranges, https без tls и http с tls отвергнуты; file context/relative paths при другом cwd; check без runtime/сети/password hash; invalid serve до bind |
| M06-CFG-02 | Empty/malformed/oversize/неregular/небезопасные cert/key, multiple/encrypted keys, key mismatch, invalid DER в chain; RSA2048 и P-256 positive; одного bad listener достаточно для полного отказа; safe Display/Debug/CLI |
| M06-TLS-01 | Реальные TLS1.2 и TLS1.3; old versions отвергнуты; ALPN absent/h1/h2+h1/h2-only; нет early data/resumption/tickets/keylog/secret extraction; две server instances без provider-global conflict |
| M06-TLS-02 | Клиент проверяет proxy CA/chain/SAN/expiry; wrong CA/name/expired и перепутанная site CA не дают HTTP/auth/DNS/dial. Доказать именно certificate failure/exit60, не network failure; chain с intermediate реально принят клиентом |
| M06-TLS-03 | Raw HTTP на TLS port, malformed/oversized/fragmented slow ClientHello, disconnect/alert; нет plaintext HTTP/fallback/auth/dial, абсолютный handshake deadline не продлевается chunks, память и задачи ограничены |
| M06-HTTP-01 | GET/HEAD/POST, streaming/chunked/trailers, large binary bodies, 100/102/103, keep-alive/pipeline, Range/SSE поверх TLS; прежний raw request-target/framing/unsupported corpus не ослаблен |
| M06-CON-01 | Внешний proxy TLS + CONNECT + отдельный site TLS: verified HTTPS1MiB upload/download equality, разные CA; site wrong trust/name/expiry отвергает клиент после допустимого CONNECT, без replay/MITM; opaque binary tunnel |
| M06-AUTH-01 | HTTP/HTTPS listeners, Basic/none, source→auth→ACL, per-request users/keep-alive/407/403/503/no100; secret chars/NFC сохранены; TLS certificate/SNI не identity; plaintext Basic transport gate не обходится |
| M06-POL-01 | TLS не обходит domain/port/IP/mixed-DNS/special deny/CONNECT port gate, username routing и egress bind; два исходящих loopback IP наблюдаемы; pool listener/user/snapshot isolation и fresh checks на hit |
| M06-IO-01 | Один plaintext writer; 103/final/CONNECT200/early payload/origin-first bytes в порядке, без потерь/дубликатов; ciphertext/control bytes не портят output accounting; exchange/200 boundary требует настоящего flush |
| M06-EOF-01 | TLS1.3 close_notify/half-close обоих направлений и reverse drain; TLS1.2 closure exchange по §7; abrupt TCP EOF/RST/truncated body. First EOF deadline сохраняется до последнего flush, без ложного успешного body и повторов |
| M06-TIME-01 | Independent handshake/header/idle clocks; TLS после handshake без HTTP закрывается по header deadline; slow client/partial encrypted writes не дают ложный idle, stalled flush ограничен; control-only traffic не продлевает tunnel idle бесконечно |
| M06-LIMIT-01 | Handshake limit общий для>=2 TLS listeners; client permit занят до TLS и до tunnel close; overload TCP close без plaintext503, queue0; handshake success освобождает только handshake slot; auth/outbound budgets независимы |
| M06-CANCEL-01 | Cancel/drop/SIGTERM на handshake, auth, 200/handoff, TLS write/flush; no new admission/late writer, все sockets/tasks возвращены; hash permit до actual completion; никаких detached/unbounded jobs |
| M06-NET-01 | Одновременные HTTP+>=2 HTTPS listeners с разными certs/IDs, IPv4/IPv6/mapped где поддержано; wildcard Basic TLS без insecure opt-in; bind failure/all-or-nothing; настоящий peer/source gate, без header spoof |
| M06-CPU-01 | Workers1 и>=2: handshake/auth pressure не блокирует независимый разрешённый HTTP/tunnel; реальный многопоточный путь, heartbeat, latency и TLS handshake cost измерены; без обещания линейного scaling/20 физических устройств |
| M06-RES-01 | TLS internal buffers/handshake flights учтены, app write buffer 64 KiB bounded; slow readers/handshake flood/repeated cancel/RST/large streams не дают роста по объёму данных/числу прошлых попыток; FD/RSS/tasks до/пик/после |
| M06-SEC-01 | Синтетический private key/credential/PHC marker не в error/Debug/log/origin/trailers; SSLKEYLOGFILE не создаёт keylog; bad PEM/unknown TLS keys/fake typed paths безопасны; own key buffers не остаются лишними copies |
| M06-OPS-01 | Изменение cert/key файлов не меняет snapshot до restart; новый startup читает новую пару, bad pair отвергает до bind; общий absolute server+runtime deadline при TLS flush/close, shutdown не ждёт close_notify новым окном |
| M06-CLI-01 | Полный HTTPS example с generated cert/key/users, check/serve/help/netguard; ручной curl HTTPS proxy с proxy-cacert и отдельным cacert; безопасный ввод quote/backslash/colon/space/Unicode password, видимые prompts и cleanup |
| M06-LOAD-01 | 10/20 logical clients с>=2 users, HTTP/CONNECT через HTTPS, controlled auth rate и отдельные handshake/auth overload; учёт всех successes/TLS failures/407/503/retries и resource peaks; без скрытых повторов |
| M06-REG-01 | Полные M01–M05:311 baseline+3 explicit resource checks, fmt/clippy/build/deny/examples/CI; сохранены M03 ready/metadata/writer, M04 EOF/progress/drain и M05 typed diagnostics/identity/semaphore/global deadline |

## 10. Стенд, CI и отчёт

Добавить полный `examples/m06-https-local.toml` с HTTPS port3129 и Basic, команды генерации CA/cert chain/key/users во временном приватном каталоге и полный cleanup. Минимум две **разные** тестовые CA: proxy CA и site CA. Достаточны имена localhost на разных портах с DNS SAN localhost и без IP SAN: wrong-name тест использует127.0.0.1. Локальный стенд не меняет system trust/hosts/routes/firewall и не требует root или внешних сайтов.

Ручной клиент использует `--proxy https://localhost:3129`, **`--proxy-cacert` для proxy** и **`--cacert` для сайта**, а credentials — интерактивным `--proxy-user alice|bob` без пароля в argv. Показать HTTP200, missing407, authenticated ACL403, HTTPS через CONNECT (upload/download), неверные CA/name на каждом TLS участке, restart новой cert/key pair. Поддержать все разрешённые символы пароля, не сериализуя сырой secret в quoted config. Сохранить no-echo и видимый prompt: перенаправление stderr curl не должно молча прятать запрос пароля, как отмечено в принятом M05 review.

Для автоматического TLS-в-TLS клиента использовать curl или корректно наслоенный rustls/tokio-rustls/MemoryBIO. Повторный `ssl.wrap_socket` на raw fileno уже TLS socket может обойти внешний TLS и не доказывает layered protocol. Не объявлять произвольный SSL/OSError сертификатной ошибкой. Proxy certificate failure проверяется **до** auth/origin; site certificate failure — после outer TLS/auth/CONNECT с наблюдаемым origin TCP, но до HTTP сайта. Curl exit60 сверять со стадией и счётчиками, а не игнорировать return code.

Обязательные команды:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
cargo test --locked
cargo test --locked --test http_limits m03_res02 -- --ignored --test-threads=1 --nocapture
cargo test --locked --test m04_limits m04_res02 -- --ignored --test-threads=1 --nocapture
cargo deny check
```

Сохранить прежние CI checks7 examples (auth-файл генерируется безопасно), Basic/HTTP/curl/TLS-site/PTy/CPU/resource regressions; добавить настоящий HTTPS-proxy curl smoke и новые M06 resource/handshake checks с явным запуском/ограничением времени. Поддержка HTTPS proxy в установленном curl подтверждается фактической командой; отсутствие capability — явный BLOCKED либо установка подходящего test client с документированным результатом, не silent skip. Ни один failed/skipped/не запущенный ignored test не считается pass.

В отчёте указать OS/Rust/provider/версии, CPU/RAM/workers, реальные handshake/TLS versions/ALPN, buffers/max_handshaking/client/auth limits, concurrency/rate, attempts/success/TLS reject/407/503/errors/retries, latency и FD/RSS/tasks. В controlled10/20 pilot можно ограничить темп до default auth capacity2; это не20 одновременных hash jobs. Отдельный overload должен быстро возвращаться к baseline; памяти не положено расти с объёмом уже переданного stream или историей чужих имён/SNI.

В PR: base/head SHA, короткая схема ownership и результаты spike, файлы/dependencies/feature flags, карта22 M06-ID→tests/commands/evidence, точный CI run, реальные негативные причины, resource measurements и ограничения. Сохранить исторические M02–M05 задания без переписывания, обновить README/help/текущее состояние. Критерий приёмки — весь контракт, необходимые checks/CI на head и ACCEPTED Codex. Слияние — отдельное решение владельца.

## 11. Источники и статус детализации

- [rustls ServerConfig/builder](https://docs.rs/rustls/0.23.45/rustls/struct.ConfigBuilder.html), [ServerConfig](https://docs.rs/rustls/0.23.45/rustls/server/struct.ServerConfig.html): выбор provider/cert/key/ALPN/session defaults. Указанная версия — просмотренный источник; implementation patch закрепляется Cargo.lock.
- [rustls ServerConnection buffer limit](https://docs.rs/rustls/0.23.45/rustls/server/struct.ServerConnection.html#method.set_buffer_limit): app buffer limit не отменяет отдельного учёта handshake/control buffering.
- [tokio-rustls flush contract](https://docs.rs/tokio-rustls/0.26.6/tokio_rustls/): запись в TlsStream не равна flush в TcpStream.
- [RFC8446, alerts/close_notify](https://www.rfc-editor.org/rfc/rfc8446.html#section-6.1), [RFC5246 closure](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.2.1), [rustls Reader](https://docs.rs/rustls/0.23.45/rustls/struct.Reader.html): clean directional EOF и unclean TCP EOF.
- [curl HTTPS proxy/TLS](https://curl.se/docs/manpage.html), параметры proxy-cacert/cacert/proxy-user: две отдельные проверки TLS.

M06 поручен владельцем после слияния M05. Точная TOML schema, численные limits, provider/features/session policy и 22 групп — детализация **SPECIFIED** Codex в рамках D01/D02/D05/D08/D12/D13. Это не заявление об отдельном утверждении владельцем каждого default; новый архитектурный разворот требует отдельного решения. Задание не является реализацией M06 и не разрешает автоматическое слияние/запуск следующих этапов.
