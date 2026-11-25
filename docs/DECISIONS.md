# Angara — решения и согласование

**M00–M08 DONE.** Редакция 1.1 от 22 ноября 2026 года. M08 слит в `b1e82ef`; после него в `main` вошли только доработки тестов и CI (#28–#38). В исторических разделах сохранены имена Codex и Claude, действовавшие на момент записи; актуальные роли закреплены в D60.

## Исходные решения владельца

| ID | Решение | Основание |
| --- | --- | --- |
| U01 | Проект называется Angara; репозиторий в аккаунте AlexeiSmol | Исходный запрос |
| U02 | Цель — аналог сервера Squid для Linux | Исходный запрос |
| U03 | Codex отвечает за архитектуру, план, задания, код-ревью и план тестов | Исходный запрос |
| U04 | DeepSeek V4.1 Flash 1017 пишет код и тесты по заданиям | Исходный запрос |
| U05 | Основная коммуникация — через GitHub, при необходимости через владельца | Исходный запрос |
| U06 | План и архитектура согласуются до реализации | Исходный запрос |

## Согласованные решения

| ID | Решение | Статус | Влияние |
| --- | --- | --- | --- |
| D01 | Rust, Tokio, hyper, rustls; один crate и один процесс | APPROVED | M01 закрепляет совместимые toolchain/зависимости |
| D02 | v0.1 — HTTP/1.1 + CONNECT, auth, ACL, TLS-вход и эксплуатация | APPROVED | Первый эксплуатационный выпуск после M08 |
| D03 | Parent proxy и HTTP cache после v0.1; обе функции обязательны | APPROVED | M09/M10 не зависят от повторного подтверждения потребности |
| D04 | Сначала Ubuntu Server 24.04 x86_64 / systemd; затем проверка других Linux | APPROVED | Поддержка других систем объявляется после их испытаний |
| D05 | Сначала логин/пароль и ACL: локальные пользователи с Argon2id, Basic через защищённый транспорт | APPROVED | Ключи, LDAP и квоты не требуются в v0.1 |
| D06 | Deny по умолчанию; явный доступ к внутренним сетям; конечный IP проверяется | APPROVED | Определяет policy и resolver |
| D07 | TOML; порт 3128, первое прослушивание loopback | APPROVED | Порт прокси отделён от будущего порта управления |
| D08 | Reload ACL/users/совместимых лимитов; listener/TLS config через restart | APPROVED | Изменение workers и egress-профилей также требует restart в v0.1 |
| D09 | Тесты и CI на каждом этапе, без заранее выдуманных показателей скорости | APPROVED | 10–20 устройств — пилот, не предел архитектуры |
| D10 | Слияние и выпуски — решение владельца; автоматический запуск моделей отдельно | APPROVED | Согласование M00 не равно поручению слить PR |
| D11 | Лицензия и будущая публичность — отдельное решение владельца | DONE | Владелец выбрал MIT (`LICENSE`). Публичный репозиторий `AlexiVladSmol/Angara2` создан с очищенной историей: без `docs/reviews/` и личных адресов; Issue и PR остались в приватном репозитории |
| D12 | Использование множества CPU-ядер | APPROVED REQUIREMENT | Многопоточный Tokio, настройка workers, ограниченные CPU-задачи |
| D13 | Работа с несколькими сетевыми интерфейсами | APPROVED REQUIREMENT | Несколько listeners, egress-профили и выбор исходящего адреса |
| D14 | В будущем современный TUI управления | APPROVED REQUIREMENT | M11, общий control service, без логики proxy внутри UI |
| D15 | Возможный локальный web-интерфейс, ориентир 127.0.0.1:7029 | OPTIONAL / PLANNED | M12 после решения о реализации web; API управления общий с TUI |
| D16 | Личный сервер, организация и много внешних пользователей — перспективные сценарии; старт 10–20 устройств | APPROVED | Отдельно измерять устройства, запросы, соединения и туннели |

## Детализация ближайшего этапа Codex

| ID | Контракт M02-r1 | Статус/основание |
| --- | --- | --- |
| D17 | Source allow-list → first-match ACL запроса до DNS → отдельная first-match IP-политика каждого кандидата; отсутствие разрешения — deny | SPECIFIED: детализация D06 для задания M02 по поручению владельца |
| D18 | SystemResolver, bounded фактические lookup, timeout не освобождает бюджет работающего blocking вызова, dial только к проверенному SocketAddr | SPECIFIED: детализация ресурсных и DNS-контрактов |
| D19 | Один egress на запрос; system или bind_ip; выбор по listener/source/domain/method/port; без скрытой смены профиля; bind_device позже | SPECIFIED: минимальный контракт D13 |
| D20 | Совместимое расширение schema_version=1; старые config валидны, отсутствующие новые правила запрещают outbound; M02 ещё без HTTP-сервера | SPECIFIED: границы M02 и регрессии M01 |

Полная семантика, conservative IANA default, IDNA-профиль, численные пределы и тесты — в [M02_NETWORK_POLICY.md](tasks/M02_NETWORK_POLICY.md). Это проектная детализация Codex в рамках утверждённой архитектуры, не утверждение о новом отдельном согласовании каждого поля владельцем.

## Детализация M03-r1

| ID | Контракт | Основание |
| --- | --- | --- |
| D21 | Настоящий serve HTTP/1.1 на всех listeners, all-or-nothing startup, trusted peer и базовый bounded shutdown | SPECIFIED: выполнение M03/D01/D13, развитая эксплуатация остаётся M07 |
| D22 | Bounded origin pool реализуется в M03; перед каждым reuse повторные ACL/DNS/IP, изоляция origin/endpoint/egress/generation, permit до закрытия socket | SPECIFIED: конкретизация принятой архитектуры и NET-03 |
| D23 | Строгий библиотечный framing и raw negative corpus, локальный Expect/100, ordered 1xx/103, streaming bodies/trailers; narrow writer adapter допустим без собственного parser | SPECIFIED: конкретизация HTTP-01–07 с учётом возможностей hyper; невозможность выполнить контракт выносится отдельным блокером |
| D24 | Отдельный client socket budget, ограниченные headers/bridge/pool, HTTP deadlines и 18 групп приёмки | SPECIFIED: необходимая ресурсная защита M03, численные defaults выбраны Codex в задании |

Это детализация задания Codex в рамках поручения владельца от 9 ноября 2026 года; отдельное согласование каждого параметра владельцем не заявляется. Полный контракт — [M03-r1](tasks/M03_HTTP_PROXY.md).

## Основание согласования и история

Источник — ответ владельца в чате проекта 9 ноября 2026 года: выбран Rust; сначала Ubuntu, затем другие системы; перенос cache/parent допустим, но реализация обязательна; перспективно все три сценария, начальный тест 10–20 устройств; сначала логин/пароль и ACL. Дополнены требования нескольких CPU-ядер и сетевых интерфейсов, будущего TUI и возможного локального web-интерфейса. Остальное исходное предложение подтверждено фразой «С остальным согласен».

9 ноября 2026 года владелец поручил выдать DeepSeek задание M02 после принятия и слияния M01. Редакция 0.3 фиксирует завершение M00/M01 и исполнимый контракт M02-r1; дальнейшие этапы не запускались.

Ревизия 0.1 была предложением. В 0.2 зафиксировано согласование D01–D10 и добавлены D12–D16. Детали workers, egress и control service в архитектуре — проектная детализация Codex для выполнения требований; они не означают, что владелец уже выбрал конкретную UI-библиотеку или параметры железа.

Приватность существующего репозитория — наблюдаемое состояние GitHub. Этот план не меняет доступы или видимость репозитория.

9 ноября 2026 года M02 принят повторным ревью на f487996eea4976fe7456a529e0b76dd05e5884f2: все четыре замечания исправлены, 127 Linux-тестов/CI прошли. После сообщения владельца «Выполни слияние и напиши задание M03» PR #7 слит: merge-коммит 45e8815e736d2415b833a33213fca9adeea65b0b. Незавершённая документация M02 из PR #5 перенесена в постановку M03 с сохранением исторического M02-r1; main README реализации сохранён. Документы подготовки M03 не утверждают, что его код уже реализован.

## Открытые данные к первому пилоту

- CPU/RAM/каналы первого сервера, реальное число соединений на устройство и численные цели latency/throughput/RSS.
- Перечень следующих Linux-дистрибутивов, сроки их испытаний и необходимость ARM64.
- Лицензия; UI-библиотеки; окончательное решение о web-панели и её порте.

Расширения auth, bandwidth limits и квоты получают отдельные задания, когда понадобятся. Персональный, корпоративный и многопользовательский сценарии не означают автоматического требования к кластеру или внешней БД в первом выпуске.

## Порядок следующих решений

Решение владельца из чата или GitHub записывается с датой, источником и D-ID. Архитектурное предложение Codex не выдаётся за уже принятое решение владельца. Новые сведения дополняют журнал, сохраняя историю.

M00–M06 завершены; M07 получает Ready Issue #20 с закреплёнными SHA базового кода и постановки задачи. Слияние и выпуск выполняет владелец либо участник по его явному поручению.

## Приёмка M03 и постановка M04 — 10 ноября 2026 года

M03 принят ревью Codex ACCEPTED на `96af256d5f45d73e4a9860cdb500c2d1d9e5a3e8`: 196 основных Linux-тестов + две resource-проверки; три независимых прогона по 24000 HTTP requests, все R1–R9 закрыты. По сообщению владельца «Делай слияние» PR #10 слит в `9330cd59ec1d69ea5aa2cd4a5b58f8e65cb7c22a`, Issue #9 закрыт completed. Затем владелец поручил: «Приступай к написанию следующего задания. Настало время M04».

| ID | Контракт/изменение | Основание |
| --- | --- | --- |
| D25 | Ограниченный vendored hyper 1.12 patch сохраняет исходный request-target в typed extensions до URI normalization; parser/framing не меняется | ACCEPTED IMPLEMENTATION: принято в M03/PR #10, слитом по поручению владельца; scope/diff описан в vendor/hyper-1.12.0/ANGARA_PATCH.md |
| D26 | M04: CONNECT на существующем HTTP ingress, штатный upgrade, сохранение early bytes и single writer; TCP connect после прежних ACL/DNS/IP/egress до 200 | SPECIFIED: детализация запланированного M04/CON-01–04 в рамках нового поручения владельца |
| D27 | connect.allowed_ports=[443], пустой список запрещает CONNECT, максимум 64 уникальных порта; source/request/IP allow остаются обязательными | SPECIFIED: safe port gate M04-r1; численные значения выбраны Codex для задания |
| D28 | Непрозрачный bounded relay, общий byte-progress idle; first EOF запускает один абсолютный half-close drain (default 5000 ms); общий shutdown без detached tasks | SPECIFIED: детализация lifecycle M04-r1/CON-04, общих resource требований и принятых исправлений R1/R2/R5 |
| D29 | CONNECT владеет отдельным Connected, не использует HTTP pool, расходует общие client/outbound/connecting budgets; TLS сайта остаётся сквозным | SPECIFIED: детализация D01/D06/D12/D13; auth/TLS-listener/операции не переносятся из M05/M06/M07 |

Полный контракт и 18 групп приёмки: [M04-r1](tasks/M04_CONNECT_TUNNELS.md). База реализации закреплена независимо от SHA постановки; новая архитектурная развилка требует отдельного решения. Перенесены исторические M02-r1/M03-r1 из документации PR #8 без переписывания их содержания; текущий пакет M04 заменяет несведённый пакет постановки M03. Это сохранение принятых контрактов и обновление статуса, а не повторная реализация M02/M03 или слияние PR #8.

## Приёмка M04 и постановка M05 — 11 ноября 2026 года

M04 принят [ревью Codex ACCEPTED](https://github.com/AlexeiSmol/Angara/pull/13#issuecomment-6792835709) на `e7afedf47b6874e2f1902c7740addce759b30131`: 242 основных Linux-теста, три отдельно запускаемые resource-проверки, CI `42988221130` успешен. R1–R5 закрыты: origin EOF сохраняет обратный поток, каждый positive partial write обновляет progress, один first-EOF deadline охватывает финальный bridge flush, TLS helper различает certificate/transport failures, ранний split-head payload проверен. По поручению «Выполнить слияние» PR #13 слит в `49037888f6ab5f3a843a54fc13d2b2e1e278ba9a`, Issue #11 завершён. Следующее поручение владельца: «напиши задание для этапа M05».

| ID | Контракт/изменение | Основание |
| --- | --- | --- |
| D30 | M05: Basic отдельно на listener, default none; plain nonloopback требует allow_insecure_basic, каждый HTTP/CONNECT request проверяется до policy/DNS/dial | SPECIFIED: детализация согласованного D05; M06 TLS не реализуется раньше срока |
| D31 | Strict users TOML version=1, 1 MiB/1024 users; username case-sensitive ASCII, disabled, безопасные file permissions; CLI users hash с TTY/stdin, UTF-8/NFC, без argv password | SPECIFIED: управляемые локальные пользователи и минимальная безопасная административная операция M05 |
| D32 | Argon2id v19 m=19456 KiB/t=2/p=1, salt16/output32; PHC validate до hashing; hash profile фиксирован, замеры обязательны | SPECIFIED: исходный профиль по OWASP, выбран Codex; не отдельное утверждение владельцем параметров |
| D33 | Проверенная snapshot-bound identity в request/outbound, user ACL и routing; pool изолирован по listener/user/anonymous наряду с прежним key | SPECIFIED: D05/D06/D13 и предусмотренное M03 расширение identity; deny/IP/egress не обходятся |
| D34 | Shared auth max_verifying=2 (1..16), нулевая admission queue, wait timeout2000ms; overload/timeout503, credential failure407; permit живёт фактической blocking closure, dummy unknown/disabled | SPECIFIED: bounded CPU/RAM и корректная отмена M05, D12; начатый Argon2 не обещается abortable |
| D35 | M05 users snapshot обновляется restart; no auth cache/reload/online CRUD, secret redaction и zeroization своих buffers; 20 приёмочных групп + прежние регрессии | SPECIFIED: граница M05/M06/M07, без новых обязательств UI/LDAP/квот |

Полный текущий контракт — [M05-r1](tasks/M05_AUTH_USERS.md). Кодовая база и SHA документации закрепляются независимо в Ready Issue; допускается начало реализации до merge docs PR. Исторические M02-r1/M03-r1/M04-r1 перенесены без переписывания из пакета M04. Новый пакет заменяет несведённую постановку PR #12; закрытие прежнего docs PR после сохранения его документов не является его слиянием или запуском реализации M05. Код proxy/тесты/CI этот пакет не меняет.

## Приёмка M05 и постановка M06 — 12 ноября 2026 года

M05 получил [ACCEPTED](https://github.com/AlexeiSmol/Angara/pull/16#issuecomment-6822181782) на `349a4e5c1153464779858a8b7a81c5c0b4af33dd`:311 основных тестов+3 resource checks, CI43198437631, M05-R1–R3 закрыты. По поручению «делай слияние» PR #16 слит в `be548e5f613dfe8d83bc1c09d6f351be202789c6`, Issue #14 completed; tree20f2c7ed49e638a1b19a9565ab60c1336a195957 совпадает с accepted head. Новое поручение: «Пиши задание для М06 этапа».

| ID | Контракт/изменение | Основание |
| --- | --- | --- |
| D36 | M06 transport=https поверх прежнего HTTP/CONNECT pipeline; один cert/key snapshot на listener, startup до bind, file context как в M05 | SPECIFIED: детализация D01/D02/D05 и поручения M06; без MITM/SNI routing/parent |
| D37 | Chain/key по 1 MiB,1..16 certs, strict PEM/DER/key matching/permissions; restart для смены файлов, client проверяет trust/name/time | SPECIFIED: D08 и безопасная preparation; собственный PKIX/ASN.1 parser не вводится |
| D38 | rustls0.23/tokio-rustls0.26, explicit ring provider, TLS1.2/1.3 и h1 ALPN; no early data/resumption/tickets/keylog/compression | SPECIFIED: библиотечная TLS policy первого стенда; версии patches/лицензии проверяются lock/deny |
| D39 | Общий handshake budget32 (1..256), queue0, deadline5000ms (100..60000), client permit с accept; ранний source gate, overload до TLS закрывает TCP | SPECIFIED: resource защита одновременно с TLS; defaults выбраны Codex |
| D40 | Plaintext single writer/bridge, настоящий TLS flush до boundary; TLS1.3 directional EOF/drain, TLS1.2 closure по RFC5246; один shutdown deadline | SPECIFIED: сохранение M03–M05 lifecycle с явной разницей версий TLS, без raw socket обхода |
| D41 | Две независимые CA, настоящий TLS-в-TLS,22 группы, baseline311+3 и real overload/latency/RSS evidence | SPECIFIED: M06 acceptance; это не утверждение о выполненных тестах M06 или production readiness |

Полный контракт — [M06-r1](tasks/M06_TLS_LISTENERS.md). Base code и SHA документации закрепляются независимо в Ready Issue. Исторические M02–M05 task docs сохранены побайтово из пакета M05; общий пакет M06 заменяет несведённую постановку PR #15 без её merge. Принятый implementation README M05 сохранён с обновлением статуса и небольшой doc-правкой: интерактивный curl prompt в negative name check больше не скрывается stderr redirect. Source/tests/CI/Cargo/vendor этот docs пакет не меняет.

## Приёмка M06 и постановка M07 —13 ноября2026 года

M06 [ACCEPTED Codex](https://github.com/AlexeiSmol/Angara/pull/19#issuecomment-6849197123) на c1b9f1b00850b6b8bf8d83f89b4e657f12c63d85; R1–R3 закрыты. По прямому «делай слияние» PR #19 merged в60aebdaec3240a8139a90c920589388f312e360c, Issue #17 completed; tree5fb4a963dc539f269b04fd5c5f968e398ede04d5 совпадает с accepted snapshot. Post-merge CI43403004578 success:357 основных+3 explicit resource checks. Локальная M04/RST нестабильность не объявлялась pass, воспроизведена и на base M05 и явно сохранена в review. Поручение владельца: «Напиши задание для этапа М07».

| ID | Детализация ближайшего этапа | Основание |
| --- | --- | --- |
| D42 | Одна immutable root ArcSwap>=1.9.5, snapshot на exchange после gate, old requests/tunnels завершаются на G; max16 опубликованных живых roots | SPECIFIED Codex: D01/D08/D12 и поручение M07, без собственной atomic-pointer реализации |
| D43 | Exact hot allow-list access/routing/users/совместимые caps/timeouts; mixed restart change отвергается целиком; policy reload не читает TLS files | SPECIFIED: D08, сохранение M06 prepared TLS; check/startup остаются полными |
| D44 | Shared services/budgets/pool и actual job permits не пересоздаются reload-ом; hot client/outbound caps глобальны; retire old idle/leases | SPECIFIED: ресурсные/identity инварианты M02–M06 и D09/D12 |
| D45 | In-process typed status/metrics/validate/reload(expected generation)/shutdown; preparation1/queue0, cancellation fence, SIGHUP bounded | SPECIFIED: D08/D14, будущие M11/M12; сетевой admin API сейчас не вводится |
| D46 | Bounded JSON Lines stderr, typed privacy allow-list без user/IP/authority/query/secrets; record4096, queue1024 default/drop-newest; metrics<=2048 series | SPECIFIED: F08/N02/N04 и M07; выбранная privacy policy, не обещание чувствительного audit |
| D47 | Один absolute shutdown deadline для server/control/log/runtime; max1 process-lifetime stderr worker, library sink без скрытого global logger; blocked-sink spike | SPECIFIED: сохранение M05/M06 deadline и bounded observability; lossless logging не обещается |
| D48 | M07-r1:25 групп, main TOML1MiB/regular FD/owner/mode, стабилизация forced M04 EOF/RST test20 повторов, baseline357+3 | SPECIFIED: эксплуатационное задание; не результат уже выполненного M07, M08/release отдельно |

Полный контракт — [M07-r1](tasks/M07_OPERATIONS.md). Кодовая база закреплена независимо от SHA документации; поля/defaults — проектная детализация Codex в рамках согласованных требований, не отдельное подтверждение каждого числа владельцем. Исторические task docs M02–M06 перенесены побайтово из пакета M06 @88434ed7d6a866186fcecf4d926b55087017944c; M01 сохраняется из main. Пакет M07 заменяет несведённый docs PR #18 после сохранения истории, без его merge и без source/test/CI/Cargo/vendor изменений.

## Приёмка M07 и постановка M08 — 16 ноября 2026 года

Этапы M00–M07 приняты и слиты. База M08 — `main` на `4656430caf034e28fc6dba9ff340d7ddde9a4711`. M07 принят на `fdf8046cd3d6ba285cadff3d8c529bc25fa337a0`, PR #22 слит, Issue #20 закрыто. Обе проверки на коммите слияния прошли. Исходная регрессия включает 412 основных Linux-тестов и три отдельные ресурсные проверки. [Заключение M07](https://github.com/AlexeiSmol/Angara/pull/22#issuecomment-6913889015) · [CI на коммите слияния](https://github.com/AlexeiSmol/Angara/actions/runs/43849853953)

| ID | Решение | Основание |
| --- | --- | --- |
| D49 | Выдать DeepSeek задание M08 на кандидат v0.1 для Ubuntu Server 24.04 x86_64 | Поручение владельца после слияния M07. F10, N05 и N07 из M00 |
| D50 | Поставлять архив с манифестом и контрольными суммами, устанавливать в версионные каталоги, поддерживать явное обновление и откат | Детализация Codex для воспроизводимой установки и проверки A→B→A |
| D51 | Запускать сервис через systemd от пользователя `angara`. Проверять готовность и результат reload запросом через прокси. Задать срок остановки с учётом предела конфигурации M07 | Контракт M08-r1 на основе принятого жизненного цикла приложения |
| D52 | Проверять 10 и 20 клиентов, часовой профиль, несколько workers и два разных интерфейса на изолированном стенде | Начальный масштаб согласован владельцем. Длительность, конкретные пороги и способ измерения определил Codex для этой редакции |
| D53 | Разделить техническую приёмку кандидата, выбор лицензии, проверку владельца и решение о публичном выпуске | В M00 лицензия отложена. Слияние M07 и постановка M08 поручены владельцем |

Задания M02–M07 перенесены из документационного PR #21 без изменения содержимого. Применимые контракты доступны из пакета 0.9. [M08-r1](tasks/M08_RELEASE_CANDIDATE.md) · [Issue #23](https://github.com/AlexeiSmol/Angara/issues/23)

## Смена ревьюера, приёмка M08 и доработки — 17–20 ноября 2026 года

| ID | Решение | Основание |
| --- | --- | --- |
| D54 | С 17 ноября 2026 года проектирование, задания и ревью ведёт Claude вместо ChatGPT / Codex. Роли DeepSeek и владельца не меняются | Поручение владельца |
| D55 | Репозиторий перенесён в `AlexiVladSmol/Angara` 18 ноября 2026 года. Номера Issue и PR и история сохранены; старые ссылки на `AlexeiSmol/Angara` перенаправляются | Действие владельца |
| D56 | Ревью публикуется комментарием в PR и копией `docs/reviews/<ID>_<sha>.md` в ветке PR с `[skip ci]`. Копия содержит только текст ревью | Выбор владельца, 18 ноября 2026 года |
| D57 | После закрепления кандидата новый полный прогон с soak нужен только при изменении `src/` или `packaging/`. Правки тестов, CI и документов проверяются обычным CI PR | Детализация ревьюера; применялась в #27–#38 |
| D58 | M08 принят на `515365a` (архив B SHA-256 `e6fba6415f5d143d79d9c202a88a7c64abd9fe698ef186c672492bea1ed2dc8c`) и слит в `b1e82ef` | Ревью ACCEPTED 19 ноября 2026 года; слияние по поручению владельца |
| D59 | Тестовый стенд владельца (Ubuntu 24.04, 1 vCPU, 1 ГБ RAM) используется ревьюером для проверки скриптов на архивах из CI. Сборка на стенде не выполняется | Стенд предоставлен владельцем 19 ноября 2026 года |

Доработки после слияния M08, все — только тесты и CI: #27/#28 — зеркало и таймаут `debootstrap` в boot-проверке; #29/#30 — жёсткий таймаут, размонтирование rootfs и сигналы; #31/#32 — нестабильный тест `m05_auth` (BrokenPipe); #33/#34 — таймауты `wget` для `debootstrap`; #35/#36 — сигналы во время очистки и общий helper записи stdin; #37/#38 — молчаливое падение `streaming.sh` и общий trap `ERR`. [Заключение M08](https://github.com/AlexiVladSmol/Angara/pull/25#issuecomment-7001950215)

## Разделение ролей и работа с нескольких клиентов — 22 ноября 2026 года

| ID | Решение | Основание |
| --- | --- | --- |
| D60 | С 22 ноября 2026 года архитектура, задания и стратегия тестирования — ChatGPT Astra 6.2; код-ревью — Claude Opus 5.5; реализация, тесты и CI — DeepSeek V4.1 Flash 1017. D54 сохраняется как история и заменён в части проектирования, заданий и ревью | Поручение владельца |
| D61 | Один GitHub-аккаунт может использоваться с нескольких клиентов. На каждом клиенте отдельный SSH-ключ; новые коммиты — от `AlexiVladSmol <358176669+AlexiVladSmol@users.noreply.github.com>`; одна ветка на Issue активна только на одном клиенте; домашний клиент — разработка и локальные тесты, рабочий стенд — целевая приёмка Ubuntu 24.04, Squid, systemd и нагрузка; контекст — в Issue/PR | Поручение владельца |

## M09 — parent proxy — 22 ноября 2026 года

| ID | Решение | Основание |
| --- | --- | --- |
| D62 | Для M09 parent получает числовой IP, проверенный Angara (вариант 1): доменный HTTP и клиентский CONNECT используют внешний `CONNECT <verified-ip>:<port>`, HTTP к IP-литералу — absolute-form с проверенным IP. Ошибка parent не переключает запрос в direct или другой parent. Parent definitions, transport, CA и содержимое credentials применяются при restart; routing (default_parent/next_hop) входит в hot reload. Parent pool reuse в M09 не включён. `Via` использует `runtime.instance_id`, чтобы отличать экземпляры в цепочке | Выбор владельца от 19 ноября 2026 года, зафиксирован в Issue #42 |
| D63 | Завершение CONNECT-туннеля через HTTPS-parent: после EOF клиента ошибки `BrokenPipe`, `NotConnected`, `ConnectionReset` и `UnexpectedEof` на shutdown записи parent считаются нормальным half-close. `UnexpectedEof` на чтении parent принимается как EOF только если клиент уже завершил свою сторону; обрыв до EOF клиента остаётся `failed/error`. Это компромисс: TLS без `close_notify` неотличим от обрыва после client EOF. Direct и HTTP-parent сохраняют прежнюю классификацию. HTTP к имени идёт через `parent_client`, а не `connect::run`, поэтому его классификация не меняется | AlexiVladSmol/Angara#50; реальный Squid 6.14 по TLS отправляет `close_notify`, затем сразу закрывает соединение; последующая запись `close_notify` от Angara получает `BrokenPipe`/`ECONNRESET`. Ветка `UnexpectedEof` на чтении — защита для parent, которые `close_notify` не отправляют |
| D64 | Если CONNECT-туннель завершается ошибкой ввода-вывода (`TunnelEnd::Io`), байты, уже переданные relay в мост к клиенту, всё равно дописываются в сокет клиента. Ожидание ограничено `connect.half_close_timeout` от момента ошибки. Исход остаётся `failed/error`, `tunnel_bytes` не меняется. Если мост уже завершился (в том числе с ошибкой записи клиенту), ожидания нет. Способ закрытия клиентского сокета не меняется; сигнализация обрыва через RST — отдельное решение. Принудительная остановка прерывает ожидание через `abort_all`; `Io` фиксируется в учёте туннеля до ожидания, поэтому и тогда записывается `failed/error`, а не `cancelled/shutdown`. Остановка до обнаружения ошибки по-прежнему даёт `cancelled/shutdown`. Регрессия — `tests/m09_tunnel_drain.rs` и unit-тесты `relay_io_*`, `relay_abort_*` в `src/http/server.rs` | Issue #52; исполнитель — Claude, исключение из D60 по решению владельца |
| D65 | M10: ограниченный общий RAM-кеш. Хранятся только полные `200` на обычный `GET` с HTTP-схемой назначения и direct-маршрутом. Явная свежесть: `s-maxage` → `max-age` → `Expires` относительно `Date`; без эвристик. `Authorization`/`Cookie` запроса, `Range`/`If-Range`, клиентские `If-*`, тела, `Set-Cookie`, `private`, `no-store`, ответный `no-cache`, `206`, trailers и `Vary` кроме `Accept-Encoding` исключаются из чтения и/или хранения. Ключ включает канонический URI с портом и точным path/query, вариант, listener, identity/anonymous, egress, проверенные endpoints и поколение политики. `only-if-cached` без допустимой записи — 504 без origin. После неошибочного небезопасного метода URI инвалидируется во всех вариантах и разделах; epoch отменяет публикацию уже начатого наполнения. Начальные лимиты при `enabled = true`: 32 МиБ, 1 МиБ на объект, 512 записей, 8 наполнений; параметры применяются при restart. Учёт бюджета включает данные, ключи, заголовки и фиксированную запись; медленные читатели удерживают учтённые байты до освобождения. Метрики: `cache_hit`, `cache_miss`, `cache_bypass`, `cache_revalidation`, `cache_eviction`, `cache_fill_refusals`, `cache_entries`, `cache_bytes`; URL/query/ключи/пользователи/заголовки не журналируются | AlexiVladSmol/Angara2#1; политика утверждена владельцем 23 ноября 2026 года |
