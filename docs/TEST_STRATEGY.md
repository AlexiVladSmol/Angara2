# Angara — стратегия тестирования

**Редакция 1.3 от 27 ноября 2026 года.** Приняты M00–M10; M11 в работе по Issue #18. Уточнены роли: тесты принимает Claude Opus 5.5, задания и стратегию готовит ChatGPT Astra 6.2. Исходный набор M08 включал 412 основных Linux-тестов и три отдельно запускаемые ресурсные проверки. M08 добавил в CI сборку архивов A и B и стендовые jobs: установщик, systemd, функциональные и сетевые проверки, нагрузку, A→B→A, загрузку в nspawn и в одноразовой VM, а также часовой soak по `workflow_dispatch`. M10 добавляет матрицу CACHE-01 и отдельные проверки конфигурации кеша. M11 добавляет
матрицу A01–A12, API/PTY-тесты и проверку прав записи.

## 1. Принципы

Каждый тест проверяет наблюдаемое поведение или контракт, а не копирует алгоритм реализации. Базовые тесты воспроизводимы без доступа к внешнему Интернету: локальные origin, TCP/TLS echo, управляемый DNS и raw TCP-клиент. Реальный curl проверяет совместимость; специальные клиенты проверяют ошибочные байты, которые curl не генерирует.

Все стенды используют временные каталоги, динамически выделенные порты, предсказуемые данные и cleanup. Специальное разрешение loopback в тестовом config не меняет production defaults. Времена по возможности контролируются тестовыми часами или наблюдаемыми событиями. Тест не должен «проходить», потому что сервер не успел запуститься или запрещённый origin оказался недоступен сам по себе.

Требование связано с тестом через ID из PROJECT_BRIEF.md и таблицы ниже. Минимальный отчёт: SHA, команды, среда, passed/failed/skipped, причина skip и ссылка на CI. Фактические результаты не заполняются заранее.

## 2. Матрица сценариев

| ID | Сценарий и проверяемый результат | Этап |
| --- | --- | --- |
| CFG-01 | Корректный TOML; неизвестные поля, неверные диапазоны, конфликт listener и небезопасный auth отклоняются | M01, M05–M06 |
| CFG-02 | check не открывает listener, не выполняет DNS и не соединяется с upstream; ошибке соответствует ненулевой exit code | M01 |
| CFG-03 | Worker auto/явное число, ноль/переполнение, несколько listener id, дубли и пересечение wildcard; неподдержанные будущие поля отклоняются | M01 |
| CPU-01 | Runtime создаёт заданное число workers, исполняет задачи и корректно завершается; HTTP/CONNECT проверены с 1/2/4 workers при доступных CPU | M01, M03–M08 |
| NET-01 | Два listeners работают одновременно с ожидаемыми правилами; ошибка обязательного bind отменяет весь запуск | M03 |
| NET-02 | Контрольные origin видят именно выбранный source IP; маршрут по listener/source/user/назначению не подменяет ACL | M02–M05 |
| NET-03 | Разные egress/generation не смешиваются в pool; повторный запрос не уходит через чужой профиль | M03, M07 |
| NET-04 | Недоступный bind IP/device, несовместимое семейство и исчезновение адреса дают отказ без fallback через другой профиль | M02–M08 |
| NET-05 | Стенд с двумя veth/NIC подтверждает исходящий интерфейс при настроенных маршрутах; отличие от двух IP на loopback отражено в отчёте | M08 |
| NET-06 | Отклонённые ACL/auth не открывают origin через альтернативный egress; DNS использует задокументированную системную политику | M02–M05 |
| TGT-01 | DNS, IPv4, IPv6, IPv4-mapped IPv6, обязательный CONNECT порт, userinfo и некорректный authority | M02 |
| ACL-01 | First-match и deny по умолчанию; комбинации источника, домена, пользователя, метода и порта | M02, M05 |
| ACL-02 | DNS-смена, смесь разрешённых и запрещённых IP, private/link-local/metadata и прямой IP не обходят политику | M02 |
| ACL-03 | Суффикс домена проверяет границу метки; регистр и завершающая точка нормализуются одинаково | M02 |
| ACL-04 | При отказе нет исходящего SYN/соединения к контрольному origin; тест отдельно доказывает его доступность | M02–M05 |
| HTTP-01 | GET/HEAD/POST/PUT/DELETE/OPTIONS; тело бинарное и текстовое; end-to-end данные сохранены | M03 |
| HTTP-02 | Keep-alive, несколько последовательных запросов, chunked, trailers, HEAD/204/304 и информационные ответы | M03 |
| HTTP-03 | Absolute-form преобразован корректно; Host согласован; hop-by-hop/Connection поля удалены, Authorization сайта сохранён | M03 |
| HTTP-04 | Expect: 100-continue не зависает при allow, early error и отказе auth; корректный порядок сообщений | M03, M05 |
| HTTP-05 | CL+TE, конфликтующие CL, повреждённый chunk, CRLF, недопустимый request-target и большие заголовки не приводят к smuggling | M03 |
| HTTP-06 | Origin оборвал тело, reset сокета, клиент ушёл, POST частично отправлен: нет автоматического повторения и вечных задач | M03 |
| HTTP-07 | Range, If-Range, SSE/долгий HTTP stream проходят согласно таймаутам; неподдержанный Upgrade имеет явный исход | M03 |
| CON-01 | CONNECT передаёт бинарные байты в обе стороны; TLS handshake и полезные данные проходят сквозным образом | M04 |
| CON-02 | Запрещённый порт/IP и connect timeout/refused не дают успешного CONNECT; отказ до открытия туннеля | M04 |
| CON-03 | Байты сразу после заголовков CONNECT сохранены; успешный ответ без CL/TE | M04 |
| CON-04 | EOF/half-close обоих направлений, drain, reset, idle timeout, отмена и SIGTERM не теряют уже принятые байты в пределах политики и не оставляют задачи | M04, M07 |
| AUTH-01 | Нет credentials, плохой пароль, некорректный Basic, неизвестный пользователь → 407 с корректным challenge | M05 |
| AUTH-02 | Смена identity на keep-alive; удаление пользователя и следующий запрос после reload | M05, M07 |
| AUTH-03 | Маркер пароля отсутствует в origin, журналах, диагностике, ошибках и CI artifacts | M05 |
| AUTH-04 | Перегрузка дорогими проверками ограничена; неверный credential большого размера отсекается до хэширования | M05 |
| TLS-01 | Клиент доверяет test CA, проверяет hostname; wrong CA, name и expired certificate вызывают ожидаемый клиентский отказ | M06 |
| TLS-02 | HTTP и TLS listeners различаются; plaintext не принимается как TLS; plain Basic вне loopback запрещён без явного исключения | M06 |
| OPS-01 | Атомарный reload; некорректный файл сохраняет поколение; новый keep-alive request берёт новое поколение | M07 |
| OPS-02 | Активный CONNECT следует зафиксированной политике отзыва; restart-required изменение отклоняется целиком | M07 |
| OPS-03 | SIGTERM ограничивает drain; повторный запуск не оставляет процессов/портов/задач; permit и FD возвращаются | M07 |
| OBS-01 | Коды исходов, байты и длительности верны; нет секретов и labels с неограниченной кардинальностью | M07 |
| LOAD-01 | Slow headers, slow upload/download, backpressure, auth flood и connection flood не создают неограниченные очереди | M03–M07 |
| LOAD-02 | Большой поток при фиксированном числе соединений не требует памяти пропорционально объёму; FD/задачи возвращаются после завершения | M03–M08 |
| REL-01 | Чистая установка, check, старт/стоп/restart systemd, права файлов, обновление и откат конфигурации | M08 |
| PARENT-01 | Отдельные credentials, TLS проверка parent, CONNECT, отказ родителя, egress, ограниченные повторы, петли | M09, обязательно |
| CACHE-01 | Freshness, validators/304, no-store/private, Vary, обход неподдержанных случаев, isolation, eviction и abort | M10, обязательно |
| ADMIN-01 | CLI/TUI используют одинаковый validator и apply; конфликт поколения отвергается; UI не читает секреты | M07 в объёме control service, M11 |
| ADMIN-02 | TUI корректно показывает ограниченные снимки, обрабатывает обрыв API; выход из TUI не останавливает proxy | M11 |
| ADMIN-03 | Web выключен по умолчанию, слушает loopback; admin auth, Host/Origin/CSRF и конфликт порта проверены | M12, если выбран |

### Контракт приёмки M03

Точные 18 групп M03-SRV/HTTP/POL/POOL/NET/RES/CPU/CFG/REG находятся в [задании M03-r1](tasks/M03_HTTP_PROXY.md). База 45e8815e736d2415b833a33213fca9adeea65b0b — 127 пройденных Linux-тестов M02. Serve впервые открывает HTTP listeners: старые stub/help/netguard ожидания меняются адресно, check и invalid serve остаются без сети. Остальные M02 сценарии сохраняются.

Обязательны фактические raw framing/Expect/103/trailers сценарии, origin accept counters для pool reuse/изоляции, реальный peer и egress, fresh DNS при pool hit, ограниченные body queues/завершение tasks/permits, process shutdown и малый resource report. Проверки проходят на настоящем server path, а не только helper functions. Ограничение server 1xx API hyper фиксируется spike, но не исключает требование. Протокольный corpus включает запрос-ловушку после неоднозначного framing; CL+TE может быть обработан только безопасным исходом RFC 9112 с обязательным close либо отклонён.

### Контракт приёмки M02

Точные M02-TGT/ACL/IP/DNS/NET/CFG/ERR/REG сценарии находятся в [задании M02-r1](tasks/M02_NETWORK_POLICY.md). Обязательно сохранить покрытие исходных 53 тестов M01; ожидания для реализованных в M02 новых ключей меняются по правилам совместимости в задании. Дополнительно обязательны отсутствие DNS/dial при раннем deny, IP-проверка каждого DNS-кандидата, удержание permit до реального завершения blocking lookup, реальный TCP dial и наблюдаемый bind двух исходящих loopback IP. Коды классов ошибок и негативные сценарии проверяются по внешнему поведению.

В историческом контракте M02 check и serve не создают сетевой runtime. M03 намеренно заменяет serve stub настоящим сервером и адаптирует его netguard; запрет сети у check сохраняется. Pool и несколько принимающих listeners проверяются в M03, два NIC — в M08; два исходящих loopback IP M02 не заменяют эти проверки.

Историческая матрица принятого CONNECT — [M04-r1](tasks/M04_CONNECT_TUNNELS.md#7-обязательная-матрица-приёмки-18-m04-id). Она конкретизирует CON-01–04, ACL/CFG/NET/LOAD/OPS: early-byte handoff, single writer и порядок 200, отсутствие ложного успеха, TLS site с проверкой CA/имени клиентом, общий budget, bounded relay/drain/shutdown. Прежние M01–M03 проверки сохраняются; изменение старого 501 для CONNECT не разрешает ослабить TRACE/Upgrade/framing/pool assertions.

M03 R1–R9 закрыты на 96af256, PR #10 слит в 9330cd5. Регрессии особенно защищают output counters только для hyper bytes, shared byte-progress idle, один 100 Continue, trailer nominations, bounded task ownership/shutdown, исходный request-target и explicit sender.ready() перед HTTP pool reuse. Эти требования остаются при рефакторинге CONNECT adapters.

### Контракт приёмки M05

Полная матрица 20 M05-ID и точные resource/CI команды — в [M05-r1](tasks/M05_AUTH_USERS.md#9-обязательная-матрица-приёмки--20-m05-id). Baseline: accepted e7afedf, merge 4903788, 242 основных и три separately run resource checks, успешный CI 42988221130. M04-R1–R5 остаются постоянными regression: reverse drain при origin EOF, progress каждого partial write, единый deadline до финального bridge flush, точная проверка TLS errors и раннего payload.

Auth: real Argon2/PHC и bounded verifier mocks для lifecycle; source-denied/malformed без hash/DNS/dial; unknown/disabled через dummy; одинаковый 407, bounded overload/timeout 503, user ACL 403. Проверять request identity на keep-alive/pipeline и на прямом safe outbound API, pool isolation, user egress, TTY no-echo, users file preparation без сети/runtime, transport opt-in, secret markers. Auth jobs удерживают permits после cancel до actual completion; network shutdown не получает нового grace window. Рост RSS/jobs/FD измеряется отдельно от функциональных assertions.

Локальные auth HTTP+CONNECT TLS fixtures работают без внешних сайтов; 10/20 logical clients не подменяют физические устройства/несколько NIC. В отчёте разделить controlled-rate success и overload с учётом всех 503/retries. Все M01–M04 проверки и три explicit resource checks сохраняются; новое тестирование выполняет DeepSeek вместе с реализацией, docs PR не выдаёт их за уже выполненные.

### Контракт приёмки M06

Точные 22 M06-ID и команды — [M06-r1](tasks/M06_TLS_LISTENERS.md#9-обязательная-матрица-приёмки--22-m06-id). База be548e5, accepted349a4e5,311 основных + 3 explicit resource checks; CI43198437631. M05-R1–R3 остаются regression: один runtime/server deadline, typed safe diagnostics (backtick/fake index), безопасные PHC files и интерактивные пароли со специальными символами.

TLS tests разделяют proxy и site trust: разные CA, SAN/expiry/chain errors проверяет реальный клиент, не любой SSL/OSError. Proxy failure не допускает auth/DNS/dial; site failure приходит после допустимого outer TLS/CONNECT. Layered TLS реализован корректным curl/rustls/MemoryBIO client. Проверяются TLS1.2/1.3/ALPN, zero-queue handshake budget, no plaintext fallback, delayed ClientHello, startup atomicity, generic transport writer/flush, TLS1.3 half-close и TLS1.2 closure semantics, abrupt EOF, first-EOF/global shutdown deadlines.

Ключи генерируются во private tempdir, passwords/private key/PHC не выводятся в artifacts; SSLKEYLOGFILE/keylog/early data/resumption выключены. RSS/FD/tasks и фактическая latency записываются;10/20 logical clients с controlled auth rate не подменяют physical NIC/devices. Полные M01–M05 и3 explicit resource checks обязательны. M06 теперь принят:357 основных тестов+3 resource checks, post-merge CI43403004578 success. Его историческое задание остаётся неизменным; документационная постановка M07 не реализует новые операции.

### Контракт приёмки M07

Полная матрица **25 M07-ID** — [M07-r1](tasks/M07_OPERATIONS.md), Issue #20. Нужны атомарная публикация/CAS/rollback, whole snapshot для old/new exchanges/users, per-request source/auth/policy и pool isolation, глобальные budgets при cap lower/raise и actual native jobs, max16 roots, cancel/late prepare, SIGHUP storm и один shutdown deadline с blocked TLS/log pipe. JSON секреты/кардинальность/record sizes/overflow и metrics actual lifecycle проверяются как самостоятельные свойства, не копией helpers.

Контрольные M06 cases: continuous256B/20ms передаёт16KiB дольше idle1s; early write на21ms + stall завершается примерно через1s от последней записи; zero-progress также bounded. Не возвращать synthetic timer progress. Негативные проверки обязаны отвергать outer timeout и отличать clean TLS close от допустимого force RST.

M04 forced-shutdown test стабилизируется в M07: EOF или конкретный reset допускаются только при действительном force close с actual cleanup; >=20 последовательных Linux повторов, без skip и без ослабления graceful/body/half-close checks. Прежние локальные failures не суммируются в pass. Resource/load reports считают все attempts/errors/retries и проверяют bounded queues/threads/FD/RSS/generations;10/20 clients не означают physical devices/NIC. Systemd/release soak остаются M08.

## 3. Уровни проверок

**Unit:** канонизация целей, правила ACL, схема config, ошибки credentials, преобразования разрешённых заголовков, состояние limiter. Ожидания выводятся из требований и RFC, а не из тех же helper-функций, которые проверяются.

**Integration:** настоящий процесс Angara или сервис через публичный интерфейс, локальный origin, TCP/TLS endpoints и контролируемый resolver. Проверяются фактические запросы, ответы, байты, количество соединений и завершение.

**End-to-end:** curl через HTTP и HTTPS proxy, HTTP и HTTPS сайты тестового стенда, файлы, uploads, Range и долгие туннели. Неподдерживаемая возможность конкретной сборки curl отмечается; обязательный release сценарий запускается на runner, где она доступна. Ручной браузерный сценарий владельца дополняет автоматические проверки.

**Property/fuzz:** нормализаторы URI/authority, конфигурация, ACL, преобразования заголовков и raw HTTP boundary. Добавляются по мере появления кода. Fuzzer имеет CPU/RAM/time limits и не выпускает трафик в Интернет. При обнаруженной ошибке минимальный воспроизводитель становится регрессией.

**Load/soak/fault:** измерения latency, throughput, RSS, FD, задач и ошибок при HTTP, CONNECT, TLS и auth. Ошибки DNS/connect/reset, медленные peers и неверный reload встраиваются в стенд. Публичный runner не используется для точных сравнений скорости.

## 4. Проверки CI

| Событие | Проверки | Условие введения |
| --- | --- | --- |
| PR | Format, lint, locked build, unit/integration, проверка документации и config | С M01, проверки добавляются с соответствующей функцией |
| Изменение зависимостей и выпуск | Advisory/license policy, lockfile, происхождение и список зависимостей | Инструмент и допустимая политика утверждаются в M01; исключения документируются |
| Изменение parser/policy/transport | Целевой негативный корпус и ограниченный fuzz smoke | С M02/M03 |
| По согласованному расписанию или вручную | Более длинный fuzz, soak, дополнительные платформы | После настройки runner и лимитов расходов |
| Release candidate | Полная обязательная регрессия, установка на целевой ОС, load/soak, артефакт и checksums | M08 |

Конкретные команды и версии CI-инструментов пишет DeepSeek в M01. План не создаёт workflows, расписания или automation сам по себе. Actions из внешних репозиториев предлагается закреплять commit SHA; PR jobs не получают write tokens и production secrets. Возможность технической защиты main проверяется отдельно для приватного репозитория и текущего тарифа.

## 5. Нагрузка и целевые значения

Первый benchmark фиксирует CPU/RAM, ядро/дистрибутив, сборку, конфигурацию, TLS/auth режим, сеть, origin и параметры клиента. Раздельно измеряются small HTTP, streaming большого объекта и CONNECT. Сравнение со Squid выполняется только при сопоставимых ACL, auth, TLS, журналировании и кэше.

Первый обязательный пилот охватывает 10 и 20 устройств либо явно обозначенную эмуляцию такого числа независимых клиентов. Число устройств, идентичностей, запросов, TCP-соединений и CONNECT-туннелей приводится отдельно. Профили с одним и несколькими соединениями на клиента фиксируются до запуска; предел соединений не устанавливается равным 20 только из-за размера пилота.

На доступном многоядерном стенде сравниваются 1/2/4 workers при одинаковой конфигурации, с CPU по потокам и общими ресурсами. Результат не обязан быть линейным: цель — подтвердить многопоточную работу, отсутствие сериализации всего трафика и измерить поведение. Ограниченный runner с одним CPU не подтверждает масштабирование.

NET-05 выполняется в отдельном Linux-стенде с двумя интерфейсами и явной маршрутизацией; доступность namespaces/capabilities указывается. Если стенд недоступен в текущем CI, сценарий переносится на подходящий runner до заявления о проверенной поддержке нескольких NIC, а не помечается пройденным по двум loopback IP.

После базового прогона владелец утверждает необходимое число соединений, throughput и допустимые latency/RSS. До этого блокирующие инварианты: нет неконтролируемого роста при фиксированной нагрузке, поток не буферизуется целиком, после завершения возвращаются FD/permits/задачи и перегрузка приводит к ограниченному отказу.

В [M08-r1](tasks/M08_RELEASE_CANDIDATE.md) закреплены две когорты (10 и 20 клиентов), часовой прогон с TLS и Basic на 20 клиентах и отдельный профиль перегрузки. Документ задаёт длительность, объёмы потоковой передачи, исходные пороги RSS/FD и формат измерений. Рабочую нагрузку клиентов и физические устройства учитывать раздельно. [Issue #23](https://github.com/AlexeiSmol/Angara/issues/23)

Проверка утечки RSS в `tests/m08/soak.py` не использует один warmed baseline:
`tests/m08/soak_rss.py` переходит на поминутные медианы, выделяет ступени
аллокатора от 8 МиБ (не более двух во второй половине прогона), вычитает их и
проверяет наклон Theil–Sen не больше 128 КиБ/мин. Это ловит линейную утечку
16–32 МиБ/ч и не падает от одной поздней ступени. Абсолютный предел
`peak_kib <= 524288` сохранён. Все значения, найденные ступени и пороги
пишутся в `soak.json` как `rss_check`. Синтетические ступени, утечки и
лестница проверяются `tests/m08/soak_rss_test.py` на поминутных медианах
семи реальных прогонов; этот self-test запускается в CI. Baseline остаётся в
отчёте для диагностики и проверки FD, но не является решающим для RSS.
Короткие когорты 10/20 клиентов проверяют абсолютный пик RSS и FD; проверку
утечки по наклону выполняет только часовой soak.

### Приёмка M08 на установленном архиве

Полный перечень содержит 18 групп. Проверить происхождение артефакта, безопасную установку, реальный systemd, смену версии A→B→A, две сети и несколько CPU. Для каждого результата фиксировать полный SHA и SHA-256 архива. Часовой сценарий должен запускаться до слияния на ветке реализации или на отдельной VM. Регрессию и отрицательные сценарии M01–M07 сохранить. [M08-r1](tasks/M08_RELEASE_CANDIDATE.md)

### Контракт приёмки M09 (PARENT-01)

Локальные проверки: `cargo test --locked --test config_m09` (11 тестов) и `cargo test --locked --test m09_parent` (35 тестов).

| Строка PARENT-01 | Тесты |
| --- | --- |
| Старый конфиг, выбор по правилам, default и явный direct | `m09_cfg01`, `m09_cfg02`, `m09_parent07`, `m09_parent13`, `m09_parent22` |
| HTTP и HTTPS до parent; HTTP к имени/IP, клиентский CONNECT, path/query, Host, IPv6, большой POST | `m09_parent01`, `m09_parent02`, `m09_parent03`, `m09_parent08`, `m09_parent09`, `m09_parent12`, `m09_parent15` |
| Разделение секретов | `m09_parent04`, `m09_parent14`, `m09_parent23` |
| Клиентские отказы и DNS | `m09_parent20` (IP deny, нулевые счётчики), `m09_parent21` (ACL deny, нулевые счётчики), `m09_parent02` (parent получает числовой IP) |
| HTTP к имени через туннель | `m09_parent02`, `m09_parent05`, `m09_parent11` |
| TLS и отказы parent | `m09_parent05`, `m09_parent06`, `m09_parent08`, `m09_parent10`, `m09_parent11`, `m09_parent19`, `m09_parent25` (обрыв без replay POST) |
| TLS-parent: `close_notify`, обрыв и parent ID в отказе CONNECT | `m09_parent28` (client EOF → success/completed), `m09_parent29` (обрыв до client EOF → failed/error), `m09_parent30` (407/503 CONNECT → `parent_id`,`route=parent`,`reason=error`), `m09_parent31` (`close_notify` + немедленный TCP close → success/completed) |
| Сетевой интерфейс и поколения | `m09_parent13`, `m09_parent23` (два parent/credentials), `m09_parent24` (bind_ip source + IPv6 target) |
| Петли и ресурсы | `m09_parent16a` (A→B без петли, оба Via в HTTP), `m09_parent16b` (HTTP к IP: петля, счётчик на вернувшемся A), `m09_parent16c` (клиентский CONNECT: петля), `m09_parent16d` (HTTP к имени: петля), `m09_parent16e`/`16f` (цепочка A→B без петли для CONNECT/HTTP, оба Via во внешнем CONNECT), `m09_parent17` (10 HTTP + 10 CONNECT), `m09_parent18` (tunnel log) |
| Angara как parent: HTTP-порт только для адреса A | `m09_parent27` |
| Совместимость со Squid | реальный Squid smoke на Ubuntu 24.04; см. отчёт PR |

Дополнительно: `m09_cfg11` проверяет `runtime.instance_id` и стабильный default; `m09_cfg03`/`m09_cfg04` — неизвестные/зарезервированные ID; `m09_cfg07` — режимы credentials 0600/0640/0644; `m09_cfg10` — непригодный parent IP.

Реальный Squid на Ubuntu 24.04: HTTP parent, `CONNECT` к проверенному IP для доменного HTTP и клиентского CONNECT, отдельный экземпляр на своём порту, ограниченный список CONNECT-портов и проверка отказа при снятии разрешения. HTTPS-parent проверяется локальным TLS fixture: Squid как HTTPS parent не является стандартным режимом. Режимы с parent Basic auth проверены локальным контрольным parent; для реального Squid smoke использовался анонимный HTTP parent. Это ограничение фиксируется в отчёте PR, а не выдаётся за проверенное.

## 6. Как Claude Opus 5.5 принимает тесты

Claude Opus 5.5 оценивает соответствие сценария требованию, проверяет отрицательные случаи и качество assertions. Независимо запускает доступные существенные проверки либо читает реальные CI logs для точного SHA; недоступный локальный runtime указывает как ограничение. Самоотчёт DeepSeek без воспроизводимых команд и результатов недостаточен.

Итоговое заключение различает: подтверждённые проверки, вывод по прочитанному коду, неисполненные сценарии и открытые риски. Процент coverage может помогать искать пробелы, но не заменяет матрицу протокольных, ACL и ресурсных инвариантов.

### Контракт приёмки M10 (CACHE-01)

Локальные проверки: `cargo test --locked --test config_m10` (6 тестов),
`cargo test --locked --test m10_cache` (46 тестов), `m10_limits` (3 Linux-теста
RSS/медленного читателя/реестра epoch) и unit-тесты `cache::tests` (16 тестов).
Полный прогон на ветке реализации: `cargo test --locked` — 539 passed, 0 failed, 3 ignored;
`cargo test --locked --test m10_cache` повторяется для проверки стабильности.

| Строка CACHE-01 | Тесты |
| --- | --- |
| Выключен / холодный / прогретый | `m10_cache01`–`m10_cache03`: два GET → один origin; старый конфиг/`enabled=false` → два origin; path/query/порт |
| Свежесть и варианты | `m10_cache04`–`m10_cache08`: `Age`/граница, `s-maxage`, `Expires`/`Date`, gzip/identity/отсутствие `Accept-Encoding`, `Vary: *`; unit `vary_change_removes_incompatible_variant` |
| Ревалидация | `m10_cache09`–`m10_cache14`, `m10_cache34`–`m10_cache36`, `m10_cache39`, `m10_cache47`: ETag/Last-Modified → 304 → полное тело; 200 заменяет; ошибка/таймаут/отказ соединения — штатная ошибка прокси; непригодный 304 и другой/слабый ETag → один безусловный GET; многострочный `Cache-Control` в 304; клиентские `If-*`/Range |
| Приватность и ACL | `m10_cache15`–`m10_cache19`, `m10_cache30`, `m10_cache38`: Authorization/Cookie/Set-Cookie, пользователи, listeners, egress, поколение, ACL deny на прогретом кеше, журналы/метрики без URL и тел |
| Маршрутизация | `m10_cache20`, `m10_cache21`, `m10_cache28`, `m10_cache40`: parent bypass, CONNECT, смена endpoint, отказ parent после предыдущего успеха |
| Инвалидирование | `m10_cache27`, `m10_cache33`, `m10_cache44`, `m10_cache48`: POST инвалидирует URI, same-origin `Location`, наполнение другого URI не отменяется, 8300 idle POST при удерживаемом медленном наполнении A не отменяют его; unit `invalidation_discards_an_inflight_fill`, `invalidation_of_another_uri_keeps_the_inflight_fill`, `active_uri_registry_is_empty_after_finish_and_drop`, `invalidation_between_two_fills_cancels_the_second` |
| Память и потоковая передача | `m10_cache22`–`m10_cache24`, `m10_cache31`, `m10_cache32`, `m10_cache43`, `m10_cache45`, `m10_cache46`, `m10_limits01`, `m10_limits02`, `m10_limits03`: малый бюджет/LRU, 20 клиентов на прогретой записи и при малом бюджете, слишком большой/оборванный ответ, trailers, reload/shutdown во время наполнения, RSS после крупных `no-store` ответов, медленный читатель, ограниченный реестр epoch URI и 8300 idle invalidations; unit `store_evicts_and_accounts_bodies`, `incomplete_or_oversized_fill_is_not_published`, `slow_reader_keeps_evicted_object_accounted`, `revalidation_updates_header_accounting` |
| Директивы клиента | `m10_cache25`–`m10_cache26`, `m10_cache37`: `only-if-cached` холодный/тёплый/просроченный → 504 или ответ; `no-cache`/`min-fresh` → upstream |
| Конфигурация | `m10_cfg01`–`m10_cfg06`: отсутствие/выключение, defaults, диапазоны, cross-field предел, restart-required, `angara check` |
| TLS-вход | `m10_cache29` (HTTPS listener использует тот же кеш) |

Кеш по умолчанию выключен. Полный `workflow_dispatch` с часовым soak по D57
обязателен для изменения `src/`. Отдельный сценарий `tests/m08/cache_load.sh`
запускается в Ubuntu CI job `10/20 clients, workers and streaming`, использует
10 и 20 клиентов, проверяет `cache_hit`/`cache_miss`/`cache_entries`/`cache_bytes`
и RSS-прирост, затем когорту из 128 уникальных URI при `max_entries = 64` и
проверяет `cache_eviction > 0`. Штатный soak с выключенным кешем сам по себе не
подтверждает CACHE-01.

### Контракт приёмки M11 (A01–A12)

Локальные автоматические проверки M11:

```sh
cargo test --locked --test m11_control
cargo test --locked --test m11_tui
cargo test --locked --lib
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

`m11_control` покрывает снимки двух клиентов, страницы users/blocks/access,
события, добавление/смену пароля, старый/новый `407`, блокировки, истечение
по серверным часам без записи TOML, рестарт после истечения, дубликат,
конфликт версии, внешнюю правку, ACL first-match реальным HTTP, сохранение
комментариев/секций, `restart_required`, право записи и лимиты строки/страницы.
`m11_tui` запускает бинарник в PTY, проверяет отрисовку, поиск, resize,
альтернативный экран, восстановление терминала и состояние «нет связи».

| ID | Автоматическая часть | Ручная/стендовая часть |
| --- | --- | --- |
| A01 | PTY: две сессии не требуются для API; `snapshot`/`connections` | Две SSH-панели, закрытие одной при трафике, восстановление терминала |
| A02 | `m11_write01`: add/password, старый 407, новый 200, ACL 403 | Проверка на установленном unit |
| A03 | `m11_write01`: блокировка, keep-alive/new CONNECT/кеш — 407 | Открытый CONNECT до/после блокировки на стенде |
| A04 | `m11_write01`, `m11_expiry01`: временная/бессрочная, снятие, v1/v2 | Две сессии и отображение часового пояса |
| A05 | `m11_expiry01`: до/граница/после и рестарт | Реальный systemd и часы стенда |
| A06 | `m11_conflict01`, `m11_external01` | Сравнение черновика с актуальной версией |
| A07 | `m11_acl01`, `m11_acl02`: create/move/delete, first-match | Комментарии, соседние секции, CONNECT |
| A08 | `m11_restart01`: restart-required, прежнее поколение | Отказ reload после сохранения на стенде |
| A09 | `m11_conflict01`, `m11_external01`; отказ до/после rename — unit `control_files` | Обрыв связи/рестарт writer, права |
| A10 | `m11_auth01`: read-only peer не пишет; ответы/события без пароля/PHC | Проверка `nobody`, прав файлов и unit |
| A11 | `m11_api01`: события и общий курсор; `m11_tui` | Две TUI и независимый клиент, пропуск событий |
| A12 | `m11_limits01`; полный regression `cargo test --locked` | Нагрузка без TUI и с медленными клиентами, RSS/латентность на стенде |

Скриншоты: `docs/screenshots/m11-wide.png` (120×32, пользователи) и
`docs/screenshots/m11-narrow.png` (80×24, доступ). Они получены
`examples/m11_screenshot.rs` на синтетических данных и не содержат реальных
паролей, PHC или адресов инфраструктуры.

Для изменения `src/`/`packaging/` по D57 нужен полный `workflow_dispatch` с
часовым soak на финальном SHA; запускает владелец.
