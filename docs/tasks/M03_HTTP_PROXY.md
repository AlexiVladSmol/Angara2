# DeepSeek: M03 — потоковый HTTP/1.1 proxy

Статус: READY, редакция M03-r1 от 9 ноября 2026 года.
Постановка и ревью: Codex. Реализация, тесты и CI: DeepSeek V4.1 Flash 1017.
База реализации: main, коммит `45e8815e736d2415b833a33213fca9adeea65b0b`.
M02 принят [повторным ревью](https://github.com/AlexeiSmol/Angara/pull/7#issuecomment-6742067237) и слит в PR #7 по поручению владельца. На Linux проходят 127 тестов; это исходная регрессия M03.

## 1. Наблюдаемый результат и порядок работы

`angara serve --config <path>` действительно запускает HTTP/1.1 forward proxy на всех настроенных HTTP listeners. Через него локальный curl выполняет GET/HEAD/POST/PUT/DELETE/OPTIONS, передаёт большие и потоковые тела, получает ответы и повторно использует клиентское соединение. Источник берётся из принятого TCP-сокета. Для каждого запроса выполняются правила M02; origin наблюдает выбранный egress bind IP.

В M03 входят корректность HTTP, ограниченный origin connection pool и необходимые этому пути лимиты/остановка. CONNECT-туннель — M04; локальные пользователи и 407 — M05; TLS listener — M06; reload, развитая телеметрия и control service — M07. Промежуточный сервер предназначен для изолированного локального стенда до M05/M06.

Начать с короткого плана в связанном Issue: зависимости/features, границы модулей, владение соединениями и задачами, API policy/pool, способ обработки 1xx и framing, последовательность тестов. Ветка `feat/<issue>-m03-http-proxy` создаётся от указанной базы кода, PR — в main. Согласованная документация читается на SHA, закреплённом в Issue; открытый PR постановки не блокирует реализацию. Не сливать документацию или чужую реализацию без поручения владельца.

Выполнять части последовательно, с проверками после каждой:

1. Короткий технический spike на закрепляемой версии hyper: строгий framing, Expect/100, 103 → final, trailers и lifetime Body. Результат и выбранный механизм записать в Issue.
2. HTTP конфигурация, transaction startup всех listeners, trusted peer context, ограниченный учёт задач и остановка.
3. Один потоковый обмен через policy/egress M02: канонизация, заголовки, ошибки и тела.
4. Keep-alive, bounded pool и повторная авторизация при reuse; 1xx/trailers/Expect и негативный raw TCP-корпус.
5. Backpressure, отмена, таймауты, многопоточность, CLI/CI и инструкция ручного стенда.

Наличие spike не заменяет реализацию функций в основном пути и их приёмку. Если выбранная библиотека не позволяет выполнить контракт, описать конкретный блокер и варианты в Issue; не объявлять passed по обходному демонстрационному примеру.

## 2. Архитектурные границы и M02

| Компонент | Ответственность |
| --- | --- |
| listener / server | All-or-nothing bind, accept, trusted peer IP/listener_id, client permits, registry задач |
| proxy/http | Одна HTTP-транзакция, framing, преобразование заголовков, потоковые тела, mapping ошибок |
| policy / target / routing | Единая канонизация и те же проверки M02; права не выдаются HTTP adapter или pool |
| resolver / transport | Общие бюджеты M02, один свежий lookup домена на запрос, dial проверенного SocketAddr |
| pool | Ограниченные пригодные HTTP/1.1 origin connections, lease до завершения обмена, eviction |
| body / I/O wrappers | Backpressure, ограниченные буферы, idle/cancellation, завершение lease и permits |
| runtime / CLI | Запуск и контролируемая остановка; check остаётся без сети |

Названия модулей можно адаптировать. Один процесс/crate, многопоточный Tokio; никакой глобальной блокировки на весь обмен/тело. Нельзя держать mutex pool во время DNS, connect, чтения или записи тела.

Использовать hyper 1.x с HTTP/1 client/server и необходимыми runtime adapters (например hyper-util TokioIo, http-body-util, bytes). Tokio signal и другие фактически нужные features разрешены. Точные совместимые версии закрепить Cargo.lock и указать в плане. Не менять Rust toolchain, не добавлять HTTP/2/TLS/reqwest с собственным DNS/автоповторами, unsafe, fork/patch hyper или новый HTTP backend без отдельного решения. Имеющийся http/IDNA/IP normalizer M02 сохраняется.

Сеть origin получает уже разрешённый IP. Высокоуровневый connector hyper-util, который заново разрешит имя или сам выполнит retry, не должен обходить M02. Использовать handshake над `Connected` либо эквивалентную закрытую границу владения.

Для pool разрешён необходимый рефакторинг M02: разделить подготовку авторизованного плана и открытие нового сокета. План содержит canonical target, source/listener, matched rule, один egress, generation и разрешённые адреса, создаётся только проверяющим кодом. Сохранить `open_outbound` как полный безопасный путь и все его регрессии. Не вводить публичные unchecked constructors или второй, менее строгий набор ACL для HTTP.

Порядок для каждого нового HTTP-запроса, включая второй запрос на том же клиентском соединении и pool hit:

1. Зафиксировать config snapshot/generation, взять реальный peer IP и listener_id; X-Forwarded-For/Forwarded не заменяют peer.
2. Проверить форму запроса, HTTP version, Host/framing, source gate и request ACL.
3. Выбрать один egress, выполнить один свежий DNS lookup для Domain и IP-политику каждого кандидата; для прямого IP — тот же IP-контроль без DNS.
4. Искать pool connection только среди разрешённых сейчас endpoints, затем при необходимости dial по правилам M02.
5. Выполнить один обмен без автоматического повторения запроса. Ошибка после начала записи не повторяет ни headers, ни body.

Отсутствие DNS cache и повторный lookup при reuse — консервативный контракт M03. Будущая оптимизация DNS не может быть внесена молча. Generation в M03 остаётся 1; корректность разделения разных поколений проверяется через библиотечный интерфейс/fixtures, reload не добавляется.

## 3. Listener, CLI и остановка

- `check` по-прежнему только загружает/валидирует config: никакого runtime, bind, DNS или connect.
- `serve` валидирует config до сетевых действий, создаёт runtime с заданным worker_threads и подготавливает все обязательные listeners. При ошибке любого bind закрывает уже открытые сокеты и не начинает обслуживание ни на одном listener. Код startup/runtime failure — 3; прежний смысл «proxy не реализован» и соответствующая справка заменяются.
- После успешной подготовки всех listeners начинается accept. По каждому соединению фиксируются peer IP и стабильный listener_id. IPv6 wildcard реализует согласованный IPV6_V6ONLY, чтобы не разрушить разрешённую M01 комбинацию IPv4+IPv6 listeners.
- Client budget общий для всех listeners и clone; permit удерживается до фактического закрытия client socket, включая keep-alive idle. Отказ source gate закрывает клиентское соединение до чтения тела/DNS/dial; HTTP 403 выдаётся, если запрос уже безопасно разобран. До появления HTTP-сообщения допустимо закрытие без ответа.
- При исчерпании client budget не создавать растущую очередь ожидающих permit задач. Допустим один временный принятый сокет на accept loop, немедленно закрываемый при отказе; это не новая обслуживающая задача.
- Базовая остановка по SIGINT/SIGTERM и через библиотечный shutdown handle обязательна уже здесь. Остановить accept, запретить новые обмены/выдачу pool leases, закрыть idle pool, завершить активные операции в пределах shutdown_timeout_ms; затем отменить и дождаться учтённых задач/закрытия сокетов.
- У shutdown один общий deadline, а не полный shutdown_timeout_ms на каждую задачу по очереди. Все spawned connection/pool/body tasks учитываются. Начатый blocking getaddrinfo имеет задокументированное ограничение M02; остановка не объявляет его принудительно отменённым и не обходится новым бюджетом.
- Нормальное завершение по сигналу — 0, ошибка конфигурации — 1, usage — 2, ошибка запуска/неожиданное завершение сервера — 3. Готовность объявлять только после полного startup. Библиотечный тестовый API может использовать заранее связанные sockets с портом 0; production config по-прежнему отвергает port=0.

## 4. HTTP request/response и заголовки

### 4.1 Формы и методы

Вход M03 — HTTP/1.1, absolute-form `http://authority/path?query`. HTTP/1.0 при распознанном запросе — 505 и close; HTTP/2/h2c не включаются, его preface не должен попадать на origin. Origin-form, userinfo, fragment, https absolute-form, неправильные authority/port, неоднозначные numeric IP и запрещённые символы отклоняются по M02. Поддержать IPv4/IPv6/mapped и IDNA-совместимые ASCII wire имена, включая исправленные hex-подобные метки.

К origin отправляется origin-form с теми же path/query bytes и согласованным Host. Host обязателен ровно один; отсутствие, дубли или конфликт с URI — 400/close до DNS/dial. Не выбирать назначение по Host вместо absolute URI. Применять правила RFC 9112 для OPTIONS absolute-form с пустым path/query, когда последнему proxy требуется отправить `*`.

Forwarding работает для корректных method tokens, разрешённых ACL; обязательные проверки GET/HEAD/POST/PUT/DELETE/OPTIONS и PATCH. TRACE в M03 отвергается 501 без отражения заголовков. Корректный CONNECT получает 501 без TCP dial; неверный CONNECT target — 400. Upgrade/WebSocket запрос — 501/close без dial. Нельзя возвращать успешный CONNECT или 101. Неожиданный upstream 101 — 502/close и eviction.

### 4.2 Hop-by-hop и end-to-end

Для запросов и ответов обработать все строки Connection и все перечисленные ими field names без учёта регистра; сначала разобрать nominations, затем удалять. Удалить Connection, Proxy-Connection, Keep-Alive, Upgrade и соответствующие поля. Неверный token list — безопасный отказ/close. Не ограничиваться удалением первого Connection или фиксированным списком.

Transfer-Encoding, Content-Length, TE и Trailer согласуются с фактическим outgoing body/framing, а не копируются независимо. TE не пересылается как произвольный transfer coding; согласованная поддержка `trailers` и её Connection option формируются на соответствующем hop. Чанковое кодирование может быть создано заново. Никогда не выдавать CL+TE одновременно.

Proxy-Authorization и Proxy-Authentication-Info не отправляются origin, в том числе через trailers; в M03 они не дают прав и не запускают auth. Origin Authorization/WWW-Authenticate, Cookie/Set-Cookie, Range/If-Range, условные запросы, Content-Encoding и остальные допустимые end-to-end поля сохраняют смысл. Повторные Set-Cookie не склеивать через запятую. Содержимое не декомпрессировать и не преобразовывать.

Добавлять `Via: 1.1 angara` в forwarded request/response с сохранением предыдущих Via. При обнаружении своего received-by token `angara` во входной цепочке — 508/close до DNS/dial; не искать простую подстроку в hostname. Локальные ошибки не обязаны выдавать Via как forwarded сообщение.

У OPTIONS проверить Max-Forwards: корректное неотрицательное значение декрементировать при пересылке; 0 обработать локальным финальным 204 без origin, после source gate/request ACL. Неверное/дублированное или непредставимое значение — 400. Не добавлять Max-Forwards, если его не было. TRACE остаётся 501. Эти локальные ветки не обходят ACL.

### 4.3 Framing и негативные сообщения

Использовать готовый HTTP parser/decoder. Запрещено писать собственный парсер сырых HTTP/chunked сообщений или считать split по CRLF полноценной защитой. Проверить поведение именно закреплённой версии, до того как изменения parser скрыты нормализованной HeaderMap.

- Конфликтующие/некорректные CL, неподдержанные transfer codings, repeated chunked, chunked не последним, malformed chunk, obs-fold, whitespace перед двоеточием и CRLF/control injection дают безопасный отказ и закрытие соответствующих соединений. M03 поддерживает только одно chunked transfer coding; gzip/deflate и другие transfer codings, в том числе перед chunked, отклоняются (request 400, response 502). Content-Encoding остаётся end-to-end и передаётся без изменения.
- Для CL+TE допустимы только два безопасных исхода RFC 9112 §6.3: отказ/close либо обработка по TE с удалением CL, однозначным outgoing framing и обязательным закрытием входного соединения после ответа. Зафиксировать один фактический исход в тестах. Silent keep-alive после такой комбинации запрещён. Это не ослабление теста до «любой 200»: тест доказывает границы тела и отсутствие второго запроса на origin.
- Одинаковые дубли CL могут нормализоваться библиотекой только при одном недвусмысленном framing; различные значения всегда отклоняются. Проверить обе формы: отдельные поля и comma-list.
- При ошибке body после отправки финальных headers не дописывать вторую HTTP-ошибку в поток; оборвать передачу, закрыть соединения и убрать origin из pool.
- Негативный raw TCP-корпус включает запрос-ловушку после неоднозначного/повреждённого сообщения. Подтвердить, что origin не получил неожиданный дополнительный запрос; один лишь статус первого ответа не доказывает отсутствие smuggling.

## 5. Тела, trailers, Expect и промежуточные ответы

Тела запросов/ответов передаются потоково с backpressure. Запрещены collect/to_bytes/read_to_end и память, растущая вместе с body size. Разрешены ограниченные небольшие локальные error bodies. Upstream response должен начинать поступать клиенту до окончания большого body; аналогично upload начинается до полного чтения клиента.

Поддержать fixed CL, chunked request/response, binary bytes, пустое тело, HTTP response до EOF, HEAD и статусы 204/304. Не отправлять запрещённое тело; CL у HEAD/304 может отражать длину представления по RFC, а не размер пустой payload. Неверный upstream framing не должен загрязнять pool или следующий ответ.

Trailers проходят в обе стороны при допустимом HTTP/1.1 framing и согласовании приёма. Фильтруются Connection-nominated и запрещённые trailer поля: framing/routing/authentication/control (в частности CL, TE, Host, Connection, Authorization, Proxy-Authorization и их proxy-auth companions). Не превращать trailer с такими полями в обычный header. Протокольную ошибку закрыть; допустимые синтетические `X-Checksum` trailers сохранить. Пределы числа/байтов trailers такие же, как для headers; пустые/повторные допустимые поля обрабатываются библиотекой без склеивания специальных значений.

Для `Expect: 100-continue` proxy локально управляет ожиданием: сначала проверки и готовность разрешённого origin connection, затем при необходимости 100 перед чтением body; Expect к origin не пересылается. Ранний deny/error отдаёт финальный ответ/close без 100 и без чтения всего upload. Неизвестное expectation — 417/close до dial. Клиент, который ждёт 100 и ещё не отправил тело, не должен зависать; клиент, который отправил тело сразу, также работает. Не выдавать два 100 для одного expectation.

Промежуточные origin ответы 102/103 и другие допустимые 1xx, кроме неподдержанного 101, передаются клиенту в порядке до final response; headers фильтруются теми же правилами. Они не завершают обмен и не обновляют абсолютный срок ожидания финальных response headers. Проверить несколько 103, затем 200 и тело; origin 100 при удалённом Expect считается неподдержанным ответом upstream: 502/close до final headers, без повторного локального 100. Обычный 100 для клиентского expectation генерирует именно proxy. Этот ограниченный случай не выдаётся за прозрачное forwarding всех возможных upstream 100.

**Известная граница библиотеки:** при подготовке задания hyper 1.12.0 имеет client `on_informational`, но обычный server Service возвращает один Response и не даёт просто вернуть 103, затем 200. См. [hyper #2426](https://github.com/hyperium/hyper/issues/2426) и [server encoder](https://github.com/hyperium/hyper/blob/v1.12.0/src/proto/h1/role.rs). Поэтому обязательна проверка из шага 1; наличие callback на клиенте само по себе не закрывает forwarding 1xx.

Допустим узкий bounded adapter записи interim heads из типизированных http status/headers, если серверный API закреплённой версии не умеет их выдавать. Все output writes, включая автоматический 100, interim и final headers/body, должны иметь одного упорядоченного владельца; нельзя параллельно писать raw bytes напрямую в socket из callback. HTTP parsing/framing остаётся библиотечным. Не сериализовать непроверенные сырые строки. Очередь максимум 16 interim heads и 64 KiB суммарно на обмен; overflow завершает обмен ошибкой/close, а не скрытым пропуском 1xx или unbounded queue. Если такой adapter нельзя сделать корректно без изменения архитектуры, вынести конкретный вопрос до основной реализации; молча терять 103 нельзя.

## 6. Connection pool и владение ресурсами

Origin keep-alive reuse должен быть реализован и проверен. Минимальный ключ: canonical origin (тип host, имя/IP и port), фактический endpoint IP:port, egress_id и config generation; допустима более строгая изоляция по listener. Разные host/egress/generation не объединяются. Идентичности пока нет; M05 расширит ограничения reuse, не вводить автоматически разрешённого placeholder user.

- Lease эксклюзивен на HTTP/1.1 обмен. В M03 не нужен upstream pipelining; одна активная транзакция на origin connection.
- Возвращать в idle pool только после полного успешного завершения request body и response body/trailers, здорового protocol driver и допустимого keep-alive обоих сообщений.
- Response headers или выдача Body клиенту не освобождают socket permit и не разрешают следующему запросу занять тот же stream. Полная отмена/ошибка/ранний response при незавершённом upload закрывает origin connection; не выполнять неограниченное draining.
- Drop downstream Body, client disconnect, framing error, idle/response timeout, server shutdown, origin close/reset и обнаруженный stale socket приводят к eviction и освобождению permit после закрытия реального сокета.
- Idle sockets тоже удерживают общий outbound permit M02. При давлении на outbound budget можно вытеснить idle socket, закрыв его до нового dial; нельзя создать временный неучтённый stream.
- При pool miss/full нет неограниченной очереди ожидания свободного соединения. Допустим немедленный 503 при исчерпании общего бюджета. Бounded lookup/eviction не создают вечный registry всех встреченных доменов: после удаления последнего socket пустой key удаляется.
- Все clone/listeners используют один pool и одни budgets данного server instance. Два независимых server instance в тесте могут иметь разные снимки; соединение нельзя передать из поколения 1 в поколение 2.
- При смене DNS-ответа разрешается reuse только socket с endpoint, входящим в новый разрешённый набор. Не совпал — новый dial/отказ; старый socket не выдаётся этому запросу.
- Автоматического retry после pool failure нет даже для GET; это консервативная политика M03. Следующий отдельный клиентский запрос может открыть новое соединение. Повторные IP connect attempts до отправки HTTP сохраняют пределы M02.

## 7. Конфигурация и сроки

schema_version остаётся 1. Старые четыре примера валидны. Все уровни deny_unknown_fields, нули/отрицательные/overflow и неразрешённые поля отклоняются без эха значений/секретов. Добавляется только нужный HTTP объём:

| Поле | Default | Допустимое значение и смысл |
| --- | --- | --- |
| limits.max_client_connections | limits.max_connections | 1..=65535, принятые клиентские sockets во всех listeners, включая keep-alive idle |
| http.max_headers | 100 | 1..=256, число полей каждого request/response/interim/trailer section |
| http.response_header_timeout_ms | 30000 | 100..=300000, от начала отправки upstream request headers до final response headers, включая время upload; 1xx не перезапускают срок |
| http.pool_max_idle | min(16, limits.max_connections) | 0..=min(1024, limits.max_connections), общее число idle origin sockets; 0 выключает retention |
| http.pool_max_idle_per_key | min(2, http.pool_max_idle) | 0 при общем 0; иначе 1..=http.pool_max_idle |
| http.pool_idle_timeout_ms | 15000 | 100..=300000, срок нахождения socket в idle pool |

limits.max_connections сохраняет M02 budget исходящих sockets: connecting, leased и idle. max_client_connections — отдельный входящий budget, они не расходуют один permit дважды. Имена/смысл этих лимитов явно описать в README, включая суммарный предел FD и существующий transport.max_connecting.

Имеющиеся limits.max_header_bytes (1024..=1048576) и header_read_timeout_ms применяются к входному head на каждом keep-alive запросе; байты проверяются на parsing boundary, а не только после создания HeaderMap. Upstream head/interim/trailers также ограничены max_header_bytes/max_headers. Нельзя незаметно поднять минимальные 1024 до внутреннего минимального буфера hyper. Обосновать конкретные builder settings/adapters и проверить фактические пределы.

transport.total_timeout_ms остаётся сроком авторизации/DNS/pool checkout/new connect; конец срока проверяется перед выдачей connection. Он не ограничивает всё тело большого HTTP stream. Response-header timeout выше ограничивает и слишком долгий upload до ответа; это осознанная политика M03 с настраиваемым пределом.

limits.idle_timeout_ms ограничивает отсутствие фактического I/O progress в активном HTTP обмене и ожидание следующего keep-alive запроса. Ожидание очереди/lock и простое выполнение poll без байтов не считаются progress. Долгий ответ/SSE с регулярными данными живёт дольше idle_timeout; остановившийся upload/download завершается в пределах срока. Header timeout имеет абсолютный срок на head: drip-feed байтов его не продлевает. После каждой async границы не возвращать просроченный успех по аналогии с исправлением M02.

Внутренние ограничения bridge: не более двух queued data frames и 64 KiB queued body bytes на направление. Описать также ограниченные I/O/parser buffers и driver tasks; увеличение этих величин требует обоснования и корректировки задания, а не зависит от размера тела. Ограничение interim очереди — раздел 5. Целое тело в RAM не допускается даже при малой тестовой нагрузке.

## 8. Ошибки и прекращение обмена

Пока final response headers не отправлены, использовать локальные ограниченные сообщения без URI, query, credentials, headers и конфигурационных значений:

| Причина | HTTP результат |
| --- | --- |
| InvalidTarget / Host / request framing / неверный Max-Forwards | 400 и close |
| Входные headers превышают предел | 431 и close; oversized target может получить 414, если распознан отдельно |
| Header read timeout | 408/close; если parser ещё не может безопасно ответить, закрытие без HTTP ответа |
| SourceDenied / AccessDenied / DestinationDenied | 403 и close, без origin при раннем отказе |
| Неподдержанный CONNECT / TRACE / Upgrade | 501 и close, без dial |
| Неподдержанная распознанная HTTP version | 505 и close |
| Неизвестный Expect | 417 и close |
| DnsBusy / OutboundBusy / ограничение работы | 503 и close, Retry-After: 1 допустим |
| DnsTimeout / ConnectTimeout / TotalTimeout / response header timeout | 504 и close |
| DnsFailed / DnsNoAddresses / DnsTooManyAddresses / ConnectFailed / BindFailed / NoCompatibleAddress | 502 и close |
| Ошибочный upstream HTTP, неожиданный 101, превышение upstream header/interim limits | 502 и close |
| Ошибка внутреннего route/config invariant | 500 и close |
| Обнаруженная Via loop | 508 и close |

При library parser error точный статус может генерироваться библиотекой; обязательны безопасное framing, закрытие и отсутствие неожиданного origin request. Допустимое исключение из 400/close для CL+TE строго ограничено разделом 4.3 и документируется по фактической версии parser.

Ошибка после final headers обрывает stream, помечает exchange как failed и исключает connection из pool. Не подменять частичный ответ успешным пустым телом и не приписывать 502 к его body. Client disconnect отменяет связанную upstream работу; отмена ожидающего DNS не снимает permit с реальной blocking операции M02.

Модель ошибок остаётся типизированной. Журналы этого этапа — минимальные startup/shutdown и безопасный класс ошибки; не добавлять несогласованные access logs, полные URL или метрики по произвольным доменам. Полный OBS/control остаётся M07.

## 9. Обязательная приёмка

Все стенды локальные/автономные: origin с записью запросов, raw TCP peers, spy resolver/dialer через реальный server path, реальные IP sockets и отдельный процесс CLI. Origin доказывает доступность положительным контролем; отсутствие соединения при deny не засчитывается по изначально неработающему origin. Порты динамические в тестовом API, процессы/задачи/FD закрываются и при assertion failure.

| ID | Обязательный наблюдаемый сценарий |
| --- | --- |
| M03-SRV-01 | Serve обслуживает все listeners, readiness после всех bind; занятый второй bind даёт код 3 и отсутствие обслуживания/утечки первого; IPv4+IPv6 wildcard не конфликтуют с IPV6_V6ONLY |
| M03-SRV-02 | Один общий client budget через два listeners/clone; освобождение после idle/drop; check и invalid serve не делают сеть; SIGTERM/handle shutdown ограничен, ports и задачи возвращаются |
| M03-HTTP-01 | GET/HEAD/POST/PUT/DELETE/OPTIONS/PATCH; пустой/двоичный payload, большие upload/download; origin-form, Host, path/query bytes, status и end-to-end headers совпадают |
| M03-HTTP-02 | Несколько последовательных и pipelined клиентских запросов на одном TCP с упорядоченными ответами; CL/chunked/EOF response, HEAD/204/304; допустимые trailers в обе стороны |
| M03-HTTP-03 | Все Connection nominations и их регистр/дубли, Proxy-Connection, framing regeneration; Proxy-Authorization secret marker отсутствует на origin, в trailers и диагностике, origin Authorization сохранён; Set-Cookie не склеен |
| M03-HTTP-04 | Expect client ждёт 100 перед body; ранние ACL/error без 100/полного drain; тело сразу после headers; unknown Expect; origin 103/103/200 в порядке, предел 1xx, неожиданный 101 |
| M03-HTTP-05 | Raw negative corpus: CL+TE в обоих порядках, conflicting/equal duplicate CL, comma CL, repeated/непоследний/неподдержанный TE, obs-fold/CRLF, bad chunks и запрос-ловушка; нет desync и второго неожиданного запроса |
| M03-HTTP-06 | Частичный POST и client/origin reset/EOF/cancellation не повторяют запрос, не делают второй final response, исключают stream из pool и возвращают задачи/permits |
| M03-HTTP-07 | Range/If-Range, условный запрос и SSE/долгий stream; первый chunk до конца body; Upgrade/TRACE/CONNECT/HTTP1.0 отказы без dial, Via loop, OPTIONS Max-Forwards |
| M03-POL-01 | Реальный peer IP/listener, поддельный Forwarded/XFF не выдаёт права; source/request deny без DNS/dial; IP deny без connect; исправления mapped CIDR и hex-like host доступны через HTTP ingress |
| M03-POL-02 | На одном client keep-alive первый разрешённый, второй запрещённый запрос; pool hit не обходит source/request/IP ACL и свежий DNS; смешанный DNS фильтруется, изменившийся разрешённый endpoint не использует старый socket |
| M03-POOL-01 | Повторный разрешённый запрос действительно использует тот же origin socket (счётчик accept); lease до EOF/trailers, различия host/endpoint/egress/generation изолированы; full/idle expiry/close/drop eviction ограничены |
| M03-NET-01 | Два HTTP listeners и два реальных loopback egress IP: origin записывает ожидаемый source; bind failure/family mismatch не меняет egress; pool reuse не смешивает профили |
| M03-RES-01 | Max bytes/count headers/trailers, slow headers/slow body, outbound busy, response header timeout, регулярный SSE и остановившийся stream; просроченный результат не возвращается успешно |
| M03-RES-02 | Большой поток при фиксированной concurrency: медленный получатель создаёт backpressure; ограниченные bridge/pool/tasks; после многих завершений/ошибок FD, permits и registry возвращаются к ограниченному baseline |
| M03-CPU-01 | Полный HTTP path с worker_threads=1/2/4 в пределах доступного стенда, независимые соединения прогрессируют одновременно; многопоточный runner даёт свидетельство работы более одного worker, без обещания линейного ускорения |
| M03-CFG-01 | Старые четыре и новые M03 configs проходят check; defaults/bounds/overflow/unknown HTTP fields/зависимости pool limits; server errors не печатают значения, URI/query/credential markers |
| M03-REG-01 | Покрытие 127 Linux-тестов M02, включая исправленные четыре замечания, сохранено; намеренные изменения старых ожиданий serve/help/netguard документированы; fmt/clippy/locked build/tests/deny и CI Ubuntu 24.04 проходят |

Групп — 18. На многоядерном стенде CPU-01 проверяет фактическое выполнение нескольких workers, не выводит масштабирование из одного лишь числа потоков. Один CPU/отсутствие IPv6/нужного инструмента отражаются как конкретное ограничение; обязательные Ubuntu-сценарии должны быть выполнены в подходящем CI до принятия. Два loopback IP не выдаются за проверку двух NIC, которая остаётся M08.

Для resource evidence использовать ограниченный воспроизводимый сценарий: фиксированные 4–8 соединений, поток минимум 64 MiB, затем не менее 200 коротких завершений/обрывов с закрытием или expiry idle pool. Записать config, peak RSS/FD и учёт задач/сокетов; измерение не требует обещания определённого throughput. Дополнить проверкой ограниченных очередей по наблюдаемому producer/consumer progress. Сравнение RSS нескольких размеров тела и возврат ресурсов информативнее одиночного «памяти хватило». Границы времени/ресурсов выбрать до прогона и обосновать для runner.

## 10. Регрессии, команды и результат PR

Исполнитель пишет реальные код, тесты, fixtures, CI и README. Предпочтительная структура тестов: http_server/http_forward/http_framing/http_pool/http_limits; это рекомендация, не требование имён файлов.

Существующие проверки M02 меняются только там, где M03 намеренно заменяет serve stub:

- Удалить ожидание exit=3 для корректного serve и сообщение «не реализован»; добавить процессные positive/startup failure/shutdown tests.
- CLI help отражает реально работающий serve; check/help/version/invalid serve остаются без сети.
- Linux netguard больше не запрещает сеть корректному serve: он проверяет check/help/version и serve с невалидным config, плюс прежний положительный контроль обнаружения socket. Не отключать проверку целиком.
- Сохранить смысл остальных policy/resolver/outbound/config/runtime тестов M01/M02; не уменьшать счётчик путём удаления неудобных сценариев.

На Ubuntu Server/runner 24.04:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
cargo test --locked
cargo run --locked -- check --config examples/minimal.toml
cargo run --locked -- check --config examples/multi-listener.toml
cargo run --locked -- check --config examples/m02-policy.toml
cargo run --locked -- check --config examples/m02-egress-local.toml
cargo run --locked -- check --config examples/m03-http-local.toml
cargo deny check
```

Добавить полный examples/m03-http-local.toml: loopback listener, явные source/request/IP allow для локального origin, system/bind_ip egress и новые HTTP defaults. Он не расширяет production defaults. В README привести воспроизводимый локальный origin и curl с `--noproxy '' --proxy http://127.0.0.1:<proxy-port>`: GET, binary POST, HEAD, chunked upload, Range и SSE; ожидание кода/байтов и cleanup. Не использовать публичный сайт как единственный тест. Безопасный пример не требует root и не меняет системные маршруты/firewall.

CI содержит обязательные runtime/CLI/raw negative/curl/resource checks, ограниченные timeout, pinned Actions, read-only token и прежнюю dependency policy. Малый фиксированный raw corpus обязателен на каждый PR; автоматический fuzz smoke parser/headers/target допускается дополнительно с фиксированными seed/CPU/RAM/time без внешней сети. Не добавлять scheduled runs или платные внешние сервисы.

В PR приложить: Issue, base/head/docs SHA, зависимости/features, архитектуру ownership/pool/1xx, таблицу всех 18 M03-ID с фактическими результатами и местом теста, CI ссылки, реальные команды, resource/CPU evidence, ограничения и инструкция ручного стенда. Не считать passed недоступную проверку и не заполнять результат заранее. Codex проводит ревью текущего head; M04 и merge требуют следующего поручения владельца.

## 11. Источники и пределы постановки

- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html): intermediaries, Connection/Via/Max-Forwards, Expect/1xx, semantics и trailers.
- [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html): request-target, framing, CL/TE, persistence и smuggling.
- [hyper HTTP/1 server builder](https://docs.rs/hyper/latest/hyper/server/conn/http1/struct.Builder.html), [client builder](https://docs.rs/hyper/latest/hyper/client/conn/http1/struct.Builder.html), [informational callback](https://docs.rs/hyper/latest/hyper/ext/fn.on_informational.html): наличие API перепроверяется на выбранной точной версии.
- [M02-r1](M02_NETWORK_POLICY.md), [архитектура](../ARCHITECTURE.md), [тестовая стратегия](../TEST_STRATEGY.md), [решения](../DECISIONS.md).

Численные HTTP defaults, консервативный pool и конкретизация протокольных сценариев — детализация Codex в рамках поручения подготовить M03; они не выдаются за отдельный выбор каждого параметра владельцем. Реализация M03, её тесты и замеры на момент постановки ещё не выполнены.
