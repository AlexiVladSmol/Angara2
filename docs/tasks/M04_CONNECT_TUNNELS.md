# DeepSeek: M04 — CONNECT и потоковые TCP-туннели

Статус: READY, редакция **M04-r1 от 10 ноября 2026 года**.
Постановка и ревью: Codex. Реализация, тесты и CI: DeepSeek V4.1 Flash 1017.
База реализации: `main` @ **`9330cd59ec1d69ea5aa2cd4a5b58f8e65cb7c22a`**.
M03 принят [ревью ACCEPTED](https://github.com/AlexeiSmol/Angara/pull/10#issuecomment-6769570729) на `96af256d5f45d73e4a9860cdb500c2d1d9e5a3e8` и слит в [PR #10](https://github.com/AlexeiSmol/Angara/pull/10). Исходная регрессия: 196 основных Linux-тестов и две отдельно запускаемые resource-проверки; три независимых прогона по 24000 HTTP-запросов без ошибочных 502. Это результаты M03, а не заранее заполненный отчёт M04.

## 1. Результат, границы и порядок работы

Через HTTP-listener Angara клиент устанавливает `CONNECT host:port HTTP/1.1`, получает 200 после успешного разрешённого TCP connect и обменивается непрозрачными байтами в обе стороны. Через туннель проходят настоящий TLS handshake и HTTPS-запрос к локальному тестовому сайту. Сайт и клиент завершают TLS; Angara передаёт байты. Обычный HTTP/1.1 proxy M03 продолжает работать на тех же listeners и общих бюджетах.

В M04 входят CONNECT validation, policy/DNS/egress M02, безопасный HTTP→tunnel handoff, ранние байты, streaming/backpressure, EOF/ограниченный half-close drain, idle timeout, отмена, интеграция с shutdown, конфигурация, тесты и локальный стенд.

Auth/users — M05, TLS-listener до самого proxy — M06, reload/журналы/control service — M07, systemd/release — M08, parent/cache/TUI/web — M09–M12. Не добавлять MITM, TLS termination сайта, WebSocket Upgrade вне CONNECT, HTTP/2 ingress, UDP/MASQUE/HTTP/3, retry/replay или кэш туннелей. M04 не требует доступа к внешним сайтам и публичного развёртывания промежуточного сервера.

1. Прочитать AGENTS, ARCHITECTURE, DECISIONS, TEST_STRATEGY и этот документ на SHA постановки из Ready Issue. Создать `feat/<номер-Issue>-m04-connect` **от указанной базы кода**, PR направить в `main`. Неслитый PR документации не блокирует реализацию по закреплённому Issue и не разрешает слияние чужих PR.
2. Оставить в Issue короткий план: ownership sockets/permits/tasks, переход через hyper upgrade, сохранение read buffer, writer/barrier, EOF/idle/shutdown, зависимости и порядок проверок.
3. Сначала выполнить узкий spike на закреплённом hyper 1.12.0 с действующим adapter M03: CONNECT+ранний payload одним write, 200 без CL/TE, origin-first bytes, сохранение живого туннеля после окончания HTTP driver и освобождение при отмене. Привести фактический результат. Spike входит в M04 и не заменяет реализацию/регрессии.
4. Реализовать проверку/открытие туннеля и его жизненный цикл; затем отрицательные, интеграционные, ресурсные и многопоточные сценарии, CI и документацию.
5. Передать PR с матрицей всех 18 M04-ID, base/head SHA, командами, результатами, ссылками на CI и оставшимися ограничениями. Самостоятельно M04 не принимать и не сливать.

## 2. Текущий код и разрешённый рефакторинг

На базе M03 `Proxy::handle` отвечает на валидный CONNECT кодом 501. `CanonicalTarget`, `check_host_header`, `OutboundService::open_outbound`, авторизованный `OutboundPlan` и владеющий outbound permit тип `Connected` уже существуют. Их проверки не дублировать менее строгим CONNECT-путём.

В `src/http/server.rs` клиент обслуживается через `SplitIo`, bridge 64 KiB, единственный `writer_loop`, `ConnectionOutput` и `ExchangeBody`. Окончание HTTP driver сейчас ведёт к завершению writer/client task. Для туннеля этого недостаточно: успешный upgrade завершает HTTP-фазу, но не жизнь клиентского socket.

Разрешён необходимый локальный рефакторинг `http/server`, `forward`, adapters и lifecycle, новый модуль CONNECT/relay и минимальные конфигурационные типы. Сохранить публичный безопасный `open_outbound`, общие budgets и HTTP-инварианты M03. Допустим типизированный результат HTTP/tunnel или bounded передача владения; имена типов не предписываются.

HTTP parsing/framing остаётся у hyper. Использовать штатные `with_upgrades`, `hyper::upgrade::on`, `Upgraded`/`TokioIo` либо эквивалентный штатный механизм с сохранением буфера. Это разрешение на CONNECT handoff, не на поддержку произвольного HTTP Upgrade. Нельзя отбрасывать `read_buf` при downcast/разборке Upgraded или брать только голый socket.

Согласованный в M03 patch `hyper::ext::OriginalRequestTarget` сохраняется без расширения parser/framing. Он нужен и для исходного CONNECT target. Самостоятельный parser, второй framing decoder, новый backend, дополнительный vendor patch и unsafe требуют отдельного решения до реализации. Toolchain и production dependencies без необходимости не менять. Для локального TLS fixture предпочтительны Python `ssl` и временная CA через OpenSSL; test-only TLS crates допустимы в принятом Rust/TLS стеке, с обоснованием features, lockfile и dependency policy. TLS-код production в M04 не добавлять.

## 3. CONNECT request и установление туннеля

### 3.1. Валидация до DNS/dial

- Поддерживается HTTP/1.1 и метод `CONNECT` с обычной чувствительностью имени метода к регистру. До service hyper по-прежнему ограничивает head bytes/count и время чтения каждого head.
- Только authority-form с явным портом 1..=65535: `example.test:443`, `127.0.0.1:443`, `[::1]:443`. Нет default port в request-target. Схема, `/path`, query, fragment, userinfo, пустой/нулевой/переполненный порт и неоднозначный IP запрещены.
- Использовать исходный `OriginalRequestTarget` и нормализатор M02. ASCII case, trailing dot, IDNA и IPv4-mapped IPv6 имеют прежнюю семантику. Не выполнять второй DNS lookup через высокоуровневый connector.
- Ровно один валидный Host. Сохранить контракт `check_host_header`: canonical host должен совпадать; если Host содержит порт — он равен target port; Host без порта допустим для CONNECT и не подставляет 80/443 в target. Отсутствующий, дублированный или несовпадающий Host → 400/close.
- CONNECT не имеет HTTP content. В M04 допустимы отсутствие CL и эффективный `Content-Length: 0`. Ненулевой CL, любой TE, Trailer или попытка передать framed body → отказ/close до dial. Противоречивый/повреждённый framing остаётся ошибкой hyper. Одинаковые CL, уже однозначно нормализованные hyper к нулю, не требуют второго parser.
- Любой Expect на CONNECT → 417/close без 100 и без dial. Не читать Incoming body ради запуска hyper 100. HTTP Upgrade/его Connection nomination на CONNECT → 400/close. Via-loop сохраняет 508/close. Обычные TRACE и HTTP Upgrade вне CONNECT сохраняют явный отказ M03.
- Данные после полного корректного head без HTTP content — ранние байты туннеля. Не объявлять их HTTP body/следующим запросом и не анализировать на содержание. До allow+connect они не передаются ни одному origin; при отказе discard/close.

Коды относятся к запросам, доставленным service. Если hyper отвергает некорректный head раньше, документировать и тестировать фактический безопасный parser outcome: не 2xx, close, нет dial и обработки запроса-ловушки. Не менять parser ради унификации status code.

### 3.2. Единая политика и исходящий socket

Для каждой попытки установки CONNECT, включая CONNECT после обычных запросов на keep-alive:

1. Зафиксировать config generation, реальный peer IP и listener_id. X-Forwarded-For/Forwarded, Host и proxy credentials не создают trusted identity.
2. Проверить source gate, `connect.allowed_ports` и request ACL M02 до DNS/dial. Все три условия нужны одновременно. Port list ограничивает, но не выдаёт право доступа. Наличие Proxy-Authorization до M05 не меняет решение.
3. По тем же routing rules выбрать один egress; для домена выполнить свежий bounded DNS, проверить каждый IP и порт назначения. Numeric IP проверяется без DNS. Смесь allow/deny не разрешает dial запрещённого кандидата.
4. Открыть один разрешённый `Connected` через общий outbound service M03. Допустимы только ограниченные connect attempts по разрешённым endpoints до передачи туннельных байтов, в рамках deadlines M02. Fallback на другой egress или повторный resolve запрещены.
5. После реального успешного TCP connect и готовности управляемого handoff вернуть **ровно один 200**. До этого 200 не формируется. Ошибка DNS/connect, deny, cancel и budget exhaustion не маскируются успешным CONNECT.

CONNECT всегда открывает отдельный origin TCP stream. Не брать socket из HTTP origin pool, не выполнять над ним HTTP client handshake, не отправлять origin строку CONNECT/HTTP-заголовки и не возвращать завершённый туннель в pool. Разные CONNECT не объединяются даже для одинакового authority. При этом используют **тот же** outbound semaphore и max_connecting, что HTTP; создание отдельного OutboundService с новым независимым бюджетом недопустимо.

200 подтверждает TCP tunnel, а не успешный TLS handshake или сертификат сайта. Закрытие origin после состоявшегося connect не превращается в новый HTTP-ответ после 200.

## 4. Граница HTTP → tunnel и порядок байтов

Успешный ответ заканчивается обычной пустой строкой. На wire **нет Content-Length, Transfer-Encoding, Trailer, Upgrade, Connection/Proxy-Connection или HTTP response body**; не добавлять даже CL:0. Reason phrase не фиксируется, тест проверяет status 200 и headers. Date/Via допустимы; proxy-auth поля и произвольные request headers в ответ не копируются. Test client после 200 переключается с чтения HTTP head на raw tunnel I/O: ожидание HTTP body/EOF здесь ошибочно.

До передачи первого tunnel byte клиенту весь HTTP head 200 должен пройти через упорядоченный output. У client write half всегда один владелец. Сохранить порядок последних 103/final/body предыдущего HTTP-обмена, затем CONNECT 200, затем origin bytes. Нельзя писать raw 200 или tunnel bytes в socket параллельно с writer_loop. При сохранении bridge FIFO writer должен оставаться живым на всю соответствующую фазу; при передаче write half сначала доказать drain HTTP-байтов. Переписывать счётчик produced/consumed кредитами другого потока запрещено.

Все уже прочитанные после request head байты из hyper read buffer передаются origin **ровно один раз**, затем продолжается чтение socket. Проверить payload в одном write с CONNECT, разделённый по нескольким write и размером больше внутреннего read buffer. Payload с `GET ...`, `CONNECT ...`, CRLF и бинарными нулями остаётся непрозрачным; второй policy/DNS/dial и новый HTTP response на нём не возникают.

CONNECT разрешён как первый запрос и после полностью корректного HTTP-обмена на keep-alive, в том числе в pipeline. После успешного CONNECT это соединение больше не возвращается к HTTP parsing. Неудачный CONNECT в M04 заканчивается финальным error/close; остаток не интерпретируется как новый HTTP request.

Client permit остаётся у живой сессии после завершения hyper connection future; `Connected` вместе с outbound permit — до фактического закрытия origin socket. Failed/aborted upgrade освобождает оба, а не оставляет за собой уже открытый origin.

## 5. Relay, EOF, таймауты и отмена

### 5.1. Потоковая передача

Передавать произвольные bytes без изменения в обоих направлениях, включая одновременную передачу, origin-first greeting и длительное одностороннее движение. Нет collect/read_to_end/to_bytes на tunnel payload, накопления всего сообщения, проверки TLS/SNI/HTTP внутри туннеля или записи payload в журналы. Полный сбор допустим только в ограниченном test client, не в relay/production.

Буферы relay фиксированы: не более **64 KiB на направление**; рекомендуются 16 KiB. Уже существующие bounded bridge/header buffers M03 могут сохраняться отдельно. Все новые каналы и registry bounded по числу активных client sockets; нет fire-and-forget task на каждый read/write, накопления истории закрытых туннелей или mutex, удерживаемого на время network I/O. Slow reader даёт backpressure отправителю.

### 5.2. EOF и half-close drain

При нормальном EOF одной стороны сначала дописать уже прочитанные от неё данные в противоположный socket, затем выполнить write-half shutdown этой стороны назначения. Не терять последний непустой буфер и не дублировать его. Обратное направление может допередать ответ в пределах ограниченного drain; это особенно важно для клиента, который отправил request и закрыл write half, ожидая response.

При первом read EOF запустить **один абсолютный** срок `connect.half_close_timeout_ms`, включающий flush уже принятых bytes и завершение второго направления. Его не продлевают обратный progress, повторный EOF или новый локальный этап. По завершении обеих сторон либо по deadline закрыть оба sockets, освободить permits и убрать задачи. Бесконечный reverse stream после half-close не должен продлевать сессию. Это проектная bounded drain policy; не обещание бесконечно поддерживать TCP half-close.

Если drain deadline/force shutdown/reset делает доставку невозможной, остаток discard вместе с закрытием. Гарантия сохранения bytes действует при нормальном EOF и доступном получателе в пределах установленного drain, а не после hard reset. Отдельно проверить симметричный origin EOF.

### 5.3. Idle и setup deadlines

- До connect: deadlines DNS/transport M02 и header-read M03. Существующий `response_header_timeout` HTTP origin не превращается в лимит времени жизни CONNECT.
- От успешного dial до завершения HTTP→tunnel handoff — ограниченный этап, максимум `limits.idle_timeout_ms`, с отменой и более ранним shutdown deadline. Невозможность отправить 200/завершить upgrade не держит origin бесконечно.
- Активный туннель: `limits.idle_timeout_ms` — время **отсутствия фактического byte progress в обоих направлениях**. Progress — успешное чтение/запись положительного числа bytes; poll/wakeup, пустой read, размер выделенного buffer и проверка таймера progress не создают.
- Progress только в одном направлении сохраняет активный туннель. Нельзя ставить независимый read timeout, который закроет исправный upload/download из-за молчания второй стороны. Таймер общий/эквивалентно согласованный, обновления другого worker видимы.
- EOF drain и shutdown имеют собственные абсолютные сроки; активность не продлевает их. Общего жёсткого лимита длительности здорового активного туннеля в M04 нет.

После 200 любые ошибки, RST, idle/drain timeout и отмена закрывают туннель; не добавлять 4xx/5xx, HTML, HTTP trailers или диагностические строки в payload. При RST не делать неограниченный graceful drain и не повторять пользовательские bytes.

### 5.4. Shutdown и Drop

Вся сессия setup/upgrade/relay/drain принадлежит учтённой client task или bounded task registry, которую реально отменяет и дожидается HttpServer. Нельзя сохранить `OnUpgrade`/relay/writer в detached spawn после окончания HTTP future.

При shutdown перестать accept и создавать новые туннели. Установленные сессии могут завершиться в пределах **единого** `limits.shutdown_timeout_ms`; при истечении срока закрыть sockets, abort и join задач. Не добавлять свежие фиксированные окна по 1 секунде к разным фазам. Drop — принудительное прекращение с освобождением ресурсов после отмены задач; штатный async shutdown возвращается после их фактического завершения. Сохранить R5-регрессию M03.

Проверить отмену во время dial/ожидания upgrade, активной передачи, blocked write и half-close drain. Фактическая blocking DNS работа сохраняет учёт M02 до своего окончания; это не разрешение держать уже отменённый CONNECT client/origin или его relay task.

## 6. Конфигурация и исходы

`schema_version = 1`, прежние пять примеров и CLI/check остаются совместимыми. Добавляется необязательный root `[connect]` с `deny_unknown_fields`; остальные настройки/границы M02/M03 сохраняются.

| Поле | Default | Контракт |
| --- | --- | --- |
| `connect.allowed_ports` | `[443]` | Список из 0..=64 уникальных integer-портов 1..=65535; пустой список запрещает CONNECT. Не открывает доступ без source/request/IP allow |
| `connect.half_close_timeout_ms` | `5000` | Integer 100..=300000; абсолютный срок после первого read EOF, включая pending-byte drain |

Отсутствующий `[connect]` и явно пустой `[connect]` используют defaults. Неверный тип, ноль/отрицательный/overflow порт, дубликат, 65-й элемент, неизвестный ключ и неверный диапазон timeout отклоняются безопасным ConfigError без эха значений/секретов. Не добавлять отдельный listener transport или собственный независимый max_tunnels; предел активных туннелей следует из общих client/outbound budgets.

Пример добавляемой секции (полный валидный локальный пример создаёт исполнитель):

```toml
[connect]
allowed_ports = [443] # в изолированном тесте явно указать ephemeral порт fixture
half_close_timeout_ms = 5000
```

`limits.max_client_connections` учитывает HTTP keep-alive и CONNECT до закрытия клиента; `limits.max_connections` — все connecting/HTTP leased/HTTP idle/tunnel origin sockets. Когда один из бюджетов исчерпан, используется ограниченный отказ M03/M02, не очередь. Для accept-level overflow допустимо немедленное закрытие без parse/ответа; когда service уже обслуживает CONNECT и исчерпан outbound budget — 503/close. Idle HTTP sockets могут занимать budget; допустим прежний 503 либо bounded eviction с закрытием socket до нового dial. Нельзя выдать CONNECT новый неучтённый permit.

Ошибки service до 200:

| Условие | Результат |
| --- | --- |
| Невалидный target/Host/body-framing/CONNECT Upgrade | 400 + close; слишком длинные target/Host/head — прежний 414/431, если выявлены service/parser |
| Неподдерживаемый HTTP version | Прежний 505/close либо ранний безопасный parser reject |
| CONNECT Expect / Via-loop | Соответственно 417 / 508 + close |
| Source, allowed_ports, request ACL или IP deny | 403 + close; при pre-DNS deny нет DNS/dial, при IP deny нет dial запрещённого endpoint |
| DNS/connecting/outbound budget busy | 503 + close |
| DNS timeout, connect timeout, общий transport timeout | 504 + close |
| DNS failed/no address/too many answers, connect refused/reset, bind/family failure, cancel outbound | Прежний bounded mapping M03, обычно 502 + close; без 200 |
| Невалидный route / внутренний setup failure до ответа | 500 + close; при начатом shutdown — 503/close, если HTTP-ответ ещё возможен |

Валидационные ошибки имеют приоритет до dial; для нескольких одновременно неверных полей не нужен новый искусственный порядок поверх hyper. Не раскрывать dialed/private addresses, raw target, credentials, payload и системные детали в локальном error body. Внутренние ограничения и реальные исходы описать в README.

## 7. Обязательная матрица приёмки: 18 M04-ID

Все группы обязательны, количество конкретных test functions выбирает исполнитель. Существующие test helpers можно расширять; test fixture не заменяет production relay и не пропускает policy/budgets.

| ID | Наблюдаемый результат и минимальные сценарии |
| --- | --- |
| M04-CFG-01 | Defaults/empty section/empty ports, границы и все invalid cases §6; пять старых примеров проходят check без runtime/DNS/bind/connect; новый полный CONNECT example валиден |
| M04-CON-01 | Реальный TCP endpoint получает binary bytes ровно один раз; client-first, origin-first и simultaneous traffic; IPv4, домен, IPv6 и mapped IPv6 с прежней нормализацией |
| M04-CON-02 | Raw invalid authority/port/userinfo/path/query/fragment/Host/version; CL>0/TE/Trailer и Expect; нет 100/200/dial на недопустимом запросе; запрос-ловушка не обслужен |
| M04-POL-01 | Source deny, request ACL deny и запрещённый allowed_ports с resolver/dialer spies дают ноль DNS/dial; список портов и поддельные XFF/Proxy-Authorization не обходят ACL |
| M04-POL-02 | Numeric IP без DNS; домен — свежий DNS на каждый новый CONNECT; private/link-local/loopback/mapped и mixed answers по M02; DNS change во втором CONNECT не использует старый endpoint |
| M04-CON-03 | Реальные refused/RST при установке и управляемые DNS/connect timeouts/busy; status mapping, отсутствие ложного 200 и освобождение ресурсов; доступность контрольного endpoint доказана отдельно |
| M04-CON-04 | CONNECT+early bytes одним write, split write и payload больше read buffer; полная сохранность, origin-first greeting следует после полного 200, на wire нет CL/TE; в том числе после предыдущего большого HTTP body/103 |
| M04-CON-05 | TLS handshake и HTTPS response через настоящий туннель с временной test CA; клиент проверяет имя/CA; wrong name и wrong CA завершаются клиентским отказом, tunnel cleanup проверен; реальный curl smoke без -k |
| M04-CON-06 | HTTP GET→CONNECT на keep-alive и pipeline сохраняет порядок; после 200 HTTP-looking payload непрозрачен и не создаёт новых dial; два CONNECT имеют разные origin accepts и не берут/не возвращают HTTP pool socket |
| M04-IO-01 | Client и origin write-half EOF симметричны: последний буфер дописан, ответ после EOF клиента доставлен в пределах drain; обратный бесконечный progress не продлевает half_close_timeout; blocked drain прекращается |
| M04-IO-02 | Idle без progress закрывает; upload-only и download-only идут дольше idle_timeout с регулярными bytes и не обрываются; проверка не подменяет idle абсолютным временем жизни |
| M04-IO-03 | Client disconnect/RST, origin RST, отмена setup/upgrade/relay/blocked write: закрыты оба sockets, нет второго HTTP-ответа/повтора bytes, следующий независимый запрос здоров |
| M04-RES-01 | Малые общие client/outbound/max_connecting budgets на двух listeners: HTTP и CONNECT конкурируют за один budget; permits не освобождаются после 200/окончания HTTP driver; overload ограничен, после close доступность восстановлена |
| M04-RES-02 | Большой streaming payload, backpressure шести slow consumers, обрывы и минимум 200 последовательных туннелей; FD/RSS/tasks и permits возвращаются к bounded baseline, нет роста пропорционально total bytes |
| M04-SRV-01 | Shutdown во время dial/upgrade/active/half-close и Drop; current-thread runtime, повторные forced shutdown при shutdown_timeout=1 ms, origin EOF и tasks→baseline; нет detached relay/barrier и скрытого +1 s; SIGTERM CLI |
| M04-NET-01 | Два listeners, source/listener routing и фактические egress bind IP origin; IPv6 обязательно на Ubuntu runner; два loopback IP не выдаются за проверку двух физических NIC |
| M04-CPU-01 | Workers 1/2/4, параллельный прогресс независимых туннелей; 10 и 20 независимых лёгких клиентов с одним tunnel каждый в конфигурации, допускающей такую concurrency; свидетельство >1 worker внутри Angara path на многопоточном стенде |
| M04-REG-01 | Вся регрессия M01–M03, HTTP methods/body/trailers/Expect/1xx/pool/raw target/R1–R9, check/netguard/curl; старую ожидаемую 501 для CONNECT заменить новым точным сценарием, TRACE/Upgrade и негативные HTTP assertions не ослаблять |

### Ресурсный и временной evidence

Для M04-RES-02 на Linux зафиксировать baseline после прогрева, лимиты, buffers, concurrency, `/proc/self/fd`, VmRSS, число живых Tokio tasks/fixture tasks и число активных origin sockets. Не считать накопленный accept counter измерением утечки; отдельный сценарий CON-06 доказывает отсутствие reuse туннелей. Освобождение permits проверять новым разрешённым dial после завершения/отмены при малом budget; учитывать заранее настроенный HTTP pool retention/expiry.

Обязательный slow-consumer сценарий: три раунда по шесть соединений, каждое запрашивает/генерирует **64 MiB** потока без предварительного collect. Ограничить socket buffers (например 4096), прочитать 200, остановить consumer на 250 ms, зафиксировать progress производителя: один sender не должен успеть сбросить все 64 MiB в неограниченную очередь. Для выбранного Ubuntu runner фиксировать до запуска: max переданных producer bytes <16 MiB на соединение за паузу, прирост RSS ≤128 MiB, после закрытия/expiry/shutdown FD ≤baseline+8, session tasks возвращаются к baseline. Проверить backpressure обоих направлений, cleanup и успешную короткую передачу после обрывов. Если пределы стенда не подходят, объяснить до объявления успеха, а не увеличивать их после падения без анализа.

Для EOF/idle/shutdown использовать события и малые управляемые сроки; тест не должен зависеть от произвольного sleep. Forced shutdown с configured 1 ms должен завершаться с разумным запасом runner (например <500 ms) и после cleanup дать tasks baseline, а не только закрытый port. Нагрузочный тест не заменяет управляемые fault/timeout проверки. Расходы CPU/RSS/time тестов ограничить; resource evidence запускать отдельно последовательно, если он зависит от process baseline.

CPU evidence записывать внутри реального Angara outbound/relay path, не только в origin handler. Не обещать линейное ускорение; 10/20 клиентов — обозначенная эмуляция устройств, не предельная вместимость и не измерение физических NIC. Полный soak/release профиль остаётся M08.

## 8. Стенд, CI и результаты PR

- Добавить `examples/m04-connect-local.toml` с source gate и узким IP allow для локального стенда, явным safe port list и описанием замены порта на ephemeral. Не расширять default IP policy ради теста.
- Добавить воспроизводимый TCP echo/stream и локальный TLS/HTTPS fixture, инструкции создания временной CA/сертификата с SAN и cleanup. Private key генерируется во временной директории, не коммитится и не попадает в CI artifacts. Синтетические test credentials/payload не содержат данные владельца.
- Автоматический curl через реальный `angara serve`: HTTPS GET с `--cacert`, upload/download через TLS site, отрицательные denied port/недоступный endpoint, затем обычный HTTP GET M03. Проверить proxy действительно использован, включая корректный NO_PROXY override для loopback. Никаких внешних URL или `-k` вместо проверки доверия.
- CI Ubuntu 24.04 сохраняет fmt, clippy с `-D warnings`, locked build/test, cargo deny, netguard и M03 smoke; добавляет M04 raw/TLS/curl/IPv6/resource проверки и фиксирует exact head SHA. Dev fixtures/dependencies объявить в плане и закрепить; privileged ports/root/Docker для базового стенда не требуются.
- README описывает текущее поведение CONNECT, список портов, взаимодействие limits, idle/half-close policy, errors, локальный HTTPS smoke и границы следующих этапов. Сообщения CLI/README после реализации не утверждают, что CONNECT по-прежнему отсутствует.

В PR указать: Issue; base/head SHA; таблицу M04-ID → test/command/result; фактические команды и runner; passed/failed/skipped отдельно; CI run и resource/CPU evidence; clean-clone locked build; совместимость examples; ограничения. Пропущенный обязательный Linux/TLS/IPv6 сценарий не считается пройденным и должен быть исполнен на подходящем стенде до приёмки. В отчёте не подменять счётчики origin evidence неподтверждёнными заявлениями о throughput.

### Условия остановки

Поставить конкретный вопрос до расширения реализации, если корректный handoff требует второго HTTP/framing decoder, изменения vendor patch/backend, unsafe, обхода OutboundService/ACL, независимого неучтённого бюджета или изменения согласованного протокольного результата. Обычные локальные refactoring/названия модулей/выбор bounded channel исполнитель решает сам. Недоступность обязательного runner/fixture или воспроизводимый новый дефект фиксируются в PR; тесты не отключаются ради зелёного статуса.

## 9. Основание и ссылки

Владелец 10 ноября 2026 года поручил слить M03, затем подготовить M04. Этот документ детализирует уже запланированный CONNECT в рамках D01/D04/D06/D12/D13; численные defaults и M04-ID — контракт задания Codex, не утверждение об отдельном согласовании владельцем каждой цифры. Новые архитектурные развилки по-прежнему требуют решения.

- [RFC 9110 §9.3.6 — CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): authority, TCP tunnel, отсутствие CL/TE в успешном ответе, ограничение назначений и завершение туннеля.
- [RFC 9112 §3.2.3 и §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.3): authority-form и граница HTTP/tunnel после успешного CONNECT.
- Закреплённый [hyper upgrade.rs](https://github.com/AlexeiSmol/Angara/blob/9330cd59ec1d69ea5aa2cd4a5b58f8e65cb7c22a/vendor/hyper-1.12.0/src/upgrade.rs), `server/conn/http1.rs` и действующие adapters: проверять фактический API этой версии, не документацию latest другой версии.
- [Ревью M03 с ошибкой readiness](https://github.com/AlexeiSmol/Angara/pull/10#issuecomment-6769107397) и [итог ACCEPTED](https://github.com/AlexeiSmol/Angara/pull/10#issuecomment-6769570729): сохранить explicit ready(), единый output и владение задачами.

Завершение M04: актуальный PR прошёл все группы, Codex опубликовал ACCEPTED на точном SHA, затем владелец выполнил или явно поручил слияние. До этого следующий этап M05 не начинать.
