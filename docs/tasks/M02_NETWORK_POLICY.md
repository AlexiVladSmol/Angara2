# DeepSeek: M02 — назначения, ACL, DNS и исходящие соединения

Статус: READY, редакция M02-r1 от 9 ноября 2026 года.
Постановка и ревью: Codex. Реализация, тесты и CI: DeepSeek V4.1 Flash 1017.
Исходный код: main, коммит a60ba386391a69319c57dda745119746d00a3510. M01 принят ревью и слит; его 53 теста — обязательная регрессия.

## 1. Результат этапа и порядок работы

Создать библиотечный путь open_outbound: доверенный контекст клиента → каноническое назначение → source gate → ACL запроса → выбор egress → DNS → проверка каждого IP → TCP connect только к проверенному IP. Продемонстрировать настоящие системный resolver и TCP dial с выбранным исходящим IP на локальном стенде.

В M02 ещё нет принимающего HTTP-сервера и forwarding. Команды check и serve сохраняют поведение M01: check проверяет config без сетевых вызовов; serve после проверки возвращает 3 («proxy ещё не реализован»), не создаёт сетевой runtime и не слушает порты. Пробовать новые сетевые компоненты через библиотечный API и интеграционные тесты. Обработка HTTP появляется в M03, CONNECT-туннель — M04, аутентификация — M05.

В начале оставить в Issue короткий план с последовательностью работ и выбранными зависимостями. Рабочая ветка feat/<issue>-m02-network-policy создаётся от main, содержащего указанную базу; PR направляется в main. Закреплённая редакция этого задания и SHA документации указаны в Issue. PR постановки задачи хранит контракт отдельно; его незавершённое слияние не блокирует реализацию по Ready Issue. Не сливать чужие PR и не выбирать следующую задачу самостоятельно.

Внутри одного задания выполнять небольшие проверяемые части:
1. Типы назначения и совместимая строгая конфигурация.
2. Source gate, pre-DNS ACL, IP-политика и routing.
3. Ограниченный resolver и безопасный dial.
4. Сборка конвейера, реальные интеграционные тесты, документация и CI.
Допустимы несколько коммитов; завершение M02 оценивается по всем критериям, а не по наличию отдельных модулей.

## 2. Модули и границы

| Модуль/объект | Ответственность |
| --- | --- |
| target | Разбор и канонизация HTTP absolute-form / CONNECT authority, доменов и IP |
| policy | Source gate, правила запроса и дополнительная политика каждого IP |
| routing | Выбор одного egress-профиля для запроса |
| resolver | Системное разрешение имён с пределами реальной работы; тестовая подмена |
| transport | TCP к SocketAddr с bind_ip, сроками, отменой и разрешениями ресурсов |
| OutboundService | Единая композиция этих границ на неизменяемом снимке настроек |
| RequestContext | Реальный peer IP и listener_id, позднее получаемые от принимающего сокета |
| CanonicalTarget | Режим HTTP/CONNECT, метод, типизированный host, эффективный port и HTTP path/query |
| AuthorizedEndpoint | Проверенный SocketAddr, исходное назначение, egress_id и поколение config |
| Connected | Сокет и его метаданные; владеет разрешением на весь срок открытого соединения |

Имена типов можно адаптировать к идиоматичному Rust, сохраняя контракты. Все сетевые сервисы разделяют общие бюджеты при clone; нельзя создавать новые лимитеры на каждый запрос.

Контекст источника не берётся из X-Forwarded-For или других HTTP-заголовков. В M02 клиента представляет переданный библиотечному API доверенный контекст; M03 получает его из сокета. Публичный интерфейс верхнего уровня всегда выполняет полную проверку; безопасный dial не должен принимать имя для повторного DNS. Проверенный endpoint создаётся только внутри проверяющего пути, без публичного «unchecked» конструктора.

Поколение фиксируется на весь запрос. В M02 достаточно неизменяемого снимка с поколением 1; тесты могут создавать независимые поколения. Reload и connection pool не реализуются. Метаданные уже должны позволять в M03/M07 отличать origin, endpoint, egress и поколение.

## 3. Назначение и нормализация

Использовать готовые парсеры URI/authority и IP, а не собственный HTTP-парсер. Работа с уже выделенным request-target не означает разбор сырых HTTP-сообщений.

### HTTP

- Принимать absolute-form со схемой http (схема без учёта регистра), непустым host и портом 1–65535. Если порт отсутствует, эффективный порт 80.
- Отклонять https absolute-form, origin-form, одиночный *, fragment, userinfo, неоднозначный/пустой authority, пробелы, управляющие символы и обратную косую черту.
- Сохранять path/query без декодирования percent-encoding и без изменения пути; пустой путь превращается в /. Query-only даёт /?query. Query и путь не участвуют в ACL этого этапа.
- URI, credentials и значения полей не включаются в текст ошибок.

### CONNECT

- Только host:port или [IPv6]:port. Порт обязателен; 0 и выход за u16 запрещены.
- Схема, path/query, fragment, userinfo и IPv6 без скобок запрещены.
- CONNECT выбирается только методом CONNECT. Регистр HTTP method значим; методы проверяются готовым token-парсером, не переводятся в верхний регистр молча.

### Общие правила

- Канонический host — Domain или Ip, не универсальная строка для дальнейшего угадывания.
- Для доменов: единый IDNA/UTS #46 нормализатор с совместимым нестрогим web-профилем и запретом forbidden domain code points (например domain_to_ascii_cow с AsciiDenyList::URL, без STD3 strict); затем ASCII lowercase и удаление одной завершающей точки. Проверять пустые метки, длину метки ≤63 байт и имени без завершающей точки ≤253 байт. После IDNA допустимы только ASCII a-z, 0-9, underscore, hyphen и точки-разделители; glob/regex и символ * в host selectors не поддерживаются. Отклонять percent-encoding, @, двоеточие и разделители URI внутри домена. Обычные ASCII underscore/hyphen, допустимые выбранным нестрогим IDNA-профилем, не отбрасывать дополнительным «strict» режимом без необходимости.
- На входе HTTP URI используется ASCII URI: международное имя в request-target передаётся как A-label. Unicode-домены в правилах config приводятся тем же нормализатором к A-label. Проверить эквивалентность Unicode config и соответствующего ASCII имени.
- Для IP использовать IpAddr; IPv4-mapped IPv6 назначения нормализовать до IPv4 до сравнения ACL и выбора семейства. Scoped/zone IPv6 назначения пока отвергать.
- Нестандартные числовые IPv4 формы 127.1, 0177.0.0.1, 2130706433 и 0x7f000001 отвергать как неоднозначные, не отдавать их системному resolver как DNS-имена.
- Host header проверяется отдельной функцией по уже каноническому target; адрес назначения всегда берётся из request-target. Выбранная в архитектуре строгая политика Angara отвергает противоречащий Host, а будущий forwarding заново формирует Host из target. Это дополнительная политика продукта, не утверждение, что RFC требует отвергать несовпадение.
- Для HTTP отсутствие порта в Host означает 80; для CONNECT отсутствие порта в Host сравнивается с портом target (например CONNECT example.com:443 и Host: example.com допустимы). Регистр, завершающая точка и представление IPv6 нормализуются одинаково. Отсутствие/дубли Host в HTTP/1.1 отвергаются протокольным слоем M03/M04; в M02 проверить отдельный helper на отсутствующее, неверное и противоречащее значение.
- Ограничить вход request-target до 8192 байт и Host до 1024 байт до дорогостоящего разбора.

## 4. ACL — три независимые проверки

Все правила хранятся в исходном порядке. Отсутствие разрешения не превращается в allow. Нельзя использовать доступный egress как разрешающее правило.

### 4.1 Source gate

access.source_allow — список CIDR реальных адресов клиентов. Отсутствующий или пустой список запрещает всех. Сравнение после нормализации IPv4-mapped IPv6. Отказ источника не вызывает resolver и dial.

### 4.2 Правила запроса до DNS

access.rules — упорядоченные allow/deny правила. Первое полностью совпавшее правило завершает эту фазу; нет совпадения — deny.

Поля: id, action; необязательные listeners, sources, methods, ports, host_exact, host_suffix.
- Внутри списка — OR, между заданными полями — AND.
- Отсутствующий selector означает «любой»; явно пустой список — ошибка config.
- host_exact и host_suffix взаимоисключающие. Оба содержат только домены, не IP/CIDR; это повторно проверить после IDNA-нормализации.
- host_exact совпадает только с этим доменом. host_suffix включает сам домен и поддомены по границе метки: example.com и a.example.com совпадают, notexample.com и example.com.attacker.test — нет.
- Domain selectors не совпадают с IP literal. Поэтому доменный allow-list с default deny не обходится прямым IP.
- Правило без selectors — явное catch-all; допустимо для allow и deny. Порядок таких правил не переставлять автоматически.
- IDs уникальны; неверная action, метод, порт, домен, CIDR или неизвестный listener_id — ошибка check.

User selectors, auth, Proxy-Authorization и проверка паролей в M02 не реализуются и не принимаются в config. Их добавляет M05; не создавать placeholder identity, которая автоматически разрешает доступ.

Разрешённый запрос сохраняет ID совпавшего правила в структурированных метаданных, а не в тексте, содержащем исходный URI.

### 4.3 Проверка каждого IP после DNS

access.ip_rules содержит id, action и непустой список networks (CIDR). Для allow дополнительно допускается allow_special = true/false; у deny такое поле отвергается. First-match; default определяется access.ip_default:
- public_only (по умолчанию): без совпавшего правила разрешён только обычный глобальный unicast;
- deny: без совпавшего правила IP запрещён.

Для совпавшего allow правило дополнительно должно пройти проверку категории адреса: специальный адрес требует allow_special = true в этом же правиле. Deny запрещает всегда. Никакое allow не разрешает unspecified, multicast и limited broadcast; эти адреса непригодны как TCP target в M02. Scoped IPv6 уже отвергнут.

Консервативная политика Angara для public_only: блокировать специальные префиксы из обоих IANA Special-Purpose registries, в том числе записи с Globally Reachable=true; дополнительно блокировать multicast, reserved IPv4 240.0.0.0/4 и IPv6 вне 2000::/3. Это выбор продукта, а не характеристика маршрутизируемости всех записей IANA. Внутренние сети и тестовый loopback разрешаются явно узким IP-правилом с allow_special=true. Обычное широкое доменное allow не открывает доступ к ним.

Таблицу специальных префиксов сохранить в исходниках/fixture с источником и датой снимка IANA; check и тесты не скачивают её из сети. Проверить private, loopback, link-local/metadata, CGNAT, документационные сети, unspecified, multicast, IPv4-mapped IPv6 и IPv6 transition/NAT64 ranges. CIDR с ненулевыми host bits отвергается, чтобы конфигурация не исправлялась молча.

Каждый уникальный ответ resolver проверяется отдельно. При смеси разрешённых/запрещённых IP использовать только разрешённые. Если таких нет — никакого connect. Прямой IP проходит ту же IP-политику без DNS. Разрешённый домен не отменяет IP-проверку.

## 5. Egress и маршрутизация

egress — профили двух видов:
- mode = "system": обычная маршрутизация ОС, без bind_ip;
- mode = "bind_ip": обязательный конкретный исходящий IP, bind к IP:0 перед connect.

Bind_ip не может быть wildcard/unspecified, multicast, IPv4-mapped или scoped IPv6. IP не обязан совпадать с bind входного listener. Существование адреса на сервере check не проверяет: это сетевой результат реального dial.

routing.default_egress — существующий ID; routing.rules — first-match правила с id, egress_id и теми же selectors, что у request ACL, кроме action. Выбор выполняется после pre-DNS allow и до DNS. На запрос выбирается один профиль, общий для всех допустимых IP-кандидатов. IP/CIDR selectors маршрута и user selectors в M02 пока не поддержаны; destination в routing этого этапа означает нормализованный домен и порт.

Правила выбирают путь, но не расширяют ACL. Неизвестные ссылки, повторяющиеся IDs и несовместимые параметры профиля отвергаются до запуска. Без routing.rules используется явный default, а не первый профиль массива.

Семейство bind_ip должно подходить кандидату; неподходящие по семейству кандидаты пропускаются до connect. Если не осталось совместимых — NoCompatibleAddress. Ошибка bind не запускает fallback на system или другой профиль. Допустимые попытки других IP назначения используют только уже выбранный профиль.

SO_BINDTODEVICE, автоматическая смена сетевых настроек, policy routing/firewall сервера, балансировка каналов и изоляция DNS по интерфейсу не входят в M02. Поле bind_device пока отклоняется. Реальная проверка двух физических/виртуальных NIC — M08; M02 обязан показать работу двух исходящих IP на Linux loopback. Привязка исходящего IP сама по себе не обещает выбор физического интерфейса при произвольной конфигурации маршрутов ОС.

## 6. Resolver и безопасный dial

### Resolver

Нужен настоящий SystemResolver, использующий системную политику разрешения имён Ubuntu/Linux, и внедряемая тестовая реализация. Собственный DNS-протокол, внешний публичный DNS по умолчанию и DNS-кэш не добавлять.

Системный lookup работает вне async worker threads. Число реально начатых/поставленных в blocking pool операций ограничено dns.max_in_flight. Использовать немедленный Busy при исчерпании бюджета; не создавать очередь ожидания на каждый новый запрос.

Особенно проверить timeout/cancellation: начавшийся блокирующий системный lookup нельзя считать отменённым только потому, что клиент перестал ждать. Разрешение на работу удерживается до фактического окончания lookup, операция остаётся в ограниченном реестре работ. Иначе повторные таймауты обойдут лимит. Для spawn_blocking permit должен жить внутри реальной работы, а не только во внешнем future ожидания. Просроченный результат не вызывает dial.

При остановке resolver прекращает приём новых работ, отменяет ещё не начатые, ограниченно ожидает завершения. Системный вызов, который уже выполняется, не обещается принудительно прерванным: остаточные работы должны быть ограничены, учтены и описаны как ограничение системного backend. Не объявлять shutdown_timeout доказательством уничтожения таких потоков.

Результат — ограниченный список уникальных IpAddr, без произвольного порта. Пустой результат — DnsNoAddresses; превышение max_answers после дедупликации — DnsTooManyAddresses и отказ целиком. Новое разрешение в рамках одного open_outbound не выполняется. Отдельный последующий запрос заново проверяет весь путь и новый DNS-ответ.

### TCP dial и ресурсы

- Подавать в реальный TcpSocket::connect именно проверенный SocketAddr; вызов connect с hostname или ToSocketAddrs на этой границе запрещён.
- Последовательные попытки разрешённых адресов в порядке resolver после дедупликации; максимум max_connect_attempts. В M02 нет Happy Eyeballs и параллельных гонок.
- Общий total_timeout_ms отсчитывается с входа open_outbound; DNS и каждая попытка ограничены меньшим из своего timeout и оставшегося общего срока. При исчерпании общего срока TotalTimeout имеет приоритет над частными timeout-классами.
- При bind-ошибке вернуть BindFailed сразу; при connect refused/unreachable можно пробовать следующий совместимый разрешённый IP в пределах срока/лимита. Полезные HTTP-данные M02 не отправляет; автоматического retry HTTP-запросов нет.
- Лимит одновременно открытых/открываемых outbound-соединений равен limits.max_connections; отдельный общий бюджет max_connecting ограничивает попытки connect. Без свободного разрешения — Busy без скрытой очереди.
- Connected удерживает разрешение outbound всё время жизни сокета; API не отдаёт живой «голый» сокет отдельно от guard. Не смешивать этот бюджет с будущим входным бюджетом M03 так, чтобы один запрос дважды захватывал один semaphore.
- Отмена/timeout закрывают незавершённый TcpSocket и возвращают разрешения; drop Connected закрывает stream и освобождает лимит. У реального blocking DNS есть отдельно описанное исключение, но его собственный permit остаётся занят до завершения.
- Нельзя создавать соединения к запрещённым кандидатам даже как «пробу доступности».

Минимальные классы ошибок: InvalidTarget, SourceDenied, AccessDenied, DestinationDenied, RouteInvalid, DnsBusy, DnsTimeout, DnsFailed, DnsNoAddresses, DnsTooManyAddresses, NoCompatibleAddress, OutboundBusy, ConnectTimeout, ConnectFailed, BindFailed, TotalTimeout; Cancelled — если API имеет явную отмену (drop future сам по себе не обязан возвращать ошибку). Названия можно адаптировать; нельзя различать их только свободным текстом. HTTP status mapping — M03/M04.

## 7. Конфигурация и совместимость

Сохранить schema_version = 1: это совместимое добавление реализованных полей. Все валидные примеры M01 продолжают проходить check; при отсутствии новых разделов исходящий доступ запрещён source gate/ACL, default egress = system. Смысл регрессий M01 сохраняется. Исключение по ожидаемому развитию schema: egress/routing/dns/transport/access теперь реализованы, поэтому старые проверки «этот ключ пока не поддержан» адаптируются к новой схеме. Каждый такой случай заменить положительным тестом корректного раздела и отрицательным тестом неверного типа/неизвестного вложенного поля; не сохранять заведомо устаревший текст ошибки и не удалять проверку строгости.

Новые разделы: access, dns, transport, массив egress, routing. Отсутствующие access.rules/ip_rules/routing.rules — пустые массивы. Если egress отсутствует, создать документированный системный профиль id=system; если список задан, он не пуст и используются только перечисленные профили. При отсутствии routing.default_egress значение system; неизвестная ссылка — ошибка, а не выбор первого элемента.

Все уровни остаются deny_unknown_fields. Предел каждого списка rules, profiles, selectors и CIDR — 256 элементов, ID — 1..=64 ASCII букв/цифр/._-; дубли IDs в пределах категории отвергать. Домен/CIDR/URI проверяются соответствующим типом; schema не принимает «будущие» TLS/auth/users/cache/admin/parent/bind_device. IDs egress глобальны среди профилей, rule IDs уникальны внутри source-independent request/IP/routing категорий.

| Параметр | Default | Допустимый диапазон |
| --- | --- | --- |
| dns.timeout_ms | 3000 | 100..=30000 |
| dns.max_in_flight | 4 | 1..=64 |
| dns.max_answers | 16 | 1..=64 |
| transport.total_timeout_ms | 10000 | 100..=120000 |
| transport.connect_timeout_ms | 3000 | 100..=30000, не больше total_timeout_ms |
| transport.max_connect_attempts | 3 | 1..=8 |
| transport.max_connecting | min(32, limits.max_connections) | 1..=256 и не больше limits.max_connections |

Это стартовые ограничители для пилота, не обещание пропускной способности. Default total_timeout выбирается независимо от dns.timeout; на выполнении действует общий deadline. Проверить нули, отрицательные значения, переполнение, верхние границы и несовместимые ссылки.

Сохранять исправления M01: ошибки не печатают URI, credentials или значения config, управляющие символы экранируются, длина диагностик ограничена. Реальные адреса/домены/профили не подставлять в свободный текст ошибки валидации. Структурированные служебные метаданные возвращаются вызывающему коду, без нового журналирования трафика.

### Пример M02 для check

Это спецификация будущего examples/m02-policy.toml. Новые поля реализует DeepSeek; на M01 такой файл пока отвергается.

~~~toml
schema_version = 1

[runtime]
worker_threads = "auto"

[limits]
max_connections = 256
max_header_bytes = 32768
header_read_timeout_ms = 10000
idle_timeout_ms = 60000
shutdown_timeout_ms = 10000

[[listeners]]
id = "proxy-loopback"
bind = "127.0.0.1:3128"
transport = "http"

[access]
source_allow = ["127.0.0.0/8", "::1/128"]
ip_default = "public_only"

[[access.rules]]
id = "deny-example-admin"
action = "deny"
host_exact = ["admin.example.com"]

[[access.rules]]
id = "allow-example-http"
action = "allow"
methods = ["GET", "HEAD"]
ports = [80]
host_suffix = ["example.com"]

[[access.rules]]
id = "allow-example-connect"
action = "allow"
methods = ["CONNECT"]
ports = [443]
host_suffix = ["example.com"]

[dns]
timeout_ms = 3000
max_in_flight = 4
max_answers = 16

[transport]
total_timeout_ms = 10000
connect_timeout_ms = 3000
max_connect_attempts = 3
max_connecting = 32

[[egress]]
id = "system"
mode = "system"

[routing]
default_egress = "system"
~~~

Добавить второй examples/m02-egress-local.toml: два listener_id, профили bind_ip=127.0.0.1 и 127.0.0.2, routing по listener_id и узкие loopback IP-правила allow_special=true. В README пометить его как лабораторный. Весь пример должен реально проходить check; проверка не выполняет DNS и не открывает сокеты.

Точная форма новых IP/routing правил для лабораторного примера (полный TOML):

~~~toml
schema_version = 1

[runtime]
worker_threads = 2

[limits]
max_connections = 256
max_header_bytes = 32768
header_read_timeout_ms = 10000
idle_timeout_ms = 60000
shutdown_timeout_ms = 10000

[[listeners]]
id = "lab-a"
bind = "127.0.0.1:3128"
transport = "http"

[[listeners]]
id = "lab-b"
bind = "127.0.0.2:3128"
transport = "http"

[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow-local-lab"
action = "allow"
listeners = ["lab-a", "lab-b"]

[[access.ip_rules]]
id = "allow-loopback-target"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true

[[egress]]
id = "via-a"
mode = "bind_ip"
bind_ip = "127.0.0.1"

[[egress]]
id = "via-b"
mode = "bind_ip"
bind_ip = "127.0.0.2"

[routing]
default_egress = "via-a"

[[routing.rules]]
id = "route-a"
listeners = ["lab-a"]
egress_id = "via-a"

[[routing.rules]]
id = "route-b"
listeners = ["lab-b"]
egress_id = "via-b"
~~~


## 8. Проверки и критерии приёмки

Базовая среда — Ubuntu 24.04 x86_64. Тесты автономны: локальные TCP endpoints, контролируемый resolver/dialer, временные каталоги и динамические порты. Публичный Интернет не является условием корректности. IPv6 на целевом Ubuntu runner проверяется реально; недоступность стенда описать, а не засчитать как успешный тест.

| ID | Обязательное наблюдаемое поведение |
| --- | --- |
| M02-TGT-01 | HTTP scheme/default port/path/query; CONNECT port/bracket IPv6; плохие формы/порты/userinfo/fragment/control отклонены |
| M02-TGT-02 | Case/trailing dot/IDNA единообразны для targets и rules; Host helper не подменяет target; недопустимые numeric IPv4 и scope отвергнуты |
| M02-ACL-01 | Source gate, AND/OR selectors, порядок allow/deny, catch-all и default deny; deny до DNS даёт ноль resolver/dial вызовов |
| M02-ACL-02 | Exact/suffix по меткам; не совпадают notexample.com, example.com.attacker.test и IP literal вместо разрешённого домена |
| M02-IP-01 | IANA special/private/metadata/CGNAT/multicast/IPv6/mapped адреса закрыты по умолчанию; узкий allow_special открывает только допустимый заданный диапазон |
| M02-IP-02 | Смешанный DNS-ответ фильтруется; полностью запрещённый ответ не вызывает dial; прямой IP проходит ту же политику без resolver |
| M02-DNS-01 | Пустой, дублирующий, ошибочный и чрезмерный ответ; дедупликация, порядок и классификация ошибок |
| M02-DNS-02 | DNS timeout/drop ожидания не освобождает бюджет ещё работающего blocking lookup; повторные вызовы получают Busy; после реального завершения бюджет возвращается |
| M02-DNS-03 | Два запроса с разными DNS-ответами повторно проверены; в одном запросе dial получает ровно проверенный IP, повторного lookup нет |
| M02-NET-01 | Реальный TCP endpoint получает соединение и данные через Connected; полная связка policy → resolver → dial, а не только изолированные helpers |
| M02-NET-02 | Два egress-профиля: endpoint наблюдает выбранные 127.0.0.1/127.0.0.2; выбор по listener/source/domain/port и запрет маршрутизацией обойти ACL |
| M02-NET-03 | Отсутствующий исходящий IP, несовместимое семейство и bind failure; нет fallback к system или второму профилю |
| M02-NET-04 | Общий и per-attempt deadline, лимит попыток, отказ/обрыв, drop connect future и Connected возвращают сокеты/permits; open/connecting/DNS бюджеты не обходятся clone |
| M02-CFG-01 | Новые примеры и старые M01 configs; ошибки CIDR/ID/references/selectors/limits, неизвестные и будущие поля; check/serve не вызывают сеть |
| M02-ERR-01 | Синтетический секрет в URI/userinfo/плохих полях не попадает в ошибки; newline/ESC в ключах не создают новые записи |
| M02-REG-01 | Покрытие исходных 53 тестов M01 сохранено; ожидания намеренно реализованных новых ключей адаптированы по разделу 7; все обязательные проверки проходят |

Отрицательный сетевой тест не должен проходить из-за недоступности контрольного origin. Отдельно доказать его доступность разрешённым запросом; для «нет попытки» использовать наблюдаемую границу dial/счётчик вызовов. Не ограничиваться коротким ожиданием accept без позитивного контроля.

Тесты таймингов — через управляемые события, внедряемый медленный backend и тестовое время, где применимо. Не удерживать реальные blocking lookup навсегда: управляемая заглушка обязана завершиться в cleanup. Проверить отсутствие неучтённой работы после освобождения тестового стенда. Реальный SystemResolver должен быть реализован и проверен небольшим smoke на системном локальном имени; особенности локального resolver отделить от детерминированных policy-тестов.

Связь с общей матрицей: TGT-01, ACL-01/02/03/04, NET-02/04/06, CFG-01/02/03, CPU-01 в применимом объёме. Реальные listeners NET-01, pool NET-03 и стенд нескольких NIC NET-05 принимаются на следующих этапах, не выдаются за выполненные тестами двух loopback IP.

## 9. Зависимости, CI и границы изменений

Разрешены необходимые модули, расширение config/runtime, тесты/fixtures, примеры, инструкции и CI. Tokio того же закреплённого семейства получает net/time/sync для реальных socket/deadline/budget операций; runtime включает нужные I/O/time drivers только при его явном создании. CLI check/serve сетевой runtime не создают.

Для URI, CIDR и IDNA использовать зрелые библиотеки (например http, ipnet, idna) вместо самописных парсеров. Выбор и features обосновать в плане; обновить Cargo.lock и dependency policy только в фактически необходимом объёме. Не менять Rust toolchain и не добавлять hyper/rustls до использующего их этапа. Новые license/advisory исключения, unsafe и существенные альтернативные DNS backend сначала вынести отдельным решением; работа M02 по данному контракту этого не требует.

Сохранить существующие CI permissions и закрепление actions SHA. Команды:
~~~console
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
cargo test --locked
cargo run --locked -- check --config examples/minimal.toml
cargo run --locked -- check --config examples/multi-listener.toml
cargo run --locked -- check --config examples/m02-policy.toml
cargo run --locked -- check --config examples/m02-egress-local.toml
cargo deny check
~~~

Если Tokio macros нужны только тестам, ограничить их назначение. Дополнительные стенды и tests публикуются вместе с кодом. Не отключать netguard ради включённых net features: он обязан продолжать подтверждать отсутствие сети именно в CLI check/serve.

Не входят: сервер HTTP, передача HTTP/CONNECT, TLS, users/auth, parent/cache, TUI/web, reload/pool, bind_device, NUMA/affinity, установка маршрутов и systemd.

## 10. Отчёт DeepSeek и приёмка Codex

В PR: Issue, base/head SHA, итоговое поведение; таблица всех M02-ID с командами/результатами; версии/runner; фактические CI ссылки; добавленные зависимости; примеры конфигурации; ресурсные пределы; ограничения системного DNS и непроверенные сценарии.

Фактические результаты не заполнять заранее. Ошибка окружения и skip не равны passed. Готовность: все обязательные M02-ID и регрессии выполнены, нет блокирующих замечаний, Codex проверил точный head. Если пришлось менять оговорённую семантику ACL, IP-политики или fallback, сначала зафиксировать решение, а не адаптировать ожидания тестов под код.

В конце checkpoint: что сделано, SHA, команды, оставшиеся ограничения и ссылка на PR. Следующий этап M03 выдаёт Codex после принятия M02 и указания владельца.

## 11. Первичные источники

- [RFC 9110, HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html), CONNECT и authority.
- [RFC 9112, HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html), request-target и Host.
- [IANA IPv4 Special-Purpose Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/).
- [IANA IPv6 Special-Purpose Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/).
- [Tokio TcpSocket](https://docs.rs/tokio/latest/tokio/net/struct.TcpSocket.html), bind и connect к SocketAddr.
- [Tokio spawn_blocking](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html), пределы и невозможность abort начатой blocking работы.
- [IDNA domain_to_ascii_cow](https://docs.rs/idna/latest/idna/fn.domain_to_ascii_cow.html), профиль нормализации.

RFC задают протокол; порядок ACL, консервативная IP-политика, limits и отказ от скрытого fallback — контракты Angara, определённые Codex для M02.
