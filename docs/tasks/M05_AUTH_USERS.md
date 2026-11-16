# DeepSeek: M05 — локальные пользователи, Basic и ACL по identity

Статус: READY, редакция **M05-r1 от 11 ноября 2026 года**.
Постановка и ревью: Codex. Реализация, тесты и CI: DeepSeek V4.1 Flash 1017.
База реализации: `main` @ **`49037888f6ab5f3a843a54fc13d2b2e1e278ba9a`**.
M04 принят [ревью ACCEPTED](https://github.com/AlexeiSmol/Angara/pull/13#issuecomment-6792835709) на `e7afedf47b6874e2f1902c7740addce759b30131` и слит в [PR #13](https://github.com/AlexeiSmol/Angara/pull/13). Исходная регрессия: 242 основных Linux-теста, три отдельно запускаемые resource-проверки, успешный CI `42988221130`; M04-R1–R5 закрыты. Это результаты M04, а не отчёт о реализации M05.

## 1. Результат и порядок работы

На listener с обязательной Basic-аутентификацией каждый HTTP-запрос и установка CONNECT требуют действующих credentials локального пользователя. Проверенная identity участвует в ACL и выборе egress. Неверные credentials возвращают 407 без DNS, dial, 100 Continue и открытия туннеля. Пароли хранятся только как salted Argon2id PHC; дорогие проверки ограничены и выполняются вне async workers. Действующий HTTP/CONNECT путь M02–M04 сохраняет свои проверки и ресурсные гарантии.

В M05 входят локальная база пользователей, безопасная генерация хэша CLI, конфигурация auth, единый auth guard, пользовательские selectors ACL/routing, изоляция HTTP pool, лимиты/отмена auth, тесты, CI и инструкции стенда. Первые испытания — Ubuntu Server 24.04 x86_64, 10–20 логических клиентов на локальном стенде; это не доказательство работы на 20 физических устройствах или нескольких NIC.

TLS до proxy — M06; reload пользователей, эксплуатационные журналы/метрики/control service — M07; release/systemd — M08; parent/cache/TUI/web — M09–M12. В M05 не добавлять LDAP, PAM, ключи, bearer tokens, группы/роли, сетевую БД, auth cache, квоты, per-user connection/bandwidth limits, автоматический lockout или онлайн-редактирование пользователей. Существующие общие client/outbound/DNS/connect/pool budgets сохраняются.

1. Прочитать AGENTS, ARCHITECTURE, DECISIONS, TEST_STRATEGY и это задание на SHA документации из Ready Issue. Ветка `feat/<номер-Issue>-m05-auth` создаётся от **базы кода выше**, PR направляется в `main`. Незавершённый PR постановки не блокирует работу и не разрешает слияние других PR.
2. Оставить в Issue короткий план: подготовка users snapshot, auth guard обоих ingress-путей, передача identity в policy/outbound/pool, blocking admission/ownership/cancellation, CLI и проверки. Указать необходимые зависимости.
3. Сначала подтвердить узкими тестами, что HTTP и CONNECT проходят один guard, неизвестный пользователь использует dummy verification, отмена запроса не освобождает permit ещё работающего verifier. Затем реализовать весь контракт и регрессии.
4. Передать PR с матрицей всех 20 M05-ID, base/head SHA, фактическими командами, CI и ресурсными измерениями. Самостоятельно принимать/сливать этап или начинать M06 нельзя.

## 2. База кода и границы рефакторинга

`Config`, `RequestContext`, `RequestMeta`, `OutboundService`, `OutboundPlan`, `Connected` и bounded origin pool уже существуют. В `src/http/forward.rs` обычный HTTP и CONNECT обрабатываются отдельными ветками; обе должны получить одинаковую проверку обязательной auth. Добавить модуль auth с ограниченным backend и непрозрачной проверенной identity. Не строить отдельный сетевой путь для авторизованных запросов.

Сохранить `open_outbound`/подготовку авторизованного плана, source gate, pre-DNS first-match ACL, IP-проверку **каждого** кандидата, egress bind и budgets. `RequestContext::new` без credentials остаётся anonymous, но не разрешает открыть outbound для listener, требующего Basic. На этой границе обязательна повторная проверка наличия подходящей проверенной identity; простого вызова HTTP guard недостаточно для безопасного библиотечного API. Нельзя дать публичный конструктор `authenticated("admin")`, флаг `auth_ok` или произвольную строку, принимаемую за результат backend. Identity привязана к загруженному auth snapshot; токен от другого server/backend snapshot не удовлетворяет обязательной auth текущего сервера. Username доступен policy через проверенный тип.

Сохранить принятый metadata-only patch hyper 1.12.0 (`OriginalRequestTarget`), его scope и отрицательный request-target корпус. Не менять framing/parser, не добавлять pre-parser, самодельную криптографию или unsafe. Argon2, PHC/base64, CSPRNG, zeroization, Unicode NFC и чтение TTY без echo использовать через поддерживаемые библиотеки. Эти необходимые зависимости разрешены в рамках M05; совместимость Rust 1.97/MSRV, lockfile, лицензии и advisories проверяются. Новая parser/crypto архитектура требует отдельного решения.

Особенно сохранить explicit `sender.ready().await` перед повторным HTTP send под прежним deadline, единственный client writer/bridge 64 KiB, output accounting только hyper bytes, interim limits, общий byte-progress idle, first-EOF absolute drain и ownership CONNECT после завершения HTTP driver. Auth не создаёт второй writer или очередь ответов.

## 3. Конфигурация и безопасная подготовка

`schema_version = 1` сохраняется. Старые шесть примеров без новых полей остаются валидными; default listener auth — `none`, как на прежнем лабораторном стенде. Все новые таблицы/поля строгие, `deny_unknown_fields`, без принимаемых «на будущее» параметров.

| Поле | Default и проверка |
| --- | --- |
| `listeners[].auth` | `"none"`; только `"none"` / `"basic"`, без смены регистра |
| `listeners[].allow_insecure_basic` | `false`; `true` допустимо только с `auth="basic"` |
| `[auth].users_file` | Обязательный непустой путь, если таблица `[auth]` объявлена; Basic listener требует эту таблицу |
| `[auth].max_verifying` | `2`, целое `1..=16`, общий бюджет всех listeners данного server instance |
| `[auth].verify_timeout_ms` | `2000`, целое `100..=30000`, срок ожидания результата запроса, а не обещание отменить Argon2 |
| `access.rules[].users` | Необязательный непустой список `1..=256` уникальных локальных username |
| `routing.rules[].users` | Те же правила и семантика; не добавляется в `access.ip_rules` |

В M05 transport остаётся `http`. Для `auth="basic"` незашифрованный bind вне loopback, включая `0.0.0.0` / `::`, отклоняется при `check` и `serve`, если нет явного `allow_insecure_basic=true`. Loopback определяется по bind IP с нормализацией IPv4-mapped, не по адресу подключившегося клиента. Проверить IPv4, IPv6 и mapped. Исключение не меняет source/IP ACL. `X-Forwarded-Proto`, CONNECT к HTTPS-сайту и «локальный» peer не превращают listener в TLS. M06 расширит реальный transport; сейчас TLS не имитировать.

Путь users_file разрешается относительно каталога **основного TOML**, абсолютный путь допустим. `check --config` и `serve --config` выполняют одну подготовку снимка до runtime/listen/DNS/dial. `check` может читать локальные файлы, но не создаёт Tokio runtime, сокеты, blocking hash jobs и не проверяет пароли. Ошибки любых объявленных users/auth данных отвергают запуск целиком, в том числе если все listeners пока `none`; частичной базы и fail-open нет.

Сохранить чистую `Config::parse` для прежних конфигураций. Конфигурация с users_file требует явного base directory/file context: добавить подготовку с таким контекстом; `Config::parse` без него возвращает понятную безопасную ошибку. Любой публичный путь создания сервера обязан получить полностью подготовленный snapshot либо отклонить неподготовленную конфигурацию до bind. Не читать относительный путь из случайного cwd и не оставлять обход через тестовый/библиотечный конструктор. Разрешается уточнить внутренние типы, сохранив этот контракт и совместимость старых auth-free вызовов.

Образец новых полей, **фрагмент для объединения с полной M04-конфигурацией**:

```toml
[auth]
users_file = "users.toml"
max_verifying = 2
verify_timeout_ms = 2000

[[listeners]]
id = "proxy-auth-local"
bind = "127.0.0.1:3128"
transport = "http"
auth = "basic"

[[access.rules]]
id = "alice-local-http"
action = "allow"
listeners = ["proxy-auth-local"]
users = ["alice"]
methods = ["GET", "POST", "CONNECT"]
ports = [8080, 8443]
```

Этот фрагмент не заменяет source_allow, IP allow_special локального стенда, CONNECT port gate и routing/egress. Общие allow rules не должны случайно открывать назначения всем пользователям до пользовательского правила.

## 4. Users snapshot, PHC и административная команда

Файл — UTF-8 TOML, до **1 MiB** при чтении, до **1024** users, `version = 1`, строгие поля на всех уровнях. Проверять предел чтением не более limit+1, а не одним metadata.size перед неограниченным read. Из одного открытого regular-file handle получить metadata и прочитать содержимое. Ошибки чтения/UTF-8/схемы/любого пользователя отвергают весь snapshot.

```toml
version = 1

[[users]]
username = "alice"
password_hash = "<полный PHC из angara users hash; этот шаблон невалиден>"
disabled = false
```

Обязательны `username` и `password_hash`; `disabled` — boolean, default false. Пустая база допускается явно (`version=1`, `users=[]`) и не разрешает ни одного входа. Username — `1..=64` ASCII bytes: первый символ буква/цифра, далее буквы/цифры/`._-`; регистр значим, имена уникальны. Паролей в plaintext, fallback на plaintext и специальных универсальных пользователей нет. Неизвестные имена в ACL допустимы: они никому не дают identity, поэтому удаление пользователя не требует удаления его правил. Disabled users остаются валидными записями и никогда не проходят auth.

Linux: проверять права **открытого** файла; owner — effective UID сервиса либо root, нет group write и любых world permissions (`mode & 0o027 == 0`; например 0600/0640). Нерегулярный файл, небезопасные права/owner — ошибка, без автоматического chmod/chown и без требования запускать proxy от root. Документировать доверенный административный каталог. Ссылка допустима только на regular target, проверяемый по тому же открытому handle; не проверять metadata одного файла, а читать другой. На иных ОС условность Unix-проверки обозначить, поддержку ОС не объявлять до испытаний.

Профиль M05 фиксирован: **Argon2id, v=19, m=19456 KiB, t=2, p=1, salt 16 bytes, output 32 bytes**. PHC до 256 ASCII bytes; проверить algorithm/version, точные m/t/p, отсутствие лишних/повторных параметров и корректные decoded salt/output **до** hash allocation/verification. Иные профили, огромные числа, Argon2i/d, пустой salt/output, испорченный PHC отвергают конфигурацию. Не доверять стоимости из файла и не полагаться на default библиотеки. Это исходный ограниченный профиль, выбранный Codex по рекомендации OWASP; в отчёте измерить стоимость на фактическом стенде. Менять профиль по результатам только явным изменением контракта, а не незаметным принятием произвольных PHC.

Добавить команды:

```text
angara users hash
angara users hash --password-stdin
```

Первая запрашивает пароль и подтверждение в TTY **без echo**; без TTY предлагает явный stdin-режим и завершается, не читая пароль неожиданно. Вторая читает одну ограниченную строку, убирая только конечный LF либо CRLF; EOF без newline допустим, дополнительные строки/bytes отклоняются. Не применять trim к паролю, не терять пробелы или двоеточия. Пароль `1..=1024` UTF-8 bytes до и после NFC, без control characters; одинаковая NFC-подготовка при создании и проверке. Пустой/слишком длинный/плохой UTF-8/несовпавшее подтверждение — отказ. Для stdin вход ограничить **1027** bytes, включая limit+1 для максимального пароля и CRLF; не читать весь pipe в память. Документировать stdin EOF и не принимать пароль через argv или собственный env-параметр.

Успех печатает в stdout только один полный PHC и newline. Salt — новые 16 bytes из OS CSPRNG, RNG failure — ошибка; одинаковые пароли дают разные salt/PHC. Команда не открывает сеть, не создаёт многопоточный runtime и не изменяет users_file. Запись/добавление/disable/delete выполняются администратором в файле с безопасными правами; после изменения в M05 нужен restart. CLI help и exit codes документировать: 0 успех, 2 неверные аргументы, 1 ошибка ввода/хэширования/локального файла. Новые режимы должны иметь сетевой guard.

Не публиковать рабочие credentials. Для примеров разрешены явно маркированные синтетические fixtures, непригодные для реального развёртывания. Добавить полный `examples/m05-auth-local.toml`, безопасную подготовку временного users_file и воспроизводимые команды `check`/`serve`; CI создаёт файл 0600, а не ослабляет проверку ради git checkout 0644.

## 5. HTTP Basic и порядок проверок

Сохранить библиотечный HTTP framing и ранние проверки M03/M04: некорректный request-target/Host/framing/Expect может получить прежний 4xx/501/505 до auth. Для корректного запроса порядок: **source gate → auth текущего listener → user/request ACL → routing → DNS → IP policy каждого кандидата → dial/reuse → HTTP response или CONNECT 200**. Source deny не запускает verifier, DNS или dial. Успешный локальный OPTIONS/Max-Forwards также требует auth и применимых ACL, хотя upstream не нужен.

Для `auth="basic"`:

- Ровно одно поле `Proxy-Authorization`; несколько полей, список credentials через запятую, иная схема, отсутствующее/пустое поле, испорченный base64 — 407. Имя поля и схема Basic case-insensitive. После scheme допустимы один или несколько SP; внешний OWS нормализуется по правилам HTTP, внутри base64 whitespace запрещён. Декодирование — standard base64 с корректным padding, без URL-safe/неоднозначных вариантов.
- До декодирования ограничить **значение** header 1536 bytes, decoded user-pass — 1089 bytes. Ранее достигнутый общий header limit сохраняет ответ 431; локальные auth limits дают 407 без hash. Не выделять память пропорционально отвергнутому полю.
- Разделить decoded значение по **первому** `:`. User — непустой UTF-8 до 64 bytes, password — непустой UTF-8 до 1024 bytes; control characters запрещены. Пароль может содержать `:` и пробелы; NFC выполняется одинаково с CLI, без case-fold/trim. Локальные account names ограничены ASCII в разделе 4; well-formed неизвестное Unicode/иное имя не создаёт пользователя и идёт через dummy verification. Невалидный UTF-8/контролы/превышение длины — синтаксический отказ до verifier.
- Для существующего enabled user проверять его PHC библиотекой с безопасным сравнением. Для well-formed неизвестного/disabled user выполнять **одну** dummy verification того же фиксированного профиля под тем же budget. Dummy PHC валидируется заранее, никогда не создаёт identity даже при совпадении пароля. Не обещать абсолютную неразличимость сетевых таймингов, но не выдавать ранний account lookup результат или разные сообщения.
- Успех создаёт проверенную immutable identity данного запроса. Она не наследуется TCP-соединением: после alice запрос без credentials снова получает 407; новый запрос bob проходит свою проверку. Проверка повторяется на каждом request, включая pool hit и CONNECT. Auth cache нет.

Ответ на любой credential failure — **407** с одним `Proxy-Authenticate: Basic realm="Angara", charset="UTF-8"`, фиксированным безопасным телом, `Connection: close` и корректным framing. Не раскрывать существование/disable пользователя. Не читать/дренировать произвольное тело отказанного запроса и не отправлять 100 Continue; закрывать соединение через штатный single writer. In-flight/pipelined bytes не должны становиться следующей авторизованной операцией. Ошибка после начавшегося response не вызывает второй status line.

На `auth="none"` identity всегда anonymous: наличие Proxy-Authorization не выдаёт права, не запускает hash и не проверяет пароль. Поле удаляется существующим фильтром перед origin; это сохраняет прежний лабораторный режим. Не переносить пользователя с соседнего listener/запроса и не принимать origin `Authorization` за proxy credentials.

## 6. Identity, ACL, routing и HTTP pool

Новый selector `users` имеет OR внутри списка, AND с прочими selectors правила. Отсутствующий selector не ограничивает identity и может совпасть с anonymous; присутствующий никогда не совпадает с anonymous. Правила по-прежнему first-match, default deny; несуществующее имя не совпадает, `*` и автоматический `authenticated` не вводятся. Пользователь не отменяет source gate, CONNECT allowed_ports, target/IP policy или egress. Успешная auth и запрещённое назначение дают прежний 403, не 407.

Расширить тем же selector routing rules: identity влияет только на выбор существующего egress после request allow; не выдаёт право dial. Проверить разные user→egress на локальных исходящих адресах и отсутствие перехода к system routing при неудачном bind. Это не испытание нескольких физических NIC.

Origin pool key содержит прежние canonical host/port, фактический IP:port, egress_id, config generation **и listener ID + authenticated username либо отдельный anonymous marker**. Auth snapshot принадлежит этому поколению/экземпляру; разные snapshots не объединяются. Даже при одинаковом origin/egress разные пользователи, anonymous и разные listeners не используют один origin TCP connection. Разрешён reuse одного пользователя в пределах прежнего lifecycle. Каждый запрос заново проходит auth, policy и DNS/IP revalidation перед reuse. Не восстанавливать identity из сохранённых заголовков idle connection. После смены user в клиентском keep-alive использовать соответствующий pool key; pipeline сохраняет порядок ответов.

CONNECT authenticates до dial и 200, затем identity фиксирована до закрытия туннеля. Payload непрозрачен, повторной HTTP auth внутри нет; credentials для сайта/приложения внутри туннеля не анализируются. Плохой пароль не создаёт `Connected` и не захватывает outbound permit; admission auth не удерживает connecting permit. Ранние tunnel bytes на отказанном CONNECT отбрасываются с закрытием, никогда не уходят origin.

## 7. Ограничение CPU, отмена и shutdown

Один backend на server instance обслуживает все listeners. Перед `spawn_blocking` применить `try_acquire_owned`: при насыщении **503 + close**, без ожидания в очереди и без создания ещё одного blocking job. Очередь ожидания auth в M05 имеет длину **ноль**. Бюджет учитывает и уже исполняющиеся, и принятые, но ещё не начавшие CPU работу closures. Blocking pool Tokio общий с DNS, но отдельные auth/DNS permits не заменяют друг друга. В M05 не менять глобальный blocking pool без обоснования.

Owned permit переносится **в closure**, освобождается только после фактической проверки и очистки её секретов, включая panic/error путь. Timeout, disconnect, отмена future и force shutdown не должны вернуть его досрочно. После timeout не ставить повторную проверку автоматически и не выдавать identity по позднему результату. Удаление из bounded job registry не должно оставлять бесконтрольный список JoinHandles или завершённых результатов.

Срок ожидания начинается при admission и равен verify_timeout_ms; timeout — **503 + close**, не upstream 504 и не ложный 407. Внутренняя ошибка verifier — безопасный 503 без детали credential. Missing/malformed credentials дают 407 до admission; well-formed wrong/unknown/disabled имеют ту же работу/budget, затем 407. Клиентский idle/header timeout и shutdown могут закрыть соединение раньше; это не отменяет учёт настоящей hash работы.

Начатый `spawn_blocking` Argon2 не обещается принудительно отменённым. При shutdown прекратить admission, закрыть клиентские операции в рамках существующего общего абсолютного shutdown deadline, не добавлять новое полное окно ожидания auth. Уже начатые closures могут завершиться позже: число ограничено max_verifying, стоимость фиксированным профилем, они сохраняют ownership permit/backend и не публикуют ответ/identity после отмены. Runtime shutdown не должен зависнуть на их join; описать это ограничение явно, как для системного DNS. В тестах после **фактического** завершения jobs подтвердить возврат счётчиков/ресурсов. Не объявлять задержавшуюся CPU работу отменённой только из-за drop JoinHandle.

На default одновременно занята память максимум двух Argon2 проверок: около **38 MiB рабочей памяти плюс overhead**, не всего RSS процесса. Hard limit 16 означает до 304 MiB плюс overhead; документировать настройку. Нет неограниченной очереди, кэша успешных/неудачных паролей, истории попыток или map по произвольным usernames/IP. Проверка пароля не блокирует async workers и не удерживает общий mutex на протяжении hash; независимые HTTP/tunnel операции продолжаются в рамках прочих лимитов.

## 8. Секреты и ошибки

Удалять Proxy-Authorization и proxy-auth companions из forwarded headers/trailers в обоих направлениях по прежнему контракту; origin не получает proxy credentials даже при auth=none. Origin `Authorization`/`WWW-Authenticate`, Cookie и end-to-end смысл сохраняются. Номинация поля через Connection не позволяет обойти auth или протащить его origin. Trailers с credentials не авторизуют запрос; сохраняются прежние запреты trailers. Чужой origin 407 не создаёт дополнительную локальную попытку и не запускает replay POST.

Пароль, decoded credential, base64 token и PHC отсутствуют в обычных Debug/Display/error/log/panic сообщениях, event labels, response body и CI artifacts. `check` не печатает users_file/TOML-строку или значение испорченного PHC. Безопасная ошибка указывает класс и структурный путь/индекс; неизвестные TOML key также sanitise от control/синтетических secret markers. Не отдавать синтаксическую цитату строки, содержащей пароль/хэш.

Секретные входные буферы и нормализованный пароль очищать поддерживаемым zeroization/secret wrapper; минимум копий, без Clone/Debug секрета. Parser raw header принадлежит hyper/http: не обещать гарантированное удаление всех библиотечных/OS копий из RAM. Созданные приложением копии/декодированные буферы очищаются и не удерживаются после запроса сверх фактической blocking проверки. Хэши считаются чувствительными данными; явный stdout команды `users hash` — документированное исключение, не общий лог. Username не включать в неограниченные labels. Полноценный telemetry pipeline остаётся M07.

## 9. Обязательная матрица приёмки — 20 M05-ID

Каждая строка получает в PR конкретные тесты/команды и фактический результат на head SHA. Mock verifier допустим для детерминированного admission/timeout/cancel, но не заменяет настоящий Argon2 и HTTP/CONNECT интеграцию. Отрицательная проверка обязана доказывать отсутствие запрещённого действия счётчиками/наблюдаемым результатом, а не только статусом.

| ID | Что доказать |
| --- | --- |
| M05-CFG-01 | Все старые шесть configs валидны; строгие новые поля/defaults/ranges; missing backend, invalid mode, users selectors/duplicates/empty; parse без file context не создаёт обхода; check без runtime/network/hash; invalid serve до bind |
| M05-CFG-02 | Относительный users_file от TOML directory при другом cwd; absolute path; missing/unreadable/nonregular/oversize/invalid UTF-8/TOML/version/users>1024/duplicates; Linux права/owner по открытому handle; ошибка одной записи отклоняет весь snapshot без утечек |
| M05-CRYPTO-01 | Реальный hash/verify выбранного Argon2id профиля; разные random salts одного пароля; wrong password; malformed/дубли/лишние PHC params, huge m/t/p/length, algorithm/version/output/salt отклонены до hash allocation; check не хэширует |
| M05-CLI-01 | TTY no-echo/confirmation через PTY; явный stdin и его limits/EOF/CRLF/extra input; UTF-8/NFC, пробелы/colon, empty/controls/invalid/oversize; только PHC stdout, безопасные errors/exit codes; no argv/env password, no network/runtime; RNG failure через контролируемый seam |
| M05-TRANSPORT-01 | Loopback IPv4/IPv6/mapped разрешён; nonloopback/wildcard Basic без opt-in отвергнут check/serve; с opt-in разрешён без обхода source/IP gate; peer/X-Forwarded-Proto/CONNECT TLS не выдают защищённый transport |
| M05-HTTP-01 | Real Basic user получает разрешённые GET/POST, streaming upload/download, body/trailers и прежний Expect:100 порядок; без credentials 407 с точным challenge/close; локальный OPTIONS также защищён |
| M05-HTTP-02 | Wrong/unknown/disabled/empty/duplicate/unsupported scheme/bad base64/UTF-8/limits; синтаксические отказы без verifier, корректные unknown/disabled через dummy; одинаковый failure body/challenge, no DNS/dial/body100, затраты и количество checks наблюдаемы |
| M05-ID-01 | Один client keep-alive: alice success → bob success с другими ACL/egress → missing/wrong 407+close; identity не наследуется; разный регистр username; упорядоченный pipeline двух пользователей без смешивания response/body |
| M05-ACL-01 | First-match/default deny; users OR и AND с listener/source/method/host/port; absent users и anonymous, unknown name; good auth + forbidden target 403; listener basic не обходится public OutboundService anonymous context или чужим snapshot token; source deny не хэширует |
| M05-ROUTE-01 | User выбирает разрешённый существующий egress; фактический source IP в двух локальных egress; bind failure без fallback; user allow не обходит special/mixed DNS/IP/CONNECT port deny; прежняя IP-кандидатная проверка сохранена |
| M05-POOL-01 | Origin считает реальные accepted connections: один user reuse; разные users, anonymous, listeners и snapshots изолированы; fresh auth+policy+DNS на hit; отказ не checkout/dial; sender.ready и прежние cancellation/lease limits сохранены |
| M05-CON-01 | Good Basic CONNECT + TLS/HTTPS реального локального сайта с CA и name verification; 1 MiB POST и 1 MiB download equality; wrong/missing auth и early payload не доходят origin, нет 200/dial; good auth + blocked port/IP даёт 403; обычный reverse drain/idle сохранён |
| M05-HEADERS-01 | Синтетические secret markers не попадают origin/ответам/ошибкам; auth=none остаётся anonymous, Proxy-Authorization удалён; origin Authorization сохранён; Connection nominations и trailers не обходят guard/filter; origin challenge не вызывает replay |
| M05-LIMIT-01 | max_verifying общий для >=2 listeners; насыщение быстро даёт 503+close, ноль ожидающих auth jobs; реальный running+queued счётчик <=limit; denied source/malformed token не занимает slot; memory bounds/без map по случайным именам |
| M05-CANCEL-01 | Контролируемый долгий verifier: request timeout, disconnect, task abort и shutdown сохраняют slot до actual job finish; новые попытки не увеличивают параллелизм; поздний success не даёт identity/response; internal error/panic безопасно освобождает permit без секрета |
| M05-CPU-01 | Workers=1 и >=2: пока verifier занят, разрешённый независимый HTTP/tunnel на listener none и async heartbeat продолжаются; настоящий Argon2 работает вне async workers; нет долгого global lock. Записать фактические CPU/threads, latency и стоимость профиля, не выдумывать throughput |
| M05-RES-01 | Повторные success/wrong/unknown/flood/cancel не накапливают jobs/results/FD/tasks; Linux RSS и FD до/пик/после actual completion; фиксированный объём соединений/проверок при росте попыток; время после CPU завершения отделено от network shutdown deadline |
| M05-OPS-01 | Общий bounded shutdown HTTP+CONNECT+pending auth, без нового grace window; отсутствие новых hash admissions/late writes; изменение users_file не меняет текущий snapshot, restart применяет password/disable/delete, invalid file отвергает новый startup целиком |
| M05-LOAD-01 | 10 и 20 логических клиентов, >=2 users/listeners, смесь HTTP/CONNECT; контролируемая скорость auth для успешного пилота и отдельный overload сверх budget. Отчёт считает все 407/503/прочие исходы, retries и latency/RSS/FD; без скрытых повторов, ложных 502/200 и потерь данных |
| M05-REG-01 | Полные M01–M04, 242 основных baseline + три explicit resource checks, fmt/clippy/build/deny, CLI/examples/netguard; raw targets, header/framing, pool ready, early CONNECT/single writer, partial-write idle, first-EOF absolute drain и TLS negative CA/name assertions не ослаблены; CI на текущем SHA |

## 10. Проверки, стенд и отчёт

Обязательные команды, новые test targets и команды resource checks указать дополнительно:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
cargo test --locked
cargo test --locked --test http_limits m03_res02 -- --ignored --test-threads=1 --nocapture
cargo test --locked --test m04_limits m04_res02 -- --ignored --test-threads=1 --nocapture
cargo deny check
```

Сохранить шесть прежних `angara check --config examples/...` из CI и добавить полный auth example, чей users_file безопасно создаётся в test temp directory. Новые resource/Argon2 cost checks выполнять явно в CI с ограниченным временем/нагрузкой. Игнорируемый локальный тест без фактического запуска не считается свидетельством. TTY проверять PTY; невозможность окружения — BLOCKED для этой строки, не выдуманный pass.

Дать ручной сценарий с генерацией временной базы и минимум двумя синтетическими пользователями: `users hash`, check, serve, HTTP через curl с proxy auth, CONNECT HTTPS с настоящей проверкой CA/hostname, wrong/no password 407, user ACL 403, disable + restart. В инструкциях пароль вводится интерактивно либо через защищённый временный client config 0600; не писать его в аргумент `curl --proxy-user user:password`, shell history, trace/verbose с credential или CI output. Auth-enabled localhost сценарий не требует root, внешнего DNS/сайта, маршрутов или firewall. Отличать proxy credentials от origin Authorization и HTTPS сайта от ещё не реализованного TLS до proxy.

Нагрузочные данные содержат SHA, OS/Rust, CPU/RAM/workers, Argon2 profile/max_verifying, тип verifier (real/mock), concurrency/rate, attempts/completed/407/503/errors, latency и resource peaks. Для functional 10/20 pilot разрешено ограничить темп до auth capacity; честно указать это. В отдельном overload испытании 503 ожидаем, но это не успешный вход; recovery проверяется новым явно учтённым запросом после освобождения budget. Нет обещания 20 одновременных password checks при default 2.

В PR приложить:

1. Base/head SHA, состав модулей/зависимостей, users schema/profile и примеры; обновления README/CLI help и текущего статуса без изменения исторических заданий.
2. Таблицу всех 20 M05-ID → test/command → результат → evidence; команды и точный CI run для текущего SHA. Сбои/пропуски перечислить отдельно.
3. Доказательства общего admission/cancel ownership, pool isolation, actual outbound source, no-leak и return-to-baseline после реального hash completion; оценку ограниченной CPU работы после shutdown.
4. Ограничения: plaintext Basic только loopback/явный opt-in, TLS listener M06, без auth cache/reload/online user CRUD; фактический профиль пилота и среды.

Критерий готовности: весь контракт реализован, 20 групп покрыты, необходимые проверки/CI прошли на head SHA, все найденные замечания исправлены и Codex выдал ACCEPTED. Слияние — только по отдельному поручению владельца.

## 11. Источники и статус детализации

- [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html): Basic user-pass, UTF-8/NFC, отсутствие шифрования. M05 локальные account IDs ограничены явно заданным ASCII namespace; это ограничение пользователей продукта, не объявление полной поддержки международных account names.
- [RFC 9110, proxy authentication](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7): 407, Proxy-Authenticate/Proxy-Authorization и граница следующего proxy.
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id): исходный профиль 19 MiB / t=2 / p=1; замеры обязательны, числа RSS/latency не гарантируются источником.
- [RustCrypto Argon2](https://docs.rs/argon2/latest/argon2/): библиотечное hashing/verification, PHC и salt; выбрать совместимую release и закрепить lockfile, параметры задавать явно.
- [Tokio spawn_blocking](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html): начатые blocking closures не отменяются обычным abort; admission и учёт фактической работы принадлежат Angara.

Это постановка Codex в рамках поручения владельца «напиши задание для этапа M05» и ранее согласованных D05/D06/D12/D13. Формат users/CLI, точные пределы, нулевая очередь и профиль Argon2 — детализация **SPECIFIED**, а не заявление об отдельном утверждении владельцем каждого значения. Новые архитектурные развилки оформляются отдельным решением; молчаливые исключения из auth/ACL/resource контракта не принимаются.
