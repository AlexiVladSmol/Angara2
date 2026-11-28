# Angara 0.1 — руководство администратора

Документ описывает установку кандидата v0.1 на Ubuntu Server 24.04 x86_64,
запуск через systemd от пользователя `angara`, безопасную начальную проверку,
включение TLS/Basic/ACL, reload, остановку, обновление и откат. С M11
описан терминальный интерфейс `angara tui`, пользователи, блокировки и ACL
через локальный API. Компилятор Rust, Docker и исходники на целевой системе
не нужны.

## 1. Что требуется на сервере

- Ubuntu Server 24.04 x86_64 с systemd в роли PID 1.
- root или sudo для установки и управления сервисом.
- `tar`, `sha256sum`, `python3` (проверка манифеста установщиком).
- `curl` для readiness-проверки и диагностики. Без curl используйте
  `angaractl ... --no-probe`, но тогда готовность подтверждается только
  состоянием unit, а не реальным запросом.
- Свободный локальный порт `3128` для начальной конфигурации.

Архив содержит один бинарник `x86_64-unknown-linux-gnu`, unit, установщик,
`angaractl`, безопасные примеры, документацию, манифест, `SHA256SUMS` и
уведомления о лицензиях зависимостей.

## 2. Проверка поставки

Получите архив и внешний `SHA256SUMS` из доверенного CI run. Проверьте
контрольную сумму **до** запуска установщика:

```sh
sha256sum -c SHA256SUMS
sha256sum angara-0.1.0-linux-x86_64-<sha>.tar.gz
```

Внешняя сумма должна совпасть с суммой из CI. Внутри архива `manifest.json`
содержит полный SHA исходников, SHA упаковщика, target, профиль, версии
rustc/Cargo, SHA-256 `Cargo.lock`, SHA-256 бинарника и список файлов. Сам
манифест покрыт внешней суммой архива. Распаковывайте в приватный каталог:

```sh
umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
tar -xzf angara-0.1.0-linux-x86_64-<sha>.tar.gz -C "$tmp" \
  --no-same-owner --no-same-permissions
cd "$tmp"/angara-0.1.0-linux-x86_64-<sha>
```

Установщик дополнительно отклоняет абсолютные пути, `..`, ссылки и
специальные файлы, сверяет каждый файл с манифестом и требует внешний
SHA-256 архива.

## 3. Установка

```sh
sudo ./install.sh \
  --archive /path/to/angara-0.1.0-linux-x86_64-<sha>.tar.gz \
  --sha256 <sha256-из-SHA256SUMS> \
  --expected-source-sha <полный-40-символьный-SHA>
```

Установщик:

- создаёт системного пользователя и группу `angara` без интерактивного входа
  и отдельную группу `angara-admin` для операторов записи;
- раскладывает версию в `/opt/angara/releases/<candidate-id>` с владельцем
  `root:root` и режимом `0755`;
- обновляет `/opt/angara/current` и `/usr/local/bin/angara` атомарной заменой
  ссылки;
- ставит unit `angara.service` и `angara-control.service`;
- создаёт `/etc/angara` с правами `root:angara 0750`, `/run/angara` с правами
  `angara:angara 0750` и начальный `angara.toml` с правами `root:angara 0640`
  только если файла ещё нет;
- не запускает и не включает сервисы;
- при повторной установке сохраняет конфигурацию, users-файл, TLS-ключи,
  группу `angara-admin` и локальные drop-in.

Проверка дерева без прав root:

```sh
./install.sh --archive ... --sha256 ... --destdir "$tmp/stage"
find "$tmp/stage" -maxdepth 5 -printf '%M %u:%g %p\n'
```

В режиме `--destdir` не вызываются `useradd`, `systemctl` и запись в системные
пути; все изменения остаются в staging-каталоге.

Если пользователь `angara` уже существует с интерактивным shell или чужим
home, установщик откажется его использовать. Если `/opt/angara` или
`/etc/angara` являются ссылкой/неуправляемым путём, установка также
завершается с диагностикой.

## 4. Первый запуск и безопасная проверка

```sh
sudo systemctl enable angara.service angara-control.service   # автозапуск после загрузки
sudo systemctl start angara.service angara-control.service
systemctl status angara.service angara-control.service
journalctl -u angara.service -n 30 --no-pager
```

Начальный конфиг слушает только `127.0.0.1:3128`, разрешает источник
loopback и не содержит ни одного allow-правила запроса. Поэтому любой
запрос получает `403` до DNS/подключения к origin. Проверьте это на
контролируемом локальном origin:

```sh
python3 -m http.server 18080 --bind 127.0.0.1 &
ORIGIN_PID=$!
code=$(curl --noproxy '' --proxy http://127.0.0.1:3128 \
  -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/)
test "$code" = "403"
kill "$ORIGIN_PID"
```

`403` подтверждает, что запрос дошёл до Angara. Отсутствие accept у origin
подтверждает запрет до dial. Не используйте `--noproxy '*'`: для проверки
нужен именно явный proxy.

Фактические идентичность, права, capabilities и лимиты:

```sh
pid=$(systemctl show -p MainPID --value angara.service)
ps -o pid,uid,gid,groups,args -p "$pid"
cat "/proc/$pid/status" | grep -E '^(Uid|Gid|Groups|CapEff|Threads|VmRSS):'
cat "/proc/$pid/limits" | grep -E 'Max open files|Max processes'
systemctl show -p LimitNOFILE -p TasksMax -p KillMode -p TimeoutStopUSec angara.service
ss -ltnp | grep "pid=$pid,"
```

Unit задаёт `User=angara`, `Group=angara`, `NoNewPrivileges=true`, пустые
`CapabilityBoundingSet`/`AmbientCapabilities`, `ProtectSystem=strict`,
`ProtectHome=true`, `PrivateTmp=true`, `PrivateDevices=true`,
`ProtectKernelTunables=true`, `ProtectKernelModules=true`,
`ProtectControlGroups=true`, `RestrictSUIDSGID=true`, `UMask=0077`,
`LimitNOFILE=16384` и `TasksMax=512`. `KillMode=control-group` и
`TimeoutStopSec=315s` покрывают максимальные 300 000 мс приложения.
Начальный профиль использует `limits.shutdown_timeout_ms = 5000`; значение
можно изменить допустимым hot-reload до следующего shutdown.

## 5. TLS, Basic и ACL

Все секреты создаются администратором. В архиве нет паролей, PHC, приватных
ключей и операторских конфигураций. Каталог `/etc/angara/tls` уже существует
с правами `root:angara 0750`.

### 5.1. Сертификат TLS-listener

Используйте PKI организации либо отдельный тестовый CA. Приватный ключ
прокси должен быть доступен только root и группе `angara`:

```sh
sudo install -m 0640 -o root -g angara \
  /path/to/proxy-key.pem /etc/angara/tls/proxy-key.pem
sudo install -m 0640 -o root -g angara \
  /path/to/proxy-chain.pem /etc/angara/tls/proxy-chain.pem
```

Цепочка и ключ проверяются при `check`/startup. Не используйте `-k`,
`--proxy-insecure` или отключение проверки имени на клиенте. Сертификат
сайта внутри CONNECT остаётся отдельным и проверяется клиентом по своей CA.

### 5.2. Локальные пользователи

Интерактивный ввод не показывает пароль и не передаёт его через argv/env:

```sh
umask 077
tmp=$(mktemp /etc/angara/.users.XXXXXX)
phc=$(angara users hash)   # интерактивно: Password/Confirm
{
  printf 'version = 1\n\n[[users]]\nusername = "alice"\n'
  printf 'password_hash = "%s"\ndisabled = false\n' "$phc"
} >"$tmp"
chown root:angara "$tmp"
chmod 0640 "$tmp"
mv -f "$tmp" /etc/angara/users.local.toml
```

Для автоматической проверки используйте только синтетический секрет и
явный `--password-stdin`, не помещая пароль в argv, environ или историю
shell:

```sh
printf '%s\n' 'synthetic-only-password' | angara users hash --password-stdin
```

PHC считается чувствительным: не выводите его в общий журнал и не храните в
мире-читаемом файле. Users-файл должен быть `root:angara 0640` (или строже).
Добавление/удаление пользователя и смена пароля применяются после restart
или допустимого reload users-файла.

### 5.3. Полный пример HTTP+HTTPS/Basic/ACL

В архиве есть готовый самостоятельный файл
`examples/m08-operations-https-basic.toml`. Это **полный** конфиг, а не
фрагмент: не добавляйте его к начальному `angara.toml` и не вставляйте
отдельные таблицы — замените основной файл целиком. Он уже содержит
`schema_version`, runtime/limits, auth, TLS, оба listener, ACL, IP-политику,
connect, egress и routing.

```sh
# каталоги и конфигурация
sudo install -d -m 0750 -o root -g angara /etc/angara/tls
sudo install -m 0640 -o root -g angara \
  /path/to/angara-0.1.0-linux-x86_64-<sha>/examples/m08-operations-https-basic.toml \
  /etc/angara/angara.toml
sudo install -m 0640 -o root -g angara /path/to/users.local.toml /etc/angara/users.local.toml
sudo install -m 0640 -o root -g angara /path/to/proxy-chain.pem \
  /etc/angara/tls/proxy-chain.pem
sudo install -m 0640 -o root -g angara /path/to/proxy-key.pem \
  /etc/angara/tls/proxy-key.pem

sudo runuser -u angara -- /usr/local/bin/angara check \
  --config /etc/angara/angara.toml
sudo systemctl restart angara.service
```

После изменения listener/TLS/auth-наличия требуется restart. Изменения ACL,
users-файла, allowed_ports, совместимых лимитов и timeout можно применить
через reload. Сначала проверьте файл от служебного UID:

```sh
sudo runuser -u angara -- /usr/local/bin/angara check \
  --config /etc/angara/angara.toml
```

`check` не открывает listener, не выполняет DNS и не подключается к origin.
Ошибка check означает, что рабочий процесс не нужно перезапускать.

Проверка после restart (замените пути на свою CA и локальный TLS-site):

```sh
# HTTP listener: разрешённый запрос
curl --noproxy '' --proxy http://127.0.0.1:3128 \
  http://127.0.0.1:18080/ -o /dev/null -w '%{http_code}\n'

# HTTPS listener без credentials: 407
curl --noproxy '' --proxy https://127.0.0.1:3129 \
  --proxy-cacert /path/to/proxy-ca.pem --proxy-user alice \
  http://127.0.0.1:18080/ -o /dev/null -w '%{http_code}\n'

# HTTPS listener с alice: разрешённый запрос (пароль вводится интерактивно)
curl --noproxy '' --proxy https://127.0.0.1:3129 \
  --proxy-cacert /path/to/proxy-ca.pem --proxy-user alice \
  --cacert /path/to/site-ca.pem https://127.0.0.1:18443/ \
  -o /dev/null -w '%{http_code}\n'
```

Не используйте `--proxy-insecure`, `-k` или отключение проверки имени. Если
CA/имя не совпадают, curl должен завершиться ошибкой сертификата, а не
получить 200. Для проверки без интерактивного ввода используйте curl-config
файл с `proxy-user` в режиме `0600`, не argv.

Перед изменением сохраните согласованный набор файлов и проверьте восстановление:

```sh
sudo install -d -m 0700 /var/lib/angara/backups
sudo tar -C /etc -czf /var/lib/angara/backups/angara-manual.tgz angara
sudo chmod 0600 /var/lib/angara/backups/angara-manual.tgz
sudo systemctl stop angara.service
sudo tar -C /etc -xzf /var/lib/angara/backups/angara-manual.tgz
sudo systemctl start angara.service
sudo runuser -u angara -- /usr/local/bin/angara check \
  --config /etc/angara/angara.toml
```

Резервная копия содержит приватные ключи и users-файл; каталог `0700` и
архив `0600` обязательны. Откат только бинарника не восстанавливает пароль
или ACL — восстанавливайте весь согласованный набор.

## 6. Reload, журнал и остановка

Запомните позицию журнала, примените SIGHUP и проверьте следующий запрос:

```sh
journalctl -u angara.service --since '1 minute ago' --no-pager -o cat
sudo systemctl reload angara.service
journalctl -u angara.service -f -o cat
# ожидается reload_applied либо reload_rejected
```

Успешный `systemctl reload` означает только отправку SIGHUP. Apply/reject
подтверждается JSON-событием и следующим запросом через тот же процесс.
Неверный файл или изменение, требующее restart, оставляет прежние ACL и PID.
Новый keep-alive запрос видит новое поколение; уже открытый CONNECT остаётся
на прежней policy. Серия SIGHUP coalesce-ится без неограниченных задач.

Журнал `serve` — JSON Lines в journald. Секреты, usernames, URL/path/query,
source/destination IP и TLS material в него не пишутся. Для диагностики
используйте event/outcome/reason, generation, listener/egress/rule IDs,
status, elapsed_ms и счётчики байтов. `log_dropped`/`log_sink_errors`
показывают потерю записей при перегрузке; lossless logging не обещается.

Штатная остановка:

```sh
sudo systemctl stop angara.service
```

Angara прекращает accept, закрывает idle pool, ждёт активные HTTP/TLS/CONNECT
в пределах `limits.shutdown_timeout_ms` и затем force-закрывает оставшиеся
сокеты/задачи. Повторный SIGTERM не продлевает исходный deadline. Порт
освобождается до завершения процесса. systemd не должен посылать SIGKILL в
пределах 315 с.

## 7. Обновление A → B → A

Обновление выполняет явную остановку A только после проверки B. Подготовьте
архив B и его внешний SHA-256.

```sh
sudo /usr/local/sbin/angaractl upgrade \
  --archive /path/to/angara-0.1.0-linux-x86_64-<B-sha>.tar.gz \
  --sha256 <B-sha256> \
  --confirm
```

До остановки A `angaractl`:

1. проверяет внешний SHA-256, дерево и манифест B;
2. разворачивает B в отдельный `/opt/angara/releases/<B>`;
3. запускает **бинарник B** с рабочей конфигурацией от `angara`
   (`check --config /etc/angara/angara.toml`);
4. делает приватную резервную копию `/etc/angara` в
   `/var/lib/angara/backups/` (0700/0600);
5. только затем останавливает A, атомарно переключает `current`, запускает B
   и выполняет readiness-запрос.

При ошибке старта B команда пытается вернуть A и печатает рабочую команду
отката. Явный откат:

```sh
sudo /usr/local/sbin/angaractl rollback --confirm
```

Откат переключает `current` на предыдущий release-каталог, восстанавливает
unit/служебный скрипт выбранной версии, запускает сервис и проверяет запрос.
Настройки, users-файл и TLS не перезаписываются. Если между остановкой и
запуском произошло прерывание, повторите `upgrade` или выполните
`angaractl recover`.

**Перед откатом на M10** снимите все временные блокировки новым бинарником
(users-файл вернётся к `version = 1`) или восстановите users-файл из
резервной копии: M10 не читает `blocked_until` и не стартует с v2.

Проверка фактической версии:

```sh
pid=$(systemctl show -p MainPID --value angara.service)
readlink -f "/proc/$pid/exe"
readlink -f /opt/angara/current
/usr/local/sbin/angaractl status
```

Активная и предыдущая версии сохраняются до решения оператора. Очистка
старых каталогов — отдельное явное действие; автоматического удаления нет.

## 8. Удаление

По умолчанию сохраняются `/etc/angara`, users/TLS и release-каталоги:

```sh
sudo /usr/local/sbin/angaractl uninstall --confirm
```

Полное удаление конфигурации и данных (необратимо):

```sh
sudo /usr/local/sbin/angaractl uninstall --confirm --purge
```

Перед удалением сделайте резервную копию конфигурации и ключей. Откат
бинарника не восстанавливает пароль, users-файл или ACL автоматически.

## 9. Parent proxy (M09)

Parent нужен, когда Angara должна выходить в сеть через другой HTTP-прокси, например Squid. Выбор задаётся в `routing`; остальные клиенты могут продолжать работать напрямую.

```toml
[runtime]
worker_threads = "auto"
instance_id = "edge-a"            # уникален для цепочки Angara

[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"     # host:port; IPv6: "[::1]:13128"
transport = "http"                # "http" | "https"

[routing]
default_egress = "system"
default_parent = "squid"

[[routing.rules]]
id = "direct-lab"
egress_id = "system"
next_hop = "direct"               # явный direct при настроенном default parent
ports = [18080]
```

Правило выбирает один next hop: `direct` или parent. Если `next_hop` не указан, используется `default_parent`; если и его нет — direct. Ошибка parent не переключает запрос в direct и не выбирает другой parent. Parent definitions, transport, CA и credentials применяются после restart; изменения `routing` входят в hot reload (SIGHUP).

`runtime.instance_id` добавляется в `Via` как `1.1 angara-<id>`. Для цепочки Angara задавайте явный `runtime.instance_id` на каждом экземпляре: значение по умолчанию `<hostname>-<port>` совпадает у клонов VM с одинаковыми hostname и портом, и тогда законная цепочка получит 508. Angara отклоняет запрос только при возврате собственного идентификатора и продолжает чужую цепочку. Прокси, которые вырезают `Via`, ослабляют эту защиту; это документированное ограничение.

### Credentials parent

Пароль хранится отдельно, не в основном TOML:

```toml
# parent-credentials.toml
version = 1
username = "angara-parent"
password = "replace-me"
```

```sh
sudo install -m 0640 -o root -g angara \
  parent-credentials.toml /etc/angara/parent-credentials.toml
```

Укажите файл в parent:

```toml
[[parents]]
id = "squid"
endpoint = "parent.example:3128"
transport = "https"
credentials_file = "parent-credentials.toml"
ca_file = "parent-ca.pem"          # необязательно; иначе системный bundle
```

Файл credentials должен принадлежать root или служебному UID и не быть доступен на запись group/other; режим `0640 root:angara` разрешает чтение службе и соответствует рецепту выше. Для `https` проверяется DNS-имя или IP SAN. Без `ca_file` используется `/etc/ssl/certs/ca-certificates.crt` (Ubuntu). Basic поверх открытого HTTP передаёт credentials обратимо закодированными; в рабочем окружении используйте TLS.

### Что видит parent

- HTTP к домену: Angara разрешает имя, применяет ACL/IP-политику и отправляет parent `CONNECT <числовой-ip>:<порт>`. После 2xx внутри туннеля идёт origin-form с исходным `Host`, path/query.
- HTTP к IP-литералу: parent получает absolute-form `http://<проверенный-ip>:<порт>/...` с исходным `Host`.
- Клиентский CONNECT: parent получает `CONNECT <числовой-ip>:<порт>`; TLS сайта остаётся сквозным.

Клиентский `Proxy-Authorization` поглощается Angara. Credentials parent добавляются только в запрос/внешний CONNECT к parent. `Via: 1.1 angara-<instance_id>` добавляется к HTTP-ответам и запросам к origin. Во внешний CONNECT Angara передаёт полученную цепочку `Via` в исходном порядке и добавляет свой идентификатор последним. Запрос отклоняется только при возврате собственного идентификатора.

### Angara как parent другой Angara

Angara можно использовать как parent для другой Angara. По умолчанию `connect.allowed_ports` разрешает только 443. Для HTTP к имени A открывает к B CONNECT на HTTP-порт назначения; если этого порта нет в списке B, B отвечает 403, а клиент A получает 502.

Открыть HTTP-порт только для A можно существующими правилами B: расширить `connect.allowed_ports` глобально, затем разрешить CONNECT к этому порту только с адреса A и запретить остальным. Правила должны стоять **до** общих allow-правил клиентов: действует первое совпадение.

```toml
[connect]
allowed_ports = [443, 80]

[[access.rules]]
id = "connect-http-only-from-angara-a"
action = "allow"
sources = ["<адрес A>/32"]
methods = ["CONNECT"]
ports = [80]

[[access.rules]]
id = "connect-http-deny-others"
action = "deny"
methods = ["CONNECT"]
ports = [80]

# далее обычные правила клиентов B
```

Проверено на стенде с портом 18480 вместо 80:

| Запрос | Результат |
| --- | --- |
| клиент → A → B, HTTP к имени | 200 |
| другой клиент (источник `127.0.0.2`) → CONNECT через B | 403 |
| другой клиент → обычный HTTP через B | 200 |

Ограничение: доступ привязан к адресу источника, поэтому клиент с того же адреса, что A, получит такой же доступ. Рецепт проверяется `angara check` и интеграционным тестом `m09_parent27_angara_parent_http_port_acl_recipe`.

### Ошибки

| Ответ | Причина |
| --- | --- |
| 502 | parent недоступен, TLS/имя/CA не прошли, parent отверг CONNECT или вернул 407 |
| 504 | истёк срок ожидания ответа parent до начала ответа клиенту |
| 200/4xx | обычный HTTP-ответ parent, кроме 407, передаётся по общим правилам |

### Проверка со Squid

На тестовой VM можно поднять отдельный Squid на `13128`, не трогая системный `squid.service`:

```sh
http_port 127.0.0.1:13128
acl localnet src 127.0.0.1/32
acl SSL_ports port 80 443 18080
acl CONNECT method CONNECT
http_access allow CONNECT localnet SSL_ports
http_access deny CONNECT !SSL_ports
http_access allow localnet
http_access deny all
```

Проверка:

```sh
angara check --config /etc/angara/angara.toml
curl -x http://127.0.0.1:3128 http://127.0.0.1:18080/
curl -p -x http://127.0.0.1:3128 http://127.0.0.1:18080/
```

Для домена добавьте тестовое имя в `/etc/hosts` и проверьте `curl -x ... http://origin.test:18080/`; в access log Squid должен быть `CONNECT 127.0.0.1:18080`, а не имя. Отдельно убедитесь, что CONNECT к порту вне `SSL_ports` даёт 502.

Ограничения M09: parent-соединения не переиспользуются; IP-политика target не применяется к самому parent (это инфраструктура администратора); Squid как HTTPS parent не является стандартным режимом, TLS parent проверяется отдельным fixture.

## 10. HTTP-кеш (M10)

Кеш выключен по умолчанию. Включите его отдельной секцией и перезапустите
службу: параметры `[cache]` применяются при старте, изменение требует restart.

```toml
[cache]
enabled = true
max_bytes = 33554432       # 32 MiB общего учтённого бюджета
max_object_bytes = 1048576 # 1 MiB на объект; не больше max_bytes
max_entries = 512
max_fills = 8
```

Поля необязательны при `enabled = true`; значения выше — defaults. Допустимые
диапазоны: `max_bytes` 65536..=1073741824, `max_object_bytes` 1024..=`max_bytes`,
`max_entries` 1..=65536, `max_fills` 1..=64. `max_object_bytes` ограничивает
учтённый размер объекта: тело, ключ, заголовки и фиксированную запись. Неверные
значения отклоняет `angara check` с путём `cache.*`.

Кешируются только полные `200` на обычный `GET` с HTTP-схемой назначения по
direct-маршруту. Запросы через parent и CONNECT в кеш не входят. Ответ должен
иметь явную свежесть: `s-maxage`, затем `max-age`, затем `Expires` с `Date`.
Без явной свежести ответ не сохраняется. На попадании Angara пересчитывает
`Age` и отдаёт сохранённые end-to-end заголовки.

Не читаются и/или не сохраняются:

- запросы с `Authorization`, `Cookie`, `Range`, `If-Range`, клиентскими
  `If-Match`/`If-None-Match`/`If-Modified-Since`/`If-Unmodified-Since`, телом;
- запросы и ответы с `no-store`; запросы с `no-cache`, `max-age=0`,
  `Pragma: no-cache`;
- ответы с `Set-Cookie`, `private`, ответным `no-cache`, `206`, trailers;
- `Vary`, кроме `Vary: Accept-Encoding`; для него gzip, identity и отсутствие
  заголовка хранятся раздельно.

`only-if-cached` без допустимой свежей записи возвращает 504 без запроса к
origin. `min-fresh` и `max-age` клиента проверяются до выдачи. Просроченная
запись ревалидируется по ETag или Last-Modified; клиент обычного GET получает
полное тело после внутреннего 304. Ошибка origin возвращается как ошибка
прокси, устаревшее тело не подставляется.

После неошибочного `POST`/`PUT`/`DELETE`/`PATCH` URI инвалидируется во всех
вариантах; начатое наполнение старого тела не публикуется. Смена поколения
конфигурации (reload) делает старые записи недоступными.

Ключ включает URI с портом и query, вариант, listener, пользователя/anonymous,
egress, проверенные IP endpoints и поколение. Пароли и заголовки в ключ не
входят. Общий бюджет учитывает тела, ключи, заголовки, фиксированную запись и
консервативную оценку элемента индекса; медленный читатель удерживает свои байты
до завершения. Накладные расходы аллокатора могут быть выше `cache_bytes`. При
нехватке места ответ продолжает потоковую передачу без сохранения.

Метрики кеша: `cache_hit`, `cache_miss`, `cache_bypass`, `cache_revalidation`,
`cache_eviction`, `cache_fill_refusals`, `cache_entries`, `cache_bytes`.
URL, query, ключи, пользователи, заголовки и тела в журналы и метки не
попадают. Начальный ориентир для 10–20 устройств — значения из примера; при
нагрузке следите за `cache_entries`, `cache_bytes`, `cache_eviction` и
`cache_fill_refusals`. Для Ubuntu CI отдельный сценарий
`tests/m08/cache_load.sh` проверяет 10 и 20 клиентов, попадания и прирост RSS.


## 11. Терминальное управление (M11)

### 11.1. Компоненты и права

M11 добавляет два независимых компонента:

| Компонент | UID | Сокет | Назначение |
| --- | --- | --- | --- |
| `angara.service` | `angara` | `/run/angara/control-read.sock` (0600, `angara:angara`) | снимки, статус, соединения, users/blocks/ACL, reload по запросу writer |
| `angara-control.service` | `root` | `/run/angara/control.sock` (0660, `root:angara`) | единственная точка записи конфигурации и users-файла |

Публичный сокет принадлежит привилегированному writer-процессу. Прокси
открывает только приватный сокет; writer подключается к нему как root или
тот же UID и не может использовать его для записи файлов. Каталог
`/run/angara` сохраняется при перезапуске прокси
(`RuntimeDirectoryPreserve=restart`), поэтому аварийный restart не удаляет
публичный сокет writer-а; при остановке каталог и оба сокета удаляются. Writer работает
только с основным TOML и путём из `[auth].users_file`, проверяет тип файла,
владельца, режим и число ссылок, сохраняет owner/group/mode и делает
атомарную замену с `fsync`.

Члены группы `angara` могут **читать** диагностику. Члены группы
`angara-admin` могут **изменять** пользователей, блокировки и ACL. Членство
в `angara` само по себе права записи не даёт: writer проверяет peer UID/GID и
`/etc/group` на стороне сервиса. Добавьте администратора в обе группы:

```sh
sudo usermod -aG angara,angara-admin "$USER"
# выйдите и войдите снова, чтобы группы применились
```

Группа `angara-admin` должна быть локальной группой в `/etc/group`: writer
читает `/etc/group` и `/etc/passwd` напрямую и не видит членство из LDAP/sssd.
Служебный UID `angara` в `angara-admin` не добавляется. Файлы должны иметь
владельца `root` и режим `0640` (группа `angara`); users-файл не должен быть
group/world-writable. Если `users_file` указывает за пределы `/etc/angara`,
добавьте каталог в `ReadWritePaths=` drop-in для `angara-control.service`.

### 11.2. Запуск панели

```sh
angara tui
# или явный сокет (например, для тестового экземпляра)
angara tui --socket /run/angara/control.sock
```

Панель работает по SSH и локально. Закрытие терминала завершает только
клиент; прокси и writer продолжают работу. Основные клавиши: `1`–`8` —
экраны, `/` — поиск, `Ctrl+P` — палитра, `?` — справка, `q` — выход,
`a/e/d` — добавить/изменить/удалить, `J/K` — порядок правил, `c/A` —
проверить/применить конфигурацию. Базовые действия помещаются в 80×24;
на широком экране список и карточка рядом, на узком — карточка отдельно.
После `Esc`/ошибки/обрыва терминал восстанавливается.

Пароль вводится только в скрытом поле формы и передаётся по локальному
сокету в одном запросе. Он не попадает в argv, окружение, историю команд,
журналы, события или preview. `angara users hash` остаётся отдельной
операцией для подготовки PHC.

### 11.3. Пользователи и блокировки

- **Добавить пользователя** — логин, два скрытых ввода, Argon2id. Дубликат
  отклоняется. Само добавление не создаёт разрешающее ACL-правило.
- **Сменить пароль** — меняется только `password_hash`; логин, блокировка и
  ACL сохраняются. Новый запрос со старым паролем получает `407`.
- **Блокировка** — одна на пользователя: бессрочная (`disabled = true`) или
  временная (`blocked_until`, абсолютный UTC). Временная действует, пока
  серверные часы строго меньше срока; на границе и после неё новый запрос
  проходит обычную проверку. Истечение не перезаписывает TOML.
- Проверка выполняется для каждого нового HTTP-запроса (включая keep-alive)
  и каждого нового CONNECT до ACL, кеша и выхода к назначению. Заблокированный
  получает штатный `407`. Уже открытые CONNECT-туннели не разрываются.
- Снятие блокировки сохраняет пользователя, пароль и ACL.

Формат users-файла:

```toml
version = 2

[[users]]
username = "alice"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$...$..."
# временная блокировка; поле отсутствует у активной учётной записи
blocked_until = "2026-11-27T18:00:00Z"

[[users]]
username = "bob"
password_hash = "$argon2id$..."
disabled = true   # бессрочная блокировка; совместимо с version = 1
```

Новый бинарник читает `version = 1` и `version = 2`. `blocked_until`
допускается только в v2; сочетание `disabled = true` и `blocked_until`
отклоняется. Файл повышается до v2 только при появлении временной
блокировки и понижается до v1, когда временных блокировок не осталось.
Старый бинарник M10 на v2 получает явную ошибку версии или `unknown field`
и не читает файл частично; для отката восстановите users-файл из резервной
копии или снимите временные блокировки новым бинарником.

### 11.4. Версии, сохранение и применение

Версия файла — SHA-256 его содержимого. Форма запоминает версию и передаёт
её при сохранении. Writer под общим `<path>.lock` (`flock`) перечитывает
файл, сверяет версию, меняет только выбранную запись/секцию через
`toml_edit` (комментарии и порядок сохраняются), проверяет кандидат штатным
`Config::load`/users-валидатором, пишет temp в том же каталоге, делает
`fsync`, сохраняет owner/group/mode, `rename` и `fsync` каталога.

Состояния в интерфейсе:

| Состояние | Значение |
| --- | --- |
| Проверено | Кандидат прошёл валидацию; файл ещё не заменён. |
| Сохранено на диске | Файл заменён; подтверждение активной версии ожидается. |
| Применено | Ядро подтвердило именно эту версию и сообщило поколение. |
| Отклонено / требуется перезапуск | Активна предыдущая политика; причина и сохранённая версия видны на экране «Конфигурация». |
| Конфликт / результат неизвестен | Запись не состоялась или ответ потерян; перед повтором сверьте версии. |

Общая блокировка защищает только сотрудничающие инструменты. `nano`/`vim`
могут её обойти; версия обнаруживает уже завершённую внешнюю правку при
следующей проверке или сохранении, но не предотвращает одновременную
перезапись. Для гарантии используйте только `angara tui`/API.

`config.validate` и `config.apply` используют те же `Config::load` и
`load_for_reload`, что CLI и SIGHUP. Успешная валидация или новый файл сами
по себе не означают применение: writer сверяет поколение и версии после
reload. При `restart_required` активная политика остаётся прежней.

### 11.5. ACL

Экран «Доступ» поддерживает `access.source_allow`, упорядоченные
`access.rules`, `access.ip_rules` и `ip_default`; клавиша `v` переключает
разделы, `i` редактирует `ip_default`. Перед заменой показывается
предпросмотр только затронутого фрагмента и соседних правил, без секретов.
Создание, изменение, удаление и перемещение правила проверяются штатным
валидатором; при ошибке рабочая конфигурация не меняется. First-match
проверяется реальным HTTP/CONNECT после применения.

### 11.6. Контракт API

Полные операции, поля, коды ошибок, события и примеры — в
[CONTROL_API.md](CONTROL_API.md). Общие лимиты перечислены ниже.

Протокол v1: JSONL на Unix-сокете, версия `1`. Не более 16 клиентов и 8
подписчиков, строка запроса/ответа до 64 KiB, страница до 100 записей,
кольцо событий 512, очередь подписчика 64 (при переполнении — повторный
снимок), таймауты чтения 5 s и записи 70 s, одна дорогая операция
(Argon2/запись/reload) одновременно. Медленный подписчик не задерживает
прокси. Ошибки имеют стабильные коды: `invalid_request`,
`unsupported_version`, `unauthorized`, `not_found`, `conflict`,
`invalid_candidate`, `restart_required`, `busy`, `timeout`, `unavailable`,
`too_large`, `shutting_down`, `unknown_result`, `resync_required`,
`internal`.

### 11.7. Проверка M11

```sh
systemctl status angara.service angara-control.service
ls -l /run/angara/control.sock /run/angara/control-read.sock
runuser -u angara -- test -r /etc/angara/angara.toml
sudo -u nobody test -r /run/angara/control.sock && echo unexpected
```

Скриншоты широкого и узкого экранов на синтетических данных:
[широкий](screenshots/m11-wide.png) и [узкий](screenshots/m11-narrow.png).

## 12. Типичные неисправности

| Симптом | Что проверить |
| --- | --- |
| `address already in use` | `ss -ltnp`, конфликт порта 3128; освободите порт и `systemctl reset-failed angara`, затем запустите снова |
| `status=203/EXEC` | `/opt/angara/current/bin/angara` существует и исполняется; `readlink -f /opt/angara/current` |
| `status=226/NAMESPACE` | sandbox unit несовместим с окружением; проверьте `systemd-analyze verify` и `/etc/systemd/system/angara.service.d/` |
| `check` не читает users/TLS | владелец/режим `root:angara 0640`, каталог `/etc/angara` не world-writable |
| TUI не подключается | проверьте `angara-control.service`, режим сокета и группы `angara`/`angara-admin`; `journalctl -u angara-control` |
| writer не стартует | при невалидном TOML на диске `angara-control.service` падает до открытия сокета; выполните `angara check --config /etc/angara/angara.toml` и `journalctl -u angara-control` |
| reload отклонён | `reload_rejected`, `outcome`; исправьте файл и повторите SIGHUP; PID/ACL должны сохраниться |
| клиент получает 407 | нет/неверные credentials; проверьте `users.local.toml` и `auth` listener |
| клиент получает 403 | нет allow-правила ACL, запрещён source/domain/IP/port или сработал default deny |
| TLS-клиент получает ошибку сертификата | проверьте CA/имя/срок; не отключайте проверку на клиенте |
| сервис ушёл в start-limit | `systemctl reset-failed angara`; устраните конфигурацию/порт, затем `systemctl restart angara.service` (restart передаётся writer-у через `PartOf=`) |
| `Too many open files` | `LimitNOFILE=16384`; проверьте `log_dropped`, активные соединения и pool |
| журнал не содержит записей | `observability.log_level`, journald, `log_dropped`; `serve` пишет JSON только в stderr/journal |

При аварийной остановке сначала сохраните `journalctl -u angara` и
`angaractl status`, затем перезапускайте. Не вставляйте пароли, PHC и
приватные ключи в Issue/PR/CI-артефакты.
