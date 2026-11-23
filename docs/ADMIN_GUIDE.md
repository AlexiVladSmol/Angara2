# Angara 0.1 — руководство администратора

Документ описывает установку кандидата v0.1 на Ubuntu Server 24.04 x86_64,
запуск через systemd от пользователя `angara`, безопасную начальную проверку,
включение TLS/Basic/ACL, reload, остановку, обновление и откат. Компилятор
Rust, Docker и исходники на целевой системе не нужны.

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

- создаёт системного пользователя и группу `angara` без интерактивного входа;
- раскладывает версию в `/opt/angara/releases/<candidate-id>` с владельцем
  `root:root` и режимом `0755`;
- обновляет `/opt/angara/current` и `/usr/local/bin/angara` атомарной заменой
  ссылки;
- ставит unit `/etc/systemd/system/angara.service`;
- создаёт `/etc/angara` с правами `root:angara 0750` и начальный
  `angara.toml` с правами `root:angara 0640` только если файла ещё нет;
- не запускает и не включает сервис;
- при повторной установке сохраняет конфигурацию, users-файл, TLS-ключи и
  локальные drop-in.

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
sudo systemctl enable angara.service   # автозапуск после загрузки
sudo systemctl start angara.service
systemctl status angara.service
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

## 10. Типичные неисправности

| Симптом | Что проверить |
| --- | --- |
| `address already in use` | `ss -ltnp`, конфликт порта 3128; освободите порт и `systemctl reset-failed angara`, затем запустите снова |
| `status=203/EXEC` | `/opt/angara/current/bin/angara` существует и исполняется; `readlink -f /opt/angara/current` |
| `status=226/NAMESPACE` | sandbox unit несовместим с окружением; проверьте `systemd-analyze verify` и `/etc/systemd/system/angara.service.d/` |
| `check` не читает users/TLS | владелец/режим `root:angara 0640`, каталог `/etc/angara` не world-writable |
| reload отклонён | `reload_rejected`, `outcome`; исправьте файл и повторите SIGHUP; PID/ACL должны сохраниться |
| клиент получает 407 | нет/неверные credentials; проверьте `users.local.toml` и `auth` listener |
| клиент получает 403 | нет allow-правила ACL, запрещён source/domain/IP/port или сработал default deny |
| TLS-клиент получает ошибку сертификата | проверьте CA/имя/срок; не отключайте проверку на клиенте |
| сервис ушёл в start-limit | `systemctl reset-failed angara`; устраните конфигурацию/порт, затем `systemctl start` |
| `Too many open files` | `LimitNOFILE=16384`; проверьте `log_dropped`, активные соединения и pool |
| журнал не содержит записей | `observability.log_level`, journald, `log_dropped`; `serve` пишет JSON только в stderr/journal |

При аварийной остановке сначала сохраните `journalctl -u angara` и
`angaractl status`, затем перезапускайте. Не вставляйте пароли, PHC и
приватные ключи в Issue/PR/CI-артефакты.
