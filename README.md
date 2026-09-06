# keenetic-xray-go

Установщик и менеджер Xray (VLESS) с автоматическим failover для роутеров
Keenetic с Entware. Собирается только под **mipsel** и **aarch64**.

Один бинарь (`keenetic-xray`), один `.ipk` на архитектуру. Установка,
настройка, автоматический failover и удалённое управление из Telegram-бота
работают от начала до конца.

Подробнее: [`docs/architecture.md`](docs/architecture.md) — как всё
устроено, [`docs/full-vs-mini.md`](docs/full-vs-mini.md) — разница
вариантов Mini/Full, [`docs/bot-control-design.md`](docs/bot-control-design.md)
— дизайн удалённого управления, [`docs/routing.md`](docs/routing.md) —
маршрутизация по доменам.

---

## Что под капотом

**Ядро — xray-core.** Ставится само: по умолчанию — size-оптимизированная
(UPX, ~7–10 МБ против ~30 МБ) сборка из релизов этого проекта, привязанная
к upstream-тегу; запасной путь — `opkg install xray-core` из фида Entware.
`install.sh --xray-core=entware` форсит фид, `--xray-core-tag=vX.Y.Z`
сажает один роутер на конкретную (например, пререлизную) сборку. Позже —
`keenetic-xray internal ensure-xray-core --tag=…` или кнопка `🧩 Ядро xray`
в боте; выбор пишется в `config.json` и переживает обновление пакета.

**Failover — конечный автомат.** Два профиля, primary и backup. Проверка
живости — настоящий HTTP-запрос через рабочий прокси (не голый ICMP), с
ретраями и списком запасных URL. Перед возвратом на primary —
изолированный пре-тест на отдельном порту, чтобы не дёргать боевой
трафик. Состояния: `ActivePrimary → Cooldown → TestingRecovery →
ConfirmingRecovery`. Флап (частые переключения) душится: цикл
«упал-вернулся» — это два сообщения в чат, а не пять; после ~4
переключений за 15 минут бот присылает одно «⚠️ primary флапает» и держит
остальные 30 минут. Обратный случай — primary тихо лежит, а backup всё
тянет — легко пропустить, поэтому после `primary_stuck_warn_hours` (по
умолчанию 3, `0` — выкл) на backup без восстановления бот присылает один
совет.

**Источник профилей.** Сырая `vless://` ссылка или URL подписки — и из CLI
(`keenetic-xray setup`), и из бота. Парсер сохраняет блоб `extra=` из
ссылки (xmux, `sc*`, padding) как есть — без него каждое новое соединение
переигрывает полный xhttp + REALITY хендшейк. `keenetic-xray transport
mode stream-up` глобально переопределяет `xhttp` `mode` (в ссылках часто
медленный `auto`); override лежит в `config.json` и переживает обновление
подписки. primary и backup можно кормить из независимых источников
(`🔗 Источники` в боте).

**Как трафик попадает в туннель.** Проекту не нужны geoip/geosite —
маршрутизацию делает сам Keenetic. Есть три пути «роутер → xray», они
сосуществуют:

- **Proxy0** (`keenetic-xray proxy0 set`) — Keenetic-интерфейс `Proxy0`
  наводится на локальный вход xray (SOCKS5 или HTTP). Дальше устройства/
  политики назначаются на `Proxy0` в вебе роутера. Тул детектит LAN-IP
  роутера (никогда не loopback) и проверяет, что настройка встала.
- **WG-транспорт** (`keenetic-xray transport wg on`) — на роутере
  поднимается интерфейс `WireguardN` в локальный `wireguard`-инбаунд
  xray: `LAN → WireguardN → xray → туннель`. Ключи (X25519 + PSK)
  генерятся сами; свой ключ Keenetic генерит и отдаёт публичный. Метка
  `description keenetic-xray-wg` — ручные WG-туннели не трогаются. MTU
  1280 и встроенный `ip tcp adjust-mss pmtu` — видео на этом пути не
  залипает.
- **Маршруты по доменам** (`keenetic-xray routes …`, KeeneticOS 5.0+) —
  именованные списки доменов/подсетей уходят в туннель через `Proxy0`
  (или `WireguardN`), остальное — напрямую. Под капотом `object-group
  fqdn keenetic-xray-*` + `dns-proxy route`. Списки namespace'нуты и
  никогда не трогают заведённые в вебе роутера.
- **Готовые списки** (`keenetic-xray routes preset …`, кнопка `📦 Готовые
  списки`) — курируемые списки по сервисам (`youtube`, `telegram`,
  `github`, … ~10 категорий), вшиты в бинарь и обновляются в репозитории
  раз в сутки. `preset add` привязывает список к пресету; бот/CLI
  показывают `⬆ +N −M`, когда после обновления агента появилась свежая
  версия, `preset sync` её подтягивает.

**MSS-клампинг.** Устройство в LAN согласует MSS ~1460 под MTU роутера
1500, но такие пакеты не влезают в путь `Proxy0 → xray → xhttp/REALITY` —
получается «чёрная дыра» PMTU, видео (Reels/Shorts) виснет на ~20 секунд.
`keenetic-xray transport mss auto` (= 1360) ставит одно правило `iptables`
mangle с меткой `keenetic-xray-mss` (пресеты 1400 / 1280 / off). Действует,
только пока `Proxy0` включён; `iptables` доустанавливается через `opkg`.

**Самолечение.** Прошивка при перестройке файрвола иногда сносит наши
правила и настройки интерфейсов. Демон возвращает их два способа: хук
`/opt/etc/ndm/netfilter.d/50-keenetic-xray.sh` (в `.ipk`), который `ndm`
дёргает на каждой пересборке файрвола → SIGUSR1 демону → мгновенная
сверка; плюс запасной опрос раз в 2 минуты. Сверяются Proxy0, маршруты,
MSS-правило и WG-интерфейс.

**Целостность конфига.** `config.json` пишется атомарно (временный файл →
`fsync` → `rename`), потеря питания в момент записи не бьёт файл.

**Удалённое управление (только Full).** Отдельный бинарь
`keenetic-xray-control-server` на VPS: очередь команд из Telegram-бота,
роутеры опрашивают его по self-signed TLS с пиннингом отпечатка.

**Mini vs Full.** Mini не запускает polling-агента (нет бота), в остальном
идентичен. На диске занимают одинаково.

---

## Установка

На роутере, по SSH. Скрипт сам определяет архитектуру через `opkg` и
ставит подходящий `.ipk` из последнего релиза. Передай ссылку/подписку —
и он настроится сам (профили, `Proxy0`, демон):

```bash
curl -fsSL https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/install.sh | sh -s -- --sub="https://provider.example/sub/token"
```

Без ссылки — поставит и сразу откроет интерактивный мастер в этой же
SSH-сессии (primary, backup, порты SOCKS/HTTP, затем Proxy0):

```bash
curl -fsSL https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/install.sh | sh
```

`curl`, не `wget`: busybox-`wget` на части Keenetic не умеет `https://`
вообще. Нет `curl` — сначала `opkg update && opkg install curl`.

Флаги: `--no-proxy0` — не трогать `Proxy0`, `--xray-core=entware` — ядро
из фида Entware, `--xray-core-tag=vX.Y.Z` — конкретная сборка ядра.

### Вручную

Скачать нужный по архитектуре `.ipk` из
[последнего релиза](https://github.com/kuzzrus/keenetic-xray-go/releases/latest)
— фид добавлять не нужно, `opkg` ставит и по URL:

```bash
opkg install https://github.com/kuzzrus/keenetic-xray-go/releases/download/v0.1.1/keenetic-xray_0.1.1-1_aarch64-3.10.ipk   # ARM-модели
opkg install https://github.com/kuzzrus/keenetic-xray-go/releases/download/v0.1.1/keenetic-xray_0.1.1-1_mipsel-3.4.ipk     # MIPS-модели
```

Если `opkg` не тянет HTTPS-редирект CDN (та же беда busybox-`wget`) —
скачай `curl`'ом и поставь локальный файл:

```bash
curl -fsSL -o /opt/keenetic-xray.ipk https://github.com/kuzzrus/keenetic-xray-go/releases/download/v0.1.1/keenetic-xray_0.1.1-1_aarch64-3.10.ipk
opkg install /opt/keenetic-xray.ipk
```

(Подставь актуальные имя/версию со страницы релизов — `install.sh` это
делает сам.)

В любом случае postinst пакета вытянет ядро xray. Дальше:

```bash
keenetic-xray setup     # вставить vless:// ссылку или URL подписки
```

**Обновление:** повторить `curl … | sh` (или кнопка `🔁 Обновить агент` в
боте). `.ipk` с v0.16.0 UPX-упакован; отдельные `keenetic-xray-linux-<arch>`
в релизе — распакованные бинари на случай, если UPX-стаб не заведётся на
конкретном ядре.

---

## Запуск

Демон стартует сам — init.d-скрипт при установке и на каждой загрузке
роутера. Руками нужно редко:

```bash
keenetic-xray daemon    # демон failover на переднем плане (посмотреть логи)
keenetic-xray menu      # нумерованная панель управления по SSH без бота
```

`menu` — статус, `doctor`, список профилей, обновить подписку, повторить
`setup`, включить/выключить `Proxy0`, перезапустить демон, хвост логов.
Каждый пункт — это отдельная подкоманда (см. CLI ниже), меню просто
удобная точка входа.

**Вотчдог.** Cron-запись, которая перезапускает демон, если он не
запущен — `rc.func` Entware сам этого не делает. Ставится включённой.
`keenetic-xray watchdog {show|enable|disable|log}` (или `🐕 Вотчдог` в
боте). `log` показывает только события перезапуска — пустой лог значит,
что вмешиваться не приходилось.

---

## Диагностика

```bash
keenetic-xray status    # профили, вариант, порты, состояние Proxy0/WG, возраст подписки
keenetic-xray doctor    # проверки: есть профили, конфиг валиден, ядро запускается,
                        # xray слушает порты, upstream Proxy0 совпадает, свободное место,
                        # MSS-правило на месте, WG-интерфейс поднят, история health-check
keenetic-xray logs [N]  # последние N строк лога демона (по умолч. 200)
```

В боте те же `/status <роутер>` и `/doctor <роутер>` (без аргумента —
обзор всех роутеров), плюс `/logs <роутер> [N]` и кнопка `📜 Логи` на
карточке. `/doctor` дополнительно показывает историю health-check:
сколько ✅/❌ за последние N проверок, причины отказов (таймаут / отказ /
DNS / HTTP 5xx) и задержку — видно, *почему* флапает. `/status` —
счётчик переключений за час.

Демон пишет свой лог (свои строки + stderr xray-core) в
`/opt/var/log/keenetic-xray/daemon.log` — самоусекается по размеру,
читается через `keenetic-xray logs` и `/logs`. Если xray падает в
краш-луп при живом демоне (5 падений за 5 минут), бот присылает
уведомление со ссылкой на `/logs`.

---

## CLI

```
keenetic-xray version
keenetic-xray setup [--from <link|url>] [--primary <sel>] [--backup <sel>] [--proxy0|--no-proxy0] [--yes]
keenetic-xray menu
keenetic-xray daemon
keenetic-xray profile {add <vless-uri>|list|remove <index>}
keenetic-xray subscription {set-url <url>|refresh|list|set-primary <i>|set-backup <i>}
keenetic-xray status
keenetic-xray doctor
keenetic-xray logs [N]
keenetic-xray variant {show|set mini|set full}
keenetic-xray agent {configure <url> <router-id> <fingerprint> <token>|enable|disable|status}
keenetic-xray proxy0 {show|set [--lan-ip=192.168.x.1] [--protocol=socks5|http] [--interface=Proxy0]|off}
keenetic-xray failover {show|set <key> <value>}
keenetic-xray routes {list|show [name]|new <name> [entries…]|add <name> <entries…>|del <name> <entries…>|rm <name>|enable <name>|disable <name>|set <name> [--iface=Proxy0|Wireguard4] [--exclusive]|apply}
keenetic-xray routes preset {list|show <name>|add <name> [--ip] [--iface=…] [--exclusive]|sync [<name>|--all]}
keenetic-xray transport {show|mode auto|packet-up|stream-up|stream-one|mode-clear|mss <1200..1452|auto|off>|wg {show|on|off}}
```

Ключи `failover set`: `check_interval_seconds`, `failures_required`,
`recovery_successes_required`, `cooldown_cycles`, `rollback_backoff_seconds`,
`check_retries`, `check_retry_delay_seconds`, `primary_stuck_warn_hours`,
`health_check_url`. `set` применяется на лету — сигналит живому демону
перечитать `config.json`, рестарт не нужен.

Те же операции есть в боте на карточке роутера: `⚙️ Порты и транспорт`
(порты, SOCKS5/HTTP, интерфейс, пресеты MSS, WG-транспорт), `📍 Маршруты`
(списки доменов кнопками), `🧩 Ядро xray`, `🐕 Вотчдог`, `🔗 Источники`,
переключение primary/backup.

---

## Удалённое управление (Telegram-бот)

`keenetic-xray-control-server` — отдельный бинарь на VPS, независимый от
установщика роутера. Очередь команд из бота, раздача polling-агентам по
self-signed TLS с пиннингом отпечатка. Дизайн —
[`docs/bot-control-design.md`](docs/bot-control-design.md).

Установка на systemd-хост (от root):

```bash
curl -fsSL https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/server-install.sh | sudo sh
```

Скачивает бинарь под архитектуру хоста, ставит hardened systemd-юнит и
гоняет мастер (`keenetic-xray-control-server setup`), который пишет
`/etc/keenetic-xray-control-server/config.json` (токен бота, allowlist
чатов, публичный URL для роутеров) и генерит сертификат. Перенастроить —
`setup` ещё раз + `systemctl restart keenetic-xray-control-server`.

**Обновление:** повторить `curl … | sudo sh`, либо кнопка
`⬆️ Обновить сервер` в меню (через systemd path-unit + root-хелпер,
которые ставит установщик). После апдейта новый процесс сам пишет в
разрешённые чаты «✅ Сервер обновлён: vX → vY».

Роутеры дальше управляются из чата. `/menu` — кнопочный UI (меню → список
роутеров → карточка). `➕ Добавить роутер` (или `/add_router home-router
Дом`) регистрирует роутер: бот генерит токен и отдаёт готовую строку
`keenetic-xray agent configure <url> <id> <fingerprint> <token>` для
запуска на роутере.

<details>
<summary>Без установщика</summary>

Собрать/скачать `keenetic-xray-control-server`, руками написать
`/etc/keenetic-xray-control-server/config.json` (0600, формат — в
`docs/bot-control-design.md`) и запустить:

```bash
KEENETIC_XRAY_CS_CONFIG=/etc/keenetic-xray-control-server/config.json \
  keenetic-xray-control-server
```

`keenetic-xray-control-server setup` работает и без установщика — пишет
только конфиг и сертификат, systemd не трогает.
</details>

---

## Сборка

```bash
go build -o keenetic-xray ./cmd/keenetic-xray
go build -o keenetic-xray-control-server ./cmd/keenetic-xray-control-server
```

Кросс-компиляция под роутер:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64  go build -trimpath -ldflags "-s -w" -o dist/keenetic-xray-linux-arm64  ./cmd/keenetic-xray
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -trimpath -ldflags "-s -w" -o dist/keenetic-xray-linux-mipsle ./cmd/keenetic-xray
```

`keenetic-xray-control-server` собирается под обычные VPS-архитектуры
(`linux/amd64`, `linux/arm64`), на роутере не работает.

Локальная сборка `.ipk` (зачем скрипт, а не только goreleaser/nfpm — в
`docs/architecture.md`):

```bash
sh packaging/build-ipk.sh <version> aarch64-3.10 dist/keenetic-xray-linux-arm64 keenetic-xray_<version>_aarch64-3.10.ipk
```

---

## Отношение к `keenetic_xray_installer`

Отдельный проект с нуля, тот же автор. Код не общий; `keenetic_xray_installer`
остаётся полезным референсом по проверенным решениям (флаги сборки, форма
CI, дизайн безопасности failover), но ничего не скопировано.

## Лицензия

MIT — см. [`LICENSE`](LICENSE).
