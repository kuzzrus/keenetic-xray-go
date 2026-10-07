<p align="center">
  <img src="docs/banner.svg" alt="keenetic-xray-go" width="760">
</p>

<p align="center">
  <a href="https://www.tbank.ru/cf/2qxNvGa3fSX"><img src="https://img.shields.io/badge/%E2%9D%A4%EF%B8%8F_%D0%9F%D0%BE%D0%B4%D0%B4%D0%B5%D1%80%D0%B6%D0%B0%D1%82%D1%8C_%D0%BF%D1%80%D0%BE%D0%B5%D0%BA%D1%82-Donate_%D1%87%D0%B5%D1%80%D0%B5%D0%B7_T--Bank-FFDD2D?style=for-the-badge&labelColor=1a1a1a" alt="Донат через T-Bank"></a>
</p>

# keenetic-xray-go

**Xray (VLESS) для роутера Keenetic: ставится одной командой, сам переключается на запасной сервер и управляется из Telegram.**

Через ваш VPN идёт только то, что вы выбрали, — например YouTube, Telegram или одно устройство. Остальной интернет работает как обычно. Если основной VPN-сервер перестал отвечать, программа сама переключится на запасной, а когда основной снова заработает — вернётся.

## Что умеет

- **Устанавливается одной командой** по SSH. Мастер настройки — на русском.
- **Запасной сервер.** Основной упал — включается запасной (и приходит сообщение в Telegram, если подключён бот). Проверка — настоящим запросом, а не пингом.
- **Вы решаете, что идёт через VPN:** готовые списки (YouTube, Telegram, Netflix, Instagram, OpenAI и десятки других), свои сайты или целое устройство.
- **Управление из Telegram:** статус, переключение серверов, списки, обновление — кнопками в чате.
- **Сам чинит настройки**, если прошивка роутера их сбросила.
- **Защищённый DNS** (DoT/DoH) — включается одной командой или кнопкой.

## Что нужно

- Роутер **Keenetic с Entware** (процессор mipsel или aarch64 — установщик определит сам).
- Ссылка `vless://` или адрес подписки от вашего VPN-провайдера (сам VPN-сервер проект не предоставляет).
- Для списков сайтов — KeeneticOS **5.0** или новее.
- Бот в Telegram — по желанию; для него нужен небольшой VPS.

## Установка

Зайдите на роутер по SSH и выполните (подставьте свой адрес подписки):

```bash
curl -fsSL https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/install.sh | sh -s -- --sub="https://provider.example/sub/token"
```

Скрипт сам определит модель роутера, поставит программу и всё настроит. Без `--sub` откроется пошаговый мастер — вставьте в него ссылку `vless://` или адрес подписки:

```bash
curl -fsSL https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/install.sh | sh
```

Нет `curl`? Сначала выполните `opkg update && opkg install curl`.

**Обновление** — та же команда ещё раз (или кнопка `🔁 Обновить агент` в боте).

## Как пользоваться

Программа запускается сама — сразу после установки и при каждой загрузке роутера. Пригодятся пять команд:

| Команда | Что делает |
|---|---|
| `keenetic-xray status` | показывает, какой сервер сейчас работает |
| `keenetic-xray doctor` | проверяет, всё ли в порядке, и подсказывает, что не так |
| `keenetic-xray menu` | меню управления прямо в SSH, без бота |
| `keenetic-xray setup` | заново ввести ссылку или подписку |
| `keenetic-xray logs` | последние строки журнала |

**Пустить через VPN только нужные сайты:**

```bash
keenetic-xray routes preset list          # какие готовые списки есть
keenetic-xray routes preset add youtube   # YouTube — через VPN
```

То же самое делается кнопками в боте: `📍 Маршруты` → `📦 Готовые списки`. Списки работают, пока устройство берёт DNS у роутера, поэтому в браузере не должен быть включён свой «безопасный DNS».

## Бот в Telegram (по желанию)

На VPS с systemd (Linux) выполните:

```bash
curl -fsSL https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/server-install.sh | sudo sh
```

Мастер спросит токен бота (его выдаёт [@BotFather](https://t.me/BotFather)), список разрешённых чатов и адрес сервера. Дальше в чате: `/menu` → `➕ Добавить роутер` — бот выдаст готовую команду для роутера. Подробнее — в [описании бота](docs/bot-control-design.md).

## Документация

- [Подробное описание](docs/reference.md) — все команды и настройки, сборка из исходников
- [Маршруты по сайтам](docs/routing.md)
- [Защищённый DNS](docs/dns.md)
- [Бот и сервер управления](docs/bot-control-design.md)
- [Как всё устроено](docs/architecture.md)
- [Full и Mini](docs/full-vs-mini.md)

## Поддержать проект

Проект бесплатный и делается в свободное время. Если он вам пригодился — [донат через T-Bank](https://www.tbank.ru/cf/2qxNvGa3fSX).

## Лицензия

MIT — см. [LICENSE](LICENSE).
