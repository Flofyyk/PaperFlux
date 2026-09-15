# PaperFlux Server

**Русский** | [English](README.en.md)

PaperFlux Server — серверная часть PaperFlux для собственного Linux VPS. Выходной узел принимает соединения от совместимых клиентов и передаёт трафик во внешнюю сеть.

Android-клиент: [PaperFlux Android](https://github.com/Flofyyk/PaperFluxAndroid).

## Что входит

- Linux exit-node.
- Транспорт через Yandex Docs и WebSocket.
- Авторизация профилем и шифрование транспортных сообщений.
- Поддержка Android-клиента: TUN, DNS/TCP-проверка и счётчики трафика.

## Развёртывание на VPS

Ниже пример для чистого Ubuntu/Debian VPS. Exit-node запускается от root: это требуется текущей реализации для работы с raw sockets.

### 1. Подготовьте сервер

Установите актуальный Go 1.26.4 или новее, Git и инструменты сборки. Затем клонируйте репозиторий и соберите бинарник:

```bash
sudo apt update
sudo apt install -y git build-essential

git clone https://github.com/Flofyyk/PaperFlux.git /opt/paperflux
cd /opt/paperflux
go mod download
go build -trimpath -o paperflux .
sudo install -m 0755 paperflux /usr/local/bin/paperflux
```

### 2. Создайте файл конфигурации

Не передавайте ссылку на документ и токен в командной строке: их видно в истории shell и списке процессов. Сохраните их в файле, доступном только root:

```bash
sudo install -d -m 0700 /etc/paperflux
sudo nano /etc/paperflux/paperflux.env
```

```ini
PAPERFLUX_DOCUMENT_URL=https://disk.yandex.ru/...
PAPERFLUX_PROFILE_ID=1
PAPERFLUX_PROFILE_TOKEN=replace-with-profile-token
```

Ограничьте доступ:

```bash
sudo chmod 600 /etc/paperflux/paperflux.env
```

Параметры должны совпадать с профилем, импортированным в Android-клиент. Для каждого пользователя создавайте отдельный профиль и токен.

### 3. Создайте systemd-сервис

Создайте `/etc/systemd/system/paperflux.service`:

```ini
[Unit]
Description=PaperFlux exit node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/paperflux
EnvironmentFile=/etc/paperflux/paperflux.env
ExecStart=/usr/local/bin/paperflux --exit-node --transport yandex --url ${PAPERFLUX_DOCUMENT_URL} --profile-id ${PAPERFLUX_PROFILE_ID} --profile-token ${PAPERFLUX_PROFILE_TOKEN}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Текущий режим exit-node использует raw sockets. Перед первым запуском добавьте правило, которое требуется ядру сервера:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

Сохраните правила firewall способом, принятым в вашей ОС, затем включите сервис:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now paperflux
```

### 4. Проверьте запуск

```bash
sudo systemctl status paperflux
sudo journalctl -u paperflux -f
```

В журнале должен появиться запуск exit-node и подключение транспорта. Не публикуйте вывод журнала без удаления ссылок, токенов и адресов.

### Обновление

```bash
cd /opt/paperflux
sudo systemctl stop paperflux
git pull --ff-only
go mod download
go build -trimpath -o paperflux .
sudo install -m 0755 paperflux /usr/local/bin/paperflux
sudo systemctl start paperflux
sudo systemctl status paperflux
```

## Параметры запуска

Основные параметры:

- `--exit-node` — запуск VPS как выходного узла.
- `--url` — ссылка на Yandex Docs.
- `--profile-id` и `--profile-token` — данные профиля.
- `--transport yandex` — транспорт по умолчанию.

Полный список доступен через `paperflux --help`.

## Документация

- [Подключение Android-клиента](docs/PAPERFLUX.md)
- [Описание PFS2](docs/SECURITY_PFS2.md)
- [Лицензия GPL-3.0-or-later](LICENSE)

## Использование

Проект предназначен для обучения, исследований и тестирования на собственных или явно разрешённых системах. Вы отвечаете за сервер, доступы, данные и трафик своего развёртывания.
