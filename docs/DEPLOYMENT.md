# Развёртывание PaperFlux на Linux VPS

[← Принцип работы](../README.md)

Ниже пример для чистого Ubuntu/Debian VPS. Exit-node запускается от root: это требуется текущей реализации для работы с raw sockets.

### 1. Подготовьте сервер

Установите актуальный Go 1.26.4 или новее, Git и инструменты сборки. Затем клонируйте репозиторий и соберите бинарник:

```bash
sudo apt update
sudo apt install -y git build-essential

git clone https://github.com/Flofyyk/PaperFlux.git
cd PaperFlux
go mod download
go build -trimpath -o paperflux .
sudo install -m 0755 paperflux /usr/local/bin/paperflux
```

### 2. Создайте файл конфигурации

Храните параметры сервиса в отдельном файле с доступом только root. Текущий CLI получает их через аргументы запуска: systemd подставляет значения из файла, поэтому они всё равно могут быть видны в списке процессов. Этот файл упрощает настройку, но не является механизмом сокрытия аргументов.

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

ID и токен должны совпадать с профилем Android-клиента. Сгенерировать случайный токен можно командой `openssl rand -hex 32`. Пример описывает один профиль с виртуальным IP `10.10.10.2`. Для другого адреса добавьте соответствующий `--client-ip` в команду сервиса.

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
EnvironmentFile=/etc/paperflux/paperflux.env
ExecStart=/usr/local/bin/paperflux --exit-node --transport yandex --url ${PAPERFLUX_DOCUMENT_URL} --profile-id ${PAPERFLUX_PROFILE_ID} --profile-token ${PAPERFLUX_PROFILE_TOKEN}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Текущий режим exit-node использует raw sockets. Правило ниже подавляет исходящие TCP RST на всём сервере, а не только для PaperFlux. Используйте выделенный VPS: такое правило затрагивает другие TCP-сервисы.

```bash
sudo iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP || \
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

Для удаления добавленного правила RST выполните:

```bash
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

### Обновление

```bash
cd PaperFlux
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
