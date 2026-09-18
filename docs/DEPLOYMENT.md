# Развёртывание PaperFlux на Linux VPS

[← Принцип работы](../README.md)

Ниже пример для чистого Ubuntu/Debian VPS. Рекомендуемый режим `proxy` не использует raw sockets, не меняет правила firewall и запускается от отдельного системного пользователя. Режим `raw` оставлен для совместимости с пакетным выходом.

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

Храните параметры сервиса в отдельном файле с доступом только владельцу сервиса. Текущий CLI получает их через аргументы запуска: systemd подставляет значения из файла, поэтому они всё равно могут быть видны в списке процессов. Этот файл упрощает настройку, но не является механизмом сокрытия аргументов.

```bash
sudo useradd --system --home /var/lib/paperflux --shell /usr/sbin/nologin paperflux
sudo install -d -o paperflux -g paperflux -m 0700 /etc/paperflux
sudo nano /etc/paperflux/paperflux.env
```

```ini
PAPERFLUX_DOCUMENT_URL=https://disk.yandex.ru/...
PAPERFLUX_PROFILE_ID=1
PAPERFLUX_PROFILE_TOKEN=replace-with-profile-token
```

Ограничьте доступ:

```bash
sudo chown paperflux:paperflux /etc/paperflux/paperflux.env
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
User=paperflux
EnvironmentFile=/etc/paperflux/paperflux.env
ExecStart=/usr/local/bin/paperflux --exit-node --mode proxy --transport yandex --url ${PAPERFLUX_DOCUMENT_URL} --profile-id ${PAPERFLUX_PROFILE_ID} --profile-token ${PAPERFLUX_PROFILE_TOKEN}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`proxy` — режим по умолчанию в этой инструкции. Он ограничивает одновременные TCP-потоки и открывает обычные исходящие соединения от VPS; root и iptables не нужны.

Если требуется пакетный режим, замените `--mode proxy` на `--mode raw`, установите `User=root` и добавьте правило ниже. Оно подавляет TCP RST только для исходящего адреса exit-node, не затрагивая остальные исходящие соединения сервера.

```bash
EXIT_IP=$(ip route get 1.1.1.1 | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)
sudo iptables -C OUTPUT -s "$EXIT_IP" -p tcp --tcp-flags RST RST -j DROP || \
  sudo iptables -A OUTPUT -s "$EXIT_IP" -p tcp --tcp-flags RST RST -j DROP
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

Для удаления правила RST в raw-режиме выполните:

```bash
EXIT_IP=$(ip route get 1.1.1.1 | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)
sudo iptables -D OUTPUT -s "$EXIT_IP" -p tcp --tcp-flags RST RST -j DROP
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
- `--urls` — одна или две ссылки на Yandex Docs через запятую; включает резервирование и распределение новых TCP-потоков.
- `--profile-id` и `--profile-token` — данные профиля.
- `--mode proxy|raw` — способ выхода VPS в интернет.
- `--transport yandex` — транспорт по умолчанию.

Полный список доступен через `paperflux --help`.
