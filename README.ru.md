# PaperFlux Server

[English](README.md) | **Русский**

PaperFlux Server — транспортное ядро и Linux-выходная нода для клиента PaperFlux Android. Нода принимает кадры от клиента, передаёт их через канал Yandex Docs и открывает соединение назначения со стороны VPS. Android-приложение публикуется отдельно в репозитории [PaperFlux Android](https://github.com/Flofyyk/PaperFluxAndroid).

Это поддерживаемый fork [p1neappleXpress/OpenFlux](https://github.com/p1neappleXpress/OpenFlux). В PaperFlux добавлены профильный сценарий клиента, ограниченные адаптивные батчи, проверки сессии и инструкции развёртывания. URL документа, токены и доступы к VPS в репозитории не хранятся.

### Путь трафика

```text
Android TUN → PaperFlux native client → Yandex Docs Engine.IO/WebSocket
           → PaperFlux exit node → TCP destination
```

Адаптер Yandex выполняет polling, переходит на WebSocket, авторизует Socket.IO-сессию и передаёт ограниченные адаптивные батчи. Формат остаётся совместимым с Base64/Socket.IO, поэтому отдельный relay-протокол не требуется.

## Компоненты

- `transport/yandex` — polling, WebSocket upgrade, авторизация и кадрирование Yandex Docs;
- `tunnel` — виртуальный интерфейс и пересылка пакетов;
- `socks5` — необязательный SOCKS5-listener для десктопа;
- `network` — разбор пакетов и контрольные суммы;
- `transport/oneme` — необязательный транспорт MAX из upstream.

## Требования
1. Golang v. 1.26.3+ — требуется для сборки бинарника десктопного клиента / выходной ноды;
2. Android Native Development Kit (NDK) v.27.0.12077973+ — требуется для сборки бинарника для Android-клиента;
3. XCode v. 26.6+ — требуется для сборки бинарника для iOS-клиента;
4. VPS / VDS выходная нода на Linux.

## Структура

```
paperflux/
├── main.go
├── transport/
│   ├── transport.go      # Transport interface
│   └── yandex/           # Yandex Docs backend
│   └── oneme/            # MAX Messenger backend
├── tunnel/
│   ├── tunnel.go         # TCP tunnel core
│   ├── endpoint.go       # Virtual NIC
│   └── rawsocket.go      # Raw socket (exit node)
├── socks5/               # SOCKS5 server
├── network/              # Checksums, packet parsing
└── utils/                # Debug logging
```

## Сборка

```bash
go mod tidy
go build -o paperflux .
```

## Сборка для Android (клиентский бинарник)
```bash
export ANDROID_NDK_HOME=<путь до вашего Android NDK>
./build_android.sh
```

## Сборка для iOS (клиентский бинарник)
```bash
export XCODE_PATH="<путь до вашего Xcode.app>" # опционально, по умолчанию /Applications/Xcode.app
./build_ios.sh
```

## Запуск выходной ноды

### 1. Настройка выходной ноды
1. У вас должен быть root-доступ выходной ноде;
2. Поддерживается только устаревший редактор документов Yandex (переключается в настройках интерфейса).

Команды для настройки выходной ноды:
```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo ./paperflux --exit-node --url "YOUR_YANDEX_DOC_URL" --debug
```

## Запуск десктопного клиента

Команды для настройки десктопного клиента:
```bash
./paperflux --client --url "YOUR_YANDEX_DOC_URL" --socks5 :1080 --debug
```

Затем настройте SOCKS5-прокси в браузере на localhost:1080.

## Флаги

| Флаг          | По умолчанию        | Описание                       |
|---------------|---------------------|--------------------------------|
| `--client`    |                     | Запуск в режиме клиента        |
| `--exit-node` |                     | Запуск в режиме ноды           |
| `--socks5`    | `:1080`             | Адрес SOCKS5 прокси            |
| `--url`       | `https://localhost` | URL документа (Yandex Docs)    |
| `--maxToken`  | ``                  | Токен авторизации (Max)        |
| `--maxUid`    | ``                  | ID пользователя (Max)          |
| `--debug`     | `false`             | Включить подробное логирование |
| `--transport` | `yandex`            | Выбор транспорта               |

## Реализация собственных транспортов

Новый backend можно реализовать через интерфейс `Transport` из `transport/transport.go` и зарегистрировать в селекторе транспортов. Для него отдельно опишите кадрирование, авторизацию и правила backpressure.

## Лицензия

Проект распространяется под лицензией **GNU General Public License v3.0 or later**.
Полный текст — в файле [LICENSE](LICENSE).

Лицензии третьих сторон — в файле [NOTICE](NOTICE).

## Дисклеймер

Только для образовательного использования. Тестируйте на собственных машинах и сетях.
