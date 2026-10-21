# Changelog / История изменений

## 0.4.1 — 2026-10-21

- Redesigned native Android UI: dark palette, large connection control, compact
  profile and traffic cards, separate connection settings and About screen.
- New adaptive launcher icon, themed monochrome icon and notification mark.
- About includes a short ICMP/WireGuard description, version, source and
  contact address bug@pizd.ec. No device-specific or experimental UI labels.
- Android versionCode 3 retains the release certificate for in-place updates.
- Added emulator checks for main/About screens and UI screenshots.

Обновлён Android-клиент: чистый интерфейс, иконка, «О приложении» и контакт.
Обновление сохраняет подпись и импортированный профиль.

## 0.4.0 — 2026-10-21

- HTTPS admin console: isolated client accounts, profile downloads, block/unblock,
  credential rotation, legacy service visibility and separate payload/wire counters.
- Adaptive transport defaults and managed-account settings, validated for both
  peers; update Android profiles, restart active services and roll back on errors.
- Reject names beyond Android's 64-byte UTF-8 profile bound.
- Include the admin console and systemd templates in Linux release archives.
- Carry forward signed Android 0.3.0 unchanged; verify native/app source identity
  before publishing. APK filename and embedded version remain 0.3.0.

Админка HTTPS, управление клиентами и параметрами адаптивного транспорта.
При изменении параметров клиента требуется скачать и импортировать профиль заново.
Подписанный Android APK остаётся версией 0.3.0; Linux обновлён до 0.4.0.

## 0.3.0 — 2026-10-17

First regular release / Первый обычный релиз.

### English

- Linux server and CLI client in one static binary (amd64 and arm64).
- Android 10+ client (arm64-v8a/x86_64), ICMP without root, Android Keystore
  profile storage, retained TUN during reconnect and IPv6 blocking.
- WireGuard encryption with an authenticated ICMP carrier; adaptive v2,
  short idle controls, bounded queues and logical lanes.
- New `init` pairs use v2, stable IDs, MTU 1280 / outer MTU 1440, two lanes,
  250 packets/s cap and a 32-request window. `init --legacy` retains v1.
  Existing configs and mobile profiles remain readable without regeneration.
- Linux and Android share handshake/restart recovery and key-free statistics.
- Strict 64 KiB config/profile bounds, private file permissions and fresh keys.
- Signed Android APK (versionCode 2), Linux archives, SHA-256 sums, license
  notices, installation guides and release notes in Russian and English.

Scope: IPv4, one encrypted peer per server instance, manual Linux routes/NAT.
Physical multipath, FEC, Windows and IPv6 transport are outside this release.
No external security audit or guarantee of ICMP availability is claimed.

### Русский

- Сервер и консольный клиент Linux в одном статическом бинарнике (amd64/arm64).
- Android 10+ (arm64-v8a/x86_64): ICMP без root, хранение профиля через Android
  Keystore, сохранение TUN при восстановлении связи и блокировка IPv6.
- Шифрование WireGuard, аутентифицированный ICMP-транспорт, адаптивный v2,
  короткие служебные пакеты в простое, ограниченные очереди и логические каналы.
- `init` по умолчанию создаёт v2: стабильные ID, MTU 1280 / внешний MTU 1440,
  два канала, предел 250 пакетов/с и окно до 32 запросов. `init --legacy` создаёт v1.
  Старые конфигурации и мобильные профили менять не требуется.
- Общее ядро Linux/Android восстанавливает обмен ключами после перезапуска
  сервера и выдаёт статистику без ключей.
- Ограничение конфигурации/профиля 64 КиБ, закрытые права файлов, отдельные ключи.
- Подписанный APK (versionCode 2), Linux-архивы, SHA-256, тексты лицензий,
  инструкции и описание релиза на русском и английском.

Границы версии: IPv4, один шифрованный клиент на экземпляр сервера,
маршруты/NAT Linux настраиваются отдельно. Физической агрегации, FEC, Windows
и передачи IPv6 нет. Внешний аудит безопасности не проводился; доступность
ICMP у конкретного оператора не гарантируется.
