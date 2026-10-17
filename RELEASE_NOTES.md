# pingtun 0.3.0 — Linux server/client + Android / сервер и клиенты

## Русский

Первый релиз без отметки prerelease: шифрованный IPv4 VPN поверх ICMP.
WireGuard отвечает за обмен ключами и шифрование; собственный транспорт
передаёт пакеты через ICMP Echo Request/Reply. Код Hans не используется.

**Скачать:**

- `pingtun_0.3.0_linux_amd64.tar.gz` — сервер и консольный клиент Linux x86-64.
- `pingtun_0.3.0_linux_arm64.tar.gz` — сервер и клиент Linux ARM64.
- `pingtun_0.3.0_android.apk` — подписанное приложение Android 10+, ARM64/x86_64.
- `SHA256SUMS` — контрольные суммы всех файлов; APK подписан тем же ключом,
  что и предыдущая сборка приложения, и устанавливается поверх неё.
- `ANDROID_SIGNING_CERT.txt` и `THIRD_PARTY_NOTICES.txt` — отпечаток сертификата
  и уведомления о лицензиях. Закрытый ключ подписи и VPN-профили не публикуются.

Linux использует один бинарник с режимами сервера/клиента. Новые конфиги
создаются через `pingtun init`, отдельный профиль телефона — `pingtun mobile-init`.
Новые пары используют адаптивный v2; существующие конфиги/профили совместимы.
Для v1 оставлена команда `init --legacy`. Android работает без root и Google
Play Services; его интерфейс пока на русском языке.

Проверено: Go race/vet/fuzz, настоящий WireGuard, Linux NAT с потерями и
перестановкой, целостность файлов, восстановление после обрыва и перезапуска
сервера, ICMP-клиент без CAP_NET_RAW; Android-эмулятор проверяет запуск,
ICMP от UID приложения и зашифрованное хранение профиля. Пользователь подтвердил
соединение и открытие сайтов через LTE на Pixel 9 Pro с GrapheneOS без root.
Linux ARM64 поставляется отдельной сборкой; это не заявление о проверке на
каждой ARM-плате. Подробности и границы испытаний — в VALIDATION.md.

Ограничения: только IPv4, один клиент на экземпляр сервера, Linux-маршруты/NAT
настраиваются отдельно. Android перехватывает и блокирует IPv6. Физической
агрегации, FEC и Windows-клиента нет. Длительный сон, смена сетей, IPv6 bypass
и системная блокировка на реальном телефоне ещё требуют проверки. Внешний
аудит безопасности не проводился. ICMP может блокироваться или ограничиваться.

Инструкции: [русская](https://github.com/bug0000/pingtun/blob/v0.3.0/INSTALL.ru.md),
[English](https://github.com/bug0000/pingtun/blob/v0.3.0/INSTALL.md).

## English

First non-prerelease: an encrypted IPv4 VPN over ICMP. WireGuard handles peer
identity, key exchange and encryption; the custom carrier uses Echo
Request/Reply. No Hans code is included.

**Downloads:**

- `pingtun_0.3.0_linux_amd64.tar.gz` — Linux x86-64 server and CLI client.
- `pingtun_0.3.0_linux_arm64.tar.gz` — Linux ARM64 server and CLI client.
- `pingtun_0.3.0_android.apk` — signed Android 10+ application, ARM64/x86_64.
- `SHA256SUMS` — checksums of all assets. The APK keeps the previous app's
  signing identity and can update it in place.
- `ANDROID_SIGNING_CERT.txt` and `THIRD_PARTY_NOTICES.txt` — public signing
  certificate fingerprint and license notices. Signing private keys and VPN
  profiles are not distributed.

One Linux binary supports both roles. Generate a new pair with `pingtun init`,
or a dedicated phone profile with `pingtun mobile-init`. New pairs use adaptive
v2; existing configs/profiles remain compatible. Use `init --legacy` for v1.
Android does not require root or Google Play Services; its UI is currently Russian.

Validation covers Go race/vet/fuzz, real WireGuard, Linux NAT with loss/reordering,
file integrity, outage/server-restart recovery and a client without CAP_NET_RAW.
Android emulator tests cover launch, app-UID ICMP and authenticated encrypted
profile storage. A user confirmed LTE connection and browsing on a Pixel 9 Pro
running GrapheneOS without root. Linux ARM64 is a separate build, not a claim
of execution on every ARM board. See VALIDATION.md for evidence and limits.

Scope: IPv4 only, one peer per server instance, separately configured Linux
routing/NAT. Android captures and blocks IPv6. Physical multipath, FEC and a
Windows client are not included. Long sleep, handoff, IPv6 bypass and system
lockdown still need real-device testing. No external security audit has been
completed. ICMP can be blocked or rate-limited by a network.

Installation: [English](https://github.com/bug0000/pingtun/blob/v0.3.0/INSTALL.md),
[русский](https://github.com/bug0000/pingtun/blob/v0.3.0/INSTALL.ru.md).
