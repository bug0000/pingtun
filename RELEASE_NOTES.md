# pingtun 0.4.0 — админка и настройки транспорта / admin console

## Русский

Linux-сервер и клиент обновлены до 0.4.0. В Linux-архивы добавлен каталог `admin`
с HTTPS-панелью, шаблонами systemd/Nginx и инструкцией `admin/README.ru.md`.

- Создание отдельных аккаунтов Android/Linux: ключи, TUN, /30, служба, nftables.
- Скачивание профилей, блокировка, разблокировка, удаление и смена пароля панели.
- Просмотр ранее настроенных служб через `legacy.json`; их удаление недоступно.
- Настройки адаптивного транспорта по умолчанию и для аккаунтов панели:
  MTU TUN/внешнего пакета, каналы, окна, тайминги, пакеты/с и ICMP Identifier.
- Проверка конфигураций обоих узлов, обновление Android-профиля и возврат старых
  файлов при ошибке применения. Активный туннель перезапускается.

После изменения транспорта скачайте и импортируйте профиль на клиенте заново.
До этого связь может прерваться. Старые ручные службы автоматически не меняются.
Панель устанавливается отдельно и требует root, systemd, nftables, forwarding
и HTTPS reverse proxy; пароли задаются локально и хранятся как scrypt-хеш.
Счётчики сбрасываются при перезапуске процесса; wire включает служебный трафик.

**Скачать:** `pingtun_0.4.0_linux_amd64.tar.gz` или
`pingtun_0.4.0_linux_arm64.tar.gz`; `pingtun_0.3.0_android.apk` — прежний
подписанный Android-клиент без изменений, versionCode 2. Переустанавливать его
для использования админки не требуется. Все файлы перечислены в `SHA256SUMS`.
Проверка релиза сверяет исходники Android и общего ядра с исходным выпуском APK.

Ограничения: IPv4, один клиент на экземпляр сервера; панель создаёт отдельный
экземпляр на аккаунт. FEC, физической агрегации и Windows-клиента нет.
Сон/смена сетей и lockdown на реальном Android требуют дальнейших испытаний.
Сохранение нескольких файлов с откатом не защищает от отключения питания
посреди обновления: при таком сбое проверьте согласованность конфигураций.

## English

Linux server/client version 0.4.0 adds an optional HTTPS admin console bundled
in both Linux archives. See `admin/README.ru.md` for systemd/Nginx installation.

Create isolated Android/Linux accounts, download private profiles, block/unblock
or delete accounts, rotate admin credentials, and view registered legacy services.
Edit adaptive transport defaults or managed-account MTUs, lanes, windows, timing,
packet-rate limits and ICMP identifier mode. Both peer configs are checked before
application. Android profiles are kept in sync; active services restart and files
are restored on application failure. Stopped accounts remain stopped.

After editing an account, download and reimport its profile on the client.
Connectivity may stop until both ends use the new settings. Legacy services
are not reconfigured. Installation needs root, systemd, nftables, forwarding and
an HTTPS reverse proxy. Statistics reset with each process restart.
Multi-file rollback does not protect against process/power failure during writes.

The signed **Android APK remains 0.3.0**, versionCode 2, with the original signing
identity and filename. No Android upgrade is required. Publication checks ensure
its app/native source inputs have not changed. Linux archives are version 0.4.0;
all assets have SHA-256 checksums and third-party license notices.

IPv4 only; one peer per server instance. No FEC, physical aggregation or Windows
client. Android sleep, handoff and lockdown still need further device validation.
