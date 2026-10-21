# pingtun 0.4.1 — Android: красиво и чисто

## Русский

Обновлён Android-клиент: спокойная тёмная палитра, крупная кнопка подключения,
компактные карточки профиля и статистики. Параметры фоновой работы вынесены
в отдельное окно настроек. Добавлены адаптивная и монохромная иконки Android
и новый значок уведомления.

Раздел «О приложении» содержит описание ICMP-туннеля и WireGuard, версию,
ссылку на исходники и контакт **bug@pizd.ec**. В пользовательских текстах нет
экспериментальных формулировок, модели телефона и персональных подробностей.

`pingtun_0.4.1_android.apk` (versionCode 3) подписан прежним сертификатом.
Устанавливайте поверх существующей версии: удалять приложение не нужно,
импортированный профиль сохранится. Сервер и профиль для изменения оформления
обновлять не требуется. Android 10+, ARM64/x86_64, без root и Google Play Services.

Linux-архивы также имеют версию 0.4.1 и содержат админку из 0.4.0.
Все файлы снабжены SHA256SUMS и уведомлениями о лицензиях.

Транспорт не менялся: IPv4 внутри ICMP, IPv6 на Android блокируется.
Работа зависит от доступности ICMP в сети. Длительный сон, смена сетей и
системная блокировка требуют дальнейших испытаний на физических устройствах.

## English

Android 0.4.1 adds a clean dark interface, prominent connection control,
profile/traffic cards, separate connection settings, adaptive/themed launcher
icons and a new notification mark. About explains the ICMP/WireGuard tunnel
and includes version, source link and **bug@pizd.ec**.

The APK uses versionCode 3 and retains its release signing certificate.
Install over the previous version to preserve the imported profile. No server
or profile changes are needed for this UI update. Android 10+, ARM64/x86_64,
no root or Google Play Services required. Linux 0.4.1 retains the 0.4.0 admin console.

Transport is unchanged: IPv4 over ICMP; Android captures and blocks IPv6.
ICMP availability is network-dependent. Long sleep, handoff and lockdown
remain further physical-device acceptance work.
