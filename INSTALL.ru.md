# Установка pingtun 0.3.0

[English](INSTALL.md) · [Android](android/README.md)

Примеры рассчитаны на Linux с systemd, iproute2, nftables и публичным IPv4.
Замените `203.0.113.10`, выберите свободную частную подсеть и укажите настоящий
внешний интерфейс сервера вместо `eth0`. Один экземпляр обслуживает одного
клиента; для следующего нужны отдельные ключи, TUN и подсеть.

## 1. Проверить и установить

Выберите архив по `uname -m`: x86_64 = amd64, aarch64 = arm64. Скачайте
SHA256SUMS из того же релиза и проверьте файлы до установки:

```sh
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf pingtun_0.3.0_linux_amd64.tar.gz
cd pingtun_0.3.0_linux_amd64
sudo install -m 755 bin/pingtun /usr/local/bin/pingtun
sudo install -d -m 755 /usr/local/libexec
sudo install -m 755 deploy/link-up.sh /usr/local/libexec/pingtun-link-up
sudo install -m 644 deploy/pingtun@.service /etc/systemd/system/
pingtun version
```

Бинарник общий для сервера и клиента. Нужны /dev/net/tun, CAP_NET_ADMIN и обычно
CAP_NET_RAW. Режим `socket_mode: ping` использует datagram ICMP без CAP_NET_RAW,
но создание Linux TUN всё ещё требует CAP_NET_ADMIN. Android создаёт TUN через
системный VPN, без root.

## 2. Создать отдельные ключи

```sh
pingtun init --server 203.0.113.10 --dir configs
# Вместо Linux-клиента — отдельный телефон:
# pingtun mobile-init --server 203.0.113.10 --dir configs-phone --name Phone --address 10.203.0.2/30
```

Новые пары используют v2 и стабильные ICMP ID. Для v1 есть `init --legacy`.
Отсутствие объекта adaptive в старом JSON тоже означает v1: протоколы сторон
должны совпадать. Существующие профили и ключи при обновлении до 0.3.0 менять не надо.
Один профиль нельзя одновременно использовать на двух устройствах.

Каталоги имеют права 0700, файлы — 0600. Передайте server.json только на сервер,
client.json — Linux-клиенту, profile.pingtun.json — телефону по закрытому каналу.
Не включайте эти файлы в репозиторий или релиз.

## 3. Сервер и постоянный адрес TUN

На сервере, где server.json находится в текущем каталоге:

```sh
sudo install -d -m 700 /etc/pingtun
sudo install -o root -g root -m 600 server.json /etc/pingtun/server.json
sudo install -d /etc/systemd/system/pingtun@server.service.d
sudo tee /etc/systemd/system/pingtun@server.service.d/address.conf >/dev/null <<'UNIT'
[Service]
ExecStartPost=/usr/local/libexec/pingtun-link-up pingtun0 10.203.0.1/30
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now pingtun@server
```

Помощник ждёт создания TUN и назначает только его адрес/состояние. При смене
interface в JSON исправьте и drop-in. Важно явно задавать владельца root:
распаковка архива может сохранить чужой UID, и ограниченная служба root не
сможет прочитать такой конфиг с правами 0600.

## 4. Forwarding, NAT и ответы ядра

Разрешите входящий IPv4 ICMP в firewall провайдера и ОС, сохранив SSH/управление.
Создайте /etc/pingtun/site.nft, заменив eth0:

```nft
table ip pingtun_site {
 chain echo_guard {
  type filter hook output priority -5; policy accept;
  icmp type echo-reply @th,64,48 0x5054554e0201 drop
 }
 chain forward {
  type filter hook forward priority 0; policy accept;
  iifname "pingtun0" ip saddr != 10.203.0.2 drop
  iifname "pingtun0" oifname "eth0" accept
  iifname "pingtun0" drop
  oifname "pingtun0" ct state established,related accept
  oifname "pingtun0" drop
 }
 chain nat {
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.203.0.2 oifname "eth0" masquerade
 }
}
```

Правило echo_guard предназначено для v2: обычный ping остаётся, отражённый
ядром запрос pingtun подавляется. Для v1 используйте deploy/kernel-echo.nft,
для диагностики — deploy/probe-kernel-echo.nft. ACCEPT отдельной nft-цепочки не
отменяет DROP других цепочек: если есть UFW/firewalld/Docker, разрешите эти
потоки и там. Пример разрешает доступ к маршрутизируемым сетям сервера;
если частные сети должны быть недоступны, добавьте ограничения по назначениям.

Для сохранения после перезагрузки:

```sh
sudo tee /etc/sysctl.d/90-pingtun.conf >/dev/null <<'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL
sudo sysctl -p /etc/sysctl.d/90-pingtun.conf
sudo nft -c -f /etc/pingtun/site.nft
sudo tee /etc/systemd/system/pingtun-firewall.service >/dev/null <<'UNIT'
[Unit]
Description=Owned pingtun firewall/NAT tables
After=network-pre.target
Before=pingtun@server.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/pingtun/site.nft
ExecStop=/usr/sbin/nft delete table ip pingtun_site
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now pingtun-firewall
```

Это явные действия администратора, не автоматика VPN-процесса. Основной маршрут
по умолчанию не меняется. Для другого экземпляра нужны свои имена таблиц/служб.
Не очищайте общий ruleset. Согласуйте порядок запуска с firewall-менеджером,
который может перезагружать правила при старте ОС.

## 5а. Linux-клиент

Установите бинарник, unit и помощник на клиенте. Сохраните client.json как
/etc/pingtun/client.json, root:root, 0600. Для pingtun@client.service создайте
такой же drop-in с адресом 10.203.0.2/30, включите и запустите службу. Проверьте
внутренний канал командой `ping -I pingtun0 10.203.0.1`.

Для первого выхода в интернет только от выбранного адреса возьмите свободные
таблицу и приоритет:

```sh
sudo ip route add unreachable default table 2050 metric 32760
sudo ip route add default dev pingtun0 table 2050 metric 10
sudo ip rule add pref 10050 from 10.203.0.2/32 lookup 2050
curl -4 --interface 10.203.0.2 https://api.ipify.org
```

Весь компьютер этот пример не перенаправляет. Команды маршрутизации не
сохраняются после перезагрузки; для постоянной работы закрепите их в сетевом
менеджере, сохранив unreachable guard. Полноценный шлюз требует отдельной
политики с исключениями LAN, управления и публичного адреса ICMP-сервера.
До смены общего default route сохраните прямой маршрут к серверу.

## 5б. Android

Установите APK, передайте отдельный profile.pingtun.json по закрытому каналу,
нажмите «Импортировать профиль». Разрешите VPN и уведомления; на GrapheneOS
оставьте разрешение «Сеть». Нажмите «Подключить». Сервер должен уже работать
с ключами именно этой пары.

Android направляет IPv4 в TUN, перехватывает и блокирует IPv6. При обрыве
транспорта TUN остаётся. Чтобы блокировка сохранялась после остановки приложения,
включите системные Always-on VPN и «Блокировать подключения без VPN».
Дополнительный режим выключенного экрана использует wake lock и сильнее
расходует батарею. Сон и смена сети ещё требуют длительной проверки.
При обновлении APK поверх предыдущего профиль сохраняется; не удаляйте приложение.

## Диагностика и откат

`pingtun check --config ...` не печатает ключи. `run --stats-interval 5s` и SIGUSR1
дают безопасные счётчики. Журнал — `journalctl -u pingtun@server`; стенд — LAB.md.
Обычный отражённый ответ ядра не считается успехом аутентификации. Параллельные
raw-экземпляры видят и чужие пакеты с другими ключами.

Для отката остановите и отключите только свои pingtun-службы, удалите их
собственные drop-in/таблицу и добавленные правило 10050/маршруты таблицы 2050.
Если меняли forwarding, восстановите прежнее значение. Удаление VPN/политики
меняет путь трафика: сохраните нужную блокировку и доступ к управлению.
Рабочие конфигурации и закрытые ключи в поставку не входят.
