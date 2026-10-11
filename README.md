# IP Shield

Защита Windows-компьютеров от перебора паролей (RDP, общие папки/SMB, MS SQL, OpenSSH) с общим списком атакующих IP для всех компьютеров сети.

## Что делает

- **Агент** (`C:\ProgramData\IPShield\agent.ps1`) запускается Планировщиком каждую минуту от имени SYSTEM:
  - читает журналы Windows: RDP (событие 140), неудачные входы (4625), MS SQL (18456), OpenSSH;
  - IP, с которого было **5 и больше неудачных попыток за 7 дней**, блокирует в брандмауэре (правила `IPShield-Ban-N`);
  - раз в 5 минут обменивается данными с приватным репозиторием `ip-shield-data`: отправляет свои находки и забирает чужие. IP, забаненный на одном компьютере, банится на всех;
  - разрешает все входящие из локальной сети (правило `IPShield-LAN`, по умолчанию 192.168.0.0/16).
- **Ярлык «IP Shield»** на рабочем столе открывает окно мониторинга (запуск от администратора):
  - **Атаки**: IP, страна, служба и порт, число попыток, первая и последняя попытка, на каких компьютерах, какие логины пробовали, статус;
  - кнопки **Разбанить** и **В исключения** действуют сразу на всех компьютерах;
  - кнопка **Выгрузить забаненные** сохраняет на рабочий стол HTML-отчёт (с поиском и сортировкой) и TXT-список IP, по одному в строке;
  - **Исключения**: ваши IP и подсети, которые никогда не блокируются;
  - **Компьютеры**: какие компьютеры подключены, когда последний раз выходили на связь, включён ли брандмауэр;
  - **Журнал агента**.

Никогда не блокируются: локальные адреса, адреса из исключений, адреса, с которых за последние 30 дней был **успешный** вход по RDP на любой из компьютеров.

## Установка и обновление

PowerShell **от имени администратора** на нужном компьютере:

```powershell
[Net.ServicePointManager]::SecurityProtocol=3072; $IPShieldToken='github_pat_ВАШ_КЛЮЧ'; irm https://raw.githubusercontent.com/xackustul-spec/ip-shield/main/install.ps1 | iex
```

Обновить уже установленный компьютер — та же команда без ключа:

```powershell
[Net.ServicePointManager]::SecurityProtocol=3072; irm https://raw.githubusercontent.com/xackustul-spec/ip-shield/main/install.ps1 | iex
```

Ключ — fine-grained token GitHub с доступом **только** к репозиторию `ip-shield-data`, право **Contents: Read and write**. Он хранится в `C:\ProgramData\IPShield\config.json`, доступ к папке только у SYSTEM и администраторов.

## Удаление

PowerShell от имени администратора:

```powershell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\IPShield\uninstall.ps1
```

## Файлы

| Где | Что |
|---|---|
| `C:\ProgramData\IPShield\config.json` | настройки и ключ GitHub (порог, окно, локальная сеть) |
| `C:\ProgramData\IPShield\state.json` | местные данные агента |
| `C:\ProgramData\IPShield\view.json` | данные для окна мониторинга |
| `C:\ProgramData\IPShield\agent.log` | журнал агента |
| `ip-shield-data/hosts/<КОМПЬЮТЕР>.json` | что нашёл каждый компьютер |
| `ip-shield-data/control.json` | общие исключения и разбаны |

## Требования

Windows 10/11 или Windows Server 2016+ (PowerShell 5.1), включённый брандмауэр Windows. Страна определяется через бесплатный сервис ip-api.com.
