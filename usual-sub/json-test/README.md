# JSON test space (GitHub only)

Это изолированный эксперимент внутри репозитория LIKVID-VPN. Он добавляет **один JSON-файл** `usual-sub/json-test/config.json` с узлами и `urltest`-балансировщиком sing-box.

- Основной парсер в `usual-sub/legacy/` не изменён.
- `usual-sub/legacy/proxies.txt`, `parsed_proxies.txt` и `dead.txt` не перезаписываются этим экспериментом.
- MosHub не обновляется и не получает никаких файлов из этой папки.
- Для источников используется существующий список `usual-sub/legacy/proxy_sources.txt` и функции извлечения/фильтрации существующего парсера.
- В JSON попадают только URI, которые удалось преобразовать в поддерживаемые sing-box outbounds. Неподдерживаемые или некорректные URI пропускаются; если не удалось собрать ни одного узла, старый JSON не перезаписывается.

## Ручной запуск локально

Из корня репозитория:

```bash
python usual-sub/json-test/build_json.py
```

Сгенерированный `config.json` — это **sing-box JSON-конфигурация**, а не текстовая подписка и не универсальный JSON для любого клиента. Включает TUN inbound и `urltest` с проверкой доступности каждые 5 минут. Импортируйте только в клиенте, совместимом с форматом sing-box config.

## GitHub Actions

Workflow `.github/workflows/update-json-test.yml` запускается вручную или раз в 6 часов. Он изменяет и коммитит только `usual-sub/json-test/config.json`. Существующий workflow обычной подписки не заменяется.
