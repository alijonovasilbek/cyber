# CyberGuard AWS Deploy

## 1. Clone

```bash
git clone https://github.com/alijonovasilbek/cyber.git
cd cyber
cp .env.example .env
```

`.env` ichida kamida quyidagilarni to'g'rilang:

- `POSTGRES_PASSWORD`
- `SECRET_KEY`
- `ALLOWED_HOSTS`
- `CORS_ALLOWED_ORIGINS`
- `CSRF_TRUSTED_ORIGINS`
- `CYBERGUARD_API_KEY`

## 2. Docker bilan ishga tushirish

```bash
docker compose up --build -d
```

Ochiladigan portlar:

- frontend: `80`
- backend api: `8000`

## 3. Tekshirish

```bash
docker compose ps
docker compose logs backend --tail 100
docker compose logs frontend --tail 100
```

Brauzer:

- `http://YOUR_SERVER_IP/`
- `http://YOUR_SERVER_IP:8000/api/dashboard/`

## 4. Muhim izoh

AWS serverga deploy qilsangiz:

- oddiy backend network scan server ulangan tarmoqni ko'radi
- foydalanuvchi kompyuterining lokal Wi-Fi/tarmog'ini ko'rish uchun `local agent` kerak

Ya'ni:

- server-side scan -> AWS yoki server tarmog'i
- local agent scan -> sayt ochilgan Windows kompyuteri tarmog'i

## 5. Local agent haqida

`local agent` Docker ichida emas. U foydalanuvchi Windows kompyuterida alohida ishga tushadi:

- `install_local_scan_protocol.bat`
- `start_local_agent.bat`

Yoki sayt ichida `RUN LOCAL SCAN`.
