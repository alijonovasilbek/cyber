# CyberGuard Run Guide

## 1. First-time setup

Project root ichida:

```bat
setup_project.bat
```

Bu skript quyidagilarni bajaradi:

- `backend/.venv` yaratadi
- backend dependency o'rnatadi
- `manage.py migrate` ishlatadi
- frontend dependency o'rnatadi

## 2. Start backend

```bat
start_backend.bat
```

Backend default:

- `http://127.0.0.1:8000`
- WebSocket: `ws://127.0.0.1:8000/ws/live`

## 3. Start frontend

```bat
start_frontend.bat
```

Frontend default:

- `http://127.0.0.1:5173`

## 3.1. Backend + frontend birga yoqish

```bat
start_all.bat
```

Bu skript:

- `start_backend.bat`
- `start_frontend.bat`

ni ketma-ket ishga tushiradi.

## 4. Local computer network scan

Agar sayt ochilgan kompyuterning o'z tarmog'ini scan qilmoqchi bo'lsangiz:

```bat
install_local_scan_protocol.bat
```

Bu faqat bir marta kerak bo'ladi.

Keyin:

```bat
start_local_agent.bat
```

Yoki bularning ikkalasini birga:

```bat
enable_local_scan.bat
```

Yoki saytdagi `RUN LOCAL SCAN` tugmasini bosing.

`Local agent` ishlasa, frontend `127.0.0.1:8765` orqali aynan shu kompyuterning:

- local IP va interface'lari
- Wi-Fi holati
- safe local network scan

ma'lumotlarini oladi.

Sayt ichida:

- `Tarmoq Skan` sahifasiga kiring
- yuqoridagi `RUN LOCAL SCAN` tugmasini bosing
- `LOCAL AGENT: ACTIVE` ko'rinsa scan shu kompyuterdan ishlaydi

## 5. API key

Frontend default API key:

```text
cyberguard-demo-key
```

Agar kerak bo'lsa brauzer console ichida:

```js
localStorage.setItem('cg_api_key', 'cyberguard-demo-key')
```

## 6. Kurs ishi uchun tavsiya oqim

1. `setup_project.bat`
2. `start_all.bat`
3. `enable_local_scan.bat`
4. brauzerda `http://127.0.0.1:5173`
5. `Tarmoq Skan -> RUN LOCAL SCAN`

## 7. Safe demo notes

- Tarmoq skani faqat safe probing ishlatadi
- Traffic simulation real hujum yubormaydi
- WebSocket live loglar demo/education uchun
- Wi-Fi SSID ko'rinishi qurilmada real Wi-Fi adapter borligiga bog'liq

## 8. Common issue

`Tarmoq Skan` bo'sh chiqsa, odatda backend turmagan bo'ladi. Avval `http://127.0.0.1:8000/api/dashboard/` ochilib javob berayotganini tekshiring.

## 9. Docker / AWS

Docker bilan:

```bat
docker_up.bat
```

To'xtatish:

```bat
docker_down.bat
```

Loglar:

```bat
docker_logs.bat
```

AWS uchun to'liq yo'riqnoma:

- `AWS_DEPLOY.md`

Muhim:

- AWS serverga deploy qilinganda oddiy scan server tarmog'ida ishlaydi
- saytni ochgan foydalanuvchi kompyuter tarmog'i uchun baribir `local agent` kerak
