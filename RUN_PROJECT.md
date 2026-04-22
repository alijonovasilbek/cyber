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

## 4. API key

Frontend default API key:

```text
cyberguard-demo-key
```

Agar kerak bo'lsa brauzer console ichida:

```js
localStorage.setItem('cg_api_key', 'cyberguard-demo-key')
```

## 5. Safe demo notes

- Tarmoq skani faqat safe probing ishlatadi
- Traffic simulation real hujum yubormaydi
- WebSocket live loglar demo/education uchun
- Wi-Fi SSID ko'rinishi qurilmada real Wi-Fi adapter borligiga bog'liq

## 6. Common issue

`Tarmoq Skan` bo'sh chiqsa, odatda backend turmagan bo'ladi. Avval `http://127.0.0.1:8000/api/dashboard/` ochilib javob berayotganini tekshiring.
