# CyberGuard AI — O'rnatish va Ishga Tushirish

## Loyiha tuzilmasi
```
cyberguard/
├── backend/          ← Django + DRF
│   ├── cyberguard/   ← sozlamalar, URL lar
│   ├── threats/      ← models, views, services, serializers
│   ├── manage.py
│   └── requirements.txt
└── frontend/
    └── src/
        ├── App.jsx           ← asosiy komponent
        ├── services/api.js   ← barcha API chaqiruvlar
        └── components/
            └── NetworkScan.jsx
```

---

## 1. Backend (Django DRF) — o'rnatish

```bash
cd cyberguard/backend

# Virtual muhit yaratish
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# Paketlarni o'rnatish
pip install -r requirements.txt

# Migratsiyalar
python manage.py makemigrations
python manage.py migrate

# Admin foydalanuvchi (ixtiyoriy)
python manage.py createsuperuser

# Serverni ishga tushirish
python manage.py runserver
```

Backend: http://localhost:8000

---

## 2. Frontend (React) — o'rnatish

```bash
cd cyberguard/frontend

# React loyiha yaratish (birinchi marta)
npm create vite@latest . -- --template react
# Keyin fayllarni almashtiring

# Paketlarni o'rnatish
npm install

# Serverni ishga tushirish
npm run dev
```

Frontend: http://localhost:5173

---

## 3. API Endpointlar

| Method | URL                        | Vazifa                          |
|--------|----------------------------|---------------------------------|
| GET    | /api/dashboard/            | Dashboard statistikasi          |
| POST   | /api/analyze/              | IP tahdid tahlili               |
| GET    | /api/network/scan/         | Local tarmoq skanerlash         |
| GET    | /api/reputation/<ip>/      | IP reputatsiyasi (AbuseIPDB)    |
| GET    | /api/logs/live/            | Real vaqt loglar                |
| GET    | /api/threats/              | Barcha tahdid loglari           |
| POST   | /api/threats/<id>/block/   | IP ni bloklash                  |
| GET    | /api/blocked/              | Bloklangan IP lar               |

---

## 4. Local IP demo ro'yxati (settings.py)

Siz o'z tarmoqingizga mos IP lar qo'shishingiz mumkin:

```python
LOCAL_DEMO_IPS = {
    '192.168.1.1':   {'name': 'Router',         'risk': 'low'},
    '192.168.1.200': {'name': 'Shubhali PC',     'risk': 'high'},
    '10.0.0.10':     {'name': 'Web Server',      'risk': 'medium'},
    # ... o'zingiznikini qo'shing
}
```

---

## 5. AbuseIPDB (haqiqiy public IP tekshirish)

1. https://www.abuseipdb.com → bepul ro'yxatdan o'ting
2. API key oling
3. `settings.py` ga kiriting:

```python
ABUSEIPDB_API_KEY = 'sizning_api_keyingiz'
```

Yoki environment variable:
```bash
export ABUSEIPDB_API_KEY="sizning_api_keyingiz"
python manage.py runserver
```

---

## 6. Tahlil qilish — POST /api/analyze/

```json
{
  "ip_address": "192.168.1.200",
  "threat_type": "brute_force",
  "algorithms": ["Random Forest", "XGBoost", "LSTM"],
  "context": "SSH portiga ko'p urinish"
}
```

Javob:
```json
{
  "ip": "192.168.1.200",
  "ip_info": {
    "is_local": true,
    "device_name": "Shubhali qurilma",
    "network_type": "LAN (uy/ofis tarmoqi)"
  },
  "threat_name": "Brute Force",
  "probability": 0.923,
  "probability_pct": "92.3%",
  "severity": "critical",
  "indicators": ["Ko'p muvaffaqiyatsiz login", "SSH/RDP portlari"],
  "mitigation": ["IP ni 24 soat bloklang", "Fail2ban sozlang", "2FA yoqing"],
  "algorithm_scores": {
    "Random Forest": 0.891,
    "XGBoost": 0.903,
    "LSTM": 0.887
  }
}
```

---

## BMI uchun demo qadamlar

1. `python manage.py runserver` — backend ishga tushiring
2. `npm run dev` — frontend ishga tushiring
3. **Network Scan** sahifasida local IP lar ko'rinadi
4. Istalgan IP ni bosib **"Tahlil qilish"** tugmasini bosing
5. **IP Tahlil** sahifasida algoritmlarni tanlang va natijani ko'ring
6. **Live Loglar** sahifasida real vaqt oqimini ko'ring
