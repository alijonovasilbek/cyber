"""
SQL Injection simulyatori.
Haqiqiy DB ga hujum qilmaydi — so'rov payloadlaridan ML feature ajratadi.
"""
import math
import random

# ── HUJUM PAYLOADI ────────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "admin'--",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "\" OR \"\"=\"",
    "' OR 2>1--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 10--",
    "1 GROUP BY 1",
    "' HAVING 1=1--",
    "1; DROP TABLE users;--",
    "1'; DROP TABLE orders;--",
    "'; INSERT INTO users(name,pass) VALUES('hacker','1234');--",
    "' AND SLEEP(5)--",
    "1' AND SLEEP(3)#",
    "' OR SLEEP(5)='",
    "'; EXEC xp_cmdshell('whoami');--",
    "'; EXEC sp_configure 'show advanced',1--",
    "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--",
    "' AND ASCII(SUBSTRING(username,1,1))>64--",
    "1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
    "' AND 1=2 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
    "1/**/OR/**/1=1",
    "1' /*!UNION*/ SELECT NULL--",
    "' OR 0x61646d696e='admin'--",
    "CHAR(39) OR CHAR(49)=CHAR(49)",
]

# ── NORMAL SO'ROVLAR ──────────────────────────────────────────────────────────
NORMAL_QUERIES = [
    "id=1", "id=42", "id=1000",
    "name=John", "name=Alice", "name=Bob Smith",
    "search=laptop", "search=phone+case", "search=red+shoes",
    "category=electronics", "category=books", "category=clothing",
    "price=100", "price=49.99", "price=250",
    "page=1", "page=2", "page=10",
    "sort=asc", "sort=desc", "sort=price",
    "filter=active", "filter=new", "filter=sale",
    "brand=Samsung", "brand=Apple", "brand=Nike",
    "color=red", "color=blue+white", "color=dark+green",
    "type=premium", "type=standard",
    "status=active", "status=pending",
    "code=ABC123", "code=PROMO2024",
    "date=2024-01-15", "date=2024-12-01",
    "q=hello+world", "q=how+to+code",
    "limit=10", "limit=25", "offset=0", "offset=50",
    "order=created_at", "order=updated_at",
    "user=admin", "user=john_doe",
    "product=12345", "product=SKU-789",
    "email=user%40example.com",
    "lang=en", "lang=uz", "lang=ru",
]

# SQL kalit so'zlar ro'yxati
SQL_KEYWORDS = [
    'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
    'FROM', 'WHERE', 'AND', 'OR', 'NULL', 'EXEC', 'EXECUTE', 'SLEEP',
    'HAVING', 'ORDER', 'GROUP', 'SUBSTRING', 'CONVERT', 'CAST', 'CHAR',
    'CONCAT', 'INFORMATION_SCHEMA', 'SYSOBJECTS', 'XP_CMDSHELL', 'SP_',
    'EXISTS', 'ASCII', 'BENCHMARK', 'WAITFOR', 'DELAY', 'INTO', 'OUTFILE',
]

COMMENT_MARKERS = ['--', '#', '/*', '*/', '/*!']
SPECIAL_CHARS   = set("'\"`;-()=<>\\/*@")


def _entropy(text: str) -> float:
    """Shannon entropiyasi — yuqori = tasodifiy/kriptografik belgilar."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return round(-sum((f / n) * math.log2(f / n) for f in freq.values()), 4)


def extract_features(payload: str) -> dict:
    """Payloaddan ML feature ajratish."""
    p_low = payload.lower()

    special_count = sum(1 for c in payload if c in SPECIAL_CHARS)
    kw_count = sum(1 for kw in SQL_KEYWORDS if kw.lower() in p_low)
    comment   = int(any(m in payload for m in COMMENT_MARKERS))
    digit_count = sum(1 for c in payload if c.isdigit())

    return {
        'payload_length':       len(payload),
        'special_char_count':   special_count,
        'sql_keyword_count':    kw_count,
        'entropy':              _entropy(payload),
        'has_comment':          comment,
        'has_union':            int('union' in p_low),
        'has_select':           int('select' in p_low),
        'has_drop_delete':      int('drop' in p_low or 'delete' in p_low),
        'has_sleep_exec':       int('sleep' in p_low or 'exec' in p_low or 'xp_' in p_low or 'waitfor' in p_low),
        'quote_count':          payload.count("'") + payload.count('"'),
        'numeric_ratio':        round(digit_count / max(len(payload), 1), 4),
        'space_count':          payload.count(' ') + payload.count('+') + payload.count('%20'),
    }


def simulate(mode='normal', count=100):
    """
    SQL Injection training data generatsiya qilish.

    Parametrlar:
        mode:  'normal' | 'attack' | 'mixed'
        count: nechta namuna (max 2000)

    Qaytaradi:
        list[dict] — feature + label + payload_preview
    """
    samples = []

    for _ in range(min(count, 2000)):
        if mode == 'normal':
            payload = random.choice(NORMAL_QUERIES)
            label = 0
        elif mode == 'attack':
            payload = random.choice(SQLI_PAYLOADS)
            label = 1
        else:  # mixed
            if random.random() > 0.5:
                payload = random.choice(SQLI_PAYLOADS)
                label = 1
            else:
                payload = random.choice(NORMAL_QUERIES)
                label = 0

        features = extract_features(payload)
        features['label'] = label
        features['payload_preview'] = payload[:60]
        samples.append(features)

    return samples


# Feature nomlari (ML uchun tartib muhim)
FEATURE_NAMES = [
    'payload_length', 'special_char_count', 'sql_keyword_count',
    'entropy', 'has_comment', 'has_union', 'has_select',
    'has_drop_delete', 'has_sleep_exec', 'quote_count',
    'numeric_ratio', 'space_count',
]
