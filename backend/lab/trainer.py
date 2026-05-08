"""
Sliding-window Neural Network trainer.

Arxitektura:
  Input:  oxirgi WINDOW_SIZE ta LogWindow → yassi vektor
          (WINDOW_SIZE × n_features = 12 × 7 = 84 ta xususiyat)
  Hidden: 128 → 64 neyrоn (ReLU)
  Output: 4 klass (normal, brute_force, port_scan, anomaly)

Bu yondashuv LSTM ning vaqt-ketma-ketlik g'oyasini
sklearn MLP orqali ifodalaydi.
"""

import os
import pickle
import logging
import numpy as np
from pathlib import Path
from collections import Counter

from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score,
    recall_score, roc_auc_score, confusion_matrix,
    classification_report,
)

logger = logging.getLogger(__name__)

WINDOW_SIZE  = 12          # 12 × 5 daqiqa = 1 soatlik tarix
MODEL_DIR    = Path(__file__).parent / 'saved_models'
MODEL_PATH   = MODEL_DIR / 'threat_model.pkl'
SCALER_PATH  = MODEL_DIR / 'scaler.pkl'
ENCODER_PATH = MODEL_DIR / 'label_encoder.pkl'

LABELS = ['normal', 'brute_force', 'port_scan', 'anomaly']


# ── Dataset tayyorlash ────────────────────────────────────────────────────

def load_windows_from_db():
    """DB dan barcha LogWindow larni vaqt bo'yicha tartiblab qaytaradi."""
    from lab.models import LogWindow
    qs = LogWindow.objects.order_by('timestamp').values(
        'failed_logins', 'success_logins', 'new_processes',
        'policy_changes', 'service_events', 'tcp_connections',
        'running_processes', 'label',
    )
    return list(qs)


def build_sequences(windows: list, window_size: int = WINDOW_SIZE):
    """
    Sliding window: har bir nuqta uchun oxirgi `window_size` ta
    yozuvni input, keyingi yozuvning label ini output qilib oladi.

    Qaytaradi: (X np.array shape [N, window_size*n_features], y list)
    """
    feature_keys = [
        'failed_logins', 'success_logins', 'new_processes',
        'policy_changes', 'service_events', 'tcp_connections', 'running_processes',
    ]
    X, y = [], []

    for i in range(window_size, len(windows)):
        seq = windows[i - window_size: i]
        flat = []
        for w in seq:
            flat.extend([w[k] for k in feature_keys])
        X.append(flat)
        y.append(windows[i]['label'])

    return np.array(X, dtype=np.float32), y


# ── Train ─────────────────────────────────────────────────────────────────

def train(session_id: int | None = None) -> dict:
    """
    DB dagi barcha LogWindow lardan model o'qitadi.
    Natijalarni TrainSession ga yozadi (session_id berilsa).

    Qaytaradi: metrikalar dict
    """
    from lab.models import TrainSession

    session = None
    if session_id:
        try:
            session = TrainSession.objects.get(pk=session_id)
            session.status = 'running'
            session.save(update_fields=['status'])
        except TrainSession.DoesNotExist:
            pass

    try:
        windows = load_windows_from_db()
        if len(windows) < WINDOW_SIZE + 10:
            raise ValueError(f"Kam ma'lumot: {len(windows)} ta yozuv. Kamida {WINDOW_SIZE + 10} kerak.")

        X, y = build_sequences(windows, WINDOW_SIZE)
        logger.info("Dataset: %d namuna, %d feature", len(X), X.shape[1])

        label_dist = Counter(y)
        logger.info("Label taqsimoti: %s", dict(label_dist))

        # Encode labels
        le = LabelEncoder()
        le.fit(LABELS)
        y_enc = le.transform(y)

        # Train/val/test: 70 / 15 / 15
        X_tv, X_test, y_tv, y_test = train_test_split(X, y_enc, test_size=0.15, random_state=42, stratify=y_enc)
        X_train, X_val, y_train, y_val = train_test_split(X_tv, y_tv, test_size=0.176, random_state=42, stratify=y_tv)

        # Scale
        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_val_s   = scaler.transform(X_val)
        X_test_s  = scaler.transform(X_test)

        # Model
        model = MLPClassifier(
            hidden_layer_sizes=(128, 64),
            activation='relu',
            solver='adam',
            max_iter=300,
            early_stopping=True,
            validation_fraction=0.1,
            random_state=42,
            verbose=False,
        )
        model.fit(X_train_s, y_train)

        # Metrikalar
        y_pred      = model.predict(X_test_s)
        y_pred_prob = model.predict_proba(X_test_s)

        acc       = accuracy_score(y_test, y_pred)
        f1        = f1_score(y_test, y_pred, average='weighted')
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall    = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        try:
            roc = roc_auc_score(y_test, y_pred_prob, multi_class='ovr', average='weighted')
        except Exception:
            roc = None

        cm = confusion_matrix(y_test, y_pred).tolist()
        logger.info("Accuracy=%.3f F1=%.3f Precision=%.3f Recall=%.3f ROC=%.3f",
                    acc, f1, precision, recall, roc or 0)

        # Har label uchun alohida metrikalar
        p_per = precision_score(y_test, y_pred, average=None, zero_division=0)
        r_per = recall_score(y_test, y_pred, average=None, zero_division=0)
        f_per = f1_score(y_test, y_pred, average=None, zero_division=0)
        per_class = {
            cls: {
                'precision': round(float(p_per[i]), 4),
                'recall':    round(float(r_per[i]), 4),
                'f1':        round(float(f_per[i]), 4),
            }
            for i, cls in enumerate(le.classes_)
        }

        # Saqlash
        MODEL_DIR.mkdir(exist_ok=True)
        with open(MODEL_PATH,   'wb') as f: pickle.dump(model,  f)
        with open(SCALER_PATH,  'wb') as f: pickle.dump(scaler, f)
        with open(ENCODER_PATH, 'wb') as f: pickle.dump(le,     f)

        metrics = {
            'accuracy':    round(acc, 4),
            'f1':          round(f1, 4),
            'precision':   round(precision, 4),
            'recall':      round(recall, 4),
            'roc_auc':     round(roc, 4) if roc else None,
            'train_rows':  len(X_train),
            'test_rows':   len(X_test),
            'confusion_matrix': cm,
            'classes':     list(le.classes_),
            'per_class':   per_class,
            'model_path':  str(MODEL_PATH),
        }

        if session:
            session.status           = 'done'
            session.accuracy         = acc
            session.f1               = f1
            session.precision        = precision
            session.recall           = recall
            session.roc_auc          = roc
            session.train_rows       = len(X_train)
            session.model_path       = str(MODEL_PATH)
            session.confusion_matrix = cm
            session.classes          = list(le.classes_)
            session.per_class        = per_class
            session.save()

        return metrics

    except Exception as exc:
        logger.error("Train xatosi: %s", exc)
        if session:
            session.status    = 'failed'
            session.error_msg = str(exc)
            session.save()
        raise


# ── Predict ───────────────────────────────────────────────────────────────

def load_model():
    """Saqlangan model, scaler, encoder ni yuklaydi."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError("Model topilmadi. Avval train qiling.")
    with open(MODEL_PATH,   'rb') as f: model  = pickle.load(f)
    with open(SCALER_PATH,  'rb') as f: scaler = pickle.load(f)
    with open(ENCODER_PATH, 'rb') as f: le     = pickle.load(f)
    return model, scaler, le


def predict_next(recent_windows: list) -> dict:
    """
    Oxirgi WINDOW_SIZE ta LogWindow dict laridan keyingi
    5 daqiqadagi tahdid ehtimollarini bashorat qiladi.

    recent_windows: list of dicts (har biri feature_keys larni o'z ichiga oladi)

    Qaytaradi:
      {
        'label': 'brute_force',
        'probabilities': {'normal': 0.05, 'brute_force': 0.82, ...},
        'confidence': 0.82,
      }
    """
    if len(recent_windows) < WINDOW_SIZE:
        raise ValueError(f"Kamida {WINDOW_SIZE} ta oyna kerak, {len(recent_windows)} ta berildi")

    model, scaler, le = load_model()

    feature_keys = [
        'failed_logins', 'success_logins', 'new_processes',
        'policy_changes', 'service_events', 'tcp_connections', 'running_processes',
    ]

    seq = recent_windows[-WINDOW_SIZE:]
    flat = []
    for w in seq:
        flat.extend([w.get(k, 0) for k in feature_keys])

    X = scaler.transform([flat])
    pred_idx  = model.predict(X)[0]
    pred_prob = model.predict_proba(X)[0]

    label = le.inverse_transform([pred_idx])[0]
    probs = {cls: round(float(p), 4) for cls, p in zip(le.classes_, pred_prob)}

    return {
        'label':         label,
        'probabilities': probs,
        'confidence':    round(float(pred_prob.max()), 4),
    }


if __name__ == '__main__':
    import django, os, sys
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberguard.settings')
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    django.setup()

    print("Model o'qitilmoqda...")
    metrics = train()
    print(f"\n{'='*40}")
    print(f"  Accuracy  : {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.1f}%)")
    print(f"  F1        : {metrics['f1']:.4f}")
    print(f"  Precision : {metrics['precision']:.4f}")
    print(f"  Recall    : {metrics['recall']:.4f}")
    if metrics['roc_auc']:
        print(f"  ROC-AUC   : {metrics['roc_auc']:.4f}")
    print(f"  Train rows: {metrics['train_rows']}")
    print(f"  Test rows : {metrics['test_rows']}")
    print(f"{'='*40}")
    print(f"\nConfusion Matrix ({metrics['classes']}):")
    for row in metrics['confusion_matrix']:
        print(' ', row)
    print(f"\nModel saqlandi: {metrics['model_path']}")
