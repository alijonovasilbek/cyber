"""
3 ta AI model: Random Forest, Neural Network (Sequential MLP), Isolation Forest.
Har model alohida saqlanadi va alohida bashorat qiladi.
"""
import json
import os
import pickle
import logging
import numpy as np
from pathlib import Path
from collections import Counter

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score,
    recall_score, roc_auc_score, confusion_matrix,
)

logger = logging.getLogger(__name__)

WINDOW_SIZE  = 12
MODEL_DIR    = Path(__file__).parent / 'saved_models'
RESULTS_FILE = MODEL_DIR / 'multi_model_results.json'
MODEL_DIR.mkdir(exist_ok=True)

LABELS = ['normal', 'brute_force', 'port_scan', 'anomaly']
FEATURE_KEYS = [
    'failed_logins', 'success_logins', 'new_processes',
    'policy_changes', 'service_events', 'tcp_connections', 'running_processes',
]


# ── Yordamchi funksiyalar ──────────────────────────────────────────────────

def _paths(name: str) -> dict:
    return {
        'model':   MODEL_DIR / f'{name}_model.pkl',
        'scaler':  MODEL_DIR / f'{name}_scaler.pkl',
        'encoder': MODEL_DIR / f'{name}_encoder.pkl',
    }


def _load_windows():
    from lab.models import LogWindow
    return list(LogWindow.objects.order_by('timestamp').values(*FEATURE_KEYS, 'label'))


def _single_X_y(windows):
    X = np.array([[float(w[k]) for k in FEATURE_KEYS] for w in windows], dtype=np.float32)
    y = [w['label'] for w in windows]
    return X, y


def _sequence_X_y(windows, ws=WINDOW_SIZE):
    X, y = [], []
    for i in range(ws, len(windows)):
        flat = [float(windows[i - ws + j][k]) for j in range(ws) for k in FEATURE_KEYS]
        X.append(flat)
        y.append(windows[i]['label'])
    return np.array(X, dtype=np.float32), y


def _standard_le():
    le = LabelEncoder()
    le.fit(LABELS)
    return le


def _per_class(y_true, y_pred, le):
    classes = list(le.classes_)
    n = len(classes)
    p = precision_score(y_true, y_pred, average=None, zero_division=0, labels=range(n))
    r = recall_score(y_true, y_pred, average=None, zero_division=0, labels=range(n))
    f = f1_score(y_true, y_pred, average=None, zero_division=0, labels=range(n))
    return {cls: {'precision': round(float(p[i]), 4),
                  'recall':    round(float(r[i]), 4),
                  'f1':        round(float(f[i]), 4)}
            for i, cls in enumerate(classes)}


def _base_metrics(y_test, y_pred, y_prob, le):
    acc  = accuracy_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    rec  = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    cm   = confusion_matrix(y_test, y_pred, labels=range(len(le.classes_))).tolist()
    roc  = None
    if y_prob is not None:
        try:
            roc = float(roc_auc_score(y_test, y_prob, multi_class='ovr', average='weighted'))
        except Exception:
            pass
    return {
        'accuracy':         round(float(acc),  4),
        'f1':               round(float(f1),   4),
        'precision':        round(float(prec), 4),
        'recall':           round(float(rec),  4),
        'roc_auc':          round(roc, 4) if roc else None,
        'confusion_matrix': cm,
        'classes':          list(le.classes_),
        'per_class':        _per_class(y_test, y_pred, le),
    }


# ── Model 1: Random Forest ─────────────────────────────────────────────────

def train_rf(windows) -> dict:
    logger.info("Random Forest o'qitilmoqda...")
    p = _paths('rf')
    X, y = _single_X_y(windows)
    le = _standard_le()
    y_enc = le.transform(y)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)

    model = RandomForestClassifier(
        n_estimators=200, max_depth=15, random_state=42,
        n_jobs=-1, class_weight='balanced',
    )
    model.fit(X_tr_s, y_tr)

    y_pred = model.predict(X_te_s)
    y_prob = model.predict_proba(X_te_s)

    metrics = _base_metrics(y_te, y_pred, y_prob, le)
    metrics['train_rows'] = len(X_tr)
    metrics['test_rows']  = len(X_te)
    metrics['feature_importance'] = {
        name: round(float(imp) * 100, 2)
        for name, imp in sorted(
            zip(FEATURE_KEYS, model.feature_importances_),
            key=lambda x: x[1], reverse=True,
        )
    }

    with open(p['model'],   'wb') as f: pickle.dump(model,  f)
    with open(p['scaler'],  'wb') as f: pickle.dump(scaler, f)
    with open(p['encoder'], 'wb') as f: pickle.dump(le,     f)

    logger.info("RF: acc=%.3f f1=%.3f", metrics['accuracy'], metrics['f1'])
    return metrics


def predict_rf(window_dict: dict) -> dict:
    p = _paths('rf')
    with open(p['model'],   'rb') as f: model  = pickle.load(f)
    with open(p['scaler'],  'rb') as f: scaler = pickle.load(f)
    with open(p['encoder'], 'rb') as f: le     = pickle.load(f)

    X = np.array([[float(window_dict.get(k, 0)) for k in FEATURE_KEYS]])
    X_s = scaler.transform(X)
    idx   = model.predict(X_s)[0]
    proba = model.predict_proba(X_s)[0]
    label = le.inverse_transform([idx])[0]
    return {
        'label':         label,
        'confidence':    round(float(proba.max()), 4),
        'probabilities': {cls: round(float(p_), 4)
                          for cls, p_ in zip(le.classes_, proba)},
    }


# ── Model 2: Neural Network (Ketma-ket MLP) ──────────────────────────────

def train_nn(windows) -> dict:
    logger.info("Neural Network o'qitilmoqda (sliding window=%d)...", WINDOW_SIZE)
    p = _paths('nn')
    X, y = _sequence_X_y(windows, WINDOW_SIZE)

    if len(X) < WINDOW_SIZE + 20:
        raise ValueError(f"Kam ma'lumot: {len(X)} ta namuna. Kamida {WINDOW_SIZE + 20} kerak.")

    le = _standard_le()
    y_enc = le.transform(y)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)

    model = MLPClassifier(
        hidden_layer_sizes=(256, 128, 64),
        activation='relu', solver='adam',
        max_iter=500, early_stopping=True,
        validation_fraction=0.1, random_state=42,
        verbose=False,
    )
    model.fit(X_tr_s, y_tr)

    y_pred = model.predict(X_te_s)
    y_prob = model.predict_proba(X_te_s)

    metrics = _base_metrics(y_te, y_pred, y_prob, le)
    metrics['train_rows'] = len(X_tr)
    metrics['test_rows']  = len(X_te)
    metrics['window_size'] = WINDOW_SIZE
    metrics['n_iter']      = model.n_iter_

    with open(p['model'],   'wb') as f: pickle.dump(model,  f)
    with open(p['scaler'],  'wb') as f: pickle.dump(scaler, f)
    with open(p['encoder'], 'wb') as f: pickle.dump(le,     f)

    logger.info("NN: acc=%.3f f1=%.3f iter=%d", metrics['accuracy'], metrics['f1'], model.n_iter_)
    return metrics


def predict_nn(recent_windows: list) -> dict:
    p = _paths('nn')
    with open(p['model'],   'rb') as f: model  = pickle.load(f)
    with open(p['scaler'],  'rb') as f: scaler = pickle.load(f)
    with open(p['encoder'], 'rb') as f: le     = pickle.load(f)

    if len(recent_windows) < WINDOW_SIZE:
        raise ValueError(f"Kamida {WINDOW_SIZE} ta oyna kerak")

    seq  = recent_windows[-WINDOW_SIZE:]
    flat = [float(w.get(k, 0)) for w in seq for k in FEATURE_KEYS]
    X    = scaler.transform([flat])
    idx  = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    label = le.inverse_transform([idx])[0]
    return {
        'label':         label,
        'confidence':    round(float(proba.max()), 4),
        'probabilities': {cls: round(float(p_), 4)
                          for cls, p_ in zip(le.classes_, proba)},
    }


# ── Model 3: Isolation Forest ─────────────────────────────────────────────

def train_iso(windows) -> dict:
    logger.info("Isolation Forest o'qitilmoqda...")
    p = _paths('iso')
    X, y = _single_X_y(windows)
    le = _standard_le()
    y_enc = le.transform(y)

    scaler = StandardScaler()
    X_s = scaler.fit_transform(X)

    # Faqat normal data da o'qitish (haqiqiy unsupervised)
    normal_mask = np.array([lbl == 'normal' for lbl in y])
    X_normal = X_s[normal_mask] if normal_mask.sum() >= 10 else X_s

    model = IsolationForest(
        n_estimators=200, contamination=0.3,
        random_state=42, n_jobs=-1,
    )
    model.fit(X_normal)

    # Baholash: -1 (anomaliya) → hujum turi, 1 → normal
    preds    = model.predict(X_s)
    scores   = model.decision_function(X_s)
    y_pred_labels = []
    for i, (pred, window) in enumerate(zip(preds, windows)):
        if pred == 1:
            y_pred_labels.append('normal')
        else:
            failed = float(window.get('failed_logins', 0))
            tcp    = float(window.get('tcp_connections', 0))
            procs  = float(window.get('new_processes', 0))
            if failed > 15:
                y_pred_labels.append('brute_force')
            elif tcp > 150:
                y_pred_labels.append('port_scan')
            elif procs > 12:
                y_pred_labels.append('anomaly')
            else:
                y_pred_labels.append('anomaly')

    y_pred_enc = le.transform(y_pred_labels)
    metrics = _base_metrics(y_enc, y_pred_enc, None, le)
    metrics['train_rows'] = int(normal_mask.sum())
    metrics['test_rows']  = len(X)
    metrics['normal_trained_on'] = int(normal_mask.sum())

    with open(p['model'],   'wb') as f: pickle.dump(model,  f)
    with open(p['scaler'],  'wb') as f: pickle.dump(scaler, f)
    with open(p['encoder'], 'wb') as f: pickle.dump(le,     f)

    logger.info("ISO: acc=%.3f f1=%.3f", metrics['accuracy'], metrics['f1'])
    return metrics


def predict_iso(window_dict: dict) -> dict:
    p = _paths('iso')
    with open(p['model'],   'rb') as f: model  = pickle.load(f)
    with open(p['scaler'],  'rb') as f: scaler = pickle.load(f)
    with open(p['encoder'], 'rb') as f: le     = pickle.load(f)

    X   = np.array([[float(window_dict.get(k, 0)) for k in FEATURE_KEYS]])
    X_s = scaler.transform(X)
    pred  = model.predict(X_s)[0]
    score = float(model.decision_function(X_s)[0])

    # score < 0 → anomaliya, > 0 → normal
    anomaly_prob = max(0.0, min(1.0, -score + 0.5))

    if pred == 1:
        label      = 'normal'
        confidence = round(1.0 - anomaly_prob, 4)
    else:
        failed = float(window_dict.get('failed_logins', 0))
        tcp    = float(window_dict.get('tcp_connections', 0))
        procs  = float(window_dict.get('new_processes', 0))
        if failed > 15:
            label = 'brute_force'
        elif tcp > 150:
            label = 'port_scan'
        elif procs > 12:
            label = 'anomaly'
        else:
            label = 'anomaly'
        confidence = round(anomaly_prob, 4)

    norm_p = round(1.0 - anomaly_prob, 4)
    att_p  = round(anomaly_prob / 3, 4)
    probs  = {
        'normal':      norm_p,
        'brute_force': att_p if label == 'brute_force' else 0.0,
        'port_scan':   att_p if label == 'port_scan'   else 0.0,
        'anomaly':     att_p if label == 'anomaly'     else 0.0,
    }
    return {
        'label':         label,
        'confidence':    confidence,
        'probabilities': probs,
        'anomaly_score': round(score, 4),
        'is_anomaly':    pred == -1,
    }


# ── Barcha modellarni o'qitish ─────────────────────────────────────────────

def train_all(session_id=None) -> dict:
    from lab.models import TrainSession

    session = None
    if session_id:
        try:
            session = TrainSession.objects.get(pk=session_id)
            session.status = 'running'
            session.save(update_fields=['status'])
        except TrainSession.DoesNotExist:
            pass

    windows = _load_windows()
    if len(windows) < WINDOW_SIZE + 20:
        err = f"Kam ma'lumot: {len(windows)} ta yozuv. Kamida {WINDOW_SIZE + 20} kerak."
        if session:
            session.status = 'failed'
            session.error_msg = err
            session.save()
        raise ValueError(err)

    results = {}
    errors  = {}

    for name, fn in [('rf', train_rf), ('nn', train_nn), ('iso', train_iso)]:
        try:
            results[name] = fn(windows)
        except Exception as e:
            logger.error("%s xatosi: %s", name, e)
            errors[name] = str(e)

    # Natijalarni faylga saqlash
    save_results(results)

    # TrainSession ni RF natijalari bilan yangilash
    if session:
        m = results.get('rf') or results.get('nn') or results.get('iso') or {}
        session.status    = 'done'
        session.accuracy  = m.get('accuracy')
        session.f1        = m.get('f1')
        session.precision = m.get('precision')
        session.recall    = m.get('recall')
        session.roc_auc   = m.get('roc_auc')
        session.train_rows = m.get('train_rows', 0)
        session.confusion_matrix = m.get('confusion_matrix')
        session.classes   = m.get('classes')
        session.per_class = {
            '_multi': results,
            **(m.get('per_class') or {}),
        }
        session.save()

    return {'results': results, 'errors': errors}


# ── Barcha modellar bilan bashorat ─────────────────────────────────────────

def predict_all(window_dict: dict, recent_windows: list | None = None) -> dict:
    out = {}
    for name, fn, needs_seq in [
        ('rf',  predict_rf,  False),
        ('nn',  predict_nn,  True),
        ('iso', predict_iso, False),
    ]:
        p = _paths(name)
        if not p['model'].exists():
            out[name] = {'error': "Model o'qitilmagan"}
            continue
        try:
            if needs_seq:
                if not recent_windows or len(recent_windows) < WINDOW_SIZE:
                    out[name] = {'error': f'Kamida {WINDOW_SIZE} ta oyna kerak'}
                else:
                    out[name] = fn(recent_windows)
            else:
                out[name] = fn(window_dict)
        except Exception as e:
            out[name] = {'error': str(e)}
    return out


# ── Modellar holati ────────────────────────────────────────────────────────

def models_status() -> dict:
    saved = load_results()
    status = {}
    for name in ('rf', 'nn', 'iso'):
        p = _paths(name)
        trained = p['model'].exists()
        metrics = saved.get(name, {}) if trained else {}
        status[name] = {
            'trained':  trained,
            'accuracy': metrics.get('accuracy'),
            'f1':       metrics.get('f1'),
            'precision': metrics.get('precision'),
            'recall':   metrics.get('recall'),
            'roc_auc':  metrics.get('roc_auc'),
            'train_rows': metrics.get('train_rows'),
            'confusion_matrix': metrics.get('confusion_matrix'),
            'classes':  metrics.get('classes'),
            'per_class': metrics.get('per_class'),
            'feature_importance': metrics.get('feature_importance'),
        }
    return status


# ── Natijalarni diskka saqlash / yuklash ────────────────────────────────────

def save_results(results: dict):
    try:
        with open(RESULTS_FILE, 'w') as f:
            json.dump(results, f, default=str)
    except Exception as e:
        logger.warning("Natijalarni saqlashda xato: %s", e)


def load_results() -> dict:
    try:
        if RESULTS_FILE.exists():
            with open(RESULTS_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}
