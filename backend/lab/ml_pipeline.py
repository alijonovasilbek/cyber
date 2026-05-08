"""
ML pipeline: model o'qitish va bashorat qilish.
Random Forest + sklearn. Modellar backend/models/ da saqlanadi.
"""
import os
import numpy as np

try:
    import joblib
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (
        accuracy_score, f1_score, precision_score,
        recall_score, confusion_matrix,
    )
    from sklearn.preprocessing import StandardScaler
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False

from . import ddos_simulator, sqli_simulator

# Model va scaler saqlash papkasi
MODELS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'models',
)
os.makedirs(MODELS_DIR, exist_ok=True)


def _model_path(attack_type: str) -> str:
    return os.path.join(MODELS_DIR, f'{attack_type}_rf_model.joblib')

def _scaler_path(attack_type: str) -> str:
    return os.path.join(MODELS_DIR, f'{attack_type}_scaler.joblib')

def _meta_path(attack_type: str) -> str:
    return os.path.join(MODELS_DIR, f'{attack_type}_meta.joblib')


def _feature_names(attack_type: str) -> list[str]:
    if attack_type == 'ddos':
        return ddos_simulator.FEATURE_NAMES
    return sqli_simulator.FEATURE_NAMES


def _to_matrix(dataset: list[dict], feature_names: list[str]):
    """Dataset list ni numpy X, y ga aylantirish."""
    X_rows, y_rows = [], []
    for sample in dataset:
        try:
            row = [float(sample.get(f, 0) or 0) for f in feature_names]
            X_rows.append(row)
            y_rows.append(int(sample['label']))
        except (ValueError, KeyError, TypeError):
            continue
    return np.array(X_rows), np.array(y_rows)


# ── MODEL O'QITISH ────────────────────────────────────────────────────────────
def train(attack_type: str, dataset: list[dict]) -> dict:
    """
    Random Forest modelini o'qitish.

    Qaytaradi: {
        accuracy, f1, precision, recall,
        confusion_matrix, cv_score,
        feature_importance, train_size, test_size,
        normal_count, attack_count
    }
    """
    if not SKLEARN_OK:
        return {'error': 'scikit-learn o\'rnatilmagan. pip install scikit-learn'}

    feature_names = _feature_names(attack_type)
    X, y = _to_matrix(dataset, feature_names)

    if len(X) < 20:
        return {'error': f'Yetarli data yo\'q: {len(X)} namuna. Kamida 20 ta kerak.'}

    if len(set(y)) < 2:
        label = 'Normal' if y[0] == 0 else 'Hujum'
        return {'error': f'Faqat {label} namunalari bor. Ikkala sinf ham kerak.'}

    # Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # StandardScaler
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    # Random Forest
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_split=3,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced',
    )
    model.fit(X_train_sc, y_train)

    y_pred = model.predict(X_test_sc)

    accuracy  = round(float(accuracy_score(y_test, y_pred))  * 100, 2)
    f1        = round(float(f1_score(y_test, y_pred, average='weighted'))        * 100, 2)
    precision = round(float(precision_score(y_test, y_pred, average='weighted')) * 100, 2)
    recall    = round(float(recall_score(y_test, y_pred, average='weighted'))    * 100, 2)
    cm        = confusion_matrix(y_test, y_pred).tolist()

    # Cross-validation (3-fold, tezlik uchun)
    cv_scores  = cross_val_score(model, X_train_sc, y_train, cv=3, scoring='accuracy')
    cv_mean    = round(float(cv_scores.mean()) * 100, 2)

    # Feature importance
    importance = {
        name: round(float(imp) * 100, 2)
        for name, imp in zip(feature_names, model.feature_importances_)
    }
    importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))

    # Saqlash
    joblib.dump(model,  _model_path(attack_type))
    joblib.dump(scaler, _scaler_path(attack_type))
    joblib.dump({
        'feature_names': feature_names,
        'attack_type':   attack_type,
        'total_samples': len(X),
    }, _meta_path(attack_type))

    return {
        'accuracy':           accuracy,
        'f1_score':           f1,
        'precision':          precision,
        'recall':             recall,
        'cv_score':           cv_mean,
        'confusion_matrix':   cm,
        'train_size':         len(X_train),
        'test_size':          len(X_test),
        'normal_count':       int((y == 0).sum()),
        'attack_count':       int((y == 1).sum()),
        'feature_importance': importance,
    }


# ── BASHORAT ──────────────────────────────────────────────────────────────────
def predict(attack_type: str, input_features: dict) -> dict:
    """
    Yangi namunani klassifikatsiya qilish.

    Qaytaradi: {
        probability (%), prediction (0/1), label,
        normal_probability (%), severity
    }
    """
    if not SKLEARN_OK:
        return {'error': 'scikit-learn o\'rnatilmagan.'}

    if not os.path.exists(_model_path(attack_type)):
        return {'error': f'{attack_type.upper()} modeli hali o\'qitilmagan. Avval "Model O\'qitish" ni bosing.'}

    model  = joblib.load(_model_path(attack_type))
    scaler = joblib.load(_scaler_path(attack_type))

    feature_names = _feature_names(attack_type)

    try:
        X = np.array([[float(input_features.get(f, 0) or 0) for f in feature_names]])
    except (ValueError, TypeError) as e:
        return {'error': f'Feature qiymatlari noto\'g\'ri: {e}'}

    X_sc   = scaler.transform(X)
    proba  = model.predict_proba(X_sc)[0]
    pred   = int(model.predict(X_sc)[0])
    attack_prob = round(float(proba[1]) * 100, 2)

    if attack_prob >= 85:
        severity = 'critical'
    elif attack_prob >= 65:
        severity = 'high'
    elif attack_prob >= 40:
        severity = 'medium'
    else:
        severity = 'low'

    attack_labels = {'ddos': 'DDoS Hujumi', 'sqli': 'SQL Injection'}

    return {
        'probability':        attack_prob,
        'normal_probability': round(float(proba[0]) * 100, 2),
        'prediction':         pred,
        'label':              attack_labels.get(attack_type, 'Hujum') if pred == 1 else 'Normal Trafik',
        'severity':           severity if pred == 1 else 'none',
        'features_used':      feature_names,
    }


# ── MODEL HOLATI ──────────────────────────────────────────────────────────────
def status() -> dict:
    result = {}
    for at in ('ddos', 'sqli'):
        path = _model_path(at)
        exists = os.path.exists(path)
        meta = {}
        if exists and os.path.exists(_meta_path(at)):
            try:
                meta = joblib.load(_meta_path(at))
            except Exception:
                meta = {}
        result[at] = {
            'trained':       exists,
            'total_samples': meta.get('total_samples', 0),
        }
    return result
