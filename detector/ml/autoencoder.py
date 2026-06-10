"""
Нейросетевой автоэнкодер для детекции аномалий.

Принцип: сеть обучается восстанавливать «нормальный» трафик.
Записи с высокой ошибкой восстановления считаются аномалиями.
"""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_COLUMNS, FEATURE_LABELS, PROTOCOL_MAP


class TrafficAutoencoder:
  """Автоэнкодер на базе многослойного перцептрона (MLP)."""

  def __init__(self):
    self.scaler = StandardScaler()
    self.model = MLPRegressor(
      hidden_layer_sizes=(16, 8, 16),
      activation='relu',
      solver='adam',
      max_iter=800,
      random_state=42,
      early_stopping=True,
      validation_fraction=0.1,
    )
    self.threshold = None
    self.is_trained = False

  def _prepare_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
    data = df.copy()
    if 'protocol' in data.columns and 'protocol_code' not in data.columns:
      data['protocol_code'] = data['protocol'].str.lower().map(PROTOCOL_MAP).fillna(0)
    for col in FEATURE_COLUMNS:
      if col not in data.columns:
        raise ValueError(f'Отсутствует обязательный столбец: {col}')
    return data[FEATURE_COLUMNS].astype(float)

  def train(self, df: pd.DataFrame, percentile: float = 95):
    """Обучение на нормальном трафике."""
    X = self._prepare_dataframe(df)
    X_scaled = self.scaler.fit_transform(X)
    self.model.fit(X_scaled, X_scaled)

    errors = self._reconstruction_errors(X_scaled)
    self.threshold = float(np.percentile(errors, percentile))
    self.is_trained = True
    return {
      'samples': len(X),
      'threshold': round(self.threshold, 6),
      'mean_error': round(float(errors.mean()), 6),
    }

  def _reconstruction_errors(self, X_scaled: np.ndarray) -> np.ndarray:
    reconstructed = self.model.predict(X_scaled)
    return np.mean((X_scaled - reconstructed) ** 2, axis=1)

  def predict(self, df: pd.DataFrame) -> list[dict]:
    """Анализ трафика: возвращает список результатов по каждой записи."""
    if not self.is_trained:
      raise RuntimeError('Модель не обучена. Сначала выполните обучение.')

    X = self._prepare_dataframe(df)
    X_scaled = self.scaler.transform(X)
    errors = self._reconstruction_errors(X_scaled)
    reconstructed = self.model.predict(X_scaled)

    results = []
    for i, row in df.iterrows():
      is_anomaly = bool(errors[i] >= self.threshold)
      results.append({
        'index': int(i),
        'source_ip': str(row.get('source_ip', '—')),
        'dest_ip': str(row.get('dest_ip', '—')),
        'protocol': str(row.get('protocol', '—')),
        'packet_count': int(row.get('packet_count', 0)),
        'byte_volume': int(row.get('byte_volume', 0)),
        'reconstruction_error': round(float(errors[i]), 6),
        'is_anomaly': is_anomaly,
        'risk_level': self._risk_level(errors[i]),
        'top_deviations': self._top_deviations(X_scaled[i], reconstructed[i]),
      })
    return results

  def _risk_level(self, error: float) -> str:
    if error < self.threshold:
      return 'норма'
    ratio = error / self.threshold
    if ratio < 1.5:
      return 'низкий'
    if ratio < 2.5:
      return 'средний'
    return 'высокий'

  def _top_deviations(self, original: np.ndarray, reconstructed: np.ndarray, top_n: int = 3):
    diff = np.abs(original - reconstructed)
    indices = np.argsort(diff)[::-1][:top_n]
    deviations = []
    for idx in indices:
      col = FEATURE_COLUMNS[idx]
      deviations.append({
        'feature': col,
        'label': FEATURE_LABELS[col],
        'deviation': round(float(diff[idx]), 4),
      })
    return deviations

  def save(self, directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    joblib.dump(self.model, directory / 'model.joblib')
    joblib.dump(self.scaler, directory / 'scaler.joblib')
    meta = {'threshold': self.threshold, 'is_trained': self.is_trained}
    (directory / 'meta.json').write_text(json.dumps(meta), encoding='utf-8')

  @classmethod
  def load(cls, directory: Path) -> 'TrafficAutoencoder':
    ae = cls()
    ae.model = joblib.load(directory / 'model.joblib')
    ae.scaler = joblib.load(directory / 'scaler.joblib')
    meta = json.loads((directory / 'meta.json').read_text(encoding='utf-8'))
    ae.threshold = meta['threshold']
    ae.is_trained = meta['is_trained']
    return ae

  def get_architecture_info(self) -> dict:
    return {
      'type': 'Автоэнкодер (MLP)',
      'layers': '8 → 16 → 8 → 16 → 8',
      'activation': 'ReLU',
      'optimizer': 'Adam',
      'principle': (
        'Сеть сжимает входные признаки в скрытое представление '
        'и восстанавливает исходные значения. Аномалии плохо '
        'воспроизводятся — ошибка реконструкции выше порога.'
      ),
      'features': [FEATURE_LABELS[c] for c in FEATURE_COLUMNS],
      'threshold': round(self.threshold, 6) if self.threshold else None,
    }
