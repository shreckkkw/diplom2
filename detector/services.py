"""Сервисный слой: загрузка модели, анализ данных."""

from pathlib import Path

import numpy as np
import pandas as pd
from django.conf import settings

from .ml.autoencoder import TrafficAutoencoder
from .ml.features import PROTOCOL_MAP
from .models import AnalysisSession, TrafficRecord

_model_cache = None


def get_autoencoder() -> TrafficAutoencoder:
  global _model_cache
  if _model_cache is None:
    model_dir = settings.ML_MODEL_DIR
    if not (model_dir / 'model.joblib').exists():
      raise FileNotFoundError(
        'Модель не найдена. Выполните: py detector/ml/train_model.py'
      )
    _model_cache = TrafficAutoencoder.load(model_dir)
  return _model_cache


def load_traffic_csv(file) -> pd.DataFrame:
  df = pd.read_csv(file)
  required = [
    'source_ip', 'dest_ip', 'protocol', 'packet_count', 'byte_volume',
    'duration_sec', 'src_port', 'dst_port', 'connections_per_min', 'avg_packet_size',
  ]
  missing = [c for c in required if c not in df.columns]
  if missing:
    raise ValueError(f'В файле отсутствуют столбцы: {", ".join(missing)}')
  df['protocol_code'] = df['protocol'].str.lower().map(PROTOCOL_MAP).fillna(0)
  return df


def generate_demo_traffic(count: int, anomaly_ratio: float = 0.15) -> pd.DataFrame:
  """Генерация демо-данных с нормальным и аномальным трафиком."""
  rng = np.random.default_rng()
  protocols = ['tcp', 'udp', 'http', 'https', 'dns']
  anomaly_count = int(count * anomaly_ratio)
  normal_count = count - anomaly_count

  rows = []

  for _ in range(normal_count):
    proto = rng.choice(protocols)
    packet_count = int(rng.integers(5, 150))
    avg_packet_size = float(rng.integers(200, 1200))
    rows.append(_make_record(rng, proto, packet_count, avg_packet_size, normal=True))

  for _ in range(anomaly_count):
    anomaly_type = rng.choice(['flood', 'scan', 'exfil'])
    if anomaly_type == 'flood':
      rows.append(_make_record(rng, 'tcp', int(rng.integers(5000, 50000)),
                              float(rng.integers(50, 200)), normal=False))
    elif anomaly_type == 'scan':
      rows.append(_make_record(rng, 'tcp', int(rng.integers(1, 5)),
                              float(rng.integers(40, 80)), normal=False, scan=True))
    else:
      rows.append(_make_record(rng, 'tcp', int(rng.integers(100, 500)),
                              float(rng.integers(1400, 9000)), normal=False, exfil=True))

  df = pd.DataFrame(rows)
  df = df.sample(frac=1, random_state=rng.integers(0, 10000)).reset_index(drop=True)
  return df


def _make_record(rng, proto, packet_count, avg_packet_size, normal=True,
                 scan=False, exfil=False):
  if exfil:
    byte_volume = int(packet_count * avg_packet_size)
    duration = float(rng.uniform(0.1, 2))
    connections = float(rng.uniform(50, 200))
    dst_port = int(rng.integers(1024, 65535))
  elif scan:
    byte_volume = int(packet_count * avg_packet_size)
    duration = float(rng.uniform(0.01, 0.5))
    connections = float(rng.uniform(100, 500))
    dst_port = int(rng.integers(1, 1024))
  elif normal:
    byte_volume = int(packet_count * avg_packet_size * rng.uniform(0.8, 1.2))
    duration = float(rng.uniform(0.5, 25))
    connections = float(rng.uniform(1, 12))
    dst_port = 443 if proto == 'https' else (80 if proto == 'http' else int(rng.integers(1024, 65535)))
  else:
    byte_volume = int(packet_count * avg_packet_size)
    duration = float(rng.uniform(0.1, 5))
    connections = float(rng.uniform(30, 150))
    dst_port = int(rng.integers(1024, 65535))

  return {
    'source_ip': f'192.168.{rng.integers(1, 254)}.{rng.integers(1, 254)}',
    'dest_ip': f'10.0.{rng.integers(1, 50)}.{rng.integers(1, 254)}',
    'protocol': proto,
    'packet_count': packet_count,
    'byte_volume': byte_volume,
    'duration_sec': round(duration, 2),
    'src_port': int(rng.integers(1024, 65535)),
    'dst_port': dst_port,
    'connections_per_min': round(connections, 2),
    'avg_packet_size': round(avg_packet_size, 2),
    'protocol_code': PROTOCOL_MAP.get(proto, 0),
  }


def run_analysis(df: pd.DataFrame, title: str, source_file=None) -> AnalysisSession:
  ae = get_autoencoder()
  results = ae.predict(df)

  anomaly_count = sum(1 for r in results if r['is_anomaly'])
  session = AnalysisSession.objects.create(
    title=title,
    total_records=len(results),
    anomaly_count=anomaly_count,
    source_file=source_file,
  )

  records = []
  for r in results:
    row = df.iloc[r['index']]
    records.append(TrafficRecord(
      session=session,
      source_ip=r['source_ip'],
      dest_ip=r['dest_ip'],
      protocol=r['protocol'],
      packet_count=r['packet_count'],
      byte_volume=r['byte_volume'],
      reconstruction_error=r['reconstruction_error'],
      is_anomaly=r['is_anomaly'],
      risk_level=r['risk_level'],
      deviations_json=r['top_deviations'],
    ))
  TrafficRecord.objects.bulk_create(records)
  return session
