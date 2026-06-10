"""
Скрипт обучения модели на синтетических данных нормального трафика.
Запуск: py detector/ml/train_model.py
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from detector.ml.autoencoder import TrafficAutoencoder  # noqa: E402


def generate_normal_traffic(n_samples: int = 2000) -> pd.DataFrame:
  """Генерация синтетического «нормального» сетевого трафика."""
  rng = np.random.default_rng(42)
  protocols = ['tcp', 'udp', 'http', 'https', 'dns']
  protocol_weights = [0.35, 0.25, 0.15, 0.15, 0.10]

  rows = []
  for _ in range(n_samples):
    proto = rng.choice(protocols, p=protocol_weights)
    packet_count = int(rng.integers(5, 200))
    avg_packet_size = float(rng.integers(200, 1400))
    byte_volume = int(packet_count * avg_packet_size * rng.uniform(0.8, 1.2))
    duration = float(rng.uniform(0.5, 30))
    connections = float(rng.uniform(1, 15))

    if proto in ('http', 'https'):
      dst_port = 443 if proto == 'https' else 80
      src_port = int(rng.integers(1024, 65535))
    elif proto == 'dns':
      dst_port = 53
      src_port = int(rng.integers(1024, 65535))
    else:
      dst_port = int(rng.integers(1024, 65535))
      src_port = int(rng.integers(1024, 65535))

    rows.append({
      'source_ip': f'192.168.{rng.integers(1, 254)}.{rng.integers(1, 254)}',
      'dest_ip': f'10.0.{rng.integers(1, 50)}.{rng.integers(1, 254)}',
      'protocol': proto,
      'packet_count': packet_count,
      'byte_volume': byte_volume,
      'duration_sec': round(duration, 2),
      'src_port': src_port,
      'dst_port': dst_port,
      'connections_per_min': round(connections, 2),
      'avg_packet_size': round(avg_packet_size, 2),
    })

  return pd.DataFrame(rows)


def main():
  print('Генерация обучающих данных...')
  df = generate_normal_traffic(2500)
  print(f'Записей: {len(df)}')

  ae = TrafficAutoencoder()
  stats = ae.train(df, percentile=95)
  print(f'Порог аномалии: {stats["threshold"]}')
  print(f'Средняя ошибка: {stats["mean_error"]}')

  save_dir = Path(__file__).resolve().parent / 'saved'
  ae.save(save_dir)
  print(f'Модель сохранена в {save_dir}')


if __name__ == '__main__':
  main()
