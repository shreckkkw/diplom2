"""Признаки сетевого трафика для нейросетевого анализа."""

FEATURE_COLUMNS = [
    'packet_count',
    'byte_volume',
    'duration_sec',
    'src_port',
    'dst_port',
    'protocol_code',
    'connections_per_min',
    'avg_packet_size',
]

PROTOCOL_MAP = {
    'tcp': 1,
    'udp': 2,
    'icmp': 3,
    'http': 4,
    'https': 5,
    'dns': 6,
    'other': 0,
}

FEATURE_LABELS = {
    'packet_count': 'Кол-во пакетов',
    'byte_volume': 'Объём данных (байт)',
    'duration_sec': 'Длительность (сек)',
    'src_port': 'Порт источника',
    'dst_port': 'Порт назначения',
    'protocol_code': 'Протокол (код)',
    'connections_per_min': 'Соединений/мин',
    'avg_packet_size': 'Средний размер пакета',
}
