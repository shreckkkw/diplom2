from django import forms


class TrafficUploadForm(forms.Form):
  title = forms.CharField(
    label='Название анализа',
    max_length=200,
    initial='Анализ трафика',
    widget=forms.TextInput(attrs={'placeholder': 'Например: Проверка за 10.06.2026'}),
  )
  csv_file = forms.FileField(
    label='CSV-файл с трафиком',
    help_text='Столбцы: source_ip, dest_ip, protocol, packet_count, byte_volume, '
              'duration_sec, src_port, dst_port, connections_per_min, avg_packet_size',
    widget=forms.FileInput(attrs={'accept': '.csv'}),
  )


class DemoGenerateForm(forms.Form):
  title = forms.CharField(
    label='Название',
    max_length=200,
    initial='Демо-анализ',
  )
  record_count = forms.IntegerField(
    label='Количество записей',
    min_value=10,
    max_value=500,
    initial=50,
  )
  anomaly_ratio = forms.FloatField(
    label='Доля аномалий (0–0.5)',
    min_value=0.0,
    max_value=0.5,
    initial=0.15,
    help_text='Часть записей будет сгенерирована как подозрительный трафик',
  )
