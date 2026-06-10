from django.db import models


class AnalysisSession(models.Model):
  """Сессия анализа загруженного трафика."""

  title = models.CharField('Название', max_length=200)
  created_at = models.DateTimeField('Дата', auto_now_add=True)
  total_records = models.PositiveIntegerField('Всего записей', default=0)
  anomaly_count = models.PositiveIntegerField('Аномалий', default=0)
  source_file = models.FileField('Файл', upload_to='uploads/', blank=True, null=True)

  class Meta:
    verbose_name = 'Сессия анализа'
    verbose_name_plural = 'Сессии анализа'
    ordering = ['-created_at']

  def __str__(self):
    return self.title

  @property
  def anomaly_percent(self):
    if self.total_records == 0:
      return 0
    return round(self.anomaly_count / self.total_records * 100, 1)


class TrafficRecord(models.Model):
  """Результат анализа одной записи трафика."""

  RISK_CHOICES = [
    ('норма', 'Норма'),
    ('низкий', 'Низкий'),
    ('средний', 'Средний'),
    ('высокий', 'Высокий'),
  ]

  session = models.ForeignKey(
    AnalysisSession, on_delete=models.CASCADE,
    related_name='records', verbose_name='Сессия',
  )
  source_ip = models.CharField('IP источника', max_length=45)
  dest_ip = models.CharField('IP назначения', max_length=45)
  protocol = models.CharField('Протокол', max_length=20)
  packet_count = models.PositiveIntegerField('Пакетов')
  byte_volume = models.PositiveIntegerField('Байт')
  reconstruction_error = models.FloatField('Ошибка реконструкции')
  is_anomaly = models.BooleanField('Аномалия', default=False)
  risk_level = models.CharField('Уровень риска', max_length=20, choices=RISK_CHOICES)
  deviations_json = models.JSONField('Отклонения признаков', default=list)

  class Meta:
    verbose_name = 'Запись трафика'
    verbose_name_plural = 'Записи трафика'
    ordering = ['-reconstruction_error']

  def __str__(self):
    return f'{self.source_ip} → {self.dest_ip} ({self.protocol})'
