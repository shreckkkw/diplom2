from django.contrib import admin

from .models import AnalysisSession, TrafficRecord


class TrafficRecordInline(admin.TabularInline):
  model = TrafficRecord
  extra = 0
  readonly_fields = ('source_ip', 'dest_ip', 'protocol', 'is_anomaly', 'risk_level')


@admin.register(AnalysisSession)
class AnalysisSessionAdmin(admin.ModelAdmin):
  list_display = ('title', 'created_at', 'total_records', 'anomaly_count')
  inlines = [TrafficRecordInline]


@admin.register(TrafficRecord)
class TrafficRecordAdmin(admin.ModelAdmin):
  list_display = ('source_ip', 'dest_ip', 'protocol', 'is_anomaly', 'risk_level', 'reconstruction_error')
  list_filter = ('is_anomaly', 'risk_level', 'protocol')
