from django.contrib import messages
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from .forms import DemoGenerateForm, TrafficUploadForm
from .models import AnalysisSession, TrafficRecord
from .services import generate_demo_traffic, get_autoencoder, load_traffic_csv, run_analysis


class HomeView(View):
  def get(self, request):
    recent = AnalysisSession.objects.all()[:5]
    total_sessions = AnalysisSession.objects.count()
    total_anomalies = TrafficRecord.objects.filter(is_anomaly=True).count()
    try:
      model_info = get_autoencoder().get_architecture_info()
      model_ready = True
    except FileNotFoundError:
      model_info = None
      model_ready = False

    return render(request, 'detector/home.html', {
      'recent_sessions': recent,
      'total_sessions': total_sessions,
      'total_anomalies': total_anomalies,
      'model_ready': model_ready,
      'model_info': model_info,
    })


class UploadView(View):
  def get(self, request):
    return render(request, 'detector/upload.html', {'form': TrafficUploadForm()})

  def post(self, request):
    form = TrafficUploadForm(request.POST, request.FILES)
    if not form.is_valid():
      return render(request, 'detector/upload.html', {'form': form})

    try:
      df = load_traffic_csv(request.FILES['csv_file'])
      session = run_analysis(
        df,
        title=form.cleaned_data['title'],
        source_file=request.FILES['csv_file'],
      )
      messages.success(request, f'Анализ завершён. Найдено аномалий: {session.anomaly_count}')
      return redirect('session_detail', pk=session.pk)
    except Exception as e:
      messages.error(request, str(e))
      return render(request, 'detector/upload.html', {'form': form})


class DemoView(View):
  def get(self, request):
    return render(request, 'detector/demo.html', {'form': DemoGenerateForm()})

  def post(self, request):
    form = DemoGenerateForm(request.POST)
    if not form.is_valid():
      return render(request, 'detector/demo.html', {'form': form})

    try:
      df = generate_demo_traffic(
        count=form.cleaned_data['record_count'],
        anomaly_ratio=form.cleaned_data['anomaly_ratio'],
      )
      session = run_analysis(df, title=form.cleaned_data['title'])
      messages.success(request, f'Демо-анализ готов. Аномалий: {session.anomaly_count}')
      return redirect('session_detail', pk=session.pk)
    except Exception as e:
      messages.error(request, str(e))
      return render(request, 'detector/demo.html', {'form': form})


class SessionListView(View):
  def get(self, request):
    sessions = AnalysisSession.objects.all()
    return render(request, 'detector/sessions.html', {'sessions': sessions})


class SessionDetailView(View):
  def get(self, request, pk):
    session = get_object_or_404(AnalysisSession, pk=pk)
    records = session.records.all()
    filter_type = request.GET.get('filter', 'all')

    if filter_type == 'anomaly':
      records = records.filter(is_anomaly=True)
    elif filter_type == 'normal':
      records = records.filter(is_anomaly=False)

    risk_stats = session.records.values('risk_level').annotate(count=Count('id'))
    protocol_stats = session.records.filter(is_anomaly=True).values('protocol').annotate(count=Count('id'))

    return render(request, 'detector/session_detail.html', {
      'session': session,
      'records': records,
      'filter_type': filter_type,
      'risk_stats': list(risk_stats),
      'protocol_stats': list(protocol_stats),
      'normal_count': session.total_records - session.anomaly_count,
    })


class HowItWorksView(View):
  def get(self, request):
    try:
      model_info = get_autoencoder().get_architecture_info()
    except FileNotFoundError:
      model_info = None
    return render(request, 'detector/how_it_works.html', {'model_info': model_info})
