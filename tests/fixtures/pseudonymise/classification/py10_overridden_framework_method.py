from django.views import View


class ReportView(View):
    def get(self, request):
        return self.render_report(request)

    def render_report(self, request):
        return request
