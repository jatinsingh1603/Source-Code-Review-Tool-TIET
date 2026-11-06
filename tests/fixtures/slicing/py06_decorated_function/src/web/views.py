from web import app, login_required


@app.route('/export')
@login_required
def export(request):
    path = request.args['file']
    return open('/data/' + path).read()
