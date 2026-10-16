"""Public URL intent reaches planning and evidence through the ZIP endpoint."""

import io
import zipfile
from unittest.mock import Mock, patch

from application.analysis import AISettings
from application.certificate import deployment_certificate
from interfaces.http.server import App, handler_for


def test_zip_public_url_condition_reaches_planner_job_and_certificate(tmp_path):
    observed = []

    class Planner:
        def __init__(self, settings):
            pass

        def propose(self, files, available, public, *, public_url_required=False):
            observed.append((available, public, public_url_required))
            return {
                'target': 'aws-ecs-express', 'workload': 'stateless-http',
                'rationale': '공개 URL이 필요하므로 허용된 공개 컨테이너 경로를 선택합니다.',
                'evidence': [{'file': 'Dockerfile', 'quote': 'FROM node:22'}],
            }

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as bundle:
        bundle.writestr('Dockerfile', 'FROM node:22\n')
        bundle.writestr('server.js', "require('http').createServer((q,s)=>s.end('ok')).listen(8080);")
    app = App(tmp_path, AISettings('fixture-key', 'fixture-model'),
              infrastructure_planner_factory=Planner, monitor_interval=0)
    handler = handler_for(app).__new__(handler_for(app))
    handler.path = '/api/deployments'
    handler.headers = {
        'X-Sky-Token': app.token, 'Content-Length': str(len(archive.getvalue())),
        'X-Deploy-Target': 'auto', 'X-Public-Access': 'true', 'X-Public-URL-Required': 'true',
    }
    handler.rfile = io.BytesIO(archive.getvalue())
    handler.json_response = Mock()
    with patch('interfaces.http.server.AwsSettings.unavailable_reason', return_value=None), \
            patch('interfaces.http.server.CloudRunSettings.unavailable_reason', return_value=None), \
            patch.object(app, 'start_job_worker', return_value=False):
        handler.do_POST()
    assert handler.json_response.call_args.args[0] == 202
    job = app.jobs[handler.json_response.call_args.args[1]['id']]
    assert len(observed) == 1
    assert set(observed[0][0]) == {'aws-ecs-express', 'cloud-run'}
    assert observed[0][1:] == (True, True)
    conditions = {'public_access_allowed': True, 'public_url_required': True}
    assert job['deployment_policy']['public_url_required'] is True
    assert job['infrastructure_plan']['selection_conditions'] == conditions
    assert deployment_certificate(job)['decision_trace']['selection_conditions'] == conditions
