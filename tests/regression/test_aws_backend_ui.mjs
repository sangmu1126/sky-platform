import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const html = fs.readFileSync(new URL('../../src/assets/static/index.html', import.meta.url), 'utf8');
const start = html.indexOf('function compatibilityPreviewText(result){');
const end = html.indexOf("el('compatibilityPreview').onclick", start);
assert.ok(start >= 0 && end > start);
const render = vm.runInNewContext(html.slice(start, end) + '\ncompatibilityPreviewText;', {});

test('unimplemented AWS options expose suitability, pending proof and source without claiming a URL', () => {
  const text = render({
    application_ir: {evidence: [{id: 'E-handler', path: 'handler.py'}]},
    candidates: [{
      id: 'aws-lambda', status: 'unsupported_by_sky', structural_status: 'potentially_compatible',
      reasons: ['Sky 배포 어댑터는 미구현입니다.'], selection_mode: 'unavailable',
      constraint_results: [
        {rule_id: 'LAMBDA-HANDLER-01', status: 'satisfied', reason: '함수 핸들러 형태 관찰', evidence_ids: ['E-handler']},
        {rule_id: 'LAMBDA-DURATION-01', status: 'unknown', reason: '실행 시간 미검증', evidence_ids: []},
      ],
    }],
  });
  assert.match(text, /AWS Lambda \(요청 핸들러\)/);
  assert.match(text, /비교 후보 · Sky 배포 미지원/);
  assert.match(text, /적합 가능 · 추가 검증 필요/);
  assert.match(text, /접근: 미구현 · 접근 방식 미정/);
  assert.match(text, /handler\.py/);
  assert.match(text, /실행 시간 미검증/);
  assert.doesNotMatch(text, /배포 시도 가능|선택한 공개 범위 미지원/);
});

test('EC2 is not preferred without host requirements', () => {
  const text = render({candidates: [{
    id: 'aws-ec2', status: 'unsupported_by_sky', structural_status: 'not_preferred',
    reasons: ['호스트 제어 필요성 미확인'], selection_mode: 'unavailable',
  }]});
  assert.match(text, /AWS EC2 \(구조 비교\)/);
  assert.match(text, /호스트 제어 근거 없어 우선하지 않음/);
  assert.match(text, /Sky 배포 미지원/);
});


test('host-control fit does not imply the limited native EC2 adapter can deploy it', () => {
  const text = render({candidates: [{
    id: 'aws-ec2', status: 'unsupported_by_sky', structural_status: 'potentially_compatible',
    reasons: [], native_adapter: {support: 'implemented', workload_status: 'blocked', blockers: ['host-kernel-control']},
  }]});
  assert.match(text, /제한된 ZIP 경로 구현 · 자동 선택 제외/);
  assert.match(text, /명시적 ZIP 경로: 현재 앱 요구와 충돌 · host-kernel-control/);
  assert.match(text, /적합 가능 · 추가 검증 필요/);
  assert.doesNotMatch(text, /Sky 배포 미지원|배포 시도 가능/);
});

test('native handler preview still requires packaging and runtime verification', () => {
  const text = render({candidates: [{
    id: 'aws-lambda', status: 'unsupported_by_sky', structural_status: 'potentially_compatible',
    reasons: [], native_adapter: {support: 'implemented', workload_status: 'needs_review', blockers: []},
  }]});
  assert.match(text, /패키징·설정·실행 검증 필요/);
  assert.match(text, /자동 선택 제외/);
});

test('GitHub upload payload preserves the required public URL condition', () => {
  const start = html.indexOf('function githubDeploymentPayload(application,targets){');
  const end = html.indexOf('function selectedUploadBody()', start);
  assert.ok(start >= 0 && end > start);
  const elements = {
    repositoryUrl: {value: 'https://github.com/team/demo'}, repositoryBranch: {value: 'main'},
    public: {checked: true}, publicRequired: {checked: true}, githubAutoDeploy: {checked: true},
  };
  const payload = vm.runInNewContext(html.slice(start, end) + '\ngithubDeploymentPayload;', {
    el: id => elements[id],
  })('demo-app', ['auto']);
  assert.equal(payload.public_url_required, true);
  assert.equal(payload.auto_deploy, true);
});

test('public URL requirement is visible in GitHub auto mode and cleared for fixed targets', () => {
  const start = html.indexOf('const updateTargetOptions=');
  const end = html.indexOf("el('publicRequired').onchange", start);
  assert.ok(start >= 0 && end > start);
  const elements = {
    target: {value: 'auto', onchange: () => {}}, multiMode: {checked: false},
    publicRequiredOption: {hidden: true}, publicRequired: {checked: true},
    cloudSqlOptions: {}, cloudSqlExisting: {}, sqliteConversionOption: {},
  };
  vm.runInNewContext(html.slice(start, end), {el: id => elements[id], githubMode: true});
  elements.target.onchange();
  assert.equal(elements.publicRequiredOption.hidden, false);
  assert.equal(elements.publicRequired.checked, true);
  elements.target.value = 'local-docker';
  elements.target.onchange();
  assert.equal(elements.publicRequiredOption.hidden, true);
  assert.equal(elements.publicRequired.checked, false);
});

test('verified deployment and follow-up cleanup warning are displayed separately', () => {
  const start = html.indexOf('function renderInfrastructure(job){');
  const end = html.indexOf('\nfunction ', start);
  assert.ok(start >= 0 && end > start);
  const elements = {infrastructure: {}, sourceInfo: {}};
  const renderJob = vm.runInNewContext(html.slice(start, end) + '\nrenderInfrastructure;', {
    el: id => elements[id],
  });
  const job = {status: 'succeeded', finalization_state: 'needs_attention'};
  renderJob(job);
  assert.match(elements.infrastructure.textContent, /배포 완료, 이전 배포의 상태 갱신·정리 확인 필요/);
  assert.equal(job.status, 'succeeded');
  renderJob({status: 'succeeded'});
  assert.doesNotMatch(elements.infrastructure.textContent, /정리 확인 필요/);
});

test('following a verified job keeps polling while predecessor cleanup is pending', async () => {
  const start = html.indexOf('async function follow(id){');
  const end = html.indexOf('\nfunction ', start);
  const shown = [];
  let calls = 0;
  const follow = vm.runInNewContext(html.slice(start, end) + '\nfollow;', {
    selected: 'job', readOnly: false,
    api: async () => ({status: 'succeeded', finalization_state: ++calls === 1 ? 'pending' : 'complete'}),
    show: job => shown.push(job), el: () => ({open: false}), setTimeout: callback => callback(),
  });
  const result = await follow('job');
  assert.equal(calls, 2);
  assert.equal(shown[0].status, 'succeeded');
  assert.equal(shown[0].finalization_state, 'pending');
  assert.equal(result.finalization_state, 'complete');
});

test('cleanup retry is offered only for verified active local predecessors needing attention', () => {
  const start = html.indexOf('function renderFinalization(job){');
  const end = html.indexOf('function renderInfrastructure(job){', start);
  assert.ok(start >= 0 && end > start);
  const elements = {finalizationRetry: {}, finalizationInfo: {}};
  const render = vm.runInNewContext(html.slice(start, end) + '\nrenderFinalization;', {el: id => elements[id]});
  const job = {target: 'local-docker', status: 'succeeded', finalization_state: 'needs_attention', git_replaces_local_job_id: 'old'};
  render(job);
  assert.equal(elements.finalizationRetry.hidden, false);
  for(const changes of [{target: 'aws-ecs-express'}, {status: 'failed'}, {finalization_state: 'pending'}, {deployment_state: 'deleted'}]){
    render({...job, ...changes});
    assert.equal(elements.finalizationRetry.hidden, true);
  }
});

test('GitHub source actions distinguish accepted, pending and duplicate requests', () => {
  const start = html.indexOf('function githubActionMessage(action,result){');
  const end = html.indexOf('async function refreshGithubSources(){', start);
  assert.ok(start >= 0 && end > start);
  const message = vm.runInNewContext(html.slice(start, end) + '\ngithubActionMessage;', {});
  assert.match(message('retry', {changed: true}), /새 배포 작업을 접수/);
  assert.match(message('check', {changed: true}), /새 커밋의 배포 작업을 접수/);
  for (const action of ['retry', 'check']) {
    assert.match(message(action, {in_progress: true}), /이미 브랜치를 확인 중/);
    assert.match(message(action, {pending: true}), /새 배포를 시작하지 않았습니다/);
    assert.match(message(action, {changed: false}), /새 배포를 시작하지 않았습니다/);
  }
  assert.match(message('resume', {}), /중단된 커밋은 자동 실행하지 않습니다/);
  assert.match(message('pause', {}), /실행 중인 배포는 계속/);
  assert.match(message('disconnect', {}), /실행 중인 앱은 유지/);
});

test('GitHub source cards show blocked work and offer retry only after resume', async () => {
  const start = html.indexOf('function githubActionMessage(action,result){');
  const end = html.indexOf("el('resumePostgres').onclick", start);
  assert.ok(start >= 0 && end > start);
  const element = () => ({children: [], append(child) {this.children.push(child);},
    replaceChildren() {this.children = [];}});
  const elements = {githubSources: element(), githubSourceInfo: {}};
  const source = {id: 'a'.repeat(16), application_id: 'demo-app', branch: 'main',
    repository_url: 'https://github.com/team/demo', last_revision: 'b'.repeat(40),
    last_deployment_status: 'blocked', retryable: true, enabled: false};
  const calls = [];
  const render = vm.runInNewContext(html.slice(start, end) + '\nrefreshGithubSources;', {
    el: id => elements[id], document: {createElement: element}, history: async () => {},
    api: async (path, options) => {
      if (options) {calls.push(path); source.enabled = true; return {enabled: true};}
      return [source];
    },
  });
  await render();
  let card = elements.githubSources.children[0];
  assert.ok(card.children.some(child => child.textContent?.includes('실행 전 중단')));
  assert.ok(card.children.some(child => child.textContent?.includes('자동 확인 재개 후 재시도')));
  assert.ok(!card.children.some(child => child.textContent === '같은 커밋 다시 시도'));
  await card.children.find(child => child.textContent === '자동 확인 재개').onclick();
  assert.equal(calls.length, 1);
  assert.match(calls[0], /\/resume$/);
  assert.match(elements.githubSourceInfo.textContent, /자동 실행하지 않습니다/);
  card = elements.githubSources.children[0];
  assert.ok(card.children.some(child => child.textContent?.includes('실행 전 중단 · 같은 커밋 재시도 가능')));
  assert.ok(card.children.some(child => child.textContent === '같은 커밋 다시 시도'));
});
