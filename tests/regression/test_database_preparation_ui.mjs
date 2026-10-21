import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import test from 'node:test';
const html=readFileSync(new URL('../../src/assets/static/database-preparation.html',import.meta.url),'utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const job='a'.repeat(16),otherJob='b'.repeat(16),proposalId='OPR-'+'c'.repeat(24);
const operation='11111111-1111-4111-8111-111111111111';
const requestKey='22222222-2222-4222-8222-222222222222';
const proposal=(status='approved')=>({proposal_id:proposalId,status,binding:{application_id:'game'},plan:{target:{region:'ap-northeast-2',instance_id:'owned-target'},cost_estimate:{currency:'USD',incremental_monthly_cents:2500,evidence_ref:'registered-quote',valid_until:'2026-10-12T00:00:00Z'}}});
const receipt=(status='queued')=>({job_id:job,operation_id:operation,status,scope:'dedicated_target_preparation_only',data_routing_changed:false});
function context({handler,storage=new Map()}={}){
 const elements={},calls=[],timers=new Map(),events={};let now=Date.parse('2026-10-11T00:00:00Z');
 class Clock extends Date{static now(){return now}}
 const c={Date:Clock,URLSearchParams,console,
  document:{getElementById(id){return elements[id]??={textContent:'',value:'',disabled:false,checked:false,addEventListener(name,fn){this[name]=fn}}}},
  window:{location:{search:''},addEventListener(name,fn){events[name]=fn}},
  sessionStorage:{getItem:key=>storage.get(key)??null,setItem:(key,value)=>storage.set(key,value)},
  crypto:{randomUUID:()=>requestKey},clearTimeout:id=>timers.delete(id),setTimeout(fn){const id=timers.size+1;timers.set(id,fn);return id},
  async fetch(path,options){calls.push({path,options});const value=handler?await handler(path,options):path.endsWith('/operating-review')?{job_id:job,proposal:proposal()}:path.endsWith('/database-preparation')?{job_id:job,scope:'dedicated_target_preparation_only',admission_enabled:true}:receipt();return {ok:true,json:async()=>value}}
 };
 runInNewContext(script+'\nglobalThis.getState=()=>state;globalThis.element=el;',c);
 c.calls=calls;c.timers=timers;c.storage=storage;c.events=events;c.advance=seconds=>now+=seconds*1000;
 c.element('job').value=job;
 return c;
}
async function load(c){await c.loadReview();return c}
function consent(c){c.element('consent').checked=true;c.render()}
test('approved costed proposal requires explicit consent and preserves credentials policy',async()=>{
 const c=await load(context());assert.match(c.element('summary').textContent,/USD 25.00/);assert.match(c.element('summary').textContent,/registered-quote/);
 assert.equal(c.element('prepare').disabled,true);consent(c);assert.equal(c.element('prepare').disabled,false);
 assert.ok(c.calls.every(call=>call.options.credentials==='same-origin'&&call.options.cache==='no-store'));
});
test('preparation sends only the approved reference and polls locally constructed status URL',async()=>{
 const c=await load(context({handler:async(path,options)=>options.method==='POST'?{...receipt(),status_url:'https://untrusted.example/'}:path.endsWith('/operating-review')?{job_id:job,proposal:proposal()}:path.endsWith('/database-preparation')?{job_id:job,scope:'dedicated_target_preparation_only',admission_enabled:true}:receipt('succeeded')}));
 consent(c);await c.submitPreparation();const body=JSON.parse(c.calls.find(call=>call.options.method==='POST').options.body);
 assert.deepEqual(body,{proposal_id:proposalId,request_key:requestKey,confirm_preparation:true});
 assert.match(c.element('status').textContent,/데이터 이전과 트래픽 전환은 진행하지 않았습니다/);
 assert.ok(c.calls.some(call=>call.path===`/api/jobs/${job}/database-preparation/${operation}`));
 assert.ok(c.calls.every(call=>!call.path.startsWith('https:')));assert.equal(c.element('prepare').disabled,true);
});
test('ambiguous admission retries with the same key after page reload',async()=>{
 let posts=0;const storage=new Map();
 const handler=async(path,options)=>{if(options.method==='POST'){posts++;if(posts===1)throw Error('response lost');return receipt()}
 return path.endsWith('/operating-review')?{job_id:job,proposal:proposal()}:path.endsWith('/database-preparation')?{job_id:job,scope:'dedicated_target_preparation_only',admission_enabled:true}:receipt('succeeded')};
 const first=await load(context({handler,storage}));consent(first);await first.submitPreparation();assert.match(first.element('status').textContent,/response lost/);
 const second=await load(context({handler,storage}));consent(second);await second.submitPreparation();
 const bodies=[first,second].map(c=>JSON.parse(c.calls.find(call=>call.options.method==='POST').options.body));assert.deepEqual(bodies[0],bodies[1]);
});
test('queued operation resumes polling after reload and pagehide stops timers',async()=>{
 const storage=new Map([[`sky.databasePreparation.v1.${job}`,JSON.stringify({job_id:job,proposal_id:proposalId,request_key:requestKey,operation_id:operation})]]);
 const c=await load(context({storage}));assert.match(c.element('status').textContent,/실행 대기/);assert.equal(c.timers.size,1);assert.equal(c.element('prepare').disabled,true);
 c.events.pagehide();assert.equal(c.timers.size,0);
});
test('expired estimate prevents submission even if the consent box was already checked',async()=>{
 const c=await load(context());consent(c);c.advance(86400);await c.submitPreparation();assert.equal(c.calls.filter(call=>call.options.method==='POST').length,0);assert.equal(c.element('prepare').disabled,true);
});
test('disabled intake and pending review cannot request preparation',async()=>{
 const c=await load(context({handler:async path=>path.endsWith('/operating-review')?{job_id:job,proposal:proposal('pending_approval')}:{job_id:job,scope:'dedicated_target_preparation_only',admission_enabled:false}}));
 consent(c);assert.equal(c.element('prepare').disabled,true);assert.equal(c.element('approve').disabled,false);await c.submitPreparation();assert.equal(c.calls.length,2);
});
test('review approval is separate from resource preparation',async()=>{
 const c=await load(context({handler:async(path,options)=>options.method==='POST'?{proposal:proposal()}:path.endsWith('/operating-review')?{job_id:job,proposal:proposal('pending_approval')}:{job_id:job,scope:'dedicated_target_preparation_only',admission_enabled:true}}));
 await c.updateReview(true);const post=c.calls.find(call=>call.options.method==='POST');assert.ok(post.path.endsWith('/operating-review/approve'));assert.equal(JSON.parse(post.options.body).confirm_review,true);
 assert.equal(c.element('prepare').disabled,true);assert.match(c.element('status').textContent,/별도로 요청/);
});
test('stale operation response cannot update another selected job',async()=>{
 let resolve;const c=await load(context());c.getState().request={job_id:job,proposal_id:proposalId,request_key:requestKey,operation_id:operation};
 c.fetch=()=>new Promise(r=>resolve=value=>r({ok:true,json:async()=>value}));const old=c.pollOperation();
 c.getState().epoch++;c.getState().job=otherJob;c.element('status').textContent='new selection';resolve(receipt('succeeded'));await old;assert.equal(c.element('status').textContent,'new selection');assert.equal(c.timers.size,0);
});
test('storage failure blocks the network mutation and untrusted text never becomes HTML',async()=>{
 const c=await load(context({handler:async path=>path.endsWith('/operating-review')?{job_id:job,proposal:{...proposal(),binding:{application_id:'<script>untrusted</script>'}}}:{job_id:job,scope:'dedicated_target_preparation_only',admission_enabled:true}}));
 assert.match(c.element('summary').textContent,/<script>untrusted/);assert.equal(c.element('summary').innerHTML,undefined);
 c.sessionStorage.setItem=()=>{throw Error('storage blocked')};consent(c);await c.submitPreparation();assert.equal(c.calls.filter(call=>call.options.method==='POST').length,0);
});
test('unknown status fails closed and does not claim success',async()=>{
 const c=await load(context());c.getState().request={job_id:job,proposal_id:proposalId,request_key:requestKey,operation_id:operation};c.fetch=async()=>({ok:true,json:async()=>receipt('available')});await c.pollOperation();assert.match(c.element('status').textContent,/상태 범위/);assert.equal(c.timers.size,0);
});
test('pending request for an older proposal cannot become a fresh preparation',async()=>{
 const storage=new Map([[`sky.databasePreparation.v1.${job}`,JSON.stringify({job_id:job,proposal_id:'OPR-'+'d'.repeat(24),request_key:requestKey})]]);
 const c=await load(context({storage}));consent(c);assert.equal(c.element('prepare').disabled,true);await c.submitPreparation();assert.equal(c.calls.filter(call=>call.options.method==='POST').length,0);assert.match(c.element('status').textContent,/이전 제안/);
});
test('needs_attention is terminal and never enables a fresh request',async()=>{
 const c=await load(context());c.getState().request={job_id:job,proposal_id:proposalId,request_key:requestKey,operation_id:operation};c.fetch=async()=>({ok:true,json:async()=>receipt('needs_attention')});await c.pollOperation();c.render();assert.match(c.element('status').textContent,/자동 재실행이 중단/);assert.equal(c.timers.size,0);assert.equal(c.element('prepare').disabled,true);
});
test('corrupt stored request fails closed instead of minting another key',async()=>{
 const storage=new Map([[`sky.databasePreparation.v1.${job}`,'{"request_key":"unsafe"}']]);const c=await load(context({storage}));consent(c);await c.submitPreparation();assert.equal(c.calls.length,0);assert.equal(c.element('prepare').disabled,true);
});

test('browser back-forward cache restores polling instead of retaining a disabled form',async()=>{
 const storage=new Map([[`sky.databasePreparation.v1.${job}`,JSON.stringify({job_id:job,proposal_id:proposalId,request_key:requestKey,operation_id:operation})]]);
 const c=await load(context({storage}));c.getState().busy=true;c.events.pagehide();await c.events.pageshow({persisted:true});
 assert.equal(c.getState().busy,false);assert.equal(c.element('load').disabled,false);assert.equal(c.timers.size,1);assert.equal(c.element('prepare').disabled,true);
});

test('attention explains changed approval and retains the existing request',async()=>{
 const c=await load(context());const saved={job_id:job,proposal_id:proposalId,request_key:requestKey,operation_id:operation};
 c.getState().request=saved;c.fetch=async()=>({ok:true,json:async()=>({...receipt('needs_attention'),reason_code:'approval_changed_after_preparation'})});
 await c.pollOperation();c.render();
 assert.match(c.element('status').textContent,/승인·권한 또는 배포 조건이 변경/);
 assert.match(c.element('status').textContent,/운영자에게 전달/);
 assert.match(c.element('status').textContent,/새 준비 요청을 보내지 마세요/);
 assert.match(c.element('status').textContent,new RegExp(operation));
 assert.equal(c.getState().request,saved);assert.equal(c.timers.size,0);assert.equal(c.element('prepare').disabled,true);
});
test('reason codes only render fixed guidance for their matching status',async()=>{
 const c=await load(context());c.getState().request={job_id:job,proposal_id:proposalId,request_key:requestKey,operation_id:operation};
 c.fetch=async()=>({ok:true,json:async()=>({...receipt('succeeded'),reason_code:'target_evidence_mismatch'})});await c.pollOperation();
 assert.match(c.element('status').textContent,/준비 작업 완료/);assert.doesNotMatch(c.element('status').textContent,/일치하는지|운영자에게 전달/);
 c.fetch=async()=>({ok:true,json:async()=>({...receipt('needs_attention'),reason_code:'<script>private error</script>'})});await c.pollOperation();
 assert.doesNotMatch(c.element('status').textContent,/script|private error/);assert.match(c.element('status').textContent,/운영자에게 전달/);
});
test('temporary validation failure keeps polling the existing operation',async()=>{
 const c=await load(context());c.getState().request={job_id:job,proposal_id:proposalId,request_key:requestKey,operation_id:operation};
 c.fetch=async()=>({ok:true,json:async()=>({...receipt('queued'),reason_code:'validation_retry_pending'})});await c.pollOperation();c.render();
 assert.match(c.element('status').textContent,/같은 작업의 재시도/);assert.equal(c.timers.size,1);assert.equal(c.element('prepare').disabled,true);
 assert.equal(c.calls.filter(call=>call.options.method==='POST').length,0);
});
