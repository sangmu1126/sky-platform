import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import test from 'node:test';
const html=readFileSync(new URL('../../src/assets/static/operating-lifecycle.html',import.meta.url),'utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const job='a'.repeat(16),proposal='OPR-'+'b'.repeat(24),operation='11111111-1111-4111-8111-111111111111';
const value=()=>({job_id:job,application_id:'app',phase:'approved',revision:3,database_role:'shared_workload',proposal_status:'approved',proposal_id:proposal,operations:[],capabilities:{review:true,prepare:true,cutover:false,effect_review:false},effect:null,performance:null});
function context({handler,storage=new Map()}={}){
 const elements={},calls=[],events={},timers=[];
 const c={URLSearchParams,console,document:{getElementById(id){return elements[id]??={value:'',textContent:'',disabled:false,checked:false,addEventListener(n,f){this[n]=f}}}},window:{location:{search:''},addEventListener(n,f){events[n]=f}},sessionStorage:{getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,v)},crypto:{randomUUID:()=>operation},setTimeout:f=>{timers.push(f);return timers.length},clearTimeout(){},async fetch(path,options){calls.push({path,options});const response=handler?await handler(path,options):path.endsWith('/operating-review')?{proposal:{proposal_id:proposal}}:value();return {ok:true,json:async()=>response}}};
 runInNewContext(script+'\nglobalThis.getState=()=>state;globalThis.element=el;',c);c.element('job').value=job;Object.assign(c,{calls,storage,events,timers});return c;
}
test('loading or reopening the page only observes; no automatic consent or replay',async()=>{
 const c=context();await c.load();assert.equal(c.calls.length,2);assert.ok(c.calls.every(x=>!x.options.method));assert.equal(c.element('prepare').disabled,true);assert.match(c.element('message').textContent,/조회 자체는 배포나 복구를 실행하지 않습니다/);
});
test('lost response keeps the same job-scoped idempotency key after reopening',async()=>{
 let posts=0;const storage=new Map(),handler=async(path,options)=>{if(options.method==='POST'){posts++;if(posts===1)throw Error('response lost');return {operation_id:operation,status:'queued'}}return path.endsWith('/operating-review')?{proposal:{proposal_id:proposal}}:value()};
 const a=context({handler,storage});await a.load();a.element('consent').checked=true;a.render();await a.act('prepare');assert.equal(posts,1);
 const b=context({handler,storage});await b.load();assert.equal(posts,1);b.element('consent').checked=true;b.render();await b.act('prepare');
 const body=c=>JSON.parse(c.calls.find(x=>x.options.method==='POST').options.body);assert.deepEqual(body(a),body(b));assert.equal(body(b).request_key,operation);assert.ok(b.calls.every(x=>x.options.credentials==='same-origin'&&x.options.cache==='no-store'));
});
test('unknown results block new mutations and absent recovery authority stays disabled',async()=>{
 const c=context({handler:async()=>({...value(),phase:'needs_attention',capabilities:{},operations:[{id:operation,kind:'db_dedicated_cutover',status:'needs_attention',requires_attention:true,recovery_enabled:false}]})});await c.load();assert.equal(c.element('cutover').disabled,true);assert.equal(c.element('resume').disabled,true);assert.match(c.element('recovery').textContent,/등록된 웹 복구 실행기가 없습니다/);assert.ok(c.calls.every(x=>!x.options.method));
});
test('changing jobs clears stale capabilities and earlier consent on failed lookup',async()=>{
 let fail=false;const c=context({handler:async(path)=>{if(fail)throw Error('not found');return path.endsWith('/operating-review')?{proposal:{proposal_id:proposal}}:value()}});await c.load();c.element('consent').checked=true;c.render();assert.equal(c.element('prepare').disabled,false);fail=true;c.element('job').value='f'.repeat(16);await c.load();assert.equal(c.getState().value,null);assert.equal(c.element('prepare').disabled,true);assert.equal(c.element('consent').checked,false);
});
