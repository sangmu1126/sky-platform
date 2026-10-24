import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {webcrypto} from 'node:crypto';
import test from 'node:test';
const source=readFileSync(new URL('../../src/assets/static/cognito-auth.js',import.meta.url),'utf8');
const app='https://sky.example.test',domain='https://personal.auth.ap-northeast-2.amazoncognito.com';
const config={origin:app,client_id:'client123',authorization_endpoint:domain+'/oauth2/authorize',token_endpoint:domain+'/oauth2/token',logout_endpoint:domain+'/logout',redirect_uri:app+'/auth/callback',logout_uri:app+'/login',scopes:['openid','sky/deploy']};
const key='sky-cognito-pkce-v1';
function boot({path='/prepare',query='',hash='',storage=new Map(),tokenReply,configuration=config}={}){
 const calls=[],redirects=[],replacements=[],elements=new Map();
 const location={origin:app,pathname:path,search:query,hash,assign:url=>redirects.push(url)};
 const element=()=>({textContent:'',append(){},addEventListener(name,fn){this[name]=fn;}});
 elements.set('sky-login',element());elements.set('sky-login-status',element());elements.set('message',element());
 const c={URL,URLSearchParams,Headers,TextEncoder,Uint8Array,AbortSignal,Date,crypto:webcrypto,btoa:s=>Buffer.from(s,'binary').toString('base64'),
 sessionStorage:{getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
 document:{readyState:'complete',getElementById:id=>elements.get(id),querySelector:()=>element(),createElement:element},
 window:{location,history:{replaceState(a,b,path){replacements.push(path);location.search='';location.hash='';location.pathname=path;}},
 async fetch(path,options={}){calls.push({path,options});const value=path==='/auth/config'?configuration:path===config.token_endpoint?(tokenReply||{token_type:'Bearer',access_token:'fixture-access-token',expires_in:600,refresh_token:'must-not-be-stored'}):{ok:true};return {ok:true,headers:new Headers({'content-type':'application/json'}),json:async()=>value};}}};
 runInNewContext(source,c);return {...c,storage,calls,redirects,replacements,elements};
}
async function until(fn){for(let i=0;i<100;i++){if(fn())return;await new Promise(r=>setTimeout(r,2));}assert.fail('Browser flow did not settle');}
async function start(){const c=boot();await until(()=>c.redirects.length);return c;}
function callback(storage,changes={}){const tx=JSON.parse(storage.get(key));return boot({path:'/auth/callback',query:'?'+new URLSearchParams({code:'one-time-code',state:tx.state}),storage,...changes});}

test('authorization uses code, S256 and a bounded one-tab transaction',async()=>{
 const c=await start(),url=new URL(c.redirects[0]),tx=JSON.parse(c.storage.get(key));
 assert.equal(url.origin,domain);assert.equal(url.searchParams.get('response_type'),'code');assert.equal(url.searchParams.get('code_challenge_method'),'S256');
 assert.match(tx.verifier,/^[A-Za-z0-9_-]{64}$/);assert.match(tx.state,/^[A-Za-z0-9_-]{43}$/);assert.equal(tx.redirect_uri,config.redirect_uri);
 const challenge=Buffer.from(await webcrypto.subtle.digest('SHA-256',new TextEncoder().encode(tx.verifier))).toString('base64url');
 assert.equal(url.searchParams.get('code_challenge'),challenge);assert.ok(!url.href.includes(tx.verifier));
 assert.equal(c.calls.length,1);assert.equal(c.storage.size,1);
});

test('callback consumes transaction and keeps access/refresh tokens out of storage and history',async()=>{
 const started=await start(),c=callback(started.storage);assert.equal(await c.window.skyAuth.ready,true);
 assert.equal(c.storage.size,0);assert.deepEqual(c.replacements,['/prepare']);
 const exchange=c.calls.find(x=>x.path===config.token_endpoint),body=new URLSearchParams(exchange.options.body);
 assert.equal(body.get('code'),'one-time-code');assert.equal(body.get('grant_type'),'authorization_code');assert.equal(body.get('redirect_uri'),config.redirect_uri);assert.equal(exchange.options.credentials,'omit');assert.equal(exchange.options.redirect,'error');assert.ok(!body.has('client_secret'));
 await c.window.skyAuth.fetch('/api/config',{headers:{Authorization:'untrusted'}});
 const sent=c.calls.at(-1);assert.equal(sent.options.headers.get('Authorization'),'Bearer fixture-access-token');assert.equal(sent.options.credentials,'omit');
 assert.ok(!JSON.stringify([...c.storage]).includes('fixture-access-token'));assert.ok(!c.replacements.some(x=>x.includes('token')||x.includes('one-time-code')));
 await assert.rejects(c.window.skyAuth.fetch('https://evil.test/api/config'));
 await assert.rejects(c.window.skyAuth.fetch('/auth/config'));
 c.window.skyAuth.logout();assert.equal(new URL(c.redirects.at(-1)).pathname,'/logout');
 await assert.rejects(c.window.skyAuth.fetch('/api/config'));
});

for(const variant of ['state','missing','expired','future','fragment','duplicate','replay']){
 test('invalid '+variant+' callback never reaches token endpoint',async()=>{
  const started=await start(),tx=JSON.parse(started.storage.get(key));let changes={};
  if(variant==='state')changes.query='?code=one&state=wrong';
  if(variant==='missing')changes.query='?state='+tx.state;
  if(variant==='duplicate')changes.query='?code=one&code=two&state='+tx.state;
  if(variant==='fragment')changes.hash='#access_token=untrusted';
  if(variant==='expired'||variant==='future'){tx.created+=variant==='expired'?-700000:700000;started.storage.set(key,JSON.stringify(tx));}
  if(variant==='replay')started.storage.delete(key);
  const c=boot({path:'/auth/callback',query:'?code=one&state='+tx.state,storage:started.storage,...changes});
  await assert.rejects(c.window.skyAuth.ready);assert.equal(c.calls.length,1);assert.equal(c.storage.size,0);
 });
}

test('login landing waits for user action and no credential is persisted',async()=>{
 const c=boot({path:'/login'});assert.equal(await c.window.skyAuth.ready,false);assert.equal(c.redirects.length,0);
 c.elements.get('sky-login').click();await until(()=>c.redirects.length);assert.equal(c.storage.size,1);
});

test('configuration cannot redirect login to another application',async()=>{
 const c=boot({configuration:{...config,redirect_uri:'https://evil.test/callback'}});await assert.rejects(c.window.skyAuth.ready);assert.equal(c.redirects.length,0);
});

test('invalid token reply never authenticates API calls',async()=>{
 const started=await start(),c=callback(started.storage,{tokenReply:{token_type:'Bearer',access_token:'bad',expires_in:0}});
 await assert.rejects(c.window.skyAuth.ready);await assert.rejects(c.window.skyAuth.fetch('/api/config'));
 assert.ok(!c.calls.some(x=>x.path==='/api/config'));
});
