/* Access tokens stay in memory. Session storage contains only a short-lived PKCE transaction. */
(() => {
  'use strict';
  // A same-origin operating panel reuses the parent's in-memory session.
  try { if (window.parent && window.parent !== window && window.parent.location.origin === window.location.origin && window.parent.skyAuth) { window.skyAuth = window.parent.skyAuth; return; } } catch {}
  const nativeFetch = window.fetch.bind(window), transactionKey = 'sky-cognito-pkce-v1';
  const callbackParams = new URLSearchParams(window.location.search), callbackFragment = window.location.hash;
  const isCallback = window.location.pathname === '/auth/callback';
  if (isCallback) window.history.replaceState(null, '', '/prepare');
  let config, accessToken = null, expiresAt = 0;
  const fail = () => new Error('로그인을 확인할 수 없습니다. 로그인 화면에서 다시 시도해 주세요.');
  const b64 = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const random = size => b64(crypto.getRandomValues(new Uint8Array(size)));
  function dom(fn) { if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',fn,{once:true}); else fn(); }
  function showError() { dom(() => { const target=document.getElementById('sky-login-status')||document.getElementById('message');if(target) target.textContent=fail().message; }); }
  async function json(response) {
    if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw fail();
    return response.json();
  }
  function validate(value) {
    if (value.origin !== window.location.origin || !value.origin.startsWith('https://') || value.redirect_uri !== value.origin+'/auth/callback' || value.logout_uri !== value.origin+'/login' || !/^[A-Za-z0-9]{1,128}$/.test(value.client_id) || !Array.isArray(value.scopes) || !value.scopes.length || value.scopes.some(s=>typeof s!=='string'||!/^[!-~]{1,128}$/.test(s))) throw fail();
    const authorize=new URL(value.authorization_endpoint),token=new URL(value.token_endpoint),logout=new URL(value.logout_endpoint);
    if(authorize.protocol!=='https:'||!authorize.hostname.endsWith('.amazoncognito.com')||authorize.username||authorize.password||authorize.port||authorize.pathname!=='/oauth2/authorize'||authorize.search||authorize.hash||token.href!==authorize.origin+'/oauth2/token'||logout.href!==authorize.origin+'/logout') throw fail();
    return value;
  }
  async function login() {
    await configured;
    const verifier=random(48),state=random(32),created=Date.now();
    const challenge=b64(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))));
    sessionStorage.setItem(transactionKey,JSON.stringify({verifier,state,created,redirect_uri:config.redirect_uri}));
    const url=new URL(config.authorization_endpoint);
    url.search=new URLSearchParams({response_type:'code',client_id:config.client_id,redirect_uri:config.redirect_uri,scope:config.scopes.join(' '),state,code_challenge:challenge,code_challenge_method:'S256'}).toString();
    window.location.assign(url.href);
  }
  async function finish() {
    const saved=sessionStorage.getItem(transactionKey);sessionStorage.removeItem(transactionKey);
    if (callbackFragment || callbackParams.has('error') || callbackParams.getAll('code').length!==1 || callbackParams.getAll('state').length!==1) throw fail();
    let transaction;try{transaction=JSON.parse(saved);}catch{throw fail();}
    if(!transaction||typeof transaction.state!=='string'||transaction.state!==callbackParams.get('state')||typeof transaction.verifier!=='string'||!/^[A-Za-z0-9_-]{64}$/.test(transaction.verifier)||transaction.redirect_uri!==config.redirect_uri||!Number.isSafeInteger(transaction.created)||Date.now()-transaction.created<0||Date.now()-transaction.created>600000)throw fail();
    const code=callbackParams.get('code');if(!code||code.length>4096)throw fail();
    const value=await json(await nativeFetch(config.token_endpoint,{method:'POST',credentials:'omit',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:config.client_id,redirect_uri:config.redirect_uri,code,code_verifier:transaction.verifier}).toString()}));
    if(value.token_type!=='Bearer'||typeof value.access_token!=='string'||!value.access_token.length||value.access_token.length>16384||!Number.isSafeInteger(value.expires_in)||value.expires_in<1||value.expires_in>86400)throw fail();
    accessToken=value.access_token;expiresAt=Date.now()+value.expires_in*1000;
  }
  const configured=jsonFromConfig();
  async function jsonFromConfig(){config=validate(await json(await nativeFetch('/auth/config',{credentials:'omit',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(10000)})));}
  const ready=(async()=>{
    await configured;
    if(isCallback) {await finish();dom(()=>{const button=document.createElement('button');button.type='button';button.textContent='로그아웃';button.className='secondary';button.addEventListener('click',logout);(document.querySelector('header')||document.querySelector('main')).append(button);});return true;}
    if(window.location.pathname==='/login'){dom(()=>document.getElementById('sky-login')?.addEventListener('click',()=>login().catch(showError)));return false;}
    await login();return new Promise(()=>{});
  })();
  ready.catch(showError);
  function logout(){accessToken=null;expiresAt=0;sessionStorage.removeItem(transactionKey);const url=new URL(config.logout_endpoint);url.search=new URLSearchParams({client_id:config.client_id,logout_uri:config.logout_uri}).toString();window.location.assign(url.href);}
  async function authenticatedFetch(path,options={}){
    await ready;
    const url=new URL(path,window.location.origin);
    if(url.origin!==window.location.origin||!url.pathname.startsWith('/api/')||url.username||url.password)throw fail();
    if(!accessToken||Date.now()>=expiresAt){accessToken=null;throw new Error('로그인이 만료됐습니다. 다시 로그인해 주세요.');}
    const headers=new Headers(options.headers||{});headers.set('Authorization','Bearer '+accessToken);
    return nativeFetch(url.pathname+url.search,{...options,headers,credentials:'omit',cache:'no-store',redirect:'error'});
  }
  window.skyAuth=Object.freeze({ready,fetch:authenticatedFetch,login,logout});
})();
