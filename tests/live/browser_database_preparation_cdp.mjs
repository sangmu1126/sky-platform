// Trusted loopback fixture only: real Chrome DOM/network/storage, no cloud calls.
import assert from 'node:assert/strict';
import {mkdirSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';

const [origin, port, job, operation, output] = process.argv.slice(2);
assert.match(origin, /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(job, /^[a-f0-9]{16}$/);
const tabs = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const tab = tabs.find(item => item.type === 'page');
assert.ok(tab?.webSocketDebuggerUrl);
const socket = new WebSocket(tab.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(Error('Chrome socket timeout')), 10000);
  socket.addEventListener('open', () => {clearTimeout(timer); resolve();}, {once: true});
  socket.addEventListener('error', reject, {once: true});
});
const pending = new Map(), posts = [], consoleErrors = [];
let serial = 0, responseLost = false, interceptionError;
function command(method, params = {}) {
  const id = ++serial;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {pending.delete(id); reject(Error(`${method} timeout`));}, 15000);
    pending.set(id, {resolve: value => {clearTimeout(timer); resolve(value);}, reject: error => {clearTimeout(timer); reject(error);}});
    socket.send(JSON.stringify({id, method, params}));
  });
}
socket.addEventListener('message', event => {
  const value = JSON.parse(event.data), waiter = pending.get(value.id);
  if (waiter) {pending.delete(value.id);value.error ? waiter.reject(Error(value.error.message)) : waiter.resolve(value.result);return;}
  if (value.method === 'Runtime.exceptionThrown') consoleErrors.push(value.params.exceptionDetails.text);
  if (value.method === 'Network.requestWillBeSent' && value.params.request.method === 'POST') {
    posts.push({url:value.params.request.url, body:JSON.parse(value.params.request.postData)});
  }
  if (value.method === 'Fetch.requestPaused') {
    const event = value.params;
    (async () => {
      if (!responseLost && event.request.method === 'POST' && event.request.url === `${origin}/api/jobs/${job}/database-preparation`) {
        responseLost = true;
        await command('Fetch.failRequest', {requestId:event.requestId,errorReason:'ConnectionAborted'});
        await command('Fetch.disable');
      } else await command('Fetch.continueRequest', {requestId:event.requestId});
    })().catch(error => {interceptionError = error;});
  }
});
async function evaluate(expression) {
  const result = await command('Runtime.evaluate', {expression,awaitPromise:true,returnByValue:true});
  if (result.exceptionDetails) throw Error(result.exceptionDetails.text);
  return result.result.value;
}
async function until(expression, seconds=20) {
  const deadline = Date.now() + seconds*1000;
  while (Date.now() < deadline) {
    if (interceptionError) throw interceptionError;
    try {const value = await evaluate(expression); if (value) return value;}
    catch (error) {if (!/context.*destroyed|Cannot find context|Inspected target navigated/i.test(error.message)) throw error;}
    await new Promise(resolve => setTimeout(resolve,100));
  }
  throw Error('Browser preparation check timed out: '+expression);
}
async function screenshot(name) {
  if (!output) return;
  mkdirSync(output,{recursive:true});
  const capture = await command('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});
  writeFileSync(join(output,name),Buffer.from(capture.data,'base64'));
}
try {
  await command('Page.enable');await command('Runtime.enable');await command('Network.enable');
  await command('Network.setExtraHTTPHeaders',{headers:{Authorization:'deployer'}});
  // The backend fixture also uses this fixed time; production Date remains unchanged.
  await command('Page.addScriptToEvaluateOnNewDocument',{source:"Date.now=()=>Date.parse('2026-10-11T00:00:00Z');"});
  await command('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
  await command('Page.navigate',{url:`${origin}/database-preparation?job=${job}`});
  await until("document.getElementById('approve') && !document.getElementById('approve').disabled");
  assert.equal(await evaluate("document.getElementById('prepare').disabled"),true);
  assert.match(await evaluate("document.getElementById('summary').textContent"),/USD 25.00/);
  await evaluate("document.getElementById('approve').click()");
  await until("!document.getElementById('consent').disabled && document.getElementById('summary').textContent.includes('승인됨')");
  assert.equal(posts.filter(item=>item.url.endsWith('/database-preparation')).length,0);
  await screenshot('preparation-desktop.png');
  await command('Fetch.enable',{patterns:[{urlPattern:`${origin}/api/jobs/${job}/database-preparation`,requestStage:'Response'}]});
  await evaluate("document.getElementById('consent').click();document.getElementById('prepare').click()");
  await until("document.getElementById('status').textContent.includes('같은 요청 키') && !document.getElementById('prepare').disabled");
  assert.equal(responseLost,true);
  const firstKey = posts.filter(item=>item.url.endsWith('/database-preparation'))[0].body.request_key;
  await command('Page.reload');
  await until("document.getElementById('prepare')?.textContent==='동일 준비 요청 확인' && !document.getElementById('consent').disabled");
  await evaluate("document.getElementById('consent').click();document.getElementById('prepare').click()");
  await until(`document.getElementById('status').textContent.includes('${operation}') && !document.getElementById('load').disabled`);
  const admissions = posts.filter(item=>item.url.endsWith('/database-preparation'));
  assert.equal(admissions.length,2);assert.equal(admissions[1].body.request_key,firstKey);
  assert.deepEqual(Object.keys(admissions[1].body).sort(),['confirm_preparation','proposal_id','request_key']);
  await command('Page.reload');
  await until(`document.getElementById('status')?.textContent.includes('${operation}')`);
  await until("document.getElementById('status').textContent.includes('전용 DB 준비 작업 완료')");
  assert.match(await evaluate("document.getElementById('status').textContent"),/데이터 이전과 트래픽 전환은 진행하지 않았습니다/);
  assert.equal(await evaluate("document.getElementById('prepare').disabled"),true);
  await command('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  const summary = await evaluate("document.getElementById('summary').textContent");
  await evaluate("document.getElementById('summary').textContent+='\\n'+'long-evidence-'.repeat(80)");
  assert.equal(await evaluate('document.documentElement.scrollWidth<=window.innerWidth'),true);
  await evaluate(`document.getElementById('summary').textContent=${JSON.stringify(summary)}`);
  await screenshot('preparation-mobile.png');
  assert.deepEqual(consoleErrors,[]);
  const report={status:'passed',browser:'Chrome CDP',approval_separate:true,admission_posts:admissions.length,same_request_key:true,response_loss_after_server_admission:true,reload_resumes_same_operation:true,mobile_no_horizontal_overflow:true,cloud_calls:false};
  if (output) writeFileSync(join(output,'browser-result.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify(report));
} catch (error) {
  try {
    console.error(JSON.stringify(await evaluate("({status:document.getElementById('status')?.textContent,summary:document.getElementById('summary')?.textContent})")));
    await screenshot('preparation-failed.png');
  } catch { /* Preserve the original browser failure. */ }
  throw error;
} finally {
  socket.close();
}
