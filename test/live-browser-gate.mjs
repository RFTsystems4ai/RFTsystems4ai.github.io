import { chromium, firefox, webkit } from 'playwright';
import assert from 'node:assert/strict';

const BASE='https://rftsystems4ai.github.io';
const browsers=[['chromium',chromium],['firefox',firefox],['webkit',webkit]];

async function expectText(page,selector,pattern,timeout=15000){await page.locator(selector).waitFor({state:'visible',timeout});const text=(await page.locator(selector).innerText()).trim();assert.match(text,pattern,`${page.url()} ${selector} => ${text}`);return text;}
async function captureDownload(page,clickSelector){const [download]=await Promise.all([page.waitForEvent('download'),page.locator(clickSelector).click()]);return await download.path();}
async function noPageErrors(page,label){const errors=[];page.on('pageerror',e=>errors.push(String(e)));page.on('console',msg=>{if(msg.type()==='error')errors.push(`console: ${msg.text()}`)});return()=>assert.deepEqual(errors,[],`${label} browser errors: ${errors.join(' | ')}`);}

async function runBrowser(name,type){
  const browser=await type.launch({headless:true});
  const context=await browser.newContext({acceptDownloads:true,reducedMotion:'reduce'});
  try{
    const page=await context.newPage();const checkErrors=await noPageErrors(page,`${name}/start`);
    await page.goto(`${BASE}/`,{waitUntil:'domcontentloaded',timeout:30000});
    await page.waitForURL(/\/lab\/start-here\/?$/,{timeout:15000});
    await expectText(page,'h1',/Your AI chose/i);
    await expectText(page,'#verdictTitle',/CHAIN VALID/);
    await page.locator('#tamperButton').click();await expectText(page,'#verdictTitle',/BREAK AT EVENT 03/);
    await page.locator('[data-incident="actions"]').focus();await page.keyboard.press('ArrowRight');assert.equal(await page.locator('[data-incident="memory"]').getAttribute('aria-checked'),'true');
    checkErrors();

    await page.goto(`${BASE}/lab/flight-recorder/`,{waitUntil:'domcontentloaded'});const flightErrors=await noPageErrors(page,`${name}/flight`);
    await page.locator('#buildBtn').click();await page.locator('#verifyBtn').click();await expectText(page,'#reportTitle',/INTERNAL CONSISTENCY PASS/);
    const passFlight=await captureDownload(page,'#downloadBtn');
    await page.locator('#tamperBtn').click();await page.locator('#verifyBtn').click();await expectText(page,'#reportTitle',/INTERNAL CONSISTENCY FAIL AT EVENT 04/);
    const failFlight=await captureDownload(page,'#downloadBtn');flightErrors();

    await page.goto(`${BASE}/lab/official-receipt-verifier/`,{waitUntil:'domcontentloaded'});const verifierErrors=await noPageErrors(page,`${name}/verifier`);
    await page.locator('#receiptFile').setInputFiles(passFlight);await expectText(page,'#verdictWord',/AUTHENTICATED · PASS/);
    await page.locator('#resetBtn').click();await page.locator('#receiptFile').setInputFiles(failFlight);await expectText(page,'#verdictWord',/AUTHENTICATED · FAIL/);verifierErrors();

    await page.goto(`${BASE}/lab/memory-receipt/`,{waitUntil:'domcontentloaded'});const memoryErrors=await noPageErrors(page,`${name}/memory`);
    await page.locator('#loadBtn').click();await page.locator('[data-key="deployment_state"]').click();await page.locator('#verifyBtn').click();await expectText(page,'#bindingState',/^PASS$/);const passMemory=await captureDownload(page,'#downloadBtn');
    await page.locator('#tamperBtn').click();await page.locator('#verifyBtn').click();await expectText(page,'#bindingState',/^FAIL$/);const failMemory=await captureDownload(page,'#downloadBtn');memoryErrors();
    await page.goto(`${BASE}/lab/official-receipt-verifier/`,{waitUntil:'domcontentloaded'});await page.locator('#receiptFile').setInputFiles(passMemory);await expectText(page,'#verdictWord',/AUTHENTICATED · PASS/);await page.locator('#resetBtn').click();await page.locator('#receiptFile').setInputFiles(failMemory);await expectText(page,'#verdictWord',/AUTHENTICATED · FAIL/);

    await page.goto(`${BASE}/lab/timelinediff/`,{waitUntil:'domcontentloaded'});const timelineErrors=await noPageErrors(page,`${name}/timeline`);
    await page.locator('#generateBtn').click();await page.locator('#diffBtn').click();await expectText(page,'#firstDiff',/EVENT 04/);await expectText(page,'#aIntegrity',/^PASS$/);await expectText(page,'#bIntegrity',/^PASS$/);const passTimeline=await captureDownload(page,'#downloadBtn');
    await page.locator('#tamperBtn').click();await page.locator('#diffBtn').click();await expectText(page,'#bIntegrity',/FAIL/);const failTimeline=await captureDownload(page,'#downloadBtn');timelineErrors();
    await page.goto(`${BASE}/lab/official-receipt-verifier/`,{waitUntil:'domcontentloaded'});await page.locator('#receiptFile').setInputFiles(passTimeline);await expectText(page,'#verdictWord',/AUTHENTICATED · PASS/);await page.locator('#resetBtn').click();await page.locator('#receiptFile').setInputFiles(failTimeline);await expectText(page,'#verdictWord',/AUTHENTICATED · FAIL/);

    await page.goto(`${BASE}/lab/truststack/`,{waitUntil:'domcontentloaded'});const trustErrors=await noPageErrors(page,`${name}/trust`);
    for(const [packet,expected] of [['signed','ALLOW'],['legacy','HOLD'],['tampered','BLOCK'],['substituted','BLOCK']]){await page.locator(`[data-packet="${packet}"]`).click();await page.locator('#gateBtn').click();await expectText(page,'#decisionWord',new RegExp(`^${expected}$`));}
    trustErrors();

    await page.goto(`${BASE}/challenge/001-break-flight-recorder/`,{waitUntil:'domcontentloaded'});const challengeErrors=await noPageErrors(page,`${name}/challenge`);
    await expectText(page,'#verdictText',/^PASS$/);await page.locator('[data-attack="modify"]').click();await expectText(page,'#verdictText',/^FAIL$/);const failChallenge=await captureDownload(page,'#downloadBtn');challengeErrors();
    await page.goto(`${BASE}/lab/official-receipt-verifier/`,{waitUntil:'domcontentloaded'});await page.locator('#receiptFile').setInputFiles(failChallenge);await expectText(page,'#verdictWord',/AUTHENTICATED · FAIL/);

    await page.goto(`${BASE}/evolution-data/`,{waitUntil:'domcontentloaded'});const evolutionErrors=await noPageErrors(page,`${name}/evolution`);
    await expectText(page,'#integrity',/SIGNED DATASET COMMITMENT MATCH/);await page.selectOption('#scenario','cost_reduction');await page.selectOption('#retention','full_family');await page.locator('#run').click();await expectText(page,'#selectionSummary',/Cost discipline · Full family retained/);assert.equal((await page.locator('.family').count()),10);const evolutionResult=await captureDownload(page,'#download');evolutionErrors();
    await page.goto(`${BASE}/evolution-data/verify.html`,{waitUntil:'domcontentloaded'});const evolutionVerifyErrors=await noPageErrors(page,`${name}/evolution-verify`);await page.locator('#file').setInputFiles(evolutionResult);await expectText(page,'#word',/AUTHENTICATED · PASS/);await expectText(page,'#summary',/10 families/);evolutionVerifyErrors();

    console.log(`LIVE_BROWSER_PASS ${name}`);
  } finally { await context.close(); await browser.close(); }
}

for(const [name,type] of browsers) await runBrowser(name,type);
console.log('LIVE_RELEASE_GATE_PASS chromium firefox webkit');
