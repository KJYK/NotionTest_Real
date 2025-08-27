// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Client } = require('@notionhq/client');
const { createHmac, timingSafeEqual } = require('crypto');
const path = require('path');

const app = express();

// ----- 기본 설정 & CORS -----
const PORT = process.env.PORT || 3000;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || `http://localhost:${PORT}`;
app.use(cors({ origin: ALLOWED_ORIGIN, credentials: false }));
app.use(express.json({ limit: '1mb' }));

// ----- Notion 클라이언트 -----
const notion = new Client({ auth: process.env.NOTION_TOKEN });
const DB_ID = process.env.NOTION_DATABASE_ID;
const WEBHOOK_SECRET = process.env.NOTION_WEBHOOK_SECRET;

// ----- 정적 파일 서빙 -----
app.use(express.static(path.join(__dirname, 'public')));

// ----- SSE(실시간 브로드캐스트) -----
const sseClients = new Set();
function sseHeaders(res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
}
function sseSend(res, event, data = {}) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}
function sseBroadcast(event, data = {}) {
  for (const client of sseClients) {
    sseSend(client, event, data);
  }
}
let reloadTimer = null;
function scheduleReload() {
  clearTimeout(reloadTimer);
  reloadTimer = setTimeout(() => sseBroadcast('reload', { t: Date.now() }), 200);
}

app.get('/api/stream', (req, res) => {
  sseHeaders(res);
  sseSend(res, 'hello', { ok: true });
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

// 25초마다 keepalive
setInterval(() => sseBroadcast('ping', { t: Date.now() }), 25000);

// ----- 노션 데이터 → 평평한 아이템 배열 -----
function richToText(r) {
  return (r || []).map(v => v.plain_text || '').join('');
}
function getDate(prop) {
  return prop?.date?.start || null; // YYYY-MM-DD or ISO8601
}
function pageToItem(p) {
  const props = p.properties || {};
  // Title은 'item name' 권장. 만약 'Name'을 쓰고 있다면 그것도 폴백.
  const title = (props['item name']?.title || props['Name']?.title || []);
  return {
    id: p.id,
    name: (title[0]?.plain_text || '').trim(),
    level: props['level']?.number ?? null,
    upper: richToText(props['upper']?.rich_text) || null,
    dependency: richToText(props['dependency']?.rich_text) || null,
    early_start: getDate(props['early start']),
    late_start: getDate(props['late start']),
    early_finish: getDate(props['early finish']),
    late_finish: getDate(props['late finish']),
    done: props['Done']?.checkbox === true
  };
}

async function fetchAllItems() {
  let items = [];
  let cursor = undefined;
  do {
    const resp = await notion.databases.query({
      database_id: DB_ID,
      start_cursor: cursor,
      page_size: 100,
      sorts: [
        { property: 'level', direction: 'ascending' },
        { timestamp: 'last_edited_time', direction: 'ascending' }
      ]
    });
    items = items.concat(resp.results.map(pageToItem).filter(x => x.name));
    cursor = resp.has_more ? resp.next_cursor : undefined;
  } while (cursor);
  return items;
}

// ----- API: 현재 아이템 목록 -----
app.get('/api/items', async (req, res) => {
  try {
    const items = await fetchAllItems();
    res.json({ items });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'notion query failed', detail: e?.message });
  }
});

// ----- API: Notion 웹훅 수신 -----
app.post('/api/notion-webhook', async (req, res) => {
  try {
    // 1) 최초 구독 검증 단계: verification_token 수신 → 콘솔 출력해서 UI에 붙여넣기
    if (req.body && req.body.verification_token && !WEBHOOK_SECRET) {
      console.log('\n[Notion Webhook] verification_token received:');
      console.log(req.body.verification_token);
      console.log('👉 이 값을 Notion Webhooks UI의 Verify 창에 붙여넣어 검증을 완료하세요.');
      return res.status(200).json({ ok: true, step: 'verification' });
    }

    // 2) 일반 이벤트 검증(권장) - X-Notion-Signature 헤더(HMAC-SHA256)
    if (WEBHOOK_SECRET) {
      const signatureHeader = req.header('X-Notion-Signature') || req.header('x-notion-signature') || '';
      const payloadMinified = JSON.stringify(req.body);
      const calc = 'sha256=' + createHmac('sha256', WEBHOOK_SECRET).update(payloadMinified).digest('hex');

      const trusted =
        signatureHeader.length === calc.length &&
        timingSafeEqual(Buffer.from(signatureHeader), Buffer.from(calc));

      if (!trusted) {
        console.warn('[Notion Webhook] signature mismatch, ignoring.');
        return res.status(202).json({ ok: false, reason: 'signature_mismatch' });
      }
    }

    // 3) 이벤트 수신 → 클라이언트에 'reload' 브로드캐스트
    scheduleReload();

    // Notion에 2xx로 응답해야 재시도(최대 8회)가 멈춥니다.
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false });
  }
});

// ----- 서버 기동 -----
app.listen(PORT, () => {
  console.log(`\n▶ Server running: http://localhost:${PORT}`);
  console.log(`   Static: /  |  SSE: /api/stream  |  Items: /api/items  |  Webhook: /api/notion-webhook`);
});
