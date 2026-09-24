/* =====================================================================
   bank.js — قراءة كشف الحساب البنكي (Excel ‎.xlsx أو CSV) بدون مكتبات خارجية
   ---------------------------------------------------------------------
   - readStatement(bytes, fileName) → { rows: string[][] }
   - detectColumns(rows) → { header, map }  (map: date, desc[], debit, credit, amount, balance)
   - normalize(rows, map, header) → { items, errors }  كل عملية: { date, desc, dir:'out'|'in', amountH }
   - fingerprints(items) → بصمة لكل عملية لمنع الاستيراد المكرر
   - suggest(desc, dir) → رقم حساب مقترح من الكلمات الدالة
   المبالغ بالهللة (أعداد صحيحة) كبقية النظام.
   ===================================================================== */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.HirafBank = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class StatementError extends Error {}
  const MAX_ROWS = 2000;

  /* ---------------- النص ---------------- */
  /** يفك ترميز الملف: UTF-8 أولاً، وإن فشل فـ Windows-1256 (ترميز Excel العربي القديم) */
  function decodeText(bytes) {
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes).replace(/^﻿/, ''); }
    catch { return new TextDecoder('windows-1256').decode(bytes); }
  }

  /** توحيد النص العربي للمقارنة: الهمزات والتاء المربوطة والياء، وحذف التشكيل */
  function normAr(s) {
    return String(s ?? '').toLowerCase()
      .replace(/[ً-ْـ]/g, '')
      .replace(/[أإآٱ]/g, 'ا').replace(/ة/g, 'ه').replace(/ى/g, 'ي')
      .replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660))
      .replace(/\s+/g, ' ').trim();
  }

  /* ---------------- CSV ---------------- */
  function parseCSV(text) {
    const sample = text.split(/\r?\n/).slice(0, 20).join('\n');
    const count = (ch) => { let n = 0, q = false; for (const c of sample) { if (c === '"') q = !q; else if (!q && c === ch) n++; } return n; };
    const delim = [',', ';', '\t', '|'].map((d) => [d, count(d)]).sort((a, b) => b[1] - a[1])[0][0];
    const rows = []; let row = [], cell = '', q = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; }
        else cell += c;
      } else if (c === '"') q = true;
      else if (c === delim) { row.push(cell); cell = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(cell); rows.push(row); row = []; cell = '';
        if (rows.length > MAX_ROWS + 50) break;
      } else cell += c;
    }
    if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
    return rows.map((r) => r.map((c) => c.trim())).filter((r) => r.some((c) => c !== ''));
  }

  /* ---------------- XLSX (ملف ZIP بداخله XML) ---------------- */
  const u16 = (b, o) => b[o] | (b[o + 1] << 8);
  const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

  function unzipIndex(bytes) {
    let eocd = -1;
    for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) if (u32(bytes, i) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new StatementError('الملف ليس Excel صالحاً (xlsx). احفظه من Excel بصيغة xlsx أو CSV وأعد المحاولة');
    const n = u16(bytes, eocd + 10); let p = u32(bytes, eocd + 16);
    const entries = {};
    const dec = new TextDecoder('utf-8');
    for (let k = 0; k < n; k++) {
      if (u32(bytes, p) !== 0x02014b50) break;
      const method = u16(bytes, p + 10), csize = u32(bytes, p + 20), nlen = u16(bytes, p + 28), xlen = u16(bytes, p + 30), clen = u16(bytes, p + 32), off = u32(bytes, p + 42);
      const name = dec.decode(bytes.subarray(p + 46, p + 46 + nlen));
      entries[name] = { method, csize, off };
      p += 46 + nlen + xlen + clen;
    }
    return entries;
  }
  async function unzipEntry(bytes, e) {
    const lnlen = u16(bytes, e.off + 26), lxlen = u16(bytes, e.off + 28);
    const start = e.off + 30 + lnlen + lxlen;
    const data = bytes.subarray(start, start + e.csize);
    if (e.method === 0) return new TextDecoder('utf-8').decode(data);
    if (e.method !== 8) throw new StatementError('ضغط غير مدعوم داخل ملف Excel');
    if (typeof DecompressionStream === 'undefined') throw new StatementError('المتصفح قديم ولا يقرأ ملفات Excel؛ حدّث المتصفح أو احفظ الكشف بصيغة CSV');
    const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    return new Response(stream).text();
  }
  const xmlText = (s) => s.replace(/<[^>]+>/g, '')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d)).replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&amp;/g, '&');
  const colIndex = (ref) => { let n = 0; for (const ch of ref.replace(/\d+/g, '')) n = n * 26 + (ch.charCodeAt(0) - 64); return n - 1; };

  async function readXlsx(bytes) {
    const entries = unzipIndex(bytes);
    const get = async (name) => (entries[name] ? unzipEntry(bytes, entries[name]) : null);
    // أول ورقة حسب ترتيب المصنف
    let sheetPath = null;
    const wb = await get('xl/workbook.xml'), rels = await get('xl/_rels/workbook.xml.rels');
    if (wb && rels) {
      const first = wb.match(/<sheet\b[^>]*r:id="([^"]+)"/);
      if (first) {
        const rel = rels.match(new RegExp(`<Relationship\\b[^>]*Id="${first[1]}"[^>]*>`));
        const target = rel && rel[0].match(/Target="([^"]+)"/);
        if (target) sheetPath = target[1].startsWith('/') ? target[1].slice(1) : 'xl/' + target[1].replace(/^\.\//, '');
      }
    }
    if (!sheetPath || !entries[sheetPath]) sheetPath = Object.keys(entries).filter((k) => /^xl\/worksheets\/sheet\d+\.xml$/.test(k)).sort()[0];
    if (!sheetPath) throw new StatementError('لم أجد ورقة بيانات داخل ملف Excel');
    const sst = [];
    const ss = await get('xl/sharedStrings.xml');
    if (ss) for (const m of ss.matchAll(/<si>([\s\S]*?)<\/si>/g)) sst.push(xmlText((m[1].match(/<t[^>]*>[\s\S]*?<\/t>/g) || []).join('')));
    const xml = await get(sheetPath);
    const rows = [];
    for (const rm of xml.matchAll(/<row\b[^>]*>([\s\S]*?)<\/row>/g)) {
      const row = [];
      for (const cm of rm[1].matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
        const attrs = cm[1], inner = cm[2] || '';
        const ref = (attrs.match(/\br="([A-Z]+\d+)"/) || [])[1];
        const t = (attrs.match(/\bt="(\w+)"/) || [])[1];
        const v = (inner.match(/<v>([\s\S]*?)<\/v>/) || [])[1];
        let val = '';
        if (t === 's') val = sst[+v] ?? '';
        else if (t === 'inlineStr') val = xmlText((inner.match(/<t[^>]*>[\s\S]*?<\/t>/g) || []).join(''));
        else if (v != null) val = xmlText(v);
        const idx = ref ? colIndex(ref) : row.length;
        row[idx] = String(val).trim();
      }
      for (let i = 0; i < row.length; i++) if (row[i] == null) row[i] = '';
      if (row.some((c) => c !== '')) rows.push(row);
      if (rows.length > MAX_ROWS + 50) break;
    }
    return rows;
  }

  async function readStatement(bytes, fileName = '') {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const name = fileName.toLowerCase();
    if (name.endsWith('.pdf') || (u8[0] === 0x25 && u8[1] === 0x50 && u8[2] === 0x44 && u8[3] === 0x46)) {
      throw new StatementError('ملفات PDF لا تُقرأ آلياً. من تطبيق البنك أو موقعه نزّل الكشف بصيغة Excel أو CSV');
    }
    if (name.endsWith('.xls') && !(u8[0] === 0x50 && u8[1] === 0x4b)) {
      throw new StatementError('صيغة Excel القديمة (xls) غير مدعومة. افتح الملف في Excel واحفظه بصيغة xlsx أو CSV');
    }
    const rows = (u8[0] === 0x50 && u8[1] === 0x4b) ? await readXlsx(u8) : parseCSV(decodeText(u8));
    if (!rows.length) throw new StatementError('الملف فارغ');
    return { rows };
  }

  /* ---------------- التعرف على الأعمدة ---------------- */
  const KEYS = {
    date: ['تاريخ', 'date', 'التاريخ'],
    desc: ['البيان', 'بيان', 'الوصف', 'وصف', 'التفاصيل', 'تفاصيل', 'description', 'details', 'narrative', 'narration', 'particulars', 'transaction details', 'remarks', 'نوع العمليه', 'العمليه', 'memo'],
    debit: ['مدين', 'سحب', 'مسحوبات', 'خصم', 'debit', 'withdrawal', 'withdrawals', 'dr', 'money out', 'paid out'],
    credit: ['دائن', 'ايداع', 'ايداعات', 'مودعات', 'اضافه', 'credit', 'deposit', 'deposits', 'cr', 'money in', 'paid in'],
    amount: ['المبلغ', 'مبلغ', 'amount', 'value', 'القيمه'],
    balance: ['الرصيد', 'رصيد', 'balance', 'running balance'],
  };
  function classify(cell) {
    const c = normAr(cell).replace(/[():.\-_/]/g, ' ').replace(/\s+/g, ' ').trim();
    if (!c || c.length > 40) return null;
    const has = (k) => KEYS[k].some((w) => c === w || c.startsWith(w + ' ') || c.endsWith(' ' + w) || c.includes(' ' + w + ' ') || (w.length > 3 && c.includes(w)));
    if (has('balance')) return 'balance';
    if (has('debit')) return 'debit';
    if (has('credit')) return 'credit';
    if (has('date')) return 'date';
    if (has('amount')) return 'amount';
    if (has('desc')) return 'desc';
    return null;
  }
  function detectColumns(rows) {
    let best = { score: 0, header: -1, map: null };
    for (let r = 0; r < Math.min(rows.length, 40); r++) {
      const map = { date: -1, desc: [], debit: -1, credit: -1, amount: -1, balance: -1 };
      let score = 0;
      rows[r].forEach((cell, i) => {
        const k = classify(cell);
        if (!k) return;
        if (k === 'desc') { map.desc.push(i); score++; }
        else if (map[k] === -1) { map[k] = i; score++; }
      });
      const usable = map.date >= 0 && (map.amount >= 0 || map.debit >= 0 || map.credit >= 0);
      if (usable && score > best.score) best = { score, header: r, map };
    }
    if (best.map) {
      if (!best.map.desc.length) {
        // لا يوجد عمود بيان صريح: نختار أطول عمود نصي
        const used = new Set([best.map.date, best.map.debit, best.map.credit, best.map.amount, best.map.balance]);
        const sample = rows.slice(best.header + 1, best.header + 30);
        let pick = -1, len = 0;
        (rows[best.header] || []).forEach((_, i) => { if (used.has(i)) return; const l = sample.reduce((s, r) => s + String(r[i] || '').length, 0); if (l > len) { len = l; pick = i; } });
        if (pick >= 0) best.map.desc.push(pick);
      }
      return { header: best.header, map: best.map, detected: true };
    }
    return { header: -1, map: { date: -1, desc: [], debit: -1, credit: -1, amount: -1, balance: -1 }, detected: false };
  }

  /* ---------------- القيم ---------------- */
  const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12,
    يناير: 1, فبراير: 2, مارس: 3, ابريل: 4, مايو: 5, يونيو: 6, يوليو: 7, اغسطس: 8, سبتمبر: 9, اكتوبر: 10, نوفمبر: 11, ديسمبر: 12 };
  const pad2 = (n) => String(n).padStart(2, '0');
  function validYMD(y, m, d) {
    if (y < 100) y += 2000;
    if (y < 2000 || y > 2100 || m < 1 || m > 12 || d < 1 || d > 31) return null;
    const dt = new Date(Date.UTC(y, m - 1, d));
    if (dt.getUTCMonth() !== m - 1) return null;
    return `${y}-${pad2(m)}-${pad2(d)}`;
  }
  /** يعيد {iso} أو {parts:[a,b,y]} للتواريخ الملتبسة بين يوم/شهر، أو {hijri:true} */
  function parseDateCell(v) {
    let s = normAr(v);
    if (!s) return null;
    if (/^\d{4,5}(\.\d+)?$/.test(s)) { // رقم تسلسلي من Excel
      const n = Math.floor(+s);
      if (n > 20000 && n < 80000) { const dt = new Date(Date.UTC(1899, 11, 30) + n * 86400000); return { iso: dt.toISOString().slice(0, 10) }; }
      return null;
    }
    s = s.replace(/[t ]\d{1,2}:\d{2}(:\d{2})?(\.\d+)?(z|[+-]\d{2}:?\d{2})?( ?(am|pm|ص|م))?$/i, '').trim();
    let m = s.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$/);
    if (m) { if (+m[1] >= 1300 && +m[1] <= 1500) return { hijri: true }; const iso = validYMD(+m[1], +m[2], +m[3]); return iso ? { iso } : null; }
    m = s.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})$/);
    if (m) { if (+m[3] >= 1300 && +m[3] <= 1500) return { hijri: true }; return { parts: [+m[1], +m[2], +m[3]] }; }
    m = s.match(/^(\d{1,2})[-/ .]([a-z؀-ۿ]+)[-/ .,]*(\d{2,4})$/);
    const mo = m && (MONTHS[m[2]] || MONTHS[m[2].slice(0, 3)]);
    if (mo) { const iso = validYMD(+m[3], mo, +m[1]); return iso ? { iso } : null; }
    m = s.match(/^([a-z]+)[ .-](\d{1,2}),? (\d{4})$/);
    if (m && MONTHS[m[1].slice(0, 3)]) { const iso = validYMD(+m[3], MONTHS[m[1].slice(0, 3)], +m[2]); return iso ? { iso } : null; }
    return null;
  }

  /** مبلغ → هللات موقّعة (سالب = مدين/سحب). يقبل الفواصل والأقواس وعلامة - واللاحقة CR/DR */
  function parseAmount(v) {
    let s = normAr(v);
    if (!s) return null;
    let neg = false;
    if (/\bdr\b|مدين/.test(s)) neg = true;
    if (/^\(.*\)$/.test(s)) neg = true;
    s = s.replace(/sar|ر\.?س|ريال|cr|dr|مدين|دائن/g, '').replace(/[٬,\s]/g, '').replace(/٫/g, '.').replace(/[()]/g, '');
    if (/^-/.test(s) || /-$/.test(s)) { neg = true; s = s.replace(/-/g, ''); }
    if (s.startsWith('+')) s = s.slice(1);
    if (!/^\d+(\.\d+)?$/.test(s)) return null;
    const h = Math.round(Number(s) * 100);
    if (!Number.isSafeInteger(h) || h > 900000000000000) return null;
    return neg ? -h : h;
  }

  const SKIP_DESC = /رصيد افتتاحي|رصيد سابق|رصيد ختامي|الرصيد الافتتاحي|الرصيد الختامي|opening balance|closing balance|balance brought|balance carried|brought forward|carried forward|^الاجمالي|^اجمالي|^المجموع|^total/;

  function normalize(rows, map, header) {
    const items = [], errors = [];
    const desc = (r) => map.desc.map((i) => String(r[i] ?? '').trim()).filter(Boolean).join(' — ').replace(/\s+/g, ' ').slice(0, 200);
    const data = rows.slice(header + 1, header + 1 + MAX_ROWS);
    if (rows.length - header - 1 > MAX_ROWS) errors.push({ row: 0, msg: `الكشف فيه أكثر من ${MAX_ROWS} عملية؛ قُرئت أول ${MAX_ROWS} فقط. قسّمه على أكثر من ملف` });
    const parsed = [];
    let dmyVotes = 0, mdyVotes = 0;
    data.forEach((r, k) => {
      const line = header + 2 + k;
      const d = desc(r);
      if (SKIP_DESC.test(normAr(d))) return;
      let amountH = null, dir = null;
      if (map.debit >= 0 || map.credit >= 0) {
        const dv = map.debit >= 0 ? parseAmount(r[map.debit]) : null;
        const cv = map.credit >= 0 ? parseAmount(r[map.credit]) : null;
        if (dv) { amountH = Math.abs(dv); dir = 'out'; }
        else if (cv) { amountH = Math.abs(cv); dir = 'in'; }
      } else if (map.amount >= 0) {
        const av = parseAmount(r[map.amount]);
        if (av) { amountH = Math.abs(av); dir = av < 0 ? 'out' : 'in'; }
      }
      const dateRaw = map.date >= 0 ? r[map.date] : '';
      if (!amountH) {
        if (dateRaw && d && r.some((c) => /\d/.test(c))) { /* سطر بلا مبلغ (رصيد أو عنوان) — يُتجاهل بصمت */ }
        return;
      }
      const dt = parseDateCell(dateRaw);
      if (!dt) { errors.push({ row: line, msg: `السطر ${line}: تاريخ غير مفهوم «${String(dateRaw).slice(0, 20)}»` }); return; }
      if (dt.hijri) { errors.push({ row: line, msg: `السطر ${line}: التاريخ هجري؛ صدّر الكشف بالتاريخ الميلادي` }); return; }
      if (dt.parts) { if (dt.parts[0] > 12) dmyVotes++; if (dt.parts[1] > 12) mdyVotes++; }
      parsed.push({ line, dt, desc: d || '(بدون بيان)', dir, amountH, balanceRaw: map.balance >= 0 ? r[map.balance] : '' });
    });
    const mdy = mdyVotes > dmyVotes; // الافتراضي يوم/شهر/سنة كما في السعودية
    for (const p of parsed) {
      let iso = p.dt.iso;
      if (!iso) { const [a, b, y] = p.dt.parts; iso = mdy ? validYMD(y, a, b) : validYMD(y, b, a); }
      if (!iso) { errors.push({ row: p.line, msg: `السطر ${p.line}: تاريخ غير صالح` }); continue; }
      items.push({ line: p.line, date: iso, desc: p.desc, dir: p.dir, amountH: p.amountH });
    }
    return { items, errors, dateOrder: mdy ? 'mdy' : 'dmy' };
  }

  /* ---------------- منع التكرار ---------------- */
  const descKey = (s, words = 4) => normAr(s).replace(/[0-9]/g, ' ').replace(/[^\p{L}\s]/gu, ' ').replace(/\s+/g, ' ').trim().split(' ').filter((w) => w.length > 1).slice(0, words).join(' ');
  function fingerprints(items) {
    const seen = new Map();
    return items.map((it) => {
      const base = `${it.date}|${it.dir}|${it.amountH}|${normAr(it.desc).replace(/[^\p{L}\p{N}]/gu, '').slice(0, 60)}`;
      const n = (seen.get(base) || 0) + 1; seen.set(base, n);
      return `${base}#${n}`; // عمليتان متطابقتان في نفس اليوم تبقيان عمليتين
    });
  }

  /* ---------------- التصنيف المقترح ---------------- */
  const RULES = [
    ['out', ['راتب', 'رواتب', 'اجور', 'salary', 'salaries', 'payroll', 'wps', 'حمايه الاجور'], '5200'],
    ['out', ['التامينات الاجتماعيه', 'تامينات اجتماعيه', 'gosi', 'المؤسسه العامه للتامينات'], '2400'],
    ['out', ['ايجار', 'rent', 'ejar', 'اجار'], '5300'],
    ['out', ['كهرباء', 'الكهرباء', 'electricity', 'sec bill', 'مياه', 'المياه', 'water', 'nwc'], '5400'],
    ['out', ['سحب نقدي', 'صراف', 'atm', 'cash withdrawal'], '1100'],
    ['out', ['وقود', 'بنزين', 'ديزل', 'fuel', 'petrol', 'gas station', 'محطه', 'الدريس', 'aldrees', 'ساسكو', 'sasco', 'نفط', 'naft', 'petromin', 'بترومين'], '5600'],
    ['out', ['مواد', 'حديد', 'اسمنت', 'خرسانه', 'بلوك', 'رمل', 'خشب', 'دهانات', 'cement', 'steel', 'concrete', 'building', 'hardware', 'ساكو', 'saco', 'مواد بناء', 'عدد وادوات'], '5600'],
    ['out', ['رسوم', 'رسم', 'عموله', 'عمولات', 'fee', 'fees', 'charge', 'charges', 'commission', 'ضريبه القيمه المضافه على'], '5700'],
    ['out', ['stc', 'الاتصالات', 'موبايلي', 'mobily', 'زين', 'zain', 'انترنت', 'internet', 'جوال'], '5700'],
    ['in', ['راس المال', 'راسمال', 'capital', 'تمويل من المالك', 'شريك'], '3100'],
    ['in', ['نقاط البيع', 'نقاط بيع', 'pos', 'مدى', 'mada', 'settlement', 'تسويه', 'تحويل وارد', 'حواله وارده', 'incoming', 'inward', 'ايداع'], '4200'],
  ];
  function suggest(desc, dir) {
    const d = ' ' + normAr(desc) + ' ';
    for (const [rd, words, acc] of RULES) if (rd === dir && words.some((w) => d.includes(w.length <= 3 ? ` ${w} ` : w))) return acc;
    return dir === 'out' ? '5700' : '4200';
  }

  return { StatementError, MAX_ROWS, readStatement, parseCSV, readXlsx, decodeText, detectColumns, normalize, parseAmount, parseDateCell, fingerprints, descKey, suggest, normAr };
});
