/* =====================================================================
   الحرف المتكاملة — النواة المالية (core.js)
   ---------------------------------------------------------------------
   دوال حسابية "نقية" (Pure) بلا واجهة ولا قاعدة بيانات، لذلك تُختبر آلياً.

   مبادئ الدقة المالية المطبقة هنا:
   1) كل المبالغ أعداد صحيحة بالهللة (1 ريال = 100 هللة). لا تُخزَّن ولا تُجمع
      أي قيمة مالية كعدد عشري، فتختفي أخطاء الفاصلة العائمة (0.1 + 0.2).
   2) الكميات أعداد صحيحة بالألف (1 وحدة = 1000)، لدعم 2.5 م³ مثلاً.
   3) كل ضرب أو قسمة تُجرى بـ BigInt ثم تُقرَّب مرة واحدة (نصف لأعلى).
   4) الضريبة 15% تُحسب لكل بند ثم تُجمع (نفس أسلوب الفاتورة الضريبية).
   5) القيد لا يُقبل إلا متزناً: مجموع المدين = مجموع الدائن بالهللة.
   6) المخزون: FIFO أو المتوسط المرجح، وتكلفة الصرف تُطرح من القيمة المتبقية
      نفسها، فلا ينحرف رصيد المخزون ولو هللة واحدة مهما كثرت الحركات.
   7) الإهلاك: القسط الثابت، ويأخذ الشهر الأخير فرق التقريب ليساوي مجموع
      الأقساط (التكلفة − الخردة) تماماً.
   ===================================================================== */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.HirafCore = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const MAX_H = 9e15;          // حد أعلى آمن للأعداد الصحيحة (≈ 90 تريليون ريال)
  const VAT_BP = 1500;         // 15% بنقاط الأساس (basis points)
  const QTY = 1000;            // مقام الكمية

  /* ------------------------------------------------------------------
     1) الأرقام والإدخال
     ------------------------------------------------------------------ */
  // يحوّل الأرقام العربية/الفارسية إلى لاتينية ويزيل فواصل الآلاف
  function normalizeDigits(input) {
    return String(input ?? '')
      .replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660))
      .replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 0x06F0))
      .replace(/٫/g, '.')           // الفاصلة العشرية العربية ٫
      .replace(/[٬,\s]/g, '')       // فواصل الآلاف والمسافات
      .trim();
  }

  class InputError extends Error {}

  /** مبلغ نصي → هللات (عدد صحيح). يرفض السالب وأكثر من خانتين عشريتين. */
  function parseMoney(input, { allowZero = false, label = 'المبلغ' } = {}) {
    const s = normalizeDigits(input);
    if (!/^\d{1,13}(\.\d{0,2})?$/.test(s)) throw new InputError(`${label} غير صالح (أرقام فقط وبحد أقصى خانتين عشريتين)`);
    const [i, f = ''] = s.split('.');
    const h = Number(i) * 100 + Number((f + '00').slice(0, 2));
    if (!Number.isSafeInteger(h) || h > MAX_H) throw new InputError(`${label} كبير جداً`);
    if (!allowZero && h === 0) throw new InputError(`${label} يجب أن يكون أكبر من صفر`);
    return h;
  }

  /** كمية نصية → آلاف (عدد صحيح موجب). */
  function parseQty(input, { label = 'الكمية' } = {}) {
    const s = normalizeDigits(input);
    if (!/^\d{1,9}(\.\d{0,3})?$/.test(s)) throw new InputError(`${label} غير صالحة (بحد أقصى 3 خانات عشرية)`);
    const [i, f = ''] = s.split('.');
    const m = Number(i) * QTY + Number((f + '000').slice(0, 3));
    if (m <= 0) throw new InputError(`${label} يجب أن تكون أكبر من صفر`);
    return m;
  }

  function parseInteger(input, { min = 0, max = 1e9, label = 'القيمة' } = {}) {
    const s = normalizeDigits(input);
    if (!/^\d{1,10}$/.test(s)) throw new InputError(`${label} يجب أن يكون عدداً صحيحاً`);
    const n = Number(s);
    if (n < min || n > max) throw new InputError(`${label} يجب أن يكون بين ${min} و ${max}`);
    return n;
  }

  /** تاريخ بصيغة YYYY-MM-DD صالح فعلاً وضمن نطاق معقول */
  function isISODate(s) {
    if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
    const d = new Date(s + 'T00:00:00Z');
    return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s && s >= '2000-01-01' && s <= '2100-12-31';
  }
  function parseDate(s, label = 'التاريخ') {
    if (!isISODate(s)) throw new InputError(`${label} غير صالح`);
    return s;
  }
  function isMonth(s) { return typeof s === 'string' && /^\d{4}-(0[1-9]|1[0-2])$/.test(s) && s >= '2000-01' && s <= '2100-12'; }

  function cleanText(s, max = 200) {
    // يزيل محارف التحكم ويقص الطول. (الهروب من HTML يتم عند العرض)
    return String(s ?? '').replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, max);
  }

  /* ------------------------------------------------------------------
     2) الحساب الصحيح
     ------------------------------------------------------------------ */
  function assertInt(n, label = 'قيمة') {
    if (!Number.isSafeInteger(n)) throw new InputError(`${label} يجب أن تكون عدداً صحيحاً آمناً`);
    return n;
  }

  /** round(a*b/c) نصف لأعلى (بعيداً عن الصفر) باستخدام BigInt */
  function mulDivRound(a, b, c) {
    assertInt(a); assertInt(b); assertInt(c);
    if (c === 0) throw new Error('قسمة على صفر');
    const neg = (a < 0) !== (b < 0) !== (c < 0);
    const A = BigInt(Math.abs(a)), B = BigInt(Math.abs(b)), C = BigInt(Math.abs(c));
    const q = (A * B * 2n + C) / (C * 2n);
    const r = Number(q);
    if (!Number.isSafeInteger(r)) throw new InputError('الناتج أكبر من الحد المسموح');
    return neg ? -r : r;
  }

  const lineNet = (qtyM, priceH) => mulDivRound(qtyM, priceH, QTY);
  const vatOf = (netH, bp = VAT_BP) => mulDivRound(netH, bp, 10000);
  /** فصل مبلغ شامل للضريبة: الصافي = الإجمالي × 100 ÷ 115 مقرّباً، والضريبة = الباقي (فيتطابق المجموع دائماً) */
  function splitGross(grossH, bp = VAT_BP) {
    const netH = mulDivRound(grossH, 10000, 10000 + bp);
    return { netH, vatH: grossH - netH };
  }
  /**
   * بند فاتورة مشتريات (مصروف): الكمية × السعر حسب طريقة الضريبة
   *  'excl' السعر قبل الضريبة (+15%) ، 'incl' السعر شامل الضريبة ، 'none' غير خاضع
   */
  function purchaseLine(qtyM, priceH, mode) {
    const amountH = lineNet(qtyM, priceH);
    if (mode === 'incl') return splitGross(amountH);
    if (mode === 'none') return { netH: amountH, vatH: 0 };
    return { netH: amountH, vatH: vatOf(amountH) };
  }

  function sumInts(list) {
    let s = 0;
    for (const v of list) { assertInt(v); s += v; }
    if (!Number.isSafeInteger(s) || Math.abs(s) > MAX_H) throw new InputError('المجموع أكبر من الحد المسموح');
    return s;
  }

  /* ------------------------------------------------------------------
     3) التنسيق
     ------------------------------------------------------------------ */
  function fmtMoney(h) {
    assertInt(h);
    const neg = h < 0, a = Math.abs(h);
    const i = Math.floor(a / 100), f = a % 100;
    return (neg ? '-' : '') + String(i).replace(/\B(?=(\d{3})+(?!\d))/g, ',') + '.' + String(f).padStart(2, '0');
  }
  function plainMoney(h) { return fmtMoney(h).replace(/,/g, ''); }
  function fmtQty(m) {
    assertInt(m);
    const neg = m < 0, a = Math.abs(m);
    const i = Math.floor(a / QTY), f = a % QTY;
    const frac = f ? '.' + String(f).padStart(3, '0').replace(/0+$/, '') : '';
    return (neg ? '-' : '') + String(i).replace(/\B(?=(\d{3})+(?!\d))/g, ',') + frac;
  }
  /** قيمة إدخال تُعرض في حقل (بدون فواصل) */
  const moneyInput = (h) => (h ? plainMoney(h) : '');
  const qtyInput = (m) => fmtQty(m).replace(/,/g, '');

  /* ------------------------------------------------------------------
     4) الفاتورة الضريبية
     ------------------------------------------------------------------ */
  /**
   * lines: [{ kind:'goods'|'service', qtyM, priceH, ... }]
   * يعيد البنود مع netH و vatH و totalH لكل بند، والمجاميع.
   */
  function invoiceTotals(lines) {
    const out = lines.map((l) => {
      const netH = lineNet(l.qtyM, l.priceH);
      const vatH = vatOf(netH);
      return { ...l, netH, vatH, totalH: netH + vatH };
    });
    const netH = sumInts(out.map((l) => l.netH));
    const vatH = sumInts(out.map((l) => l.vatH));
    return {
      lines: out, netH, vatH, totalH: netH + vatH,
      goodsNetH: sumInts(out.filter((l) => l.kind === 'goods').map((l) => l.netH)),
      servicesNetH: sumInts(out.filter((l) => l.kind !== 'goods').map((l) => l.netH)),
    };
  }

  /* ------------------------------------------------------------------
     5) القيود المزدوجة
     ------------------------------------------------------------------ */
  /** يتحقق من القيد قبل الترحيل. lines: [{accountId, debitH, creditH}] */
  function validateJournal(lines) {
    const errors = [];
    if (!Array.isArray(lines) || lines.length < 2) errors.push('القيد يحتاج سطرين على الأقل');
    if (Array.isArray(lines) && lines.length > 100) errors.push('الحد الأقصى 100 سطر للقيد');
    let totalDebitH = 0, totalCreditH = 0, debits = 0, credits = 0;
    const accounts = new Set();
    (lines || []).forEach((l, i) => {
      const n = i + 1;
      if (!l || typeof l.accountId !== 'string' || !l.accountId) { errors.push(`السطر ${n}: اختر الحساب`); return; }
      const d = l.debitH || 0, c = l.creditH || 0;
      if (!Number.isSafeInteger(d) || !Number.isSafeInteger(c) || d < 0 || c < 0) { errors.push(`السطر ${n}: مبلغ غير صالح`); return; }
      if (d > 0 && c > 0) errors.push(`السطر ${n}: لا يجمع السطر بين مدين ودائن`);
      if (d === 0 && c === 0) errors.push(`السطر ${n}: أدخل مبلغاً مديناً أو دائناً`);
      if (d > 0) debits++;
      if (c > 0) credits++;
      totalDebitH += d; totalCreditH += c;
      accounts.add(l.accountId);
    });
    if (!errors.length) {
      if (!debits || !credits) errors.push('يجب أن يحتوي القيد على طرف مدين وطرف دائن');
      if (accounts.size < 2) errors.push('لا يمكن أن يكون الطرفان على نفس الحساب');
      if (totalDebitH > MAX_H || totalCreditH > MAX_H) errors.push('مجموع القيد أكبر من الحد المسموح');
      if (totalDebitH !== totalCreditH) errors.push(`القيد غير متزن: المدين ${fmtMoney(totalDebitH)} ≠ الدائن ${fmtMoney(totalCreditH)} (الفرق ${fmtMoney(Math.abs(totalDebitH - totalCreditH))})`);
    }
    return { ok: errors.length === 0, errors, totalDebitH, totalCreditH };
  }

  /** قيد عكسي: يبدّل المدين والدائن */
  const reverseLines = (lines) => lines.map((l) => ({ accountId: l.accountId, debitH: l.creditH || 0, creditH: l.debitH || 0, memo: l.memo || '' }));

  /* ------------------------------------------------------------------
     6) الأرصدة والتقارير
     ------------------------------------------------------------------ */
  const DEBIT_NATURE = ['Assets', 'Expenses'];
  const isPosted = (j) => j.status === 'posted' || j.status === 'reversed'; // المعكوس يبقى أثره ويُلغى بقيد العكس

  /** أرصدة الحسابات من القيود المرحّلة ضمن فترة (from/to شاملة، اختيارية) */
  function accountTotals(journals, { from = null, to = null } = {}) {
    const map = new Map();
    for (const j of journals) {
      if (!isPosted(j)) continue;
      if (from && j.date < from) continue;
      if (to && j.date > to) continue;
      for (const l of j.lines || []) {
        const t = map.get(l.accountId) || { debitH: 0, creditH: 0 };
        t.debitH += l.debitH || 0; t.creditH += l.creditH || 0;
        map.set(l.accountId, t);
      }
    }
    return map;
  }
  /** الرصيد بطبيعة الحساب: الأصول والمصروفات مدينة، والباقي دائن */
  function naturalBalance(account, totals) {
    const t = totals.get(account.id) || { debitH: 0, creditH: 0 };
    const diff = t.debitH - t.creditH;
    return DEBIT_NATURE.includes(account.type) ? diff : 0 - diff; // 0 - diff يتجنب -0
  }

  function trialBalance(accounts, journals, asOf) {
    const totals = accountTotals(journals, { to: asOf });
    const rows = accounts.map((a) => {
      const t = totals.get(a.id) || { debitH: 0, creditH: 0 };
      const net = t.debitH - t.creditH;
      return { account: a, debitH: t.debitH, creditH: t.creditH, balDebitH: net > 0 ? net : 0, balCreditH: net < 0 ? -net : 0 };
    }).filter((r) => r.debitH || r.creditH);
    const totalDebitH = sumInts(rows.map((r) => r.balDebitH));
    const totalCreditH = sumInts(rows.map((r) => r.balCreditH));
    return { rows, totalDebitH, totalCreditH, balanced: totalDebitH === totalCreditH };
  }

  function incomeStatement(accounts, journals, from, to) {
    const totals = accountTotals(journals, { from, to });
    const pick = (type) => accounts.filter((a) => a.type === type).map((a) => ({ account: a, amountH: naturalBalance(a, totals) })).filter((r) => r.amountH !== 0);
    const revenue = pick('Revenue'), expenses = pick('Expenses');
    const totalRevenueH = sumInts(revenue.map((r) => r.amountH));
    const totalExpensesH = sumInts(expenses.map((r) => r.amountH));
    return { revenue, expenses, totalRevenueH, totalExpensesH, netH: totalRevenueH - totalExpensesH };
  }

  function balanceSheet(accounts, journals, asOf) {
    const totals = accountTotals(journals, { to: asOf });
    const pick = (type) => accounts.filter((a) => a.type === type).map((a) => ({ account: a, amountH: naturalBalance(a, totals) })).filter((r) => r.amountH !== 0);
    const assets = pick('Assets'), liabilities = pick('Liabilities'), equity = pick('Equity');
    const net = incomeStatement(accounts, journals, null, asOf).netH; // أرباح الفترة حتى التاريخ
    const totalAssetsH = sumInts(assets.map((r) => r.amountH));
    const totalLiabilitiesH = sumInts(liabilities.map((r) => r.amountH));
    const totalEquityH = sumInts(equity.map((r) => r.amountH)) + net;
    return { assets, liabilities, equity, retainedH: net, totalAssetsH, totalLiabilitiesH, totalEquityH, balanced: totalAssetsH === totalLiabilitiesH + totalEquityH };
  }

  /** تقرير ضريبة القيمة المضافة: مخرجات (مبيعات) − مدخلات (مشتريات) */
  function vatReport(invoices, purchases, from, to) {
    const inRange = (d) => (!from || d >= from) && (!to || d <= to);
    const sales = invoices.filter((i) => (i.status === 'issued' || i.status === 'void') && inRange(i.issueDate));
    // الفاتورة الملغاة بعد إصدارها تُدرج ثم تُطرح في تاريخ الإلغاء
    const voids = invoices.filter((i) => i.status === 'void' && i.voidedDate && inRange(i.voidedDate));
    const buys = purchases.filter((p) => inRange(p.date) && (p.vatH || 0) > 0); // المشتريات غير الخاضعة لا تدخل الإقرار
    const outputNetH = sumInts(sales.map((i) => i.netH)) - sumInts(voids.map((i) => i.netH));
    const outputVatH = sumInts(sales.map((i) => i.vatH)) - sumInts(voids.map((i) => i.vatH));
    const inputNetH = sumInts(buys.map((p) => p.netH));
    const inputVatH = sumInts(buys.map((p) => p.vatH));
    return { outputNetH, outputVatH, inputNetH, inputVatH, netVatH: outputVatH - inputVatH, salesCount: sales.length, voidCount: voids.length, purchaseCount: buys.length };
  }

  /* ------------------------------------------------------------------
     7) حالة الفواتير والأعمار
     ------------------------------------------------------------------ */
  function daysBetween(fromISO, toISO) {
    return Math.round((Date.parse(toISO + 'T00:00:00Z') - Date.parse(fromISO + 'T00:00:00Z')) / 86400000);
  }
  /** الحالة المعروضة للفاتورة */
  function invoiceState(inv, today, soonDays = 7) {
    if (inv.status === 'draft' || inv.status === 'cancelled' || inv.status === 'void') return { key: inv.status, remainingH: 0, daysLate: 0 };
    const remainingH = Math.max(0, (inv.totalH || 0) - (inv.paidH || 0));
    if (remainingH === 0) return { key: 'paid', remainingH, daysLate: 0 };
    const late = inv.dueDate ? daysBetween(inv.dueDate, today) : 0;
    if (late > 0) return { key: 'overdue', remainingH, daysLate: late };
    if (late >= -soonDays) return { key: 'dueSoon', remainingH, daysLate: late };
    return { key: (inv.paidH || 0) > 0 ? 'partial' : 'issued', remainingH, daysLate: late };
  }

  function aging(invoices, today) {
    const b = [
      { key: 'current', label: 'غير مستحقة', h: 0 }, { key: 'd30', label: '1–30 يوم', h: 0 },
      { key: 'd60', label: '31–60 يوم', h: 0 }, { key: 'd90', label: '61–90 يوم', h: 0 }, { key: 'd90p', label: 'أكثر من 90 يوم', h: 0 },
    ];
    for (const inv of invoices) {
      const s = invoiceState(inv, today);
      if (!s.remainingH) continue;
      const d = s.daysLate;
      const i = d <= 0 ? 0 : d <= 30 ? 1 : d <= 60 ? 2 : d <= 90 ? 3 : 4;
      b[i].h += s.remainingH;
    }
    return { buckets: b, totalH: sumInts(b.map((x) => x.h)) };
  }

  /* ------------------------------------------------------------------
     8) المخزون (FIFO / المتوسط المرجح)
     ------------------------------------------------------------------ */
  const emptyStock = () => ({ qtyM: 0, valueH: 0, layers: [] });

  /** إدخال كمية بتكلفة إجمالية costH */
  function stockIn(state, qtyM, costH) {
    assertInt(qtyM); assertInt(costH);
    if (qtyM <= 0 || costH < 0) throw new InputError('حركة إدخال غير صالحة');
    const s = { qtyM: state.qtyM + qtyM, valueH: state.valueH + costH, layers: [...(state.layers || []).map((l) => ({ ...l })), { qtyM, costH }] };
    return s;
  }

  /** صرف كمية؛ يعيد التكلفة المحسوبة والحالة الجديدة. يمنع الرصيد السالب. */
  function stockOut(state, qtyM, method) {
    assertInt(qtyM);
    if (qtyM <= 0) throw new InputError('كمية الصرف غير صالحة');
    if (qtyM > state.qtyM) throw new InputError(`الكمية المطلوبة (${fmtQty(qtyM)}) أكبر من المتوفر (${fmtQty(state.qtyM)})`);
    let costH;
    let layers = (state.layers || []).map((l) => ({ ...l }));
    if (method === 'FIFO') {
      let need = qtyM; costH = 0;
      for (const l of layers) {
        if (!need) break;
        if (!l.qtyM) continue;
        const take = Math.min(need, l.qtyM);
        const c = take === l.qtyM ? l.costH : mulDivRound(l.costH, take, l.qtyM);
        l.qtyM -= take; l.costH -= c; costH += c; need -= take;
      }
      layers = layers.filter((l) => l.qtyM > 0);
    } else {
      // المتوسط المرجح: التكلفة = القيمة × (الكمية المصروفة / الكمية المتاحة)
      costH = qtyM === state.qtyM ? state.valueH : mulDivRound(state.valueH, qtyM, state.qtyM);
      // نحافظ على طبقة واحدة تمثل الرصيد (لسهولة التحويل لاحقاً)
      const remQ = state.qtyM - qtyM, remV = state.valueH - costH;
      layers = remQ > 0 ? [{ qtyM: remQ, costH: remV }] : [];
    }
    const next = { qtyM: state.qtyM - qtyM, valueH: state.valueH - costH, layers };
    return { state: next, costH };
  }

  const unitCostH = (s) => (s.qtyM > 0 ? mulDivRound(s.valueH, QTY, s.qtyM) : 0);

  /* ------------------------------------------------------------------
     9) الإهلاك (القسط الثابت)
     ------------------------------------------------------------------ */
  function monthIndex(startMonth, month) {
    const [y1, m1] = startMonth.split('-').map(Number), [y2, m2] = month.split('-').map(Number);
    return (y2 - y1) * 12 + (m2 - m1);
  }
  /** قسط شهر معين. آخر شهر يأخذ فرق التقريب ليكتمل الأساس بالضبط. */
  function monthlyDepreciation(asset, month) {
    const base = asset.costH - (asset.salvageH || 0);
    const life = asset.lifeMonths;
    if (base <= 0 || !life) return 0;
    const k = monthIndex(asset.startMonth, month);
    if (k < 0 || k >= life) return 0;
    const per = Math.floor(base / life);
    return k === life - 1 ? base - per * (life - 1) : per;
  }
  function depreciationSchedule(asset) {
    const out = [];
    const [y, m] = asset.startMonth.split('-').map(Number);
    for (let k = 0; k < asset.lifeMonths; k++) {
      const d = new Date(Date.UTC(y, m - 1 + k, 1));
      const month = d.toISOString().slice(0, 7);
      out.push({ month, amountH: monthlyDepreciation(asset, month) });
    }
    return out;
  }

  /* ------------------------------------------------------------------
     10) التصدير CSV (آمن ضد حقن الصيغ في Excel)
     ------------------------------------------------------------------ */
  const csvMoney = (h) => ({ raw: plainMoney(h) });
  function csvCell(v) {
    if (v && typeof v === 'object' && 'raw' in v) return String(v.raw);
    if (typeof v === 'number') return String(v);
    let s = String(v ?? '');
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // يمنع تنفيذ صيغ عند الفتح في Excel
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }
  function toCSV(rows) {
    return '﻿' + rows.map((r) => r.map(csvCell).join(',')).join('\r\n'); // BOM ليظهر العربي في Excel
  }

  /* ------------------------------------------------------------------
     11) التنبيهات الذكية
     ------------------------------------------------------------------ */
  function computeAlerts({ accounts, journals, invoices, items, today, lowCashH = 0 }) {
    const alerts = [];
    const totals = accountTotals(journals, { to: today });
    const cashAccs = accounts.filter((a) => a.cash);
    for (const a of cashAccs) {
      const b = naturalBalance(a, totals);
      if (b < 0) alerts.push({ level: 'bad', kind: 'cash', text: `عجز في ${a.name}: الرصيد ${fmtMoney(b)} ر.س`, target: 'accounts' });
      else if (lowCashH && b < lowCashH) alerts.push({ level: 'warn', kind: 'cash', text: `رصيد ${a.name} منخفض: ${fmtMoney(b)} ر.س`, target: 'accounts' });
    }
    const cashTotal = sumInts(cashAccs.map((a) => naturalBalance(a, totals)));
    const payable = sumInts(accounts.filter((a) => a.type === 'Liabilities').map((a) => naturalBalance(a, totals)));
    if (cashAccs.length && payable > 0 && cashTotal < payable) alerts.push({ level: 'warn', kind: 'liquidity', text: `السيولة (${fmtMoney(cashTotal)}) أقل من الالتزامات (${fmtMoney(payable)})`, target: 'reports' });
    let overdue = 0, overdueH = 0, soon = 0, soonH = 0;
    for (const inv of invoices) {
      const s = invoiceState(inv, today);
      if (s.key === 'overdue') { overdue++; overdueH += s.remainingH; }
      if (s.key === 'dueSoon') { soon++; soonH += s.remainingH; }
    }
    if (overdue) alerts.push({ level: 'bad', kind: 'overdue', text: `${overdue} فاتورة متأخرة بإجمالي ${fmtMoney(overdueH)} ر.س`, target: 'invoices', filter: 'overdue' });
    if (soon) alerts.push({ level: 'warn', kind: 'dueSoon', text: `${soon} فاتورة تستحق خلال 7 أيام بإجمالي ${fmtMoney(soonH)} ر.س`, target: 'invoices', filter: 'dueSoon' });
    const low = items.filter((i) => !i.archived && (i.reorderM || 0) > 0 && (i.qtyM || 0) <= i.reorderM);
    if (low.length) alerts.push({ level: 'warn', kind: 'stock', text: `${low.length} صنف وصل حد إعادة الطلب: ${low.slice(0, 3).map((i) => i.name).join('، ')}${low.length > 3 ? '…' : ''}`, target: 'inventory' });
    const drafts = journals.filter((j) => j.status === 'draft').length;
    if (drafts) alerts.push({ level: 'info', kind: 'approval', text: `${drafts} قيد بانتظار الاعتماد`, target: 'journal' });
    return alerts;
  }

  return {
    MAX_H, VAT_BP, QTY, InputError,
    normalizeDigits, parseMoney, parseQty, parseInteger, parseDate, isISODate, isMonth, cleanText,
    mulDivRound, lineNet, vatOf, splitGross, purchaseLine, sumInts,
    fmtMoney, plainMoney, fmtQty, moneyInput, qtyInput,
    invoiceTotals, validateJournal, reverseLines,
    accountTotals, naturalBalance, trialBalance, incomeStatement, balanceSheet, vatReport,
    daysBetween, invoiceState, aging,
    emptyStock, stockIn, stockOut, unitCostH,
    monthIndex, monthlyDepreciation, depreciationSchedule,
    csvMoney, toCSV, computeAlerts,
  };
});
