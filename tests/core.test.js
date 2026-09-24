// اختبارات النواة المالية — تشغيل: node --test tests/
const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../core.js');

// مولّد أرقام عشوائية ثابت البذرة لتكرار النتائج
function rng(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); }
const rint = (r, a, b) => a + Math.floor(r() * (b - a + 1));

test('إدخال المبالغ: صيغ صحيحة وأرقام عربية', () => {
  assert.equal(C.parseMoney('1,234.5'), 123450);
  assert.equal(C.parseMoney('٠٫١'), 10);
  assert.equal(C.parseMoney('١٢٣٤٫٥٦'), 123456);
  assert.equal(C.parseMoney('0.1') + C.parseMoney('0.2'), C.parseMoney('0.3')); // لا خطأ فاصلة عائمة
  assert.equal(C.parseMoney('0', { allowZero: true }), 0);
});

test('إدخال المبالغ: رفض القيم الخاطئة', () => {
  for (const bad of ['', '-5', '1.234', 'abc', '1e5', '12..3', 'NaN', 'Infinity', '0x10', '99999999999999.99']) {
    assert.throws(() => C.parseMoney(bad), C.InputError, bad);
  }
  assert.throws(() => C.parseMoney('0'), C.InputError);
  assert.throws(() => C.parseQty('0'), C.InputError);
  assert.throws(() => C.parseQty('1.2345'), C.InputError);
  assert.equal(C.parseQty('2.5'), 2500);
});

test('التواريخ: رفض التواريخ غير الحقيقية', () => {
  assert.ok(C.isISODate('2026-02-28'));
  assert.ok(!C.isISODate('2026-02-30'));
  assert.ok(!C.isISODate('2026-13-01'));
  assert.ok(!C.isISODate('26-1-1'));
  assert.ok(!C.isISODate('1999-12-31'));
  assert.ok(C.isMonth('2026-09')); assert.ok(!C.isMonth('2026-9'));
});

test('التقريب نصف لأعلى بدقة BigInt', () => {
  assert.equal(C.mulDivRound(1, 1, 2), 1);        // 0.5 → 1
  assert.equal(C.mulDivRound(1, 1, 3), 0);        // 0.333 → 0
  assert.equal(C.mulDivRound(2, 1, 3), 1);        // 0.667 → 1
  assert.equal(C.mulDivRound(-1, 1, 2), -1);
  assert.equal(C.mulDivRound(9e15, 1000, 1000), 9e15); // لا فيضان
});

test('ضريبة القيمة المضافة لكل بند ثم الجمع', () => {
  // 3 بنود × 0.33 ر.س: ضريبة كل بند 0.05 (0.0495 تقريب) → 0.15
  const t = C.invoiceTotals([
    { kind: 'service', qtyM: 1000, priceH: 33 }, { kind: 'service', qtyM: 1000, priceH: 33 }, { kind: 'service', qtyM: 1000, priceH: 33 },
  ]);
  assert.equal(t.netH, 99); assert.equal(t.vatH, 15); assert.equal(t.totalH, 114);
  const t2 = C.invoiceTotals([{ kind: 'goods', qtyM: 2500, priceH: 19999 }]); // 2.5 × 199.99 = 499.975 → 499.98
  assert.equal(t2.netH, 49998); assert.equal(t2.vatH, 7500); assert.equal(t2.goodsNetH, 49998);
  assert.equal(t2.totalH, t2.netH + t2.vatH);
});

test('القيد: يرفض غير المتزن ويقبل المتزن', () => {
  const ok = C.validateJournal([{ accountId: 'a', debitH: 1000, creditH: 0 }, { accountId: 'b', debitH: 0, creditH: 1000 }]);
  assert.ok(ok.ok);
  const bad = C.validateJournal([{ accountId: 'a', debitH: 1000, creditH: 0 }, { accountId: 'b', debitH: 0, creditH: 999 }]);
  assert.ok(!bad.ok); assert.match(bad.errors.join(), /غير متزن/);
  assert.ok(!C.validateJournal([{ accountId: 'a', debitH: 5, creditH: 5 }, { accountId: 'b', debitH: 0, creditH: 0 }]).ok);
  assert.ok(!C.validateJournal([{ accountId: 'a', debitH: 5, creditH: 0 }, { accountId: 'a', debitH: 0, creditH: 5 }]).ok);
  assert.ok(!C.validateJournal([{ accountId: 'a', debitH: 1.5, creditH: 0 }, { accountId: 'b', debitH: 0, creditH: 1.5 }]).ok);
  assert.ok(!C.validateJournal([{ accountId: 'a', debitH: 5, creditH: 0 }]).ok);
});

test('ميزان المراجعة والميزانية متوازنة دائماً (1000 قيد عشوائي)', () => {
  const r = rng(42);
  const types = ['Assets', 'Assets', 'Liabilities', 'Equity', 'Revenue', 'Expenses', 'Expenses'];
  const accounts = types.map((t, i) => ({ id: 'a' + i, type: t, name: 'حساب ' + i }));
  const journals = [];
  for (let k = 0; k < 1000; k++) {
    const n = rint(r, 2, 6);
    const lines = [];
    let rest = rint(r, 1, 5_000_000);
    const total = rest;
    for (let i = 0; i < n - 1; i++) {
      const part = i === n - 2 ? rest : rint(r, 0, rest);
      if (part) lines.push({ accountId: 'a' + rint(r, 0, 6), debitH: part, creditH: 0 });
      rest -= part;
    }
    lines.push({ accountId: 'a' + rint(r, 0, 6), debitH: 0, creditH: total });
    const v = C.validateJournal(lines);
    if (!v.ok) continue;
    const month = String(rint(r, 1, 12)).padStart(2, '0');
    journals.push({ status: r() < 0.9 ? 'posted' : 'draft', date: `2026-${month}-15`, lines });
  }
  const tb = C.trialBalance(accounts, journals, '2026-12-31');
  assert.ok(tb.balanced, 'ميزان المراجعة متزن');
  for (const asOf of ['2026-03-31', '2026-06-30', '2026-12-31']) {
    const bs = C.balanceSheet(accounts, journals, asOf);
    assert.ok(bs.balanced, 'الميزانية متوازنة في ' + asOf);
  }
  const is = C.incomeStatement(accounts, journals, '2026-01-01', '2026-12-31');
  assert.equal(is.netH, is.totalRevenueH - is.totalExpensesH);
});

test('القيد العكسي يلغي الأثر تماماً', () => {
  const accounts = [{ id: 'cash', type: 'Assets' }, { id: 'cap', type: 'Equity' }];
  const lines = [{ accountId: 'cash', debitH: 12345, creditH: 0 }, { accountId: 'cap', debitH: 0, creditH: 12345 }];
  const j = [{ status: 'reversed', date: '2026-01-01', lines }, { status: 'posted', date: '2026-01-02', lines: C.reverseLines(lines) }];
  const t = C.accountTotals(j);
  assert.equal(C.naturalBalance(accounts[0], t), 0);
  assert.equal(C.naturalBalance(accounts[1], t), 0);
});

for (const method of ['FIFO', 'AVG']) {
  test(`المخزون ${method}: لا تضيع أي هللة (5000 حركة عشوائية)`, () => {
    const r = rng(method === 'FIFO' ? 7 : 9);
    let s = C.emptyStock(), inH = 0, outH = 0;
    for (let k = 0; k < 5000; k++) {
      if (s.qtyM === 0 || r() < 0.45) {
        const q = rint(r, 1, 50_000), cost = rint(r, 1, 10_000_000);
        s = C.stockIn(s, q, cost); inH += cost;
      } else {
        const q = rint(r, 1, s.qtyM);
        const res = C.stockOut(s, q, method); s = res.state; outH += res.costH;
        assert.ok(res.costH >= 0);
      }
      assert.equal(s.valueH, inH - outH, 'القيمة = الوارد − المنصرف');
      if (method === 'FIFO') assert.equal(s.valueH, s.layers.reduce((a, l) => a + l.costH, 0));
      if (s.qtyM === 0) assert.equal(s.valueH, 0, 'صفر كمية = صفر قيمة');
    }
  });
}

test('FIFO يصرف من أقدم دفعة أولاً، والمتوسط المرجح يحسب المعدل', () => {
  let s = C.emptyStock();
  s = C.stockIn(s, 10000, 100000); // 10 × 10.00
  s = C.stockIn(s, 10000, 200000); // 10 × 20.00
  const f = C.stockOut(s, 15000, 'FIFO');
  assert.equal(f.costH, 100000 + 100000); // 10×10 + 5×20
  const a = C.stockOut(s, 15000, 'AVG');
  assert.equal(a.costH, 225000); // 15 × 15.00
  assert.throws(() => C.stockOut(s, 30000, 'FIFO'), /أكبر من المتوفر/);
});

test('الإهلاك: مجموع الأقساط = التكلفة − الخردة بالهللة', () => {
  const r = rng(3);
  for (let k = 0; k < 500; k++) {
    const asset = { costH: rint(r, 1000, 100_000_000), salvageH: 0, lifeMonths: rint(r, 1, 120), startMonth: '2025-0' + rint(r, 1, 9) };
    asset.salvageH = rint(r, 0, Math.floor(asset.costH / 5));
    const sched = C.depreciationSchedule(asset);
    const total = sched.reduce((a, x) => a + x.amountH, 0);
    assert.equal(total, asset.costH - asset.salvageH);
    assert.equal(sched.length, asset.lifeMonths);
  }
  const a = { costH: 1000, salvageH: 0, lifeMonths: 3, startMonth: '2026-01' };
  assert.deepEqual(C.depreciationSchedule(a).map((x) => x.amountH), [333, 333, 334]);
  assert.equal(C.monthlyDepreciation(a, '2025-12'), 0);
  assert.equal(C.monthlyDepreciation(a, '2026-04'), 0);
});

test('تقرير الضريبة: مخرجات − مدخلات مع طرح الملغاة', () => {
  const inv = [
    { status: 'issued', issueDate: '2026-09-10', netH: 100000, vatH: 15000 },
    { status: 'void', issueDate: '2026-09-11', voidedDate: '2026-09-12', netH: 20000, vatH: 3000 },
    { status: 'draft', issueDate: '2026-09-11', netH: 99999, vatH: 99999 },
    { status: 'issued', issueDate: '2026-08-30', netH: 5000, vatH: 750 },
  ];
  const pur = [{ date: '2026-09-05', netH: 40000, vatH: 6000 }];
  const v = C.vatReport(inv, pur, '2026-09-01', '2026-09-30');
  assert.equal(v.outputVatH, 15000); assert.equal(v.inputVatH, 6000); assert.equal(v.netVatH, 9000);
});

test('حالة الفاتورة والأعمار', () => {
  const inv = { status: 'issued', totalH: 1000, paidH: 400, dueDate: '2026-09-01' };
  assert.equal(C.invoiceState(inv, '2026-09-23').key, 'overdue');
  assert.equal(C.invoiceState(inv, '2026-08-28').key, 'dueSoon');
  assert.equal(C.invoiceState({ ...inv, paidH: 1000 }, '2026-09-23').key, 'paid');
  assert.equal(C.invoiceState(inv, '2026-07-01').key, 'partial');
  const ag = C.aging([inv, { status: 'issued', totalH: 500, paidH: 0, dueDate: '2026-12-01' }], '2026-09-23');
  assert.equal(ag.totalH, 1100); assert.equal(ag.buckets[1].h, 600); assert.equal(ag.buckets[0].h, 500);
});

test('CSV: يمنع حقن الصيغ ويحفظ العربية', () => {
  const csv = C.toCSV([['الاسم', 'المبلغ'], ['=HYPERLINK("http://x")', C.csvMoney(-150)], ['+cmd', '@SUM(A1)'], ['نص "مقتبس"', 'a,b']]);
  assert.ok(csv.startsWith('﻿'));
  assert.match(csv, /'=HYPERLINK/); assert.match(csv, /'\+cmd/); assert.match(csv, /'@SUM/);
  assert.match(csv, /,-1\.50/); // الأرقام السالبة الحقيقية تبقى أرقاماً
  assert.match(csv, /"نص ""مقتبس"""/);
});

test('التنبيهات: عجز نقدي وفواتير متأخرة وحد الطلب', () => {
  const accounts = [{ id: 'cash', type: 'Assets', cash: true, name: 'الصندوق' }, { id: 'exp', type: 'Expenses', name: 'مصروف' }];
  const journals = [{ status: 'posted', date: '2026-09-01', lines: [{ accountId: 'exp', debitH: 500, creditH: 0 }, { accountId: 'cash', debitH: 0, creditH: 500 }] }];
  const al = C.computeAlerts({ accounts, journals, invoices: [{ status: 'issued', totalH: 100, paidH: 0, dueDate: '2026-09-01' }], items: [{ name: 'أسمنت', qtyM: 1000, reorderM: 5000 }], today: '2026-09-23' });
  const kinds = al.map((a) => a.kind);
  assert.ok(kinds.includes('cash')); assert.ok(kinds.includes('overdue')); assert.ok(kinds.includes('stock'));
  assert.equal(al.find((a) => a.kind === 'cash').level, 'bad');
});

test('مشتريات المصروفات: شامل/قبل/بدون ضريبة — الصافي + الضريبة = المبلغ دائماً', () => {
  assert.deepEqual(C.purchaseLine(1000, 11500, 'incl'), { netH: 10000, vatH: 1500 });
  assert.deepEqual(C.purchaseLine(1000, 10000, 'excl'), { netH: 10000, vatH: 1500 });
  assert.deepEqual(C.purchaseLine(2500, 10000, 'none'), { netH: 25000, vatH: 0 });
  const r = rng(77);
  for (let i = 0; i < 5000; i++) {
    const gross = rint(r, 1, 50000000);
    const { netH, vatH } = C.splitGross(gross);
    assert.equal(netH + vatH, gross);
    // الضريبة المستخرجة لا تبعد أكثر من هللة واحدة عن 15% من الصافي
    assert.ok(Math.abs(vatH - C.vatOf(netH)) <= 1, `${gross}`);
  }
  // المشتريات غير الخاضعة لا تدخل الإقرار
  const v = C.vatReport([], [{ date: '2026-09-02', netH: 1000, vatH: 150 }, { date: '2026-09-03', netH: 900, vatH: 0 }], '2026-09-01', '2026-09-30');
  assert.equal(v.purchaseCount, 1); assert.equal(v.inputNetH, 1000);
});

// ---------------- قراءة كشف الحساب ----------------
const BK = require('../bank.js');
test('كشف الحساب: CSV بمبلغ موقّع وتواريخ يوم/شهر، وتجاهل الأرصدة والإجماليات', () => {
  const rows = BK.parseCSV('بنك\nالتاريخ,البيان,المبلغ,الرصيد\n01/09/2026,رصيد افتتاحي,,100\n02/09/2026,"رسوم, خدمة",-11.50,88.50\n13/09/2026,تحويل وارد,"1,200.00",1288.5\n,الإجمالي,1188.5,\n');
  const d = BK.detectColumns(rows);
  assert.equal(d.header, 1);
  const n = BK.normalize(rows, d.map, d.header);
  assert.deepEqual(n.items.map((i) => [i.date, i.dir, i.amountH]), [['2026-09-02', 'out', 1150], ['2026-09-13', 'in', 120000]]);
  assert.equal(BK.suggest('رسوم خدمة', 'out'), '5700');
});
test('كشف الحساب: المبالغ والتواريخ بصيغها المختلفة', () => {
  assert.equal(BK.parseAmount('(99.00)'), -9900);
  assert.equal(BK.parseAmount('1,250.75 DR'), -125075);
  assert.equal(BK.parseAmount('٨٬٠٠٠٫٥٠'), 800050);
  assert.equal(BK.parseAmount('SAR 15.1'), 1510);
  assert.equal(BK.parseAmount('abc'), null);
  assert.equal(BK.parseDateCell('2026-09-05T10:00:00').iso, '2026-09-05');
  assert.equal(BK.parseDateCell('05-Sep-2026').iso, '2026-09-05');
  assert.equal(BK.parseDateCell('46270').iso, '2026-09-05'); // رقم تسلسلي من Excel
  assert.ok(BK.parseDateCell('1448/03/12').hijri);
  assert.equal(BK.parseDateCell('31/02/2026').parts.length, 3);
});
test('كشف الحساب: عمليتان متطابقتان في يوم واحد بصمتان مختلفتان، والبصمة ثابتة', () => {
  const items = [{ date: '2026-09-05', dir: 'out', amountH: 1150, desc: 'رسوم' }, { date: '2026-09-05', dir: 'out', amountH: 1150, desc: 'رسوم' }];
  const a = BK.fingerprints(items), b = BK.fingerprints(items);
  assert.notEqual(a[0], a[1]); assert.deepEqual(a, b);
});

// ---------------- الموارد البشرية ----------------
test('التأمينات: السعودي 9.75% و11.75%، غير السعودي 2% على المنشأة، والحد الأعلى 45,000', () => {
  const sa = { basicH: 500000, housingH: 125000, gosi: true, isSaudi: true };
  assert.deepEqual(C.gosiShares(sa), { baseH: 625000, empH: 60938, erH: 73438 });
  assert.deepEqual(C.gosiShares({ ...sa, isSaudi: false }), { baseH: 625000, empH: 0, erH: 12500 });
  assert.equal(C.gosiShares({ ...sa, basicH: 6000000 }).baseH, 4500000);
  assert.deepEqual(C.gosiShares({ ...sa, gosi: false }), { baseH: 0, empH: 0, erH: 0 });
});
test('سطر المسير: الغياب = الثابت ÷ 30 × الأيام، والصافي = الإجمالي − التأمينات − السلفة', () => {
  const e = { basicH: 500000, housingH: 125000, transportH: 50000, gosi: true, isSaudi: true };
  const l = C.payrollLine(e, { absenceDays: 3, overtimeH: 20000, bonusH: 10000, penaltyH: 5000, advanceH: 50000 });
  assert.equal(l.fixedH, 675000); assert.equal(l.absenceH, 67500);
  assert.equal(l.grossH, 675000 + 20000 + 10000 - 67500 - 5000);
  assert.equal(l.netH, l.grossH - 60938 - 50000);
  assert.throws(() => C.payrollLine(e, { absenceDays: 31 }));
  // القيد متوازن دائماً: الإجمالي + حصة المنشأة = التأمينات (الحصتان) + السلفة + الصافي
  const r = rng(9);
  for (let i = 0; i < 2000; i++) {
    const emp = { basicH: rint(r, 100000, 5000000), housingH: rint(r, 0, 1500000), transportH: rint(r, 0, 100000), otherH: rint(r, 0, 100000), gosi: r() > 0.2, isSaudi: r() > 0.5 };
    const x = C.payrollLine(emp, { absenceDays: rint(r, 0, 5), overtimeH: rint(r, 0, 50000), advanceH: rint(r, 0, 50000) });
    assert.equal(x.grossH + x.gosiErH, x.gosiEmpH + x.gosiErH + x.advanceH + x.netH);
  }
});
test('نهاية الخدمة: نصف شهر لأول 5 سنوات ثم شهر، وكسور الاستقالة', () => {
  const w = 1000000; // أجر 10,000
  assert.equal(C.endOfService({ wageH: w, hireDate: '2020-01-01', endDate: '2020-01-01' }).awardH, 0);
  assert.equal(C.endOfService({ wageH: w, hireDate: '2021-01-01', endDate: '2023-01-01' }).fullH, C.mulDivRound(w, 730, 730)); // سنتان = شهر كامل
  const ten = C.endOfService({ wageH: w, hireDate: '2014-01-01', endDate: '2024-01-01' });
  assert.equal(ten.fullH, C.mulDivRound(w, 1825, 730) + C.mulDivRound(w, ten.days - 1825, 365)); // 2.5 + ~5 أشهر
  assert.equal(C.endOfService({ wageH: w, hireDate: '2024-06-01', endDate: '2026-01-01', reason: 'resign' }).awardH, 0);
  const r3 = C.endOfService({ wageH: w, hireDate: '2023-01-01', endDate: '2026-01-01', reason: 'resign' });
  assert.equal(r3.awardH, C.mulDivRound(r3.fullH, 1, 3));
  const r7 = C.endOfService({ wageH: w, hireDate: '2019-01-01', endDate: '2026-01-01', reason: 'resign' });
  assert.equal(r7.awardH, C.mulDivRound(r7.fullH, 2, 3));
  assert.equal(C.endOfService({ wageH: w, hireDate: '2014-01-01', endDate: '2026-01-01', reason: 'resign' }).awardH, C.endOfService({ wageH: w, hireDate: '2014-01-01', endDate: '2026-01-01' }).awardH);
});

test('رمز QR لهيئة الزكاة يطابق مثال الهيئة الرسمي (TLV ثم Base64)', () => {
  assert.equal(C.zatcaTLV({ seller: 'Bobs Records', vatNo: '310122393500003', timestamp: '2022-04-25T15:30:00Z', totalH: 100000, vatH: 15000 }),
    'AQxCb2JzIFJlY29yZHMCDzMxMDEyMjM5MzUwMDAwMwMUMjAyMi0wNC0yNVQxNTozMDowMFoEBzEwMDAuMDAFBjE1MC4wMA==');
  // اسم عربي: الطول بالبايت لا بالحرف
  const b = Buffer.from(C.zatcaTLV({ seller: 'الحرف', vatNo: '300000000000003', timestamp: '2026-09-24T10:00:00Z', totalH: 115, vatH: 15 }), 'base64');
  assert.equal(b[0], 1); assert.equal(b[1], Buffer.byteLength('الحرف')); assert.equal(b.subarray(2, 2 + b[1]).toString(), 'الحرف');
});
