/* =====================================================================
   الحرف المتكاملة للمقاولات — نظام المحاسبة وإدارة العملاء (app.js)
   ---------------------------------------------------------------------
   البنية:
   1) أدوات عامة وتنسيق
   2) المستخدمون والصلاحيات (RBAC) — المالك = المستخدم 1
   3) طبقة البيانات: Firebase (أونلاين مباشر) أو حفظ محلي (للمعاينة)
      كل كتابة تتم داخل "معاملة" (Transaction) واحدة تشمل:
        المستند + القيد المحاسبي + سجل المراجعة ← إما تنجح كلها أو لا شيء
   4) الخدمات المحاسبية (إصدار فاتورة، سند قبض، قيد، مشتريات، إهلاك…)
      الفواتير والسندات والمشتريات والأصول تُرحَّل قيودها آلياً.
   5) البيانات المشتقة (أرصدة، حالات، تنبيهات، مطابقات)
   6) الواجهة: الأقسام، النوافذ، التقارير، التصدير
   كل الحسابات المالية تتم في core.js بالهللة (أعداد صحيحة).
   ===================================================================== */
'use strict';

const H = window.HirafCore;

/* =====================================================================
   1) أدوات عامة
   ===================================================================== */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
/** الهروب من HTML — يُطبَّق على كل نص يأتي من المستخدم أو قاعدة البيانات (حماية XSS) */
const esc = (v) => String(v ?? '').replace(/[&<>"'`]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c]));
const icon = (name, cls = 'i') => `<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const pad = (n, w = 4) => String(n).padStart(w, '0');
const pad2 = (n) => String(n).padStart(2, '0');
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 10);

const safeStore = (storage) => ({
  get(k, d) { try { const v = storage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { storage.setItem(k, JSON.stringify(v)); } catch { /* ignore */ } },
  del(k) { try { storage.removeItem(k); } catch { /* ignore */ } },
});
const local = safeStore(window.localStorage);
const sess = safeStore(window.sessionStorage);

/* التواريخ: التاريخ المحلي للمستخدم (وليس UTC) حتى لا يتغير اليوم بعد منتصف الليل */
function todayISO() { const d = new Date(); return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`; }
const thisMonth = () => todayISO().slice(0, 7);
const nowISO = () => new Date().toISOString();
function addDaysISO(iso, n) { const d = new Date(iso + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); }
function addMonths(m, k) { const [y, mm] = m.split('-').map(Number); return new Date(Date.UTC(y, mm - 1 + k, 1)).toISOString().slice(0, 7); }
function monthEnd(m) { const [y, mm] = m.split('-').map(Number); return new Date(Date.UTC(y, mm, 0)).toISOString().slice(0, 10); }
const firstOfMonth = (iso = todayISO()) => iso.slice(0, 8) + '01';
const firstOfYear = (iso = todayISO()) => iso.slice(0, 4) + '-01-01';

const DF = new Intl.DateTimeFormat('ar-SA-u-ca-gregory-nu-latn', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
const DTF = new Intl.DateTimeFormat('ar-SA-u-ca-gregory-nu-latn', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
const MF = new Intl.DateTimeFormat('ar-SA-u-ca-gregory-nu-latn', { month: 'long', year: 'numeric', timeZone: 'UTC' });
const fmtDate = (iso) => { const s = String(iso || '').slice(0, 10); return H.isISODate(s) ? DF.format(new Date(s + 'T00:00:00Z')) : '—'; };
const fmtDateTime = (iso) => { const d = new Date(iso); return iso && !Number.isNaN(d.getTime()) ? DTF.format(d) : '—'; };
const fmtMonth = (m) => (H.isMonth(m) ? MF.format(new Date(m + '-01T00:00:00Z')) : m);
const M = (h) => `<span class="num">${H.fmtMoney(h || 0)}</span>`;
const Q = (m) => `<span class="num">${H.fmtQty(m || 0)}</span>`;

/* =====================================================================
   2) المستخدمون والصلاحيات
   ===================================================================== */
const OWNER = '1'; // مالك النظام: لا يُوقف ولا تُسحب صلاحياته
const PERM_GROUPS = [
  ['المبيعات', [['customer.write', 'إضافة وتعديل العملاء'], ['invoice.write', 'إنشاء مسودات الفواتير'], ['invoice.issue', 'إصدار الفواتير'], ['invoice.void', 'إلغاء فاتورة مُصدرة'], ['payment.create', 'تسجيل سندات القبض'], ['payment.reverse', 'عكس سندات القبض']]],
  ['المحاسبة', [['journal.create', 'إنشاء قيود يدوية'], ['journal.post', 'اعتماد وترحيل القيود'], ['journal.reverse', 'عكس القيود المرحّلة'], ['bank.import', 'استيراد كشف الحساب'], ['accounts.write', 'إضافة حسابات لدليل الحسابات']]],
  ['المشتريات والأصول', [['inventory.write', 'فواتير المشتريات والمصروفات'], ['asset.write', 'تسجيل الأصول الثابتة'], ['dep.run', 'احتساب الإهلاك الشهري']]],
  ['الموارد البشرية', [['hr.manage', 'الموظفون والسلف ونهاية الخدمة'], ['payroll.run', 'إعداد مسير الرواتب واعتماده وصرفه']]],
  ['الرقابة والإدارة', [['reports.export', 'تصدير وطباعة التقارير'], ['audit.view', 'عرض سجل المراجعة'], ['settings.write', 'تعديل بيانات المنشأة'], ['users.manage', 'إدارة المستخدمين والصلاحيات']]],
];
const ALL_PERMS = PERM_GROUPS.flatMap((g) => g[1].map((p) => p[0]));
const PERM_LABEL = Object.fromEntries(PERM_GROUPS.flatMap((g) => g[1]));
const ROLES = {
  admin: { label: 'مدير النظام', perms: ALL_PERMS },
  cfo: { label: 'المدير المالي', perms: ALL_PERMS.filter((p) => p !== 'users.manage') },
  accountant: { label: 'محاسب', perms: ['customer.write', 'invoice.write', 'invoice.issue', 'payment.create', 'journal.create', 'bank.import', 'inventory.write', 'asset.write', 'dep.run', 'hr.manage', 'payroll.run', 'reports.export'] },
  auditor: { label: 'مراجع', perms: ['audit.view', 'reports.export'] },
  sales: { label: 'مبيعات', perms: ['customer.write', 'invoice.write', 'invoice.issue', 'payment.create'] },
  hr: { label: 'موارد بشرية', perms: ['hr.manage', 'payroll.run'] },
  viewer: { label: 'مشاهدة فقط', perms: [] },
  custom: { label: 'مخصص', perms: null },
};
const DEFAULT_USERS = [
  { username: '1', name: 'المستخدم 1', role: 'admin', password: '1' },
  { username: '2', name: 'المستخدم 2', role: 'accountant', password: '2' },
  { username: '3', name: 'المستخدم 3', role: 'auditor', password: '3' },
];
const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{0,29}$/;
const EMAIL_DOMAIN = 'al-hiraf.app';
const toEmail = (u) => `${u}@${EMAIL_DOMAIN}`;
const toSecret = (p) => `hiraf-${p}`; // Firebase يشترط 6 أحرف؛ نضيف بادئة ثابتة
const normUsername = (u) => H.normalizeDigits(u).toLowerCase();
const roleLabel = (r) => ROLES[r]?.label || 'مخصص';

/** هل يملك المستخدم الحالي الصلاحية؟ (قواعد Firebase تتحقق من نفس الشيء على الخادم) */
function can(perm) {
  const u = S.user;
  if (!u || !u.active) return false;
  return u.username === OWNER || (Array.isArray(u.perms) && u.perms.includes(perm));
}
function need(perm) { if (!can(perm)) throw new H.InputError('ليست لديك صلاحية: ' + (PERM_LABEL[perm] || perm)); }
const userName = (u) => S.data.users.find((x) => x.id === u)?.name || (u ? 'المستخدم ' + u : '—');

/* =====================================================================
   دليل الحسابات الافتراضي (معرّفات ثابتة تستخدمها القيود الآلية)
   ===================================================================== */
const ACC = {
  cash: 'acc-1100', bank: 'acc-1200', ar: 'acc-1300', inv: 'acc-1400', vatIn: 'acc-1500', fa: 'acc-1600', accDep: 'acc-1690',
  ap: 'acc-2100', vatOut: 'acc-2200', capital: 'acc-3100', sales: 'acc-4100', services: 'acc-4200', cogs: 'acc-5100', depExp: 'acc-5500',
  materials: 'acc-5600', general: 'acc-5700',
  advances: 'acc-1350', salPay: 'acc-2300', gosiPay: 'acc-2400', salaries: 'acc-5200', gosiExp: 'acc-5210', eosExp: 'acc-5230',
};
const DEFAULT_ACCOUNTS = [
  ['1100', 'النقدية في الصندوق', 'Assets', { cash: true }], ['1200', 'البنك', 'Assets', { cash: true }],
  ['1300', 'العملاء (الذمم المدينة)', 'Assets', { control: 'ar' }], ['1350', 'سلف الموظفين', 'Assets', {}], ['1400', 'المخزون', 'Assets', { control: 'inventory' }],
  ['1500', 'ضريبة القيمة المضافة — مدخلات', 'Assets', {}], ['1600', 'الأصول الثابتة', 'Assets', {}],
  ['1690', 'مجمع الإهلاك', 'Assets', { contra: true }],
  ['2100', 'الموردون (الذمم الدائنة)', 'Liabilities', {}], ['2200', 'ضريبة القيمة المضافة — مخرجات', 'Liabilities', {}],
  ['2300', 'رواتب مستحقة', 'Liabilities', {}], ['2400', 'التأمينات الاجتماعية المستحقة', 'Liabilities', {}],
  ['3100', 'رأس المال', 'Equity', {}],
  ['4100', 'إيرادات المبيعات', 'Revenue', {}], ['4200', 'إيرادات الخدمات والمقاولات', 'Revenue', {}],
  ['5100', 'تكلفة المبيعات', 'Expenses', {}], ['5200', 'الرواتب والأجور', 'Expenses', {}], ['5210', 'حصة المنشأة في التأمينات', 'Expenses', {}], ['5230', 'مكافأة نهاية الخدمة', 'Expenses', {}], ['5300', 'الإيجار', 'Expenses', {}],
  ['5400', 'الكهرباء والمياه', 'Expenses', {}], ['5500', 'مصروف الإهلاك', 'Expenses', {}],
  ['5600', 'مواد ومشتريات المشاريع', 'Expenses', {}], ['5700', 'مصروفات عامة ونثرية', 'Expenses', {}],
];
const ACC_TYPES = { Assets: 'الأصول', Liabilities: 'الخصوم', Equity: 'حقوق الملكية', Revenue: 'الإيرادات', Expenses: 'المصروفات' };
const PAY_METHODS = { cash: 'نقداً', bank_transfer: 'تحويل بنكي', card: 'بطاقة / مدى', check: 'شيك' };
const SOURCE_LABEL = { manual: 'يدوي', bank: 'كشف الحساب', payroll: 'مسير الرواتب', advance: 'سلفة موظف', eos: 'نهاية الخدمة', invoice: 'فاتورة', payment: 'سند قبض', purchase: 'مشتريات', asset: 'أصل ثابت', depreciation: 'إهلاك', void: 'إلغاء فاتورة', reversal: 'قيد عكسي' };
const J_STATUS = { draft: ['بانتظار الاعتماد', 'warn'], posted: ['مرحّل', 'ok'], reversed: ['معكوس', 'neutral'], cancelled: ['ملغى', 'neutral'] };
const INV_STATUS = { draft: ['مسودة', 'neutral'], issued: ['مُصدرة', 'info'], partial: ['مدفوعة جزئياً', 'info'], dueSoon: ['تستحق قريباً', 'warn'], overdue: ['متأخرة', 'bad'], paid: ['مدفوعة', 'ok'], void: ['ملغاة', 'neutral'], cancelled: ['مسودة ملغاة', 'neutral'] };
const pill = (map, key) => { const [l, c] = map[key] || [key, 'neutral']; return `<span class="pill ${c}">${esc(l)}</span>`; };
const MAX_GOODS_LINES = 6; // حد أصناف المخزون في المستند الواحد (حدود قواعد Firestore)

const SERVER_TIME = '__SERVER_TIME__';
const COLLS = ['accounts', 'customers', 'items', 'stockMoves', 'purchases', 'invoices', 'payments', 'journals', 'assets', 'depRuns', 'users', 'settings', 'audit', 'employees', 'advances', 'payrolls'];
const HR_COLLS = new Set(['employees', 'advances', 'payrolls']); // تُقرأ فقط لمن يملك صلاحية الموارد البشرية أو المراجعة
const canHR = () => can('hr.manage') || can('payroll.run') || can('audit.view');

/* =====================================================================
   3-أ) طبقة البيانات: Firebase
   ===================================================================== */
const FB_VER = '10.12.2';
const CloudDB = {
  mode: 'cloud', fb: null, app: null, auth: null, db: null, config: null, unsubs: [],

  async init(config) {
    const base = `https://www.gstatic.com/firebasejs/${FB_VER}`;
    const [app, auth, fs] = await Promise.all([import(`${base}/firebase-app.js`), import(`${base}/firebase-auth.js`), import(`${base}/firebase-firestore.js`)]);
    this.fb = { ...app, ...auth, ...fs };
    this.config = config;
    this.app = app.initializeApp(config);
    this.auth = auth.getAuth(this.app);
    this.db = fs.getFirestore(this.app);
  },
  authUsername() { const u = this.auth.currentUser; return u && u.email ? u.email.split('@')[0] : null; },
  onAuth(cb) { this.fb.onAuthStateChanged(this.auth, () => cb(this.authUsername())); },

  async signIn(username, password) {
    const { signInWithEmailAndPassword, createUserWithEmailAndPassword } = this.fb;
    try {
      await signInWithEmailAndPassword(this.auth, toEmail(username), toSecret(password));
    } catch (e) {
      const notFound = ['auth/invalid-credential', 'auth/user-not-found', 'auth/invalid-login-credentials'].includes(e.code);
      // تهيئة أول مرة: حساب المالك (1) فقط يُنشأ تلقائياً عند أول دخول
      if (notFound && username === OWNER) {
        try { await createUserWithEmailAndPassword(this.auth, toEmail(username), toSecret(password)); return; }
        catch (e2) { throw new Error(e2.code === 'auth/email-already-in-use' ? BAD_LOGIN : fbError(e2)); }
      }
      throw new Error(notFound ? BAD_LOGIN : fbError(e));
    }
  },
  async signOut() { this.stop(); await this.fb.signOut(this.auth); },
  async readUser(username) {
    const s = await this.fb.getDoc(this.fb.doc(this.db, 'users', username));
    return s.exists() ? { id: s.id, ...s.data() } : null;
  },
  /** إنشاء حساب دخول لمستخدم آخر عبر تطبيق Firebase ثانوي (حتى لا يُسجَّل خروج المدير) */
  async createLogin(username, password) {
    const { initializeApp, getAuth, createUserWithEmailAndPassword, signOut, deleteApp } = this.fb;
    const app2 = initializeApp(this.config, 'secondary-' + uid());
    const auth2 = getAuth(app2);
    try {
      await createUserWithEmailAndPassword(auth2, toEmail(username), toSecret(password));
      await signOut(auth2);
      return true;
    } catch (e) {
      if (e.code === 'auth/email-already-in-use') return false;
      throw new Error(fbError(e));
    } finally { try { await deleteApp(app2); } catch { /* ignore */ } }
  },
  async changePassword(current, next) {
    const { EmailAuthProvider, reauthenticateWithCredential, updatePassword } = this.fb;
    const u = this.auth.currentUser;
    try { await reauthenticateWithCredential(u, EmailAuthProvider.credential(u.email, toSecret(current))); }
    catch { throw new Error('كلمة المرور الحالية غير صحيحة'); }
    await updatePassword(u, toSecret(next));
  },

  norm(data) {
    const out = {};
    for (const [k, v] of Object.entries(data)) out[k] = v && typeof v.toDate === 'function' ? v.toDate().toISOString() : v;
    return out;
  },
  resolve(data) {
    const out = {};
    for (const [k, v] of Object.entries(data)) out[k] = v === SERVER_TIME ? this.fb.serverTimestamp() : v;
    return out;
  },

  subscribe(onData, onChange, { withAudit, withHR }) {
    const { collection, onSnapshot, query, orderBy, limit } = this.fb;
    const st = Object.fromEntries(COLLS.map((c) => [c, {}]));
    const ready = new Set();
    const wanted = COLLS.filter((c) => (c !== 'audit' || withAudit) && (!HR_COLLS.has(c) || withHR));
    wanted.forEach((c) => {
      const ref = c === 'audit' ? query(collection(this.db, 'audit'), orderBy('at', 'desc'), limit(1000)) : collection(this.db, c);
      this.unsubs.push(onSnapshot(ref, (snap) => {
        const m = {};
        snap.docs.forEach((d) => { m[d.id] = this.norm(d.data({ serverTimestamps: 'estimate' })); });
        st[c] = m;
        if (ready.has(c)) snap.docChanges().forEach((ch) => onChange(c, ch.type, { id: ch.doc.id, ...ch.doc.data() }));
        ready.add(c);
        if (ready.size === wanted.length) onData(st);
      }, (err) => toast('انقطع الاتصال بقاعدة البيانات', fbError(err), 'error')));
    });
  },
  stop() { this.unsubs.forEach((u) => u()); this.unsubs = []; },

  /** معاملة Firestore: كل القراءات أولاً ثم الكتابات، وتُعاد تلقائياً عند التعارض */
  tx(fn) {
    const { runTransaction, doc, collection } = this.fb;
    return runTransaction(this.db, async (tr) => fn({
      get: async (c, id) => { const s = await tr.get(doc(this.db, c, id)); return s.exists() ? { id: s.id, ...this.norm(s.data()) } : null; },
      set: (c, id, data) => { tr.set(doc(this.db, c, id), this.resolve(data)); },
      update: (c, id, data) => { tr.update(doc(this.db, c, id), this.resolve(data)); },
      newId: (c) => doc(collection(this.db, c)).id,
    }));
  },
};

/* =====================================================================
   3-ب) طبقة البيانات: حفظ محلي (للمعاينة فقط — لا مشاركة بين الأجهزة)
   ===================================================================== */
async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
const LocalDB = {
  mode: 'local', KEY: 'hiraf-erp-local-v1', AUTH: 'hiraf-erp-auth-v1', state: null, cb: null, logins: {},
  async init() {
    this.state = local.get(this.KEY, null) || Object.fromEntries(COLLS.map((c) => [c, {}]));
    COLLS.forEach((c) => { this.state[c] ||= {}; });
    this.logins = local.get(this.AUTH, {});
    this.save();
  },
  save() { local.set(this.KEY, this.state); local.set(this.AUTH, this.logins); },
  authUsername() { return sess.get('hiraf-local-user', null); },
  onAuth(cb) { cb(this.authUsername()); },
  async signIn(username, password) {
    const h = await sha256(toSecret(password));
    if (!this.logins[username] && username === OWNER) this.logins[username] = h; // تهيئة المالك أول مرة
    if (this.logins[username] !== h) throw new Error(BAD_LOGIN);
    this.save();
    sess.set('hiraf-local-user', username);
  },
  async signOut() { this.cb = null; sess.del('hiraf-local-user'); },
  async readUser(username) { const v = this.state.users[username]; return v ? { id: username, ...structuredClone(v) } : null; },
  async createLogin(username, password) {
    if (this.logins[username]) return false;
    this.logins[username] = await sha256(toSecret(password)); this.save(); return true;
  },
  async changePassword(current, next) {
    const u = this.authUsername();
    if (this.logins[u] !== await sha256(toSecret(current))) throw new Error('كلمة المرور الحالية غير صحيحة');
    this.logins[u] = await sha256(toSecret(next)); this.save();
  },
  subscribe(onData) { this.cb = onData; onData(structuredClone(this.state)); },
  stop() { this.cb = null; },
  /** نفس قيود Firestore: لا قراءة بعد أول كتابة، والكتابة ذرّية (كلها أو لا شيء) */
  async tx(fn) {
    const draft = structuredClone(this.state);
    let wrote = false;
    const resolve = (d) => Object.fromEntries(Object.entries(d).map(([k, v]) => [k, v === SERVER_TIME ? nowISO() : structuredClone(v)]));
    const res = await fn({
      get: async (c, id) => { if (wrote) throw new Error('خطأ برمجي: قراءة بعد كتابة داخل المعاملة'); const v = draft[c][id]; return v ? { id, ...structuredClone(v) } : null; },
      set: (c, id, data) => { wrote = true; draft[c][id] = resolve(data); },
      update: (c, id, data) => { wrote = true; if (!draft[c][id]) throw new Error('المستند غير موجود'); Object.assign(draft[c][id], resolve(data)); },
      newId: () => uid(),
    });
    this.state = draft; this.save();
    if (this.cb) this.cb(structuredClone(this.state));
    return res;
  },
};

const BAD_LOGIN = 'اسم المستخدم أو كلمة المرور غير صحيحة';
function fbError(e) {
  const map = {
    'auth/operation-not-allowed': 'فعّل تسجيل الدخول بالبريد وكلمة المرور (Email/Password) في Firebase',
    'auth/too-many-requests': 'محاولات كثيرة، انتظر قليلاً ثم حاول مجدداً',
    'auth/network-request-failed': 'تحقق من اتصال الإنترنت',
    'auth/weak-password': 'كلمة المرور قصيرة جداً',
    'auth/requires-recent-login': 'سجّل الخروج ثم الدخول مرة أخرى ثم أعد المحاولة',
    'auth/invalid-api-key': 'مفتاح Firebase غير صحيح — راجع ملف firebase-config.js',
    'permission-denied': 'رفضت قاعدة البيانات العملية (صلاحيات). راجع صلاحياتك أو قواعد Firestore',
    'failed-precondition': 'تعارض في البيانات، أعد المحاولة',
    aborted: 'تعارض مع مستخدم آخر، أعد المحاولة',
    unavailable: 'لا يوجد اتصال بالإنترنت',
  };
  return map[e?.code] || e?.message || 'حدث خطأ غير متوقع';
}

/* =====================================================================
   الحالة العامة
   ===================================================================== */
function emptyData() {
  return { accounts: [], customers: [], items: [], stockMoves: [], purchases: [], catalog: [], employees: [], advances: [], payrolls: [], hr: { ...H.GOSI_DEFAULT }, invoices: [], payments: [], journals: [], assets: [], depRuns: [], users: [], audit: [], company: {}, counters: {}, accBal: new Map(), alerts: [], recon: {} };
}
const S = {
  db: null,
  user: null,          // { username, name, role, perms, active }
  entering: null,      // وعد الدخول الجاري (يمنع التكرار)
  weakPassword: false,
  section: 'dashboard',
  tabs: { hr: 'employees', reports: 'income', inventory: 'purchases', journal: 'all', invoices: 'all', customers: 'active' },
  q: {},
  period: { from: firstOfYear(), to: todayISO() },
  auditFilter: { user: '', entity: '' },
  auditSub: false,
  data: emptyData(),
  loaded: false,
};

/* =====================================================================
   4) الخدمات المحاسبية — كل خدمة = معاملة واحدة ذرّية
   ===================================================================== */
/** يكتب سطر سجل المراجعة ويعيد الحقول الموحدة لكل مستند يُكتب في نفس المعاملة.
    يجب استدعاؤه بعد انتهاء كل القراءات (قاعدة Firestore). */
function audit(t, action, entity, entityId, summary) {
  const auditId = t.newId('audit');
  t.set('audit', auditId, { at: SERVER_TIME, actor: S.user.username, actorName: S.user.name, action, entity, entityId: String(entityId), summary: H.cleanText(summary, 300) });
  return { auditId, updatedAt: nowISO(), updatedBy: S.user.username };
}
async function readCounters(t) { const c = await t.get('settings', 'counters'); if (!c) return {}; const { id, ...rest } = c; return rest; }
function bump(counters, key) { counters[key] = (counters[key] || 0) + 1; return counters[key]; }

/** ينشئ قيداً بعد التحقق من اتزانه — لا يُكتب أي قيد غير متزن */
function writeJournal(t, counters, { date, memo, lines, source, sourceId = '', status = 'posted', id: fixedId = '', extra = null }, meta) {
  const clean = lines.filter((l) => (l.debitH || 0) > 0 || (l.creditH || 0) > 0)
    .map((l) => ({ accountId: l.accountId, debitH: l.debitH || 0, creditH: l.creditH || 0, memo: H.cleanText(l.memo || '', 120) }));
  const v = H.validateJournal(clean);
  if (!v.ok) throw new H.InputError(v.errors[0]);
  if (!H.isISODate(date)) throw new H.InputError('تاريخ القيد غير صالح');
  const id = fixedId || t.newId('journals');
  const no = 'JE-' + pad(bump(counters, 'journal'), 5);
  const doc = { no, date, memo: H.cleanText(memo, 200), lines: clean, totalDebitH: v.totalDebitH, totalCreditH: v.totalCreditH, status, source, sourceId: String(sourceId), createdBy: S.user.username, createdAt: nowISO(), auditId: meta.auditId };
  if (status === 'posted') Object.assign(doc, { postedBy: S.user.username, postedAt: nowISO() });
  if (extra) Object.assign(doc, extra);
  t.set('journals', id, doc);
  return { id, no };
}
/* ---------- مساعدات الموارد البشرية ---------- */
function hrAccountsReady() {
  const miss = [ACC.advances, ACC.salPay, ACC.gosiPay, ACC.salaries, ACC.gosiExp, ACC.eosExp].filter((id) => !S.data.accounts.some((a) => a.id === id));
  if (miss.length) throw new H.InputError('حسابات الرواتب لم تُضف لدليل الحسابات بعد؛ يكفي أن يدخل مدير النظام مرة واحدة لتُضاف تلقائياً');
}
/** يوزّع مبلغ الاستقطاع على سلف الموظف المفتوحة، الأقدم أولاً */
function allocateAdvances(empId, totalH) {
  if (!totalH) return [];
  const open = S.data.advances.filter((a) => a.employeeId === empId && a.remainingH > 0).sort((a, b) => String(a.date).localeCompare(String(b.date)) || String(a.no).localeCompare(String(b.no)));
  const out = []; let left = totalH;
  for (const a of open) { if (!left) break; const x = Math.min(left, a.remainingH); out.push({ id: a.id, no: a.no, amountH: x }); left -= x; }
  if (left > 0) throw new H.InputError('قسط السلفة أكبر من المتبقي على الموظف');
  return out;
}
/** يتحقق من سطر المسير ويعيد القيم المحسوبة */
function payrollCheck(l) {
  const c = H.payrollLine(l, l, S.data.hr);
  if (c.grossH < 0) throw new H.InputError(`${l.name}: الخصومات أكبر من الراتب`);
  if (c.netH < 0) throw new H.InputError(`${l.name}: الصافي بالسالب؛ خفّض قسط السلفة أو الجزاءات`);
  const open = H.sumInts(S.data.advances.filter((a) => a.employeeId === l.employeeId).map((a) => a.remainingH));
  if ((l.advanceH || 0) > open) throw new H.InputError(`${l.name}: قسط السلفة أكبر من المتبقي (${H.fmtMoney(open)})`);
  return c;
}
/** أسطر المسير: لقطة من بيانات الموظف وقت الإعداد، مع الإضافي والغياب المُدخل سابقاً */
function buildPayrollLines(month, prev) {
  const start = month + '-01', end = monthEnd(month);
  return S.data.employees.filter((e) => e.status === 'active' && e.hireDate <= end).map((e) => {
    const p = prev.find((l) => l.employeeId === e.id);
    const defAbs = e.hireDate > start ? Math.min(30, Number(e.hireDate.slice(8)) - 1) : 0; // مباشرة خلال الشهر
    const defAdv = H.sumInts(S.data.advances.filter((a) => a.employeeId === e.id && a.remainingH > 0).map((a) => Math.min(a.installmentH, a.remainingH)));
    return { employeeId: e.id, code: e.code, name: e.name, jobTitle: e.jobTitle || '', site: e.site || '', isSaudi: !!e.isSaudi, gosi: !!e.gosi, iban: e.iban || '', bankName: e.bankName || '',
      basicH: e.basicH || 0, housingH: e.housingH || 0, transportH: e.transportH || 0, otherH: e.otherH || 0,
      overtimeH: p?.overtimeH || 0, bonusH: p?.bonusH || 0, absenceDays: p ? p.absenceDays || 0 : defAbs, penaltyH: p?.penaltyH || 0, advanceH: p ? p.advanceH || 0 : defAdv };
  });
}
/** بصمة ثابتة قصيرة لمعرّف المستند (cyrb53) — نفس العملية تعطي نفس المعرّف دائماً */
function bankDocId(str) {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < str.length; i++) { const c = str.charCodeAt(i); h1 = Math.imul(h1 ^ c, 2654435761); h2 = Math.imul(h2 ^ c, 1597334677); }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h2 >>> 0).toString(36).padStart(7, '0') + (h1 >>> 0).toString(36).padStart(7, '0') + str.length.toString(36);
}
const stockState = (it) => ({ qtyM: it.qtyM || 0, valueH: it.valueH || 0, layers: it.layers || [] });
const stockPatch = (it, meta) => ({ qtyM: it.qtyM, valueH: it.valueH, layers: it.layers, ...meta });

const Services = {
  /* ---------- التهيئة الأولى (المالك فقط) ---------- */
  async bootstrap() {
    for (const u of DEFAULT_USERS) if (u.username !== OWNER) { try { await S.db.createLogin(u.username, u.password); } catch (e) { console.warn(e); } }
    // معاملتان منفصلتان حتى لا تتجاوز أي منهما حد قواعد Firestore (20 فحصاً لكل طلب)
    await S.db.tx(async (t) => {
      const existing = {};
      for (const u of DEFAULT_USERS) existing[u.username] = await t.get('users', u.username);
      const meta = audit(t, 'create', 'system', 'bootstrap-users', 'تهيئة النظام: المستخدمون الافتراضيون');
      for (const u of DEFAULT_USERS) if (!existing[u.username]) {
        t.set('users', u.username, { name: u.name, role: u.role, perms: ROLES[u.role].perms, active: true, deleted: false, createdBy: S.user.username, createdAt: nowISO(), ...meta });
      }
    });
    await createDefaultAccounts(DEFAULT_ACCOUNTS, 'تهيئة النظام: دليل الحسابات');
  },

  /* ---------- المستخدمون ---------- */
  async saveUser({ username, name, role, perms, password }, isNew) {
    need('users.manage');
    username = normUsername(username);
    if (!USERNAME_RE.test(username)) throw new H.InputError('اسم الدخول: حروف إنجليزية صغيرة أو أرقام فقط (بدون مسافات)');
    name = H.cleanText(name, 60);
    if (!name) throw new H.InputError('اكتب الاسم الظاهر');
    if (!ROLES[role]) role = 'custom';
    const cleanPerms = username === OWNER ? ALL_PERMS : [...new Set((perms || []).filter((p) => ALL_PERMS.includes(p)))];
    if (username === OWNER) role = 'admin';
    if (!isNew && username === S.user.username && !cleanPerms.includes('users.manage') && username !== OWNER) throw new H.InputError('لا يمكنك سحب صلاحية إدارة المستخدمين من نفسك');
    if (isNew) {
      if (S.data.users.some((u) => u.id === username)) throw new H.InputError('اسم الدخول مستخدم من قبل');
      if (!password || String(password).length < 8) throw new H.InputError('كلمة المرور 8 أحرف على الأقل');
      const created = await S.db.createLogin(username, password); // حساب الدخول أولاً
      if (!created) throw new H.InputError('اسم الدخول محجوز لحساب سابق؛ اختر اسماً آخر');
    }
    await S.db.tx(async (t) => {
      const cur = await t.get('users', username);
      if (isNew && cur) throw new H.InputError('اسم الدخول مستخدم من قبل');
      if (!isNew && !cur) throw new H.InputError('المستخدم غير موجود');
      const meta = audit(t, isNew ? 'create' : 'update', 'user', username,
        `${isNew ? 'إضافة' : 'تعديل'} المستخدم ${username} (${name}) — الدور: ${roleLabel(role)} — الصلاحيات: ${cleanPerms.map((p) => PERM_LABEL[p]).join('، ') || 'مشاهدة فقط'}`);
      const data = { name, role, perms: cleanPerms, ...meta };
      if (isNew) t.set('users', username, { ...data, active: true, deleted: false, createdBy: S.user.username, createdAt: nowISO() });
      else t.update('users', username, data);
    });
  },
  async setUserActive(username, active, deleted = false) {
    need('users.manage');
    if (username === OWNER) throw new H.InputError('لا يمكن إيقاف مالك النظام أو حذفه');
    if (username === S.user.username) throw new H.InputError('لا يمكنك إيقاف حسابك');
    await S.db.tx(async (t) => {
      const cur = await t.get('users', username);
      if (!cur) throw new H.InputError('المستخدم غير موجود');
      const meta = audit(t, deleted ? 'delete' : active ? 'activate' : 'deactivate', 'user', username, `${deleted ? 'حذف' : active ? 'تفعيل' : 'إيقاف'} المستخدم ${username} (${cur.name})`);
      t.update('users', username, { active, deleted, ...meta });
    });
  },

  /* ---------- المنشأة ---------- */
  async saveCompany(c) {
    need('settings.write');
    const vat = H.normalizeDigits(c.vat);
    if (vat && !/^3\d{13}3$/.test(vat)) throw new H.InputError('الرقم الضريبي 15 رقماً يبدأ وينتهي بـ 3');
    const email = H.cleanText(c.email, 80);
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new H.InputError('البريد الإلكتروني غير صالح');
    await S.db.tx(async (t) => {
      const meta = audit(t, 'update', 'settings', 'company', 'تعديل بيانات المنشأة');
      t.set('settings', 'company', { name: H.cleanText(c.name, 120), vat, cr: H.normalizeDigits(H.cleanText(c.cr, 20)), phone: H.normalizeDigits(H.cleanText(c.phone, 20)), email, address: H.cleanText(c.address, 200), ...meta });
    });
  },

  /* ---------- الحسابات ---------- */
  async createAccount({ number, name, type }) {
    need('accounts.write');
    number = H.normalizeDigits(number);
    if (!/^\d{3,8}$/.test(number)) throw new H.InputError('رقم الحساب من 3 إلى 8 أرقام');
    if (!ACC_TYPES[type]) throw new H.InputError('نوع الحساب غير صالح');
    name = H.cleanText(name, 80); if (!name) throw new H.InputError('اسم الحساب مطلوب');
    await S.db.tx(async (t) => {
      if (await t.get('accounts', 'acc-' + number)) throw new H.InputError('رقم الحساب موجود مسبقاً');
      const meta = audit(t, 'create', 'account', 'acc-' + number, `إضافة حساب ${number} — ${name}`);
      t.set('accounts', 'acc-' + number, { number, name, type, system: false, archived: false, createdAt: nowISO(), ...meta });
    });
  },

  /* ---------- العملاء ---------- */
  async saveCustomer(id, c) {
    need('customer.write');
    const name = H.cleanText(c.name, 120);
    if (!name) throw new H.InputError('اسم العميل مطلوب');
    const vatNo = H.normalizeDigits(c.vatNo);
    if (vatNo && !/^3\d{13}3$/.test(vatNo)) throw new H.InputError('الرقم الضريبي للعميل 15 رقماً يبدأ وينتهي بـ 3');
    const phone = H.normalizeDigits(c.phone);
    if (phone && !/^\+?\d{7,15}$/.test(phone)) throw new H.InputError('رقم الجوال غير صالح');
    const email = H.cleanText(c.email, 80);
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new H.InputError('البريد الإلكتروني غير صالح');
    const data = { name, company: H.cleanText(c.company, 120), vatNo, phone, email, city: H.cleanText(c.city, 60), notes: H.cleanText(c.notes, 500) };
    await S.db.tx(async (t) => {
      const cur = id ? await t.get('customers', id) : null;
      if (id && !cur) throw new H.InputError('العميل غير موجود');
      const cid = id || t.newId('customers');
      const meta = audit(t, id ? 'update' : 'create', 'customer', cid, `${id ? 'تعديل' : 'إضافة'} العميل ${name}`);
      if (id) t.update('customers', cid, { ...data, ...meta });
      else t.set('customers', cid, { ...data, archived: false, createdBy: S.user.username, createdAt: nowISO(), ...meta });
    });
    return name;
  },
  async archiveCustomer(id, archived) {
    need('customer.write');
    await S.db.tx(async (t) => {
      const c = await t.get('customers', id); if (!c) throw new H.InputError('العميل غير موجود');
      const meta = audit(t, archived ? 'archive' : 'restore', 'customer', id, `${archived ? 'أرشفة' : 'استعادة'} العميل ${c.name}`);
      t.update('customers', id, { archived, ...meta });
    });
  },

  /* ---------- الفواتير ---------- */
  /** يحفظ مسودة: لا رقم ولا أثر محاسبي حتى الإصدار */
  async saveInvoiceDraft(id, f) {
    need('invoice.write');
    const tot = H.invoiceTotals(f.lines);
    const cust = S.data.customers.find((c) => c.id === f.customerId);
    if (!cust) throw new H.InputError('اختر العميل');
    return S.db.tx(async (t) => {
      if (id) { const cur = await t.get('invoices', id); if (!cur || cur.status !== 'draft') throw new H.InputError('لا يمكن تعديل فاتورة بعد إصدارها'); }
      const iid = id || t.newId('invoices');
      const meta = audit(t, id ? 'update' : 'create', 'invoice', iid, `${id ? 'تعديل' : 'إنشاء'} مسودة فاتورة للعميل ${cust.name} بإجمالي ${H.fmtMoney(tot.totalH)}`);
      const doc = { customerId: f.customerId, customerName: cust.name, issueDate: f.issueDate, dueDate: f.dueDate, description: f.description, lines: tot.lines, netH: tot.netH, vatH: tot.vatH, totalH: tot.totalH, paidH: 0, ...meta };
      if (id) t.update('invoices', iid, doc);
      else t.set('invoices', iid, { ...doc, status: 'draft', number: '', journalIds: [], createdBy: S.user.username, createdAt: nowISO() });
      return iid;
    });
  },

  /**
   * إصدار الفاتورة — معاملة واحدة تشمل:
   *   رقماً تسلسلياً + صرف المخزون (FIFO/متوسط) + قيداً:
   *   من حـ/ العملاء (الإجمالي)  إلى حـ/ المبيعات والخدمات (الصافي) و حـ/ ضريبة المخرجات
   *   من حـ/ تكلفة المبيعات      إلى حـ/ المخزون (تكلفة البضاعة)
   */
  async issueInvoice(id) {
    need('invoice.issue');
    return S.db.tx(async (t) => {
      const inv = await t.get('invoices', id);
      if (!inv) throw new H.InputError('الفاتورة غير موجودة');
      if (inv.status !== 'draft') throw new H.InputError('الفاتورة ليست مسودة');
      if (!H.isISODate(inv.issueDate) || !H.isISODate(inv.dueDate) || inv.dueDate < inv.issueDate) throw new H.InputError('راجع تاريخي الإصدار والاستحقاق');
      if (new Set(inv.lines.filter((l) => l.kind === 'goods').map((l) => l.itemId)).size > MAX_GOODS_LINES) throw new H.InputError(`الحد الأقصى ${MAX_GOODS_LINES} أصناف مخزون مختلفة في الفاتورة`);
      const counters = await readCounters(t);
      const items = {};
      for (const l of inv.lines) if (l.kind === 'goods' && !items[l.itemId]) { items[l.itemId] = await t.get('items', l.itemId); if (!items[l.itemId]) throw new H.InputError('صنف غير موجود في الفاتورة'); }
      // ---- الحساب (بعد القراءات) — نعيد الحساب من البنود ولا نثق بالمجاميع المخزنة ----
      const tot = H.invoiceTotals(inv.lines);
      let cogsH = 0;
      const moves = [];
      const lines = tot.lines.map((l) => {
        if (l.kind !== 'goods') return l;
        const it = items[l.itemId];
        const r = H.stockOut(stockState(it), l.qtyM, it.method); // يمنع البيع بأكثر من المتوفر
        items[l.itemId] = { ...it, ...r.state };
        cogsH += r.costH;
        moves.push({ itemId: l.itemId, qtyM: l.qtyM, costH: r.costH });
        return { ...l, costH: r.costH };
      });
      const number = 'INV-' + pad(bump(counters, 'invoice'), 5);
      // ---- الكتابات ----
      const meta = audit(t, 'issue', 'invoice', id, `إصدار الفاتورة ${number} للعميل ${inv.customerName} بإجمالي ${H.fmtMoney(tot.totalH)} (ضريبة ${H.fmtMoney(tot.vatH)})`);
      const j = writeJournal(t, counters, {
        date: inv.issueDate, memo: `فاتورة ${number} — ${inv.customerName}`, source: 'invoice', sourceId: id,
        lines: [
          { accountId: ACC.ar, debitH: tot.totalH },
          { accountId: ACC.sales, creditH: tot.goodsNetH },
          { accountId: ACC.services, creditH: tot.servicesNetH },
          { accountId: ACC.vatOut, creditH: tot.vatH },
          { accountId: ACC.cogs, debitH: cogsH },
          { accountId: ACC.inv, creditH: cogsH },
        ],
      }, meta);
      for (const [iid, it] of Object.entries(items)) t.update('items', iid, stockPatch(it, meta));
      for (const m of moves) t.set('stockMoves', t.newId('stockMoves'), { type: 'out', ...m, date: inv.issueDate, ref: 'invoice', refId: id, refNo: number, createdBy: S.user.username, createdAt: nowISO(), ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      t.update('invoices', id, { status: 'issued', number, lines, netH: tot.netH, vatH: tot.vatH, totalH: tot.totalH, cogsH, paidH: 0, journalIds: [j.id], issuedBy: S.user.username, issuedAt: nowISO(), ...meta });
      return number;
    });
  },

  async cancelDraftInvoice(id) {
    need('invoice.write');
    await S.db.tx(async (t) => {
      const inv = await t.get('invoices', id);
      if (!inv || inv.status !== 'draft') throw new H.InputError('يمكن إلغاء المسودات فقط');
      const meta = audit(t, 'cancel', 'invoice', id, `إلغاء مسودة فاتورة للعميل ${inv.customerName}`);
      t.update('invoices', id, { status: 'cancelled', ...meta });
    });
  },

  /** إلغاء فاتورة مُصدرة غير مدفوعة: قيد عكسي + إرجاع المخزون بنفس تكلفته */
  async voidInvoice(id, reason) {
    need('invoice.void');
    reason = H.cleanText(reason, 200);
    if (reason.length < 3) throw new H.InputError('اكتب سبب الإلغاء');
    await S.db.tx(async (t) => {
      const inv = await t.get('invoices', id);
      if (!inv || inv.status !== 'issued') throw new H.InputError('الفاتورة ليست مُصدرة');
      if ((inv.paidH || 0) !== 0) throw new H.InputError('على الفاتورة سندات قبض — اعكسها أولاً');
      const orig = await t.get('journals', inv.journalIds[0]);
      const counters = await readCounters(t);
      const goods = inv.lines.filter((l) => l.kind === 'goods');
      const items = {};
      for (const l of goods) if (!items[l.itemId]) items[l.itemId] = await t.get('items', l.itemId);
      for (const l of goods) items[l.itemId] = { ...items[l.itemId], ...H.stockIn(stockState(items[l.itemId]), l.qtyM, l.costH || 0) };
      const meta = audit(t, 'void', 'invoice', id, `إلغاء الفاتورة ${inv.number} — السبب: ${reason}`);
      const j = writeJournal(t, counters, { date: todayISO(), memo: `إلغاء الفاتورة ${inv.number}: ${reason}`, source: 'void', sourceId: id, lines: H.reverseLines(orig.lines) }, meta);
      for (const [iid, it] of Object.entries(items)) t.update('items', iid, stockPatch(it, meta));
      for (const l of goods) t.set('stockMoves', t.newId('stockMoves'), { type: 'in', itemId: l.itemId, qtyM: l.qtyM, costH: l.costH || 0, date: todayISO(), ref: 'void', refId: id, refNo: inv.number, createdBy: S.user.username, createdAt: nowISO(), ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      t.update('invoices', id, { status: 'void', voidReason: reason, voidedBy: S.user.username, voidedAt: nowISO(), voidedDate: todayISO(), journalIds: [...inv.journalIds, j.id], ...meta });
    });
  },

  /* ---------- سندات القبض ---------- */
  /** من حـ/ الصندوق أو البنك  إلى حـ/ العملاء — ولا يتجاوز السند المتبقي على الفاتورة */
  async recordPayment({ invoiceId, amountH, accountId, method, date, reference }) {
    need('payment.create');
    if (![ACC.cash, ACC.bank].includes(accountId)) throw new H.InputError('اختر الصندوق أو البنك');
    if (!H.isISODate(date)) throw new H.InputError('تاريخ السند غير صالح');
    return S.db.tx(async (t) => {
      const inv = await t.get('invoices', invoiceId);
      if (!inv || inv.status !== 'issued') throw new H.InputError('الفاتورة غير مُصدرة');
      const counters = await readCounters(t);
      const remaining = inv.totalH - (inv.paidH || 0);
      if (!Number.isSafeInteger(amountH) || amountH <= 0) throw new H.InputError('المبلغ غير صالح');
      if (amountH > remaining) throw new H.InputError(`المبلغ أكبر من المتبقي (${H.fmtMoney(remaining)})`);
      if (date < inv.issueDate) throw new H.InputError('تاريخ السند قبل تاريخ الفاتورة');
      const no = 'RV-' + pad(bump(counters, 'payment'), 5);
      const pid = t.newId('payments');
      const meta = audit(t, 'create', 'payment', pid, `سند قبض ${no} بمبلغ ${H.fmtMoney(amountH)} على الفاتورة ${inv.number}`);
      const j = writeJournal(t, counters, { date, memo: `سند قبض ${no} — ${inv.customerName} — ${inv.number}`, source: 'payment', sourceId: pid,
        lines: [{ accountId, debitH: amountH }, { accountId: ACC.ar, creditH: amountH }] }, meta);
      t.set('payments', pid, { no, invoiceId, invoiceNo: inv.number, customerId: inv.customerId, customerName: inv.customerName, amountH, accountId, method: PAY_METHODS[method] ? method : 'cash', date, reference: H.cleanText(reference, 60), status: 'active', journalIds: [j.id], createdBy: S.user.username, createdAt: nowISO(), ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      t.update('invoices', invoiceId, { paidH: (inv.paidH || 0) + amountH, ...meta });
      return no;
    });
  },
  async reversePayment(id, reason) {
    need('payment.reverse');
    reason = H.cleanText(reason, 200);
    if (reason.length < 3) throw new H.InputError('اكتب سبب العكس');
    await S.db.tx(async (t) => {
      const p = await t.get('payments', id);
      if (!p || p.status !== 'active') throw new H.InputError('السند غير فعّال');
      const inv = await t.get('invoices', p.invoiceId);
      const orig = await t.get('journals', p.journalIds[0]);
      const counters = await readCounters(t);
      const meta = audit(t, 'reverse', 'payment', id, `عكس سند القبض ${p.no} (${H.fmtMoney(p.amountH)}) — السبب: ${reason}`);
      const j = writeJournal(t, counters, { date: todayISO(), memo: `عكس سند القبض ${p.no}: ${reason}`, source: 'reversal', sourceId: id, lines: H.reverseLines(orig.lines) }, meta);
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      t.update('payments', id, { status: 'reversed', reversedBy: S.user.username, reversedAt: nowISO(), reverseReason: reason, journalIds: [...p.journalIds, j.id], ...meta });
      t.update('invoices', p.invoiceId, { paidH: Math.max(0, (inv.paidH || 0) - p.amountH), ...meta });
    });
  },

  /* ---------- القيود اليدوية (فصل المهام: المُنشئ ≠ المعتمِد) ---------- */
  async saveManualJournal(id, { date, memo, lines }) {
    need('journal.create');
    if (!H.isISODate(date)) throw new H.InputError('تاريخ القيد غير صالح');
    const v = H.validateJournal(lines);
    if (!v.ok) throw new H.InputError(v.errors[0]);
    const accIds = new Set(S.data.accounts.map((a) => a.id));
    if (lines.some((l) => !accIds.has(l.accountId))) throw new H.InputError('حساب غير موجود في دليل الحسابات');
    return S.db.tx(async (t) => {
      if (id) {
        const cur = await t.get('journals', id);
        if (!cur || cur.status !== 'draft') throw new H.InputError('لا يمكن تعديل قيد بعد اعتماده');
        if (cur.createdBy !== S.user.username) throw new H.InputError('يعدّل القيد من أنشأه فقط');
        const meta = audit(t, 'update', 'journal', id, `تعديل القيد ${cur.no} (${H.fmtMoney(v.totalDebitH)})`);
        t.update('journals', id, { date, memo: H.cleanText(memo, 200), lines, totalDebitH: v.totalDebitH, totalCreditH: v.totalCreditH, ...meta });
        return cur.no;
      }
      const counters = await readCounters(t);
      const meta = audit(t, 'create', 'journal', 'manual', `إنشاء قيد يدوي (${H.fmtMoney(v.totalDebitH)}) بانتظار الاعتماد: ${memo}`);
      const j = writeJournal(t, counters, { date, memo, lines, source: 'manual', status: 'draft' }, meta);
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      return j.no;
    });
  },
  async postJournal(id) {
    need('journal.post');
    await S.db.tx(async (t) => {
      const j = await t.get('journals', id);
      if (!j || j.status !== 'draft') throw new H.InputError('القيد ليس بانتظار الاعتماد');
      if (j.createdBy === S.user.username) throw new H.InputError('فصل المهام: لا يمكنك اعتماد قيد أنشأته بنفسك');
      const v = H.validateJournal(j.lines);
      if (!v.ok) throw new H.InputError(v.errors[0]);
      const meta = audit(t, 'post', 'journal', id, `اعتماد وترحيل القيد ${j.no} (${H.fmtMoney(v.totalDebitH)})`);
      t.update('journals', id, { status: 'posted', postedBy: S.user.username, postedAt: nowISO(), ...meta });
    });
  },
  async cancelJournal(id, reason) {
    await S.db.tx(async (t) => {
      const j = await t.get('journals', id);
      if (!j || j.status !== 'draft') throw new H.InputError('يمكن إلغاء القيود غير المعتمدة فقط');
      if (j.createdBy !== S.user.username && !can('journal.post')) throw new H.InputError('ليست لديك صلاحية لإلغاء هذا القيد');
      const meta = audit(t, 'cancel', 'journal', id, `رفض/إلغاء القيد ${j.no}: ${reason || ''}`);
      t.update('journals', id, { status: 'cancelled', cancelledBy: S.user.username, cancelledAt: nowISO(), cancelReason: H.cleanText(reason, 200), ...meta });
    });
  },
  async reverseJournal(id, reason) {
    need('journal.reverse');
    reason = H.cleanText(reason, 200);
    if (reason.length < 3) throw new H.InputError('اكتب سبب العكس');
    await S.db.tx(async (t) => {
      const j = await t.get('journals', id);
      if (!j || j.status !== 'posted') throw new H.InputError('يمكن عكس القيود المرحّلة فقط');
      if (!['manual', 'bank'].includes(j.source)) throw new H.InputError('هذا قيد آلي: ألغِ المستند الأصلي (الفاتورة أو السند)');
      const counters = await readCounters(t);
      const meta = audit(t, 'reverse', 'journal', id, `عكس القيد ${j.no}: ${reason}`);
      const r = writeJournal(t, counters, { date: todayISO(), memo: `عكس القيد ${j.no}: ${reason}`, source: 'reversal', sourceId: id, lines: H.reverseLines(j.lines) }, meta);
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      t.update('journals', id, { status: 'reversed', reversedBy: S.user.username, reversedAt: nowISO(), reversalId: r.id, ...meta });
    });
  },

  /* ---------- المخزون ---------- */
  async saveItem(id, f) {
    need('inventory.write');
    const name = H.cleanText(f.name, 100); if (!name) throw new H.InputError('اسم الصنف مطلوب');
    const sku = H.cleanText(f.sku, 30); if (!sku) throw new H.InputError('رمز الصنف مطلوب');
    if (S.data.items.some((i) => i.sku === sku && i.id !== id)) throw new H.InputError('رمز الصنف مستخدم من قبل');
    if (!['FIFO', 'AVG'].includes(f.method)) throw new H.InputError('طريقة التقييم غير صالحة');
    await S.db.tx(async (t) => {
      const cur = id ? await t.get('items', id) : null;
      if (id && !cur) throw new H.InputError('الصنف غير موجود');
      if (cur && cur.method !== f.method && (cur.qtyM || 0) > 0) throw new H.InputError('لا يمكن تغيير طريقة التقييم والصنف عليه رصيد');
      const iid = id || t.newId('items');
      const meta = audit(t, id ? 'update' : 'create', 'item', iid, `${id ? 'تعديل' : 'إضافة'} الصنف ${sku} — ${name} (${f.method === 'FIFO' ? 'FIFO' : 'متوسط مرجح'})`);
      const data = { sku, name, unit: H.cleanText(f.unit, 20) || 'وحدة', method: f.method, reorderM: f.reorderM || 0, salePriceH: f.salePriceH || 0, ...meta };
      if (id) t.update('items', iid, data);
      else t.set('items', iid, { ...data, qtyM: 0, valueH: 0, layers: [], archived: false, createdBy: S.user.username, createdAt: nowISO() });
    });
    return name;
  },
  /**
   * فاتورة مشتريات (مصروفات) — الطريقة المبسطة:
   *  يكتب المستخدم اسم الصنف والكمية والسعر فقط؛ الصنف يُحفظ تلقائياً في قائمة الأصناف
   *  (مشتقة من الفواتير) ولا يدخل المخزون.
   *  القيد: من حـ/ المصروف (حسب تصنيف كل بند) + ضريبة المدخلات  إلى حـ/ الصندوق أو البنك أو الموردين
   */
  async recordPurchase(f) {
    need('inventory.write');
    if (![ACC.cash, ACC.bank, ACC.ap].includes(f.payAccountId)) throw new H.InputError('اختر طريقة السداد');
    if (!H.isISODate(f.date)) throw new H.InputError('تاريخ الفاتورة غير صالح');
    if (!['incl', 'excl', 'none'].includes(f.vatMode)) throw new H.InputError('اختر طريقة الضريبة');
    const supplier = H.cleanText(f.supplier, 120) || 'مورد نقدي';
    if (f.payAccountId === ACC.ap && supplier === 'مورد نقدي') throw new H.InputError('اكتب اسم المورد للشراء الآجل');
    if (!Array.isArray(f.lines) || !f.lines.length || f.lines.length > 40) throw new H.InputError('عدد البنود من 1 إلى 40');
    const DEFAULT_EXP = { [ACC.materials]: DEFAULT_ACCOUNTS.find((a) => a[0] === '5600'), [ACC.general]: DEFAULT_ACCOUNTS.find((a) => a[0] === '5700') };
    const lines = f.lines.map((l, k) => {
      const name = H.cleanText(l.name, 100);
      if (!name) throw new H.InputError(`اكتب اسم الصنف في البند ${k + 1}`);
      if (!Number.isSafeInteger(l.qtyM) || l.qtyM <= 0) throw new H.InputError(`الكمية غير صالحة في البند ${k + 1}`);
      if (!Number.isSafeInteger(l.priceH) || l.priceH <= 0) throw new H.InputError(`السعر غير صالح في البند ${k + 1}`);
      const acc = S.data.accounts.find((a) => a.id === l.accountId);
      const okAcc = acc ? acc.type === 'Expenses' && !acc.archived && ![ACC.cogs, ACC.depExp].includes(acc.id) : !!DEFAULT_EXP[l.accountId];
      if (!okAcc) throw new H.InputError(`اختر التصنيف في البند ${k + 1}`);
      return { name, accountId: l.accountId, qtyM: l.qtyM, priceH: l.priceH, ...H.purchaseLine(l.qtyM, l.priceH, f.vatMode) };
    });
    const netH = H.sumInts(lines.map((l) => l.netH)), vatH = H.sumInts(lines.map((l) => l.vatH));
    if (netH <= 0) throw new H.InputError('إجمالي الفاتورة صفر');
    // تجميع المدين حسب الحساب (سطر واحد لكل تصنيف)
    const byAcc = new Map();
    lines.forEach((l) => byAcc.set(l.accountId, (byAcc.get(l.accountId) || 0) + l.netH));
    return S.db.tx(async (t) => {
      // حسابات التصنيف الافتراضية تُنشأ تلقائياً إن لم تكن موجودة (للأنظمة المهيأة قبل إضافتها)
      const missing = [];
      for (const id of byAcc.keys()) if (DEFAULT_EXP[id] && !(await t.get('accounts', id))) missing.push(id);
      if (missing.length && !can('accounts.write')) throw new H.InputError('حساب التصنيف غير موجود — اطلب من المدير فتح الشاشة مرة واحدة أو إضافته');
      const counters = await readCounters(t);
      const no = 'PU-' + pad(bump(counters, 'purchase'), 5);
      const pid = t.newId('purchases');
      const meta = audit(t, 'create', 'purchase', pid, `فاتورة مشتريات ${no} من ${supplier} بإجمالي ${H.fmtMoney(netH + vatH)} (${lines.length} بند)`);
      for (const id of missing) { const [n, name, type, flags] = DEFAULT_EXP[id]; t.set('accounts', id, { number: n, name, type, ...flags, system: true, archived: false, createdAt: nowISO(), ...meta }); }
      const j = writeJournal(t, counters, { date: f.date, memo: `مشتريات ${no} — ${supplier}`, source: 'purchase', sourceId: pid,
        lines: [...[...byAcc].map(([accountId, debitH]) => ({ accountId, debitH })), { accountId: ACC.vatIn, debitH: vatH }, { accountId: f.payAccountId, creditH: netH + vatH }] }, meta);
      t.set('purchases', pid, { no, kind: 'expense', supplier, supplierVat: f.supplierVat || '', ref: H.cleanText(f.ref, 40), date: f.date, payAccountId: f.payAccountId, vatMode: f.vatMode,
        lines, netH, vatH, totalH: netH + vatH, journalIds: [j.id], createdBy: S.user.username, createdAt: nowISO(), ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      return no;
    });
  },
  /** (نظام سابق) شراء أصناف مخزنية للبيع: من حـ/ المخزون + ضريبة المدخلات  إلى حـ/ الصندوق/البنك/الموردين */
  async recordStockPurchase(f) {
    need('inventory.write');
    if (![ACC.cash, ACC.bank, ACC.ap].includes(f.payAccountId)) throw new H.InputError('اختر طريقة السداد');
    if (!H.isISODate(f.date)) throw new H.InputError('تاريخ الفاتورة غير صالح');
    const supplier = H.cleanText(f.supplier, 120); if (!supplier) throw new H.InputError('اسم المورد مطلوب');
    if (!f.lines.length || f.lines.length > 30) throw new H.InputError('عدد البنود من 1 إلى 30');
    if (new Set(f.lines.map((l) => l.itemId)).size > MAX_GOODS_LINES) throw new H.InputError(`الحد الأقصى ${MAX_GOODS_LINES} أصناف مختلفة في الفاتورة`);
    const lines = f.lines.map((l) => { const netH = H.lineNet(l.qtyM, l.unitCostH); const vatH = f.withVat ? H.vatOf(netH) : 0; return { ...l, netH, vatH }; });
    const netH = H.sumInts(lines.map((l) => l.netH)), vatH = H.sumInts(lines.map((l) => l.vatH));
    return S.db.tx(async (t) => {
      const items = {};
      for (const l of lines) if (!items[l.itemId]) { items[l.itemId] = await t.get('items', l.itemId); if (!items[l.itemId]) throw new H.InputError('صنف غير موجود'); }
      const counters = await readCounters(t);
      for (const l of lines) items[l.itemId] = { ...items[l.itemId], ...H.stockIn(stockState(items[l.itemId]), l.qtyM, l.netH) };
      const no = 'PU-' + pad(bump(counters, 'purchase'), 5);
      const pid = t.newId('purchases');
      const meta = audit(t, 'create', 'purchase', pid, `فاتورة مشتريات ${no} من ${supplier} بإجمالي ${H.fmtMoney(netH + vatH)}`);
      const j = writeJournal(t, counters, { date: f.date, memo: `مشتريات ${no} — ${supplier}`, source: 'purchase', sourceId: pid,
        lines: [{ accountId: ACC.inv, debitH: netH }, { accountId: ACC.vatIn, debitH: vatH }, { accountId: f.payAccountId, creditH: netH + vatH }] }, meta);
      for (const [iid, it] of Object.entries(items)) t.update('items', iid, stockPatch(it, meta));
      for (const l of lines) t.set('stockMoves', t.newId('stockMoves'), { type: 'in', itemId: l.itemId, qtyM: l.qtyM, costH: l.netH, date: f.date, ref: 'purchase', refId: pid, refNo: no, createdBy: S.user.username, createdAt: nowISO(), ...meta });
      t.set('purchases', pid, { no, supplier, supplierVat: f.supplierVat || '', ref: H.cleanText(f.ref, 40), date: f.date, payAccountId: f.payAccountId,
        lines: lines.map((l) => ({ itemId: l.itemId, qtyM: l.qtyM, unitCostH: l.unitCostH, netH: l.netH, vatH: l.vatH })), netH, vatH, totalH: netH + vatH, journalIds: [j.id], createdBy: S.user.username, createdAt: nowISO(), ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      return no;
    });
  },

  /**
   * استيراد عمليات كشف الحساب البنكي (بعد مراجعتها في الشاشة).
   *  - سحب مصنّف «مصروفات» ← فاتورة مشتريات (تظهر في المشتريات والأصناف والإقرار الضريبي)
   *  - أي عملية أخرى ← قيد مرحّل: السحب من حـ/ التصنيف إلى حـ/ البنك، والإيداع من حـ/ البنك إلى حـ/ التصنيف
   *  - معرّف كل مستند مشتق من بصمة العملية، فالعملية نفسها لا تُرحّل مرتين ولو رُفع الكشف مرتين
   *  - الترحيل على دفعات صغيرة لأن قواعد Firestore تحد عدد الفحوص في الطلب الواحد
   */
  async importBank({ bankAccountId, rows, fileName }, onProgress) {
    need('bank.import');
    const bank = S.data.accounts.find((a) => a.id === bankAccountId);
    if (!bank || !bank.cash) throw new H.InputError('اختر حساب البنك أو الصندوق');
    const blocked = new Set([bankAccountId, ACC.ar, ACC.inv, ACC.fa, ACC.accDep]);
    const accs = new Map(S.data.accounts.map((a) => [a.id, a]));
    const file = H.cleanText(fileName, 80) || 'كشف الحساب';
    const clean = rows.map((r, k) => {
      const at = `العملية ${k + 1}`;
      if (!H.isISODate(r.date)) throw new H.InputError(`${at}: التاريخ غير صالح`);
      if (!['in', 'out'].includes(r.dir)) throw new H.InputError(`${at}: نوع العملية غير صالح`);
      if (!Number.isSafeInteger(r.amountH) || r.amountH <= 0 || r.amountH > H.MAX_H) throw new H.InputError(`${at}: المبلغ غير صالح`);
      const acc = accs.get(r.accountId);
      if (!acc || acc.archived || blocked.has(acc.id)) throw new H.InputError(`${at}: اختر تصنيفاً صالحاً`);
      const desc = H.cleanText(r.desc, 200) || 'عملية بنكية';
      const asPurchase = r.dir === 'out' && acc.type === 'Expenses';
      return { ...r, desc, acc, asPurchase, vat: asPurchase && !!r.vat, key: bankDocId(bankAccountId + '|' + String(r.ref || '')) };
    });
    if (!clean.length) throw new H.InputError('اختر عملية واحدة على الأقل');
    const CHUNK = 3;
    let posted = 0, dup = 0;
    for (let i = 0; i < clean.length; i += CHUNK) {
      const part = clean.slice(i, i + CHUNK);
      await S.db.tx(async (t) => {
        // كل القراءات أولاً (شرط المعاملات)
        const fresh = [];
        for (const r of part) {
          const exists = r.asPurchase ? await t.get('purchases', 'bk' + r.key) : await t.get('journals', 'bk' + r.key);
          if (exists) dup++; else fresh.push(r);
        }
        if (!fresh.length) return;
        const counters = await readCounters(t);
        const sum = H.sumInts(fresh.map((r) => r.amountH));
        const meta = audit(t, 'import', 'bank', bankAccountId, `استيراد ${fresh.length} عملية من «${file}» (${bank.name}) بإجمالي ${H.fmtMoney(sum)}`);
        for (const r of fresh) {
          const extra = { bankRef: r.ref, bankFile: file };
          if (r.asPurchase) {
            const { netH, vatH } = r.vat ? H.splitGross(r.amountH) : { netH: r.amountH, vatH: 0 };
            const pid = 'bk' + r.key;
            const no = 'PU-' + pad(bump(counters, 'purchase'), 5);
            const j = writeJournal(t, counters, { date: r.date, memo: `مشتريات ${no} — ${r.desc}`, source: 'purchase', sourceId: pid, id: 'bj' + r.key, extra,
              lines: [{ accountId: r.acc.id, debitH: netH }, { accountId: ACC.vatIn, debitH: vatH }, { accountId: bankAccountId, creditH: r.amountH }] }, meta);
            t.set('purchases', pid, { no, kind: 'expense', source: 'bank', ...extra, supplier: r.desc.slice(0, 120), supplierVat: '', ref: '', date: r.date, payAccountId: bankAccountId, vatMode: r.vat ? 'incl' : 'none',
              lines: [{ name: r.desc.slice(0, 100), accountId: r.acc.id, qtyM: 1000, priceH: r.amountH, netH, vatH }], netH, vatH, totalH: r.amountH, journalIds: [j.id], createdBy: S.user.username, createdAt: nowISO(), ...meta });
          } else {
            const lines = r.dir === 'out'
              ? [{ accountId: r.acc.id, debitH: r.amountH, memo: r.desc }, { accountId: bankAccountId, creditH: r.amountH }]
              : [{ accountId: bankAccountId, debitH: r.amountH }, { accountId: r.acc.id, creditH: r.amountH, memo: r.desc }];
            writeJournal(t, counters, { date: r.date, memo: r.desc, source: 'bank', sourceId: bankAccountId, id: 'bk' + r.key, extra, lines }, meta);
          }
        }
        t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
        posted += fresh.length;
      });
      onProgress?.(Math.min(i + CHUNK, clean.length), clean.length);
    }
    return { posted, dup };
  },

  /* ---------- الموارد البشرية ---------- */
  async saveEmployee(id, f) {
    need('hr.manage');
    const name = H.cleanText(f.name, 100); if (!name) throw new H.InputError('اسم الموظف مطلوب');
    if (!H.isISODate(f.hireDate)) throw new H.InputError('تاريخ المباشرة غير صالح');
    for (const [k, l] of [['basicH', 'الراتب الأساسي'], ['housingH', 'بدل السكن'], ['transportH', 'بدل النقل'], ['otherH', 'البدلات الأخرى']]) {
      if (!Number.isSafeInteger(f[k] || 0) || (f[k] || 0) < 0) throw new H.InputError(`${l} غير صالح`);
    }
    if (!(f.basicH > 0)) throw new H.InputError('الراتب الأساسي مطلوب');
    const iban = String(f.iban || '').toUpperCase().replace(/\s/g, '');
    if (iban && !/^SA\d{22}$/.test(iban)) throw new H.InputError('الآيبان 24 خانة ويبدأ بـ SA');
    const idNumber = H.normalizeDigits(f.idNumber || '');
    if (idNumber && !/^[12]\d{9}$/.test(idNumber)) throw new H.InputError('رقم الهوية أو الإقامة 10 أرقام يبدأ بـ 1 أو 2');
    const phone = H.normalizeDigits(f.phone || '');
    if (phone && !/^(05\d{8}|\+?9665\d{8})$/.test(phone)) throw new H.InputError('رقم الجوال غير صحيح (مثال: 0501234567)');
    const data = { name, jobTitle: H.cleanText(f.jobTitle, 60), site: H.cleanText(f.site, 60), isSaudi: !!f.isSaudi, nationality: H.cleanText(f.nationality, 30),
      idNumber, hireDate: f.hireDate, basicH: f.basicH, housingH: f.housingH || 0, transportH: f.transportH || 0, otherH: f.otherH || 0,
      gosi: !!f.gosi, bankName: H.cleanText(f.bankName, 40), iban, phone };
    const wage = H.fmtMoney(H.fixedWageH(data));
    return S.db.tx(async (t) => {
      if (id) {
        const cur = await t.get('employees', id);
        if (!cur) throw new H.InputError('الموظف غير موجود');
        if (cur.status !== 'active') throw new H.InputError('لا تُعدّل بيانات موظف انتهت خدمته');
        const meta = audit(t, 'update', 'employee', id, `تعديل بيانات الموظف ${cur.code} — ${name} (الأجر الثابت ${wage})`);
        t.update('employees', id, { ...data, ...meta });
        return cur.code;
      }
      const counters = await readCounters(t);
      const code = 'EMP-' + pad(bump(counters, 'employee'), 3);
      const eid = t.newId('employees');
      const meta = audit(t, 'create', 'employee', eid, `إضافة الموظف ${code} — ${name} (الأجر الثابت ${wage})`);
      t.set('employees', eid, { ...data, code, status: 'active', createdBy: S.user.username, createdAt: nowISO(), ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      return code;
    });
  },
  /** صرف سلفة: من حـ/ سلف الموظفين إلى حـ/ الصندوق أو البنك. تُسترد أقساطاً من المسير */
  async createAdvance(f) {
    need('hr.manage');
    hrAccountsReady();
    if (![ACC.cash, ACC.bank].includes(f.payAccountId)) throw new H.InputError('اختر الصندوق أو البنك');
    if (!H.isISODate(f.date)) throw new H.InputError('التاريخ غير صالح');
    if (!Number.isSafeInteger(f.amountH) || f.amountH <= 0) throw new H.InputError('مبلغ السلفة غير صالح');
    if (!Number.isInteger(f.installments) || f.installments < 1 || f.installments > 36) throw new H.InputError('عدد الأقساط من 1 إلى 36');
    const emp = S.data.employees.find((e) => e.id === f.employeeId && e.status === 'active');
    if (!emp) throw new H.InputError('اختر الموظف');
    return S.db.tx(async (t) => {
      const counters = await readCounters(t);
      const no = 'ADV-' + pad(bump(counters, 'advance'), 5);
      const aid = t.newId('advances');
      const meta = audit(t, 'create', 'advance', aid, `سلفة ${no} للموظف ${emp.name} بمبلغ ${H.fmtMoney(f.amountH)} على ${f.installments} قسط`);
      const j = writeJournal(t, counters, { date: f.date, memo: `سلفة ${no} — ${emp.name}`, source: 'advance', sourceId: aid,
        lines: [{ accountId: ACC.advances, debitH: f.amountH }, { accountId: f.payAccountId, creditH: f.amountH }] }, meta);
      t.set('advances', aid, { no, employeeId: emp.id, empName: emp.name, empCode: emp.code, date: f.date, amountH: f.amountH, installments: f.installments,
        installmentH: Math.ceil(f.amountH / f.installments), note: H.cleanText(f.note, 120), payAccountId: f.payAccountId, journalIds: [j.id],
        createdBy: S.user.username, createdAt: nowISO(), ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      return no;
    });
  },
  /** إعداد (أو إعادة إعداد) مسودة مسير الشهر من الموظفين النشطين، مع الاحتفاظ بما أُدخل سابقاً */
  async preparePayroll(month) {
    need('payroll.run');
    if (!H.isMonth(month)) throw new H.InputError('الشهر غير صالح');
    const cur0 = S.data.payrolls.find((p) => p.id === month);
    const lines = buildPayrollLines(month, cur0?.lines || []);
    if (!lines.length) throw new H.InputError('لا يوجد موظفون نشطون باشروا قبل نهاية هذا الشهر');
    return S.db.tx(async (t) => {
      const cur = await t.get('payrolls', month);
      if (cur && cur.status !== 'draft') throw new H.InputError('مسير هذا الشهر معتمد بالفعل');
      const meta = audit(t, cur ? 'update' : 'create', 'payroll', month, `${cur ? 'إعادة إعداد' : 'إعداد'} مسير رواتب ${fmtMonth(month)} (${lines.length} موظف)`);
      if (cur) t.update('payrolls', month, { lines, ...meta });
      else t.set('payrolls', month, { month, status: 'draft', lines, createdBy: S.user.username, createdAt: nowISO(), ...meta });
    });
  },
  async savePayroll(month, edits) {
    need('payroll.run');
    const cur0 = S.data.payrolls.find((p) => p.id === month);
    if (!cur0 || cur0.status !== 'draft') throw new H.InputError('المسير ليس مسودة');
    const lines = cur0.lines.map((l) => ({ ...l, ...(edits[l.employeeId] || {}) }));
    lines.forEach((l) => payrollCheck(l));
    await S.db.tx(async (t) => {
      const cur = await t.get('payrolls', month);
      if (!cur || cur.status !== 'draft') throw new H.InputError('المسير ليس مسودة');
      const meta = audit(t, 'update', 'payroll', month, `تعديل مسودة مسير ${fmtMonth(month)}`);
      t.update('payrolls', month, { lines, ...meta });
    });
  },
  /**
   * اعتماد المسير — القيد:
   *  من حـ/ الرواتب والأجور (الإجمالي) + حـ/ حصة المنشأة في التأمينات
   *  إلى حـ/ التأمينات المستحقة (الحصتان) + حـ/ سلف الموظفين (الأقساط) + حـ/ رواتب مستحقة (الصافي)
   */
  async postPayroll(month, edits = null) {
    need('payroll.run');
    hrAccountsReady();
    const p0 = S.data.payrolls.find((p) => p.id === month);
    if (!p0 || p0.status !== 'draft') throw new H.InputError('المسير ليس مسودة');
    const lines = p0.lines.map((l0) => { const l = { ...l0, ...((edits || {})[l0.employeeId] || {}) }; const c = payrollCheck(l); return { ...l, ...c, advances: allocateAdvances(l.employeeId, l.advanceH || 0) }; });
    const tot = (k) => H.sumInts(lines.map((l) => l[k]));
    const totals = { grossH: tot('grossH'), gosiEmpH: tot('gosiEmpH'), gosiErH: tot('gosiErH'), advanceH: tot('advanceH'), netH: tot('netH') };
    // قيد الاستحقاق بتاريخ نهاية الشهر، أو بتاريخ اليوم إن اعتُمد المسير قبل انتهاء الشهر
    const date = monthEnd(month) < todayISO() ? monthEnd(month) : (todayISO() < month + '-01' ? month + '-01' : todayISO());
    return S.db.tx(async (t) => {
      const cur = await t.get('payrolls', month);
      if (!cur || cur.status !== 'draft') throw new H.InputError('المسير ليس مسودة');
      const counters = await readCounters(t);
      const meta = audit(t, 'post', 'payroll', month, `اعتماد مسير ${fmtMonth(month)}: ${lines.length} موظف، الإجمالي ${H.fmtMoney(totals.grossH)}، الصافي ${H.fmtMoney(totals.netH)}`);
      const j = writeJournal(t, counters, { date, memo: `مسير رواتب ${fmtMonth(month)}`, source: 'payroll', sourceId: month, lines: [
        { accountId: ACC.salaries, debitH: totals.grossH }, { accountId: ACC.gosiExp, debitH: totals.gosiErH },
        { accountId: ACC.gosiPay, creditH: totals.gosiEmpH + totals.gosiErH }, { accountId: ACC.advances, creditH: totals.advanceH },
        { accountId: ACC.salPay, creditH: totals.netH }] }, meta);
      t.update('payrolls', month, { status: 'posted', lines, totals, date, postedBy: S.user.username, postedAt: nowISO(), journalIds: [j.id], ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      return j.no;
    });
  },
  /** صرف الرواتب: من حـ/ رواتب مستحقة إلى حـ/ البنك أو الصندوق */
  async payPayroll(month, payAccountId, date) {
    need('payroll.run');
    if (![ACC.cash, ACC.bank].includes(payAccountId)) throw new H.InputError('اختر الصندوق أو البنك');
    if (!H.isISODate(date)) throw new H.InputError('تاريخ الصرف غير صالح');
    return S.db.tx(async (t) => {
      const cur = await t.get('payrolls', month);
      if (!cur || cur.status !== 'posted') throw new H.InputError('يُصرف المسير بعد اعتماده');
      const counters = await readCounters(t);
      const meta = audit(t, 'pay', 'payroll', month, `صرف رواتب ${fmtMonth(month)} بمبلغ ${H.fmtMoney(cur.totals.netH)}`);
      const ids = [...cur.journalIds];
      if (cur.totals.netH > 0) {
        const j = writeJournal(t, counters, { date, memo: `صرف رواتب ${fmtMonth(month)}`, source: 'payroll', sourceId: month,
          lines: [{ accountId: ACC.salPay, debitH: cur.totals.netH }, { accountId: payAccountId, creditH: cur.totals.netH }] }, meta);
        ids.push(j.id);
      }
      t.update('payrolls', month, { status: 'paid', paidBy: S.user.username, paidAt: nowISO(), payAccountId, journalIds: ids, ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
    });
  },
  /** إنهاء الخدمة: تُحسب المكافأة نظاماً، ويُخصم منها المتبقي من السلف، والباقي يُصرف أو يُسجل مستحقاً */
  async terminateEmployee(id, f) {
    need('hr.manage');
    hrAccountsReady();
    if (!['employer', 'resign', 'full'].includes(f.reason)) throw new H.InputError('اختر سبب انتهاء الخدمة');
    if (![ACC.cash, ACC.bank, ACC.salPay].includes(f.payAccountId)) throw new H.InputError('اختر طريقة الصرف');
    if (!H.isISODate(f.date)) throw new H.InputError('تاريخ انتهاء الخدمة غير صالح');
    const emp = S.data.employees.find((e) => e.id === id && e.status === 'active');
    if (!emp) throw new H.InputError('الموظف غير موجود أو انتهت خدمته');
    if (f.date < emp.hireDate) throw new H.InputError('تاريخ الانتهاء قبل تاريخ المباشرة');
    const eos = H.endOfService({ wageH: H.fixedWageH(emp), hireDate: emp.hireDate, endDate: f.date, reason: f.reason });
    const open = H.sumInts(S.data.advances.filter((a) => a.employeeId === id).map((a) => a.remainingH));
    const deductH = Math.min(open, eos.awardH);
    const allocs = allocateAdvances(id, deductH);
    const netH = eos.awardH - deductH;
    const why = { employer: 'إنهاء من المنشأة أو انتهاء العقد', resign: 'استقالة', full: 'حالة مستحقة كاملة (م87)' }[f.reason];
    return S.db.tx(async (t) => {
      const cur = await t.get('employees', id);
      if (!cur || cur.status !== 'active') throw new H.InputError('الموظف غير موجود أو انتهت خدمته');
      const counters = await readCounters(t);
      const meta = audit(t, 'terminate', 'employee', id, `إنهاء خدمة ${emp.code} — ${emp.name} (${why}) مكافأة ${H.fmtMoney(eos.awardH)}${deductH ? `، خُصم منها سلف ${H.fmtMoney(deductH)}` : ''}`);
      const ids = [];
      if (eos.awardH > 0) {
        const j = writeJournal(t, counters, { date: f.date, memo: `مكافأة نهاية خدمة — ${emp.name}`, source: 'eos', sourceId: id, lines: [
          { accountId: ACC.eosExp, debitH: eos.awardH }, { accountId: ACC.advances, creditH: deductH }, { accountId: f.payAccountId, creditH: netH }] }, meta);
        ids.push(j.id);
      }
      t.update('employees', id, { status: 'terminated', termDate: f.date, termReason: f.reason, termNote: H.cleanText(f.note, 200), eosDays: eos.days,
        eosH: eos.awardH, eosAdvances: allocs, eosNetH: netH, eosPayAccountId: f.payAccountId, journalIds: ids, ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      return eos.awardH;
    });
  },
  async saveHrSettings(v) {
    need('hr.manage');
    for (const k of ['empSaudiBp', 'erSaudiBp', 'erNonSaudiBp']) if (!Number.isInteger(v[k]) || v[k] < 0 || v[k] > 3000) throw new H.InputError('النسبة بين 0% و30%');
    if (!Number.isSafeInteger(v.capH) || v.capH <= 0) throw new H.InputError('الحد الأعلى للأجر الخاضع غير صالح');
    await S.db.tx(async (t) => {
      const meta = audit(t, 'update', 'settings', 'hr', `نسب التأمينات: الموظف السعودي ${v.empSaudiBp / 100}%، المنشأة ${v.erSaudiBp / 100}%، غير السعودي ${v.erNonSaudiBp / 100}%، الحد ${H.fmtMoney(v.capH)}`);
      t.set('settings', 'hr', { empSaudiBp: v.empSaudiBp, erSaudiBp: v.erSaudiBp, erNonSaudiBp: v.erNonSaudiBp, capH: v.capH, ...meta });
    });
  },

  /* ---------- الأصول الثابتة والإهلاك ---------- */
  async createAsset(f) {
    need('asset.write');
    const name = H.cleanText(f.name, 100); if (!name) throw new H.InputError('اسم الأصل مطلوب');
    if (f.salvageH >= f.costH) throw new H.InputError('قيمة الخردة يجب أن تكون أقل من التكلفة');
    if (!H.isMonth(f.startMonth)) throw new H.InputError('شهر بدء الإهلاك غير صالح');
    if (![ACC.cash, ACC.bank, ACC.ap].includes(f.payAccountId)) throw new H.InputError('اختر طريقة السداد');
    if (S.data.depRuns.some((r) => r.id >= f.startMonth)) throw new H.InputError('يوجد إهلاك محتسب لشهر البدء أو بعده؛ اختر شهراً لاحقاً لآخر إهلاك');
    return S.db.tx(async (t) => {
      const counters = await readCounters(t);
      const no = 'FA-' + pad(bump(counters, 'asset'), 4);
      const aid = t.newId('assets');
      const meta = audit(t, 'create', 'asset', aid, `تسجيل الأصل ${no} — ${name} بتكلفة ${H.fmtMoney(f.costH)} لمدة ${f.lifeMonths} شهراً`);
      const date = f.startMonth + '-01' > todayISO() ? todayISO() : f.startMonth + '-01';
      const j = writeJournal(t, counters, { date, memo: `شراء أصل ${no} — ${name}`, source: 'asset', sourceId: aid,
        lines: [{ accountId: ACC.fa, debitH: f.costH }, { accountId: f.payAccountId, creditH: f.costH }] }, meta);
      t.set('assets', aid, { no, name, costH: f.costH, salvageH: f.salvageH, lifeMonths: f.lifeMonths, startMonth: f.startMonth, method: 'SL', status: 'active', journalIds: [j.id], createdBy: S.user.username, createdAt: nowISO(), ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
      return no;
    });
  },
  /** إهلاك شهر: من حـ/ مصروف الإهلاك  إلى حـ/ مجمع الإهلاك. معرّف المستند = الشهر، فلا يتكرر. */
  async runDepreciation(month) {
    need('dep.run');
    const pending = pendingDepMonths();
    if (!pending.length) throw new H.InputError('لا توجد أشهر مستحقة للإهلاك');
    if (month !== pending[0]) throw new H.InputError(`يجب احتساب ${fmtMonth(pending[0])} أولاً (بالترتيب)`);
    const details = S.data.assets.filter((a) => a.status === 'active').map((a) => ({ assetId: a.id, no: a.no, amountH: H.monthlyDepreciation(a, month) })).filter((d) => d.amountH > 0);
    const totalH = H.sumInts(details.map((d) => d.amountH));
    if (!totalH) throw new H.InputError('لا يوجد إهلاك لهذا الشهر');
    await S.db.tx(async (t) => {
      if (await t.get('depRuns', month)) throw new H.InputError('تم احتساب إهلاك هذا الشهر مسبقاً');
      const counters = await readCounters(t);
      const meta = audit(t, 'create', 'depreciation', month, `احتساب إهلاك ${fmtMonth(month)}: ${H.fmtMoney(totalH)} لعدد ${details.length} أصل`);
      const date = monthEnd(month) > todayISO() ? todayISO() : monthEnd(month);
      const j = writeJournal(t, counters, { date, memo: `إهلاك ${fmtMonth(month)}`, source: 'depreciation', sourceId: month,
        lines: [{ accountId: ACC.depExp, debitH: totalH }, { accountId: ACC.accDep, creditH: totalH }] }, meta);
      t.set('depRuns', month, { month, totalH, details, journalIds: [j.id], createdBy: S.user.username, createdAt: nowISO(), ...meta });
      t.set('settings', 'counters', { ...counters, auditId: meta.auditId });
    });
    return totalH;
  },
};

/** الأشهر المستحقة للإهلاك ولم تُحتسب (من أقدم شهر حتى الشهر الحالي) */
function pendingDepMonths() {
  const done = new Set(S.data.depRuns.map((r) => r.id));
  const set = new Set();
  const end = thisMonth();
  for (const a of S.data.assets.filter((x) => x.status === 'active')) {
    for (let k = 0; k < a.lifeMonths; k++) {
      const m = addMonths(a.startMonth, k);
      if (m > end) break;
      if (!done.has(m) && H.monthlyDepreciation(a, m) > 0) set.add(m);
    }
  }
  return [...set].sort();
}

/* =====================================================================
   5) البيانات المشتقة
   ===================================================================== */
/** قائمة الأصناف تُبنى تلقائياً من بنود فواتير المشتريات — لا حاجة لتعريف الصنف مسبقاً */
const itemKey = (name) => H.normalizeDigits(String(name || '')).replace(/\s+/g, ' ').trim().toLowerCase();
function purchaseCatalog(purchases) {
  const map = new Map();
  // purchases مرتبة من الأحدث؛ نمر عليها من الأقدم حتى يبقى «الأخير» هو الأحدث
  for (let i = purchases.length - 1; i >= 0; i--) {
    const p = purchases[i];
    for (const l of p.lines || []) {
      if (!l.name) continue;
      const k = itemKey(l.name);
      const c = map.get(k) || { key: k, name: l.name, count: 0, qtyM: 0, netH: 0 };
      c.name = l.name; c.count += 1; c.qtyM += l.qtyM || 0; c.netH += l.netH || 0;
      c.accountId = l.accountId; c.lastPriceH = l.priceH; c.lastVatMode = p.vatMode; c.lastDate = p.date; c.lastSupplier = p.supplier;
      map.set(k, c);
    }
  }
  return [...map.values()].sort((a, b) => String(b.lastDate).localeCompare(String(a.lastDate)) || a.name.localeCompare(b.name, 'ar'));
}
function derive(st) {
  const arr = (c) => Object.entries(st[c] || {}).map(([id, v]) => ({ id, ...v }));
  const today = todayISO();
  const users = arr('users').filter((u) => !u.deleted).sort((a, b) => a.id.localeCompare(b.id, 'en', { numeric: true }));
  const accounts = arr('accounts').sort((a, b) => String(a.number).localeCompare(String(b.number)));
  const journals = arr('journals').sort((a, b) => String(b.date).localeCompare(String(a.date)) || String(b.no).localeCompare(String(a.no)));
  const customers = arr('customers').sort((a, b) => String(a.name).localeCompare(String(b.name), 'ar'));
  const items = arr('items').sort((a, b) => String(a.sku).localeCompare(String(b.sku)));
  const invoices = arr('invoices').map((i) => ({ ...i, state: H.invoiceState(i, today) }))
    .sort((a, b) => String(b.issueDate).localeCompare(String(a.issueDate)) || String(b.number).localeCompare(String(a.number)));
  const payments = arr('payments').sort((a, b) => String(b.date).localeCompare(String(a.date)) || String(b.no).localeCompare(String(a.no)));
  const purchases = arr('purchases').sort((a, b) => String(b.date).localeCompare(String(a.date)) || String(b.no).localeCompare(String(a.no)));
  const stockMoves = arr('stockMoves').sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  const depRuns = arr('depRuns').sort((a, b) => a.id.localeCompare(b.id));
  const accumulated = new Map();
  depRuns.forEach((r) => (r.details || []).forEach((d) => accumulated.set(d.assetId, (accumulated.get(d.assetId) || 0) + d.amountH)));
  const assets = arr('assets').map((a) => ({ ...a, accumulatedH: accumulated.get(a.id) || 0, bookH: a.costH - (accumulated.get(a.id) || 0) }))
    .sort((a, b) => String(a.no).localeCompare(String(b.no)));
  const auditLog = arr('audit').sort((a, b) => String(b.at).localeCompare(String(a.at)));
  // الموارد البشرية: المسترد من كل سلفة = أقساط المسيرات المعتمدة + ما خُصم عند نهاية الخدمة
  const payrolls = arr('payrolls').sort((a, b) => b.id.localeCompare(a.id));
  const employees = arr('employees').sort((a, b) => String(a.code).localeCompare(String(b.code), 'en', { numeric: true }));
  const recovered = new Map();
  const addRec = (id, h) => recovered.set(id, (recovered.get(id) || 0) + (h || 0));
  payrolls.filter((p) => p.status === 'posted' || p.status === 'paid').forEach((p) => (p.lines || []).forEach((l) => (l.advances || []).forEach((a) => addRec(a.id, a.amountH))));
  employees.forEach((e) => (e.eosAdvances || []).forEach((a) => addRec(a.id, a.amountH)));
  const advances = arr('advances').map((a) => { const rec = Math.min(recovered.get(a.id) || 0, a.amountH); return { ...a, recoveredH: rec, remainingH: a.amountH - rec }; })
    .sort((a, b) => String(b.date).localeCompare(String(a.date)) || String(b.no).localeCompare(String(a.no)));
  const { id: _hid, auditId: _ha, updatedAt: _hu, updatedBy: _hb, ...hrSet } = (st.settings || {}).hr || {};
  const totals = H.accountTotals(journals, { to: today });
  const accBal = new Map(accounts.map((a) => [a.id, H.naturalBalance(a, totals)]));
  const alerts = H.computeAlerts({ accounts, journals, invoices, items, today });
  // المطابقات: الدفتر المساعد مقابل حساب الأستاذ العام
  const recon = {
    arSubH: H.sumInts(invoices.map((i) => (i.status === 'issued' ? i.totalH - (i.paidH || 0) : 0))),
    arGlH: accBal.get(ACC.ar) || 0,
    invSubH: H.sumInts(items.map((i) => i.valueH || 0)),
    invGlH: accBal.get(ACC.inv) || 0,
    faSubH: H.sumInts(assets.map((a) => a.costH)), faGlH: accBal.get(ACC.fa) || 0,
    depSubH: H.sumInts(depRuns.map((r) => r.totalH)), depGlH: 0 - (accBal.get(ACC.accDep) || 0),
    advSubH: H.sumInts(advances.map((a) => a.remainingH)), advGlH: accBal.get(ACC.advances) || 0,
  };
  const catalog = purchaseCatalog(purchases);
  return {
    accounts, journals, customers, items, stockMoves, purchases, catalog, employees, advances, payrolls, hr: { ...H.GOSI_DEFAULT, ...hrSet }, invoices, payments, assets, depRuns, users, audit: auditLog,
    company: (st.settings || {}).company || {}, counters: (st.settings || {}).counters || {}, accBal, alerts, recon,
  };
}

/* =====================================================================
   التشغيل والدخول
   ===================================================================== */
async function boot() {
  applyTheme(local.get('hiraf-theme', null));
  const cfg = window.HIRAF_FIREBASE;
  const configured = cfg && cfg.apiKey && !String(cfg.apiKey).startsWith('ضع');
  try {
    if (configured) { await CloudDB.init(cfg); S.db = CloudDB; $('#loginFoot').textContent = 'متصل بقاعدة البيانات الأونلاين'; }
    else { await LocalDB.init(); S.db = LocalDB; $('#loginFoot').textContent = 'لم يُربط Firebase بعد — الحفظ داخل هذا المتصفح فقط'; }
  } catch (e) {
    console.error(e);
    $('#loginFoot').textContent = 'تعذّر تحميل Firebase — تحقق من الإنترنت ثم حدّث الصفحة';
    return;
  }
  S.db.onAuth(async (username) => {
    if (username && !S.user) { try { await enterAs(username); } catch (err) { await S.db.signOut(); showLogin(); loginError(err.message, []); } }
    else if (!username && S.user) { S.user = null; leaveApp(); }
    else if (!username) showLogin();
  });
}

/** يمنع تشغيل الدخول مرتين في نفس الوقت (من النموذج ومن مراقب الجلسة) */
function enterAs(username) {
  if (S.user && S.user.username === username) return Promise.resolve();
  if (!S.entering) S.entering = afterSignIn(username).finally(() => { S.entering = null; });
  return S.entering;
}

/** بعد نجاح الدخول: قراءة ملف المستخدم وصلاحياته، وتهيئة النظام أول مرة */
async function afterSignIn(username) {
  let u = await S.db.readUser(username);
  if (!u && username === OWNER) {
    S.user = { username, name: 'المستخدم 1', role: 'admin', perms: ALL_PERMS, active: true };
    try { await Services.bootstrap(); } finally { S.user = null; }
    u = await S.db.readUser(username);
  }
  if (!u || u.deleted) throw new Error('هذا الحساب غير مسجل في النظام');
  if (!u.active) throw new Error('تم إيقاف هذا المستخدم. راجع مدير النظام');
  S.user = { username, name: u.name, role: u.role, perms: u.perms || [], active: u.active };
  enterApp();
}

function showLogin() {
  $('#app').hidden = true;
  $('#loginScreen').hidden = false;
  setTimeout(() => $('#username')?.focus(), 50);
}
function loginError(msg, fields) {
  const box = $('#loginError');
  box.querySelector('span').textContent = msg;
  box.hidden = false;
  fields.forEach((f) => f.classList.add('invalid'));
  const card = $('#loginCard');
  card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
}

$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fu = $('#fUser'), fp = $('#fPass');
  $('#loginError').hidden = true; fu.classList.remove('invalid'); fp.classList.remove('invalid');
  const username = normUsername($('#username').value.trim());
  const password = $('#password').value;
  if (!username || !password) return loginError('يرجى إدخال اسم المستخدم وكلمة المرور.', [!username && fu, !password && fp].filter(Boolean));
  if (!USERNAME_RE.test(username) || password.length > 128) return loginError(BAD_LOGIN, [fu, fp]);
  if (!S.db) return loginError('جارٍ الاتصال… حاول بعد لحظة', []);
  const b = $('#loginBtn');
  b.disabled = true; b.innerHTML = '<span class="spinner"></span> جارٍ التحقق…';
  try {
    await S.db.signIn(username, password);
    S.weakPassword = password.length < 8 || password === username;
    await enterAs(username);
    toast(`أهلاً ${S.user.name}`, 'تم تسجيل الدخول بنجاح');
  } catch (err) {
    if (S.db.authUsername()) await S.db.signOut();
    S.user = null;
    loginError(err.message || BAD_LOGIN, [fu, fp]);
    $('#password').value = ''; $('#password').focus();
  } finally { b.disabled = false; b.textContent = 'تسجيل الدخول'; }
});
['#username', '#password'].forEach((s) => $(s).addEventListener('input', (e) => e.target.closest('.field').classList.remove('invalid')));
$('#passToggle').addEventListener('click', () => {
  const p = $('#password'); const show = p.type === 'password';
  p.type = show ? 'text' : 'password';
  $('#passToggle').setAttribute('aria-label', show ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور');
  p.focus();
});

function enterApp() {
  $('#loginScreen').hidden = true;
  $('#app').hidden = false;
  $('#loginForm').reset();
  $('#loginError').hidden = true;
  updateMe();
  const pillEl = $('#modePill');
  pillEl.hidden = false;
  pillEl.classList.toggle('live', S.db.mode === 'cloud');
  pillEl.textContent = S.db.mode === 'cloud' ? 'مباشر' : 'حفظ محلي';
  S.loaded = false;
  S.section = 'dashboard';
  $('#view').innerHTML = `<div class="empty"><span class="spinner dark"></span><b>جارٍ تحميل البيانات…</b></div>`;
  startSync();
}
function startSync() {
  S.db.stop();
  S.auditSub = can('audit.view'); S.hrSub = canHR();
  S.db.subscribe(onData, onRemoteChange, { withAudit: S.auditSub, withHR: S.hrSub });
}
function updateMe() {
  $('#meName').textContent = S.user.name;
  $('#meSub').textContent = `${roleLabel(S.user.role)} · ${S.user.username}`;
  $('#meAvatar').textContent = S.user.username.slice(0, 2).toUpperCase();
}
function leaveApp() {
  S.db.stop(); closeModal();
  S.data = emptyData(); S.loaded = false; S.bank = null;
  showLogin();
}
async function logout() {
  await S.db.signOut();
  S.user = null;
  leaveApp();
  toast('تم تسجيل الخروج', 'نراك قريباً');
}

/** وصول بيانات (أول تحميل أو تحديث من أي مستخدم) */
function onData(raw) {
  if (!S.user) return;
  S.data = derive(raw);
  // تحديث صلاحياتي لحظياً إن غيّرها المدير
  const me = (raw.users || {})[S.user.username];
  if (!me || me.active === false || me.deleted) { toast('تم إيقاف حسابك', 'راجع مدير النظام', 'error'); logout(); return; }
  Object.assign(S.user, { name: me.name, role: me.role, perms: me.perms || [], active: me.active });
  updateMe();
  if (can('audit.view') !== S.auditSub || canHR() !== S.hrSub) { startSync(); return; }
  S.loaded = true;
  ensureNewAccounts();
  $('#companyName').textContent = S.data.company.name || 'للمقاولات';
  if (document.activeElement?.closest('form[data-keep]')) { renderNav(); return; } // لا نمسح نموذجاً أثناء الكتابة
  render();
}
/** ينشئ حسابات دليل الحسابات الافتراضية الناقصة على دفعات (10 لكل طلب، حدود قواعد Firestore) */
async function createDefaultAccounts(list, summary) {
  for (let i = 0; i < list.length; i += 10) {
    const part = list.slice(i, i + 10);
    await S.db.tx(async (t) => {
      const need = [];
      for (const row of part) if (!(await t.get('accounts', 'acc-' + row[0]))) need.push(row);
      if (!need.length) return;
      const meta = audit(t, 'create', 'system', 'accounts', `${summary}: ${need.map((r) => r[0]).join('، ')}`);
      for (const [n, name, type, flags] of need) t.set('accounts', 'acc-' + n, { number: n, name, type, ...flags, system: true, archived: false, createdAt: nowISO(), ...meta });
    });
  }
}
/** ترقية: إضافة حسابات المصروف الجديدة (5600، 5700) للأنظمة المهيأة قبلها — مرة واحدة بواسطة من يملك صلاحية الحسابات */
let ensuring = false;
function ensureNewAccounts() {
  if (ensuring || !S.data.accounts.length || !can('accounts.write')) return;
  const missing = DEFAULT_ACCOUNTS.filter(([n]) => !S.data.accounts.some((a) => a.id === 'acc-' + n));
  if (!missing.length) return;
  ensuring = true;
  createDefaultAccounts(missing, 'ترقية دليل الحسابات').catch((e) => console.warn('ترقية الحسابات', e)); // محاولة واحدة لكل جلسة
}
/** إشعار لحظي عندما يضيف مستخدم آخر شيئاً (يصل لكل المستخدمين) */
const LIVE_NOTES = {
  customers: (d) => `أضاف العميل ${d.name || ''}`,
  invoices: (d) => `أنشأ فاتورة للعميل ${d.customerName || ''}`,
  payments: (d) => `سجّل سند قبض ${d.no || ''} بمبلغ ${H.fmtMoney(d.amountH || 0)}`,
  purchases: (d) => `سجّل مشتريات ${d.no || ''} من ${d.supplier || ''}`,
  journals: (d) => (d.source === 'manual' ? `أنشأ قيداً بانتظار الاعتماد: ${d.memo || ''}` : ''),
  assets: (d) => `سجّل الأصل ${d.name || ''}`,
};
function onRemoteChange(coll, type, doc) {
  if (type !== 'added' || !LIVE_NOTES[coll] || !doc.createdBy || doc.createdBy === S.user?.username) return;
  const text = LIVE_NOTES[coll](doc);
  if (text) toast(userName(doc.createdBy), text);
}

/* =====================================================================
   6) الواجهة — التنقل
   ===================================================================== */
const SECTIONS = {
  dashboard: { title: 'لوحة التحكم', icon: 'home', render: renderDashboard },
  invoices: { title: 'الفواتير', icon: 'file', group: 'المبيعات', sub: 'فواتير ضريبية بضريبة القيمة المضافة 15%', render: renderInvoices },
  customers: { title: 'العملاء', icon: 'users', group: 'المبيعات', sub: 'بيانات العملاء وأرصدتهم', render: renderCustomers },
  payments: { title: 'سندات القبض', icon: 'wallet', group: 'المبيعات', sub: 'المبالغ المحصّلة من العملاء', render: renderPayments },
  inventory: { title: 'المشتريات والمصروفات', icon: 'box', group: 'المشتريات والأصول', sub: 'سجّل فاتورة المورد فقط — الأصناف تُحفظ تلقائياً', render: renderInventory },
  assets: { title: 'الأصول الثابتة', icon: 'building', group: 'المشتريات والأصول', sub: 'الإهلاك بطريقة القسط الثابت', render: renderAssets },
  bank: { title: 'كشف الحساب', icon: 'bank', group: 'المحاسبة', sub: 'ارفع كشف البنك وتُسجَّل المصروفات والإيرادات دفعة واحدة', render: renderBank, perm: 'bank.import' },
  hr: { title: 'الموارد البشرية', icon: 'id', group: 'الموارد البشرية', sub: 'الموظفون والرواتب والسلف ونهاية الخدمة', render: renderHR, perm: ['hr.manage', 'payroll.run', 'audit.view'] },
  journal: { title: 'القيود اليومية', icon: 'book', group: 'المحاسبة', sub: 'قيد مزدوج متزن — المُنشئ لا يعتمد قيده', render: renderJournal },
  accounts: { title: 'دليل الحسابات', icon: 'layers', group: 'المحاسبة', sub: 'الأرصدة من القيود المرحّلة', render: renderAccounts },
  reports: { title: 'التقارير المالية', icon: 'chart', group: 'المحاسبة', sub: 'قائمة الدخل والميزانية والضريبة والمطابقات', render: renderReports },
  audit: { title: 'سجل المراجعة', icon: 'shield', group: 'الإدارة', sub: 'كل عملية: من، ماذا، ومتى', render: renderAudit, perm: 'audit.view' },
  users: { title: 'المستخدمون والصلاحيات', icon: 'key', group: 'الإدارة', sub: 'إضافة وإيقاف وحذف المستخدمين وتحديد صلاحياتهم', render: renderUsers, perm: 'users.manage' },
  settings: { title: 'الإعدادات', icon: 'sliders', group: 'الإدارة', sub: 'بيانات المنشأة وحسابي', render: renderSettings },
};
const visible = (key) => { const p = SECTIONS[key].perm; return !p || (Array.isArray(p) ? p.some((x) => can(x)) : can(p)); };

function renderNav() {
  const overdue = S.data.invoices.filter((i) => i.state.key === 'overdue').length;
  const drafts = S.data.journals.filter((j) => j.status === 'draft' && j.createdBy !== S.user.username).length;
  const badges = { invoices: overdue, journal: can('journal.post') ? drafts : 0 };
  const groups = [];
  for (const [key, s] of Object.entries(SECTIONS)) {
    if (!visible(key)) continue;
    let g = groups[groups.length - 1];
    if (!g || g.name !== (s.group || '')) { g = { name: s.group || '', items: [] }; groups.push(g); }
    g.items.push([key, s]);
  }
  $('#nav').innerHTML = groups.map((g) => `<div class="nav-group">${g.name ? `<div class="nav-label">${esc(g.name)}</div>` : ''}
    ${g.items.map(([key, s]) => `<button class="nav-btn ${S.section === key ? 'active' : ''}" data-nav="${key}" ${S.section === key ? 'aria-current="page"' : ''}>${icon(s.icon)}${esc(s.title)}${badges[key] ? `<span class="nav-count">${badges[key]}</span>` : ''}</button>`).join('')}</div>`).join('');
}

function go(section) {
  if (!SECTIONS[section] || !visible(section)) section = 'dashboard';
  S.section = section;
  $('#app').classList.remove('nav-open');
  render(true);
  window.scrollTo({ top: 0 });
}

function render(animate = false) {
  if (!S.user) return;
  if (!visible(S.section)) S.section = 'dashboard';
  const sec = SECTIONS[S.section];
  renderNav();
  $('#pageTitle').textContent = sec.title;
  $('#pageSub').textContent = sec.sub || greeting();
  $('#newInvoiceBtn').hidden = !can('invoice.write');
  $('#weakBanner').hidden = !S.weakPassword;
  if (!S.loaded) return;
  const act = document.activeElement;
  const keep = act && act.id && $('#view').contains(act) ? { id: act.id, pos: act.selectionStart } : null;
  const view = $('#view');
  view.innerHTML = sec.render();
  if (animate) { view.style.animation = 'none'; void view.offsetWidth; view.style.animation = ''; }
  if (keep) { const n = document.getElementById(keep.id); if (n) { n.focus(); try { n.setSelectionRange(keep.pos, keep.pos); } catch { /* ignore */ } } }
}
function greeting() {
  const h = new Date().getHours();
  return `${h < 12 ? 'صباح الخير' : 'مساء الخير'}، ${S.user?.name || ''} · ${new Intl.DateTimeFormat('ar-SA-u-ca-gregory-nu-latn', { weekday: 'long', day: 'numeric', month: 'long' }).format(new Date())}`;
}
const empty = (ic, title, text = '', action = '') => `<div class="empty">${icon(ic)}<b>${esc(title)}</b>${text ? `<span>${esc(text)}</span>` : ''}${action ? `<div class="empty-act">${action}</div>` : ''}</div>`;
const btn = (action, label, { cls = 'btn-primary', ic = 'plus', data = {}, perm = null, title = '' } = {}) =>
  perm && !can(perm) ? '' : `<button type="button" class="btn ${cls}" data-action="${action}" ${Object.entries(data).map(([k, v]) => `data-${k}="${esc(v)}"`).join(' ')} ${title ? `title="${esc(title)}" aria-label="${esc(title)}"` : ''}>${ic ? icon(ic) : ''}${esc(label)}</button>`;
const tabs = (key, list) => `<div class="tabs" role="tablist">${list.map(([k, l]) => `<button type="button" class="tab ${S.tabs[key] === k ? 'active' : ''}" role="tab" aria-selected="${S.tabs[key] === k}" data-action="tab" data-key="${key}" data-tab="${k}">${esc(l)}</button>`).join('')}</div>`;
const search = (key, ph) => `<label class="search">${icon('search')}<input class="input" id="q-${key}" data-q="${key}" placeholder="${esc(ph)}" value="${esc(S.q[key] || '')}" maxlength="60" aria-label="${esc(ph)}"></label>`;
const matches = (key, ...fields) => { const q = (S.q[key] || '').trim().toLowerCase(); return !q || fields.some((f) => String(f || '').toLowerCase().includes(q)); };

/* =====================================================================
   لوحة التحكم
   ===================================================================== */
function renderDashboard() {
  const d = S.data, today = todayISO(), mStart = firstOfMonth();
  const is = H.incomeStatement(d.accounts, d.journals, mStart, today);
  const salesMonth = H.sumInts(d.invoices.filter((i) => i.status === 'issued' && i.issueDate >= mStart).map((i) => i.netH));
  const cash = (d.accBal.get(ACC.cash) || 0) + (d.accBal.get(ACC.bank) || 0);
  const alerts = d.alerts.filter((a) => a.kind !== 'approval' || can('journal.post'));
  const alertHtml = alerts.length ? `<div class="card"><div class="card-head"><h3>${icon('bell')}تنبيهات</h3><span class="hint num">${alerts.length}</span></div>
      <div class="alerts">${alerts.map((a) => `<button type="button" class="alert-row ${a.level}" data-nav="${a.target}" ${a.filter ? `data-filter="${a.filter}"` : a.kind === 'approval' ? 'data-filter="draft"' : ''}><span class="alert-dot"></span><span>${esc(a.text)}</span>${icon('chev')}</button>`).join('')}</div></div>` : '';
  const attn = d.invoices.filter((i) => ['overdue', 'dueSoon'].includes(i.state.key)).sort((a, b) => b.state.daysLate - a.state.daysLate).slice(0, 6);
  return `<div class="stack">
    ${alertHtml}
    <div class="card kpis-card"><div class="kpis">
      <div class="kpi hero"><div class="kpi-label">مبيعات الشهر (قبل الضريبة)</div><div class="kpi-value">${M(salesMonth)}<small>ر.س</small></div><div class="kpi-meta">${esc(fmtMonth(thisMonth()))}</div></div>
      <div class="kpi"><div class="kpi-label"><span class="dot warn-bg"></span>ذمم مدينة قائمة</div><div class="kpi-value">${M(d.recon.arSubH)}<small>ر.س</small></div><div class="kpi-meta">${d.invoices.filter((i) => i.state.remainingH > 0).length} فاتورة مفتوحة</div></div>
      <div class="kpi ${cash < 0 ? 'kpi-bad' : ''}"><div class="kpi-label"><span class="dot ${cash < 0 ? 'bad-bg' : 'ok-bg'}"></span>النقدية (صندوق + بنك)</div><div class="kpi-value">${M(cash)}<small>ر.س</small></div><div class="kpi-meta">${cash < 0 ? 'عجز نقدي — راجع القيود' : 'حسب القيود المرحّلة'}</div></div>
      <div class="kpi ${is.netH < 0 ? 'kpi-bad' : ''}"><div class="kpi-label"><span class="dot ${is.netH < 0 ? 'bad-bg' : 'ok-bg'}"></span>${is.netH < 0 ? 'صافي خسارة الشهر' : 'صافي ربح الشهر'}</div><div class="kpi-value">${M(Math.abs(is.netH))}<small>ر.س</small></div><div class="kpi-meta">إيرادات ${H.fmtMoney(is.totalRevenueH)} · مصروفات ${H.fmtMoney(is.totalExpensesH)}</div></div>
    </div></div>
    <div class="grid-2">
      <div class="card"><div class="card-head"><h3>الإيرادات والمصروفات</h3><span class="hint">آخر 6 أشهر</span>
        <div class="actions legend"><span><i class="navy-bg"></i>الإيرادات</span><span><i class="accent-bg"></i>المصروفات</span></div></div>
        <div class="chart">${pnlChart()}</div></div>
      <div class="card"><div class="card-head"><h3>فواتير تحتاج متابعة</h3><span class="hint">متأخرة أو تستحق خلال 7 أيام</span></div>
        ${attn.length ? `<div class="attn">${attn.map((i) => `<button type="button" class="attn-item" data-action="view-invoice" data-id="${esc(i.id)}">
          <span class="attn-mark ${i.state.key === 'overdue' ? '' : 'warn'}">${icon('clock')}</span>
          <span class="attn-body"><span class="cell-main">${esc(i.customerName)}</span><span class="cell-sub">${esc(i.number)} · ${i.state.key === 'overdue' ? `متأخرة ${i.state.daysLate} يوم` : i.state.daysLate === 0 ? 'تستحق اليوم' : `تستحق بعد ${-i.state.daysLate} يوم`}</span></span>
          <span class="attn-amt">${M(i.state.remainingH)}</span></button>`).join('')}</div>` : empty('check', 'لا فواتير تحتاج متابعة', 'كل المستحقات ضمن مواعيدها.')}
      </div>
    </div>
    <div class="card"><div class="card-head"><h3>أحدث الفواتير</h3><div class="actions"><button type="button" class="btn btn-ghost btn-sm" data-nav="invoices">عرض الكل</button></div></div>
      ${d.invoices.length ? invoiceTable(d.invoices.slice(0, 6), true) : empty('file', 'لا توجد فواتير بعد', can('invoice.write') ? 'أضف عميلاً ثم أنشئ أول فاتورة.' : '')}</div>
  </div>`;
}

function pnlChart() {
  const months = [];
  for (let k = 5; k >= 0; k--) months.push(addMonths(thisMonth(), -k));
  const data = months.map((m) => { const r = H.incomeStatement(S.data.accounts, S.data.journals, m + '-01', monthEnd(m)); return { m, rev: Math.max(0, r.totalRevenueH), exp: Math.max(0, r.totalExpensesH) }; });
  const W = 640, Ht = 240, L = 56, R = 12, T = 14, B = 34;
  const raw = Math.max(0, ...data.map((x) => Math.max(x.rev, x.exp))) / 100; // بالريال
  const mag = raw > 0 ? Math.pow(10, Math.floor(Math.log10(raw / 4))) : 250;
  const step = raw <= 0 ? 250 : mag * ([1, 2, 2.5, 5, 10].find((f) => f * mag * 4 >= raw) || 10);
  const maxH = step * 4 * 100;
  const y = (h) => T + (Ht - T - B) * (1 - h / maxH);
  const slot = (W - L - R) / data.length, bw = Math.min(26, slot / 3.2);
  const short = (v) => (v >= 1e6 ? +(v / 1e6).toFixed(1) + 'M' : v >= 1000 ? +(v / 1000).toFixed(1) + 'k' : String(v));
  let g = '';
  for (let t = 0; t <= 4; t++) { const v = step * t; g += `<line class="grid-line" x1="${L}" x2="${W - R}" y1="${y(v * 100)}" y2="${y(v * 100)}"/><text class="axis-t" x="${L - 8}" y="${y(v * 100) + 4}" text-anchor="end">${short(v)}</text>`; }
  data.forEach((d, i) => {
    const cx = L + slot * i + slot / 2;
    g += `<rect x="${cx - bw - 2}" y="${y(d.rev)}" width="${bw}" height="${Math.max(0, y(0) - y(d.rev))}" rx="4" fill="var(--navy)"><title>الإيرادات: ${H.fmtMoney(d.rev)}</title></rect>`;
    g += `<rect x="${cx + 2}" y="${y(d.exp)}" width="${bw}" height="${Math.max(0, y(0) - y(d.exp))}" rx="4" fill="var(--accent)"><title>المصروفات: ${H.fmtMoney(d.exp)}</title></rect>`;
    g += `<text class="lbl" x="${cx}" y="${Ht - 10}" text-anchor="middle">${esc(new Intl.DateTimeFormat('ar-SA-u-ca-gregory', { month: 'short', timeZone: 'UTC' }).format(new Date(d.m + '-01T00:00:00Z')))}</text>`;
  });
  return `<svg viewBox="0 0 ${W} ${Ht}" dir="ltr" role="img" aria-label="الإيرادات والمصروفات لآخر ستة أشهر">${g}</svg>`;
}

/* =====================================================================
   الفواتير
   ===================================================================== */
function invoiceTable(list, compact = false) {
  return `<div class="table-wrap"><table>
    <thead><tr><th>الفاتورة</th><th>العميل</th><th class="hide-sm">التاريخ</th>${compact ? '' : '<th>الاستحقاق</th>'}<th class="money">الإجمالي</th>${compact ? '' : '<th class="money">المتبقي</th>'}<th>الحالة</th>${compact ? '' : '<th><span class="sr">إجراءات</span></th>'}</tr></thead>
    <tbody>${list.map((i) => `<tr>
      <td><button type="button" class="link" data-action="view-invoice" data-id="${esc(i.id)}">${esc(i.number || 'مسودة')}</button></td>
      <td class="cell-main">${esc(i.customerName)}</td>
      <td class="hide-sm nowrap">${fmtDate(i.issueDate)}</td>
      ${compact ? '' : `<td class="nowrap">${fmtDate(i.dueDate)}</td>`}
      <td class="money">${M(i.totalH)}</td>
      ${compact ? '' : `<td class="money">${i.state.remainingH ? M(i.state.remainingH) : '<span class="cell-sub">—</span>'}</td>`}
      <td>${pill(INV_STATUS, i.state.key)}</td>
      ${compact ? '' : `<td><div class="row-actions">
        ${i.status === 'draft' ? btn('issue-invoice', 'إصدار', { cls: 'btn-quiet btn-sm', ic: 'send', data: { id: i.id }, perm: 'invoice.issue' }) : ''}
        ${i.state.remainingH > 0 ? btn('new-payment', 'قبض', { cls: 'btn-quiet btn-sm', ic: 'wallet', data: { invoice: i.id }, perm: 'payment.create' }) : ''}
        ${btn('view-invoice', '', { cls: 'btn-quiet btn-sm icon-btn', ic: 'eye', data: { id: i.id }, title: 'عرض' })}
      </div></td>`}
    </tr>`).join('')}</tbody></table></div>`;
}

function renderInvoices() {
  const all = S.data.invoices;
  const f = S.tabs.invoices;
  const inF = (i, k) => k === 'all' || i.state.key === k || (k === 'open' && i.state.remainingH > 0);
  const list = all.filter((i) => inF(i, f) && matches('inv', i.number, i.customerName));
  const chips = [['all', 'الكل'], ['draft', 'مسودات'], ['open', 'مفتوحة'], ['dueSoon', 'تستحق قريباً'], ['overdue', 'متأخرة'], ['paid', 'مدفوعة'], ['void', 'ملغاة']]
    .map(([k, l]) => `<button type="button" class="chip ${f === k ? 'active' : ''}" data-action="tab" data-key="invoices" data-tab="${k}">${l}<span class="n num">${all.filter((i) => inF(i, k)).length}</span></button>`).join('');
  const body = !all.length ? empty('file', 'لا توجد فواتير', '', btn('new-invoice', 'فاتورة جديدة', { cls: 'btn-primary btn-sm', perm: 'invoice.write' }))
    : list.length ? invoiceTable(list) : empty('search', 'لا نتائج', 'جرّب تغيير الفلتر أو البحث.');
  return `<div class="toolbar"><div class="chips">${chips}</div>${search('inv', 'رقم الفاتورة أو العميل')}
      ${btn('export', 'CSV', { cls: 'btn-ghost btn-sm', ic: 'download', data: { what: 'invoices' }, perm: 'reports.export' })}</div>
    <div class="card">${body}</div>`;
}

/* =====================================================================
   العملاء
   ===================================================================== */
function renderCustomers() {
  const showArchived = S.tabs.customers === 'archived';
  const list = S.data.customers.filter((c) => !!c.archived === showArchived && matches('cust', c.name, c.company, c.phone, c.vatNo));
  const rows = list.map((c) => {
    const inv = S.data.invoices.filter((i) => i.customerId === c.id && i.status === 'issued');
    const due = H.sumInts(inv.map((i) => i.state.remainingH));
    return `<tr>
      <td><div class="cell-main">${esc(c.name)}</div><div class="cell-sub">${esc([c.company, c.city].filter(Boolean).join(' · '))}</div></td>
      <td class="num start">${esc(c.phone || '—')}</td>
      <td class="hide-sm num start">${esc(c.vatNo || '—')}</td>
      <td><span class="num">${inv.length}</span></td>
      <td class="money">${due > 0 ? `<b class="warn-text">${M(due)}</b>` : M(0)}</td>
      <td><div class="row-actions">
        ${!c.archived ? btn('new-invoice', 'فاتورة', { cls: 'btn-quiet btn-sm', data: { customer: c.id }, perm: 'invoice.write' }) : ''}
        ${btn('edit-customer', '', { cls: 'btn-quiet btn-sm icon-btn', ic: 'edit', data: { id: c.id }, title: 'تعديل', perm: 'customer.write' })}
        ${btn('archive-customer', '', { cls: 'btn-quiet btn-sm icon-btn', ic: c.archived ? 'restore' : 'archive', data: { id: c.id, archived: c.archived ? '0' : '1' }, title: c.archived ? 'استعادة' : 'أرشفة', perm: 'customer.write' })}
      </div></td></tr>`;
  }).join('');
  return `<div class="toolbar">${btn('new-customer', 'عميل جديد', { perm: 'customer.write' })}
      ${tabs('customers', [['active', 'النشطون'], ['archived', 'المؤرشفون']])}${search('cust', 'الاسم أو الجوال أو الرقم الضريبي')}</div>
    <div class="card">${list.length ? `<div class="table-wrap"><table><thead><tr><th>العميل</th><th>الجوال</th><th class="hide-sm">الرقم الضريبي</th><th>فواتير</th><th class="money">المستحق</th><th><span class="sr">إجراءات</span></th></tr></thead><tbody>${rows}</tbody></table></div>`
      : empty('users', showArchived ? 'لا يوجد عملاء مؤرشفون' : 'لا يوجد عملاء', '', showArchived ? '' : btn('new-customer', 'عميل جديد', { cls: 'btn-primary btn-sm', perm: 'customer.write' }))}</div>`;
}

/* =====================================================================
   سندات القبض
   ===================================================================== */
function renderPayments() {
  const list = S.data.payments.filter((p) => matches('pay', p.no, p.customerName, p.invoiceNo, p.reference));
  const total = H.sumInts(S.data.payments.filter((p) => p.status === 'active').map((p) => p.amountH));
  return `<div class="toolbar">${btn('new-payment', 'سند قبض', { perm: 'payment.create' })}${search('pay', 'رقم السند أو العميل')}
      <span class="cell-sub">إجمالي المحصّل: <b class="text">${M(total)} ر.س</b></span></div>
    <div class="card">${list.length ? `<div class="table-wrap"><table><thead><tr><th>السند</th><th>التاريخ</th><th>العميل</th><th>الفاتورة</th><th class="hide-sm">الطريقة</th><th class="money">المبلغ</th><th>الحالة</th><th><span class="sr">إجراءات</span></th></tr></thead><tbody>
      ${list.map((p) => `<tr><td class="num start">${esc(p.no)}</td><td class="nowrap">${fmtDate(p.date)}</td><td><div class="cell-main">${esc(p.customerName)}</div>${p.reference ? `<div class="cell-sub">مرجع: ${esc(p.reference)}</div>` : ''}</td>
        <td><button type="button" class="link" data-action="view-invoice" data-id="${esc(p.invoiceId)}">${esc(p.invoiceNo)}</button></td>
        <td class="hide-sm">${esc(PAY_METHODS[p.method] || '')} · ${p.accountId === ACC.bank ? 'البنك' : 'الصندوق'}</td>
        <td class="money"><b class="${p.status === 'active' ? 'ok-text' : 'muted-text strike'}">${M(p.amountH)}</b></td>
        <td>${p.status === 'active' ? '<span class="pill ok">فعّال</span>' : '<span class="pill neutral">معكوس</span>'}</td>
        <td>${p.status === 'active' ? btn('reverse-payment', 'عكس', { cls: 'btn-quiet btn-sm', ic: 'undo', data: { id: p.id }, perm: 'payment.reverse' }) : ''}</td></tr>`).join('')}
      </tbody></table></div>` : empty('wallet', 'لا توجد سندات قبض')}</div>`;
}

/* =====================================================================
   المخزون
   ===================================================================== */
const accName = (id) => { const a = S.data.accounts.find((x) => x.id === id); if (a) return a.name; const d = DEFAULT_ACCOUNTS.find((x) => 'acc-' + x[0] === id); return d ? d[1] : '—'; };
const PAY_LABEL = { [ACC.cash]: 'نقداً (الصندوق)', [ACC.bank]: 'البنك', [ACC.ap]: 'آجل' };
const VAT_MODE_LABEL = { incl: 'شامل الضريبة', excl: 'قبل الضريبة +15%', none: 'غير خاضع للضريبة' };
const VAT_MODE_SHORT = { incl: 'شامل الضريبة', excl: '+15% ضريبة', none: 'بدون ضريبة' };
function renderInventory() {
  const legacy = S.data.items.length > 0; // أصناف مخزون من النظام السابق (إن وُجدت)
  if (!['purchases', 'catalog', 'items', 'moves'].includes(S.tabs.inventory) || (!legacy && ['items', 'moves'].includes(S.tabs.inventory))) S.tabs.inventory = 'purchases';
  const tab = S.tabs.inventory;
  const month = thisMonth();
  const mp = S.data.purchases.filter((p) => String(p.date).startsWith(month));
  const head = `<div class="toolbar">${btn('new-purchase', 'فاتورة مشتريات', { perm: 'inventory.write' })}
    ${tabs('inventory', [['purchases', 'فواتير المشتريات'], ['catalog', `الأصناف (${S.data.catalog.length})`], ...(legacy ? [['items', 'مخزون سابق'], ['moves', 'حركات المخزون']] : [])])}</div>
    <div class="card kpis-card"><div class="kpis">
      <div class="kpi hero"><div class="kpi-label">مشتريات الشهر (قبل الضريبة)</div><div class="kpi-value">${M(H.sumInts(mp.map((p) => p.netH)))}<small>ر.س</small></div><div class="kpi-meta">${esc(fmtMonth(month))} · ${mp.length} فاتورة</div></div>
      <div class="kpi"><div class="kpi-label"><span class="dot ok-bg"></span>ضريبة المدخلات للشهر</div><div class="kpi-value">${M(H.sumInts(mp.map((p) => p.vatH)))}<small>ر.س</small></div><div class="kpi-meta">تُخصم في الإقرار الضريبي</div></div>
      <div class="kpi"><div class="kpi-label"><span class="dot warn-bg"></span>مستحق للموردين (آجل)</div><div class="kpi-value">${M(S.data.accBal.get(ACC.ap) || 0)}<small>ر.س</small></div><div class="kpi-meta">رصيد حساب الموردين</div></div>
      <div class="kpi"><div class="kpi-label"><span class="dot"></span>الأصناف المسجلة</div><div class="kpi-value">${S.data.catalog.length}</div><div class="kpi-meta">تُضاف تلقائياً من الفواتير</div></div>
    </div></div>`;
  if (tab === 'catalog') {
    const l = S.data.catalog;
    return head + `<div class="card">${l.length ? `<div class="table-wrap"><table><thead><tr><th>الصنف</th><th class="hide-sm">التصنيف</th><th class="money">مرات الشراء</th><th class="money hide-sm">إجمالي الكمية</th><th class="money">آخر سعر</th><th class="money">إجمالي المصروف</th><th class="hide-sm">آخر مورد</th></tr></thead><tbody>
      ${l.map((c) => `<tr><td><div class="cell-main">${esc(c.name)}</div><div class="cell-sub">آخر شراء ${fmtDate(c.lastDate)}</div></td><td class="hide-sm">${esc(accName(c.accountId))}</td><td class="money">${c.count}</td><td class="money hide-sm">${Q(c.qtyM)}</td><td class="money">${M(c.lastPriceH)}</td><td class="money"><b>${M(c.netH)}</b></td><td class="hide-sm">${esc(c.lastSupplier || '—')}</td></tr>`).join('')}
      <tr class="total-row"><td colspan="5">الإجمالي (قبل الضريبة)</td><td class="money">${M(H.sumInts(l.map((c) => c.netH)))}</td><td class="hide-sm"></td></tr>
      </tbody></table></div>` : empty('box', 'لا توجد أصناف بعد', 'كل صنف تكتبه في فاتورة مشتريات يُضاف هنا تلقائياً.')}</div>`;
  }
  if (tab === 'moves') {
    const name = (id) => S.data.items.find((i) => i.id === id)?.name || '—';
    const l = S.data.stockMoves.slice(0, 300);
    return head + `<div class="card">${l.length ? `<div class="table-wrap"><table><thead><tr><th>التاريخ</th><th>الصنف</th><th>النوع</th><th>المستند</th><th class="money">الكمية</th><th class="money">التكلفة</th></tr></thead><tbody>
      ${l.map((m) => `<tr><td class="nowrap">${fmtDate(m.date)}</td><td class="cell-main">${esc(name(m.itemId))}</td><td>${m.type === 'in' ? '<span class="pill ok">وارد</span>' : '<span class="pill warn">منصرف</span>'}</td><td class="num start">${esc(m.refNo || '')}</td><td class="money">${Q(m.qtyM)}</td><td class="money">${M(m.costH)}</td></tr>`).join('')}
      </tbody></table></div>` : empty('box', 'لا توجد حركات')}</div>`;
  }
  if (tab === 'items') {
    const l = S.data.items.filter((i) => !i.archived);
    return head + `<div class="card">${l.length ? `<div class="table-wrap"><table><thead><tr><th>الرمز</th><th>الصنف</th><th class="hide-sm">التقييم</th><th class="money">الكمية</th><th class="money">متوسط التكلفة</th><th class="money">القيمة</th><th><span class="sr">إجراءات</span></th></tr></thead><tbody>
      ${l.map((i) => `<tr><td class="num start"><b>${esc(i.sku)}</b></td><td><div class="cell-main">${esc(i.name)}</div><div class="cell-sub">${esc(i.unit)}</div></td>
        <td class="hide-sm">${i.method === 'FIFO' ? 'FIFO' : 'متوسط مرجح'}</td><td class="money">${Q(i.qtyM)}</td><td class="money">${M(H.unitCostH(stockState(i)))}</td><td class="money"><b>${M(i.valueH)}</b></td>
        <td>${btn('edit-item', '', { cls: 'btn-quiet btn-sm icon-btn', ic: 'edit', data: { id: i.id }, title: 'تعديل', perm: 'inventory.write' })}</td></tr>`).join('')}
      <tr class="total-row"><td colspan="5">إجمالي قيمة المخزون</td><td class="money">${M(H.sumInts(l.map((i) => i.valueH || 0)))}</td><td></td></tr>
      </tbody></table></div>` : empty('box', 'لا توجد أصناف مخزنية')}</div>`;
  }
  const l = S.data.purchases;
  const summary = (p) => { const n = (p.lines || []).map((x) => x.name).filter(Boolean); return n.length ? esc(n.slice(0, 2).join('، ')) + (n.length > 2 ? ` <span class="cell-sub">+${n.length - 2}</span>` : '') : '<span class="cell-sub">أصناف مخزنية</span>'; };
  return head + `<div class="card">${l.length ? `<div class="table-wrap"><table><thead><tr><th>الرقم</th><th>التاريخ</th><th>المورد</th><th class="hide-sm">الأصناف</th><th class="hide-sm">السداد</th><th class="money hide-sm">الضريبة</th><th class="money">الإجمالي</th></tr></thead><tbody>
    ${l.map((p) => `<tr><td class="num start"><button type="button" class="link" data-action="view-purchase" data-id="${esc(p.id)}">${esc(p.no)}</button></td><td class="nowrap">${fmtDate(p.date)}</td><td><div class="cell-main">${esc(p.supplier)}</div>${p.ref ? `<div class="cell-sub">فاتورة المورد ${esc(p.ref)}</div>` : ''}</td><td class="hide-sm clamp">${summary(p)}</td><td class="hide-sm">${esc(PAY_LABEL[p.payAccountId] || '—')}</td><td class="money hide-sm">${M(p.vatH)}</td><td class="money"><b>${M(p.totalH)}</b></td></tr>`).join('')}
    </tbody></table></div>` : empty('box', 'لا توجد فواتير مشتريات', 'اضغط «فاتورة مشتريات»، اكتب الأصناف والأسعار، واحفظ — هذا كل شيء.', btn('new-purchase', 'فاتورة مشتريات', { perm: 'inventory.write' }))}</div>`;
}

/* =====================================================================
   كشف الحساب البنكي: رفع ← مراجعة التصنيف ← ترحيل
   ===================================================================== */
const B = window.HirafBank;
const BANK_BLOCKED = () => new Set([ACC.ar, ACC.inv, ACC.fa, ACC.accDep]);
function bankInit() { return { bankAccountId: S.data.accounts.some((a) => a.id === ACC.bank) ? ACC.bank : ACC.cash, file: '', rows: null, header: -1, map: null, items: null, errors: [], busy: false }; }
/** الحسابات التي يمكن التصنيف عليها، مجمّعة حسب النوع */
function bankAccountOptions(bankId) {
  const blocked = BANK_BLOCKED(); blocked.add(bankId);
  const ok = S.data.accounts.filter((a) => !a.archived && !blocked.has(a.id) && a.id !== ACC.cogs && a.id !== ACC.depExp);
  const groups = [['Expenses', 'المصروفات'], ['Revenue', 'الإيرادات'], ['Equity', 'حقوق الملكية'], ['Liabilities', 'الخصوم'], ['Assets', 'الأصول (تحويل)']];
  return groups.map(([t, l]) => [l, ok.filter((a) => a.type === t)]).filter((g) => g[1].length);
}
/** ما تعلّمه النظام من استيرادات سابقة: بيان العملية ← التصنيف الذي اختاره المستخدم */
function bankHistory(bankId) {
  const m = new Map();
  const js = S.data.journals.filter((j) => j.bankRef && j.source === 'bank' && j.status === 'posted');
  for (let i = js.length - 1; i >= 0; i--) { const j = js[i]; const l = j.lines.find((x) => x.accountId !== j.sourceId); if (l) m.set(B.descKey(j.memo), l.accountId); }
  const ps = S.data.purchases.filter((p) => p.bankRef);
  for (let i = ps.length - 1; i >= 0; i--) { const p = ps[i]; if (p.lines?.[0]) m.set(B.descKey(p.supplier), p.lines[0].accountId); }
  return m;
}
function bankRefsDone() {
  const set = new Set();
  S.data.journals.forEach((j) => j.bankRef && set.add(j.bankRef));
  S.data.purchases.forEach((p) => p.bankRef && set.add(p.bankRef));
  return set;
}
/** يبني قائمة العمليات من الملف المقروء مع التصنيف المقترح وحالة التكرار */
function bankBuild() {
  const st = S.bank;
  const n = B.normalize(st.rows, st.map, st.header);
  const refs = B.fingerprints(n.items);
  const hist = bankHistory(st.bankAccountId), done = bankRefsDone();
  const accs = new Map(S.data.accounts.filter((a) => !a.archived).map((a) => [a.id, a]));
  const blocked = BANK_BLOCKED(); blocked.add(st.bankAccountId);
  const usesPayroll = S.data.payrolls.some((p) => p.status !== 'draft');
  const firstOf = (type) => S.data.accounts.find((a) => a.type === type && !a.archived && !blocked.has(a.id) && a.id !== ACC.cogs && a.id !== ACC.depExp)?.id || '';
  st.items = n.items.map((it, k) => {
    let acc = hist.get(B.descKey(it.desc)) || 'acc-' + B.suggest(it.desc, it.dir);
    // إن كانت الرواتب تُعتمد من المسير فالتحويل البنكي يسدد «رواتب مستحقة» ولا يُحسب مصروفاً مرتين
    if (acc === ACC.salaries && usesPayroll && accs.has(ACC.salPay)) acc = ACC.salPay;
    if (!accs.has(acc) || blocked.has(acc)) acc = it.dir === 'out' ? (accs.has(ACC.general) ? ACC.general : firstOf('Expenses')) : (accs.has(ACC.services) ? ACC.services : firstOf('Revenue'));
    const ref = refs[k];
    const dup = done.has(ref);
    return { ...it, ref, accountId: acc, vat: false, include: !dup, dup, touched: false, learned: hist.has(B.descKey(it.desc)) };
  });
  st.errors = n.errors;
  st.dateOrder = n.dateOrder;
}
async function bankReadFile(file) {
  const st = S.bank || (S.bank = bankInit());
  if (!file) return;
  if (file.size > 15 * 1024 * 1024) { toast('الملف كبير جداً', 'الحد 15 ميجابايت', 'error'); return; }
  try {
    const { rows } = await B.readStatement(new Uint8Array(await file.arrayBuffer()), file.name);
    const det = B.detectColumns(rows);
    Object.assign(st, { file: file.name, rows, header: det.header, map: det.map, detected: det.detected });
    if (!det.detected) { st.items = []; st.errors = [{ msg: 'لم أتعرف على أعمدة الكشف تلقائياً. حدّد الأعمدة من «تعديل الأعمدة» ثم اضغط إعادة القراءة' }]; }
    else bankBuild();
    render();
    if (det.detected && !st.items.length) toast('لم أجد عمليات في الملف', 'تأكد أن الملف هو كشف الحساب نفسه، أو عدّل الأعمدة', 'error');
  } catch (err) {
    toast('تعذّرت قراءة الملف', err instanceof B.StatementError ? err.message : 'الملف تالف أو بصيغة غير مدعومة', 'error');
    if (!(err instanceof B.StatementError)) console.error(err);
  }
}
function renderBank() {
  const st = S.bank || (S.bank = bankInit());
  const cashAccs = S.data.accounts.filter((a) => a.cash && !a.archived);
  if (!st.items) {
    const imported = [
      ...S.data.journals.filter((j) => j.bankRef && j.source === 'bank').map((j) => { const l = j.lines.find((x) => x.accountId !== j.sourceId) || {}; return { date: j.date, desc: j.memo, acc: l.accountId, out: !!l.debitH, amt: j.totalDebitH, st: j.status, id: j.id, kind: 'j' }; }),
      ...S.data.purchases.filter((p) => p.bankRef).map((p) => ({ date: p.date, desc: p.supplier, acc: p.lines?.[0]?.accountId, out: true, amt: p.totalH, st: 'posted', id: p.id, kind: 'p' })),
    ].sort((a, b) => String(b.date).localeCompare(String(a.date))).slice(0, 150);
    return `<div class="stack">
      <div class="card"><div class="card-head"><h3>${icon('bank')}رفع كشف الحساب</h3><span class="hint">Excel ‏(xlsx) أو CSV</span></div>
        <div class="card-body bank-up">
          <div class="field"><label for="bkAcc">الكشف يخص حساب</label><select class="select" id="bkAcc">${cashAccs.map((a) => `<option value="${esc(a.id)}" ${a.id === st.bankAccountId ? 'selected' : ''}>${esc(a.number)} — ${esc(a.name)}</option>`).join('')}</select></div>
          <label class="drop" id="bkDrop" for="bkFile">${icon('upload')}<b>اسحب ملف الكشف هنا أو اضغط لاختياره</b><span>من تطبيق البنك أو موقعه: كشف الحساب ← تصدير ← Excel أو CSV</span>
            <input type="file" id="bkFile" accept=".xlsx,.csv,.txt,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" class="sr"></label>
          <ul class="bank-how">
            <li>يقرأ النظام كل سطر: التاريخ والبيان والمبلغ، ويقترح التصنيف (رواتب، إيجار، وقود، رسوم بنكية، مبيعات…).</li>
            <li>تراجع القائمة وتعدّل أي تصنيف، ويتذكر النظام اختيارك في المرات القادمة.</li>
            <li>السحوبات المصنّفة مصروفات تُسجَّل فواتير مشتريات، والباقي قيود مرحّلة. العملية المستوردة سابقاً لا تُكرر.</li>
          </ul>
        </div></div>
      <div class="card"><div class="card-head"><h3>آخر العمليات المستوردة</h3><span class="hint">${imported.length} عملية</span></div>
        ${imported.length ? `<div class="table-wrap"><table><thead><tr><th>التاريخ</th><th>البيان</th><th class="hide-sm">التصنيف</th><th class="money">سحب</th><th class="money">إيداع</th></tr></thead><tbody>
        ${imported.map((r) => `<tr class="${r.st === 'reversed' ? 'muted-text' : ''}"><td class="nowrap">${fmtDate(r.date)}</td><td><button type="button" class="link plain" data-action="${r.kind === 'j' ? 'view-journal' : 'view-purchase'}" data-id="${esc(r.id)}">${esc(r.desc)}</button>${r.st === 'reversed' ? ' <span class="pill neutral">معكوس</span>' : ''}</td><td class="hide-sm">${esc(accName(r.acc))}</td><td class="money bad-text">${r.out ? M(r.amt) : ''}</td><td class="money ok-text">${r.out ? '' : M(r.amt)}</td></tr>`).join('')}
        </tbody></table></div>` : empty('bank', 'لم يُستورد أي كشف بعد', 'ارفع أول كشف حساب من الأعلى.')}</div>
    </div>`;
  }
  const items = st.items;
  const inc = items.filter((r) => r.include);
  const outH = H.sumInts(inc.filter((r) => r.dir === 'out').map((r) => r.amountH)), inH = H.sumInts(inc.filter((r) => r.dir === 'in').map((r) => r.amountH));
  const dups = items.filter((r) => r.dup).length;
  const groups = bankAccountOptions(st.bankAccountId);
  const accType = new Map(S.data.accounts.map((a) => [a.id, a.type]));
  const bankAcc = S.data.accounts.find((a) => a.id === st.bankAccountId);
  const cols = (st.rows[st.header] || st.rows[0] || []).map((c, i) => [i, (st.header >= 0 && c) ? c : `العمود ${i + 1}`]);
  const colSel = (id, label, val, multi = false) => `<div class="field"><label for="${id}">${label}</label><select class="select" id="${id}"><option value="-1">—</option>${cols.map(([i, c]) => `<option value="${i}" ${(multi ? val.includes(i) : val === i) ? 'selected' : ''}>${esc(String(c).slice(0, 30))}</option>`).join('')}</select></div>`;
  const optHtml = (sel) => groups.map(([l, list]) => `<optgroup label="${esc(l)}">${list.map((a) => `<option value="${esc(a.id)}" ${a.id === sel ? 'selected' : ''}>${esc(a.name)}</option>`).join('')}</optgroup>`).join('');
  return `<form id="bankForm" data-keep novalidate>
    <div class="toolbar"><span class="pill info">${icon('file')}${esc(st.file)}</span><span class="cell-sub">الحساب: <b>${esc(bankAcc?.name || '')}</b></span>
      <button type="button" class="btn btn-ghost btn-sm" data-action="bk-reset">${icon('x')}ملف آخر</button></div>
    <div class="card kpis-card"><div class="kpis bank-kpis">
      <div class="kpi hero"><div class="kpi-label">عمليات مختارة للترحيل</div><div class="kpi-value">${inc.length}<small>من ${items.length}</small></div><div class="kpi-meta">${dups ? `${dups} سبق استيرادها وستُتجاهل` : 'لا توجد عمليات مكررة'}</div></div>
      <div class="kpi"><div class="kpi-label"><span class="dot bad-bg"></span>السحوبات</div><div class="kpi-value">${M(outH)}<small>ر.س</small></div><div class="kpi-meta">${inc.filter((r) => r.dir === 'out').length} عملية</div></div>
      <div class="kpi"><div class="kpi-label"><span class="dot ok-bg"></span>الإيداعات</div><div class="kpi-value">${M(inH)}<small>ر.س</small></div><div class="kpi-meta">${inc.filter((r) => r.dir === 'in').length} عملية</div></div>
      <div class="kpi ${inH - outH < 0 ? 'kpi-bad' : ''}"><div class="kpi-label"><span class="dot"></span>صافي الحركة</div><div class="kpi-value">${M(inH - outH)}<small>ر.س</small></div><div class="kpi-meta">يُضاف إلى رصيد ${esc(bankAcc?.name || 'البنك')}</div></div>
    </div></div>
    ${st.errors.length ? `<div class="card bank-errors"><div class="card-head"><h3>${icon('alert')}أسطر لم تُقرأ (${st.errors.length})</h3><span class="hint">لن تُرحّل؛ أضفها يدوياً إن لزم</span></div><ul>${st.errors.slice(0, 15).map((e) => `<li>${esc(e.msg)}</li>`).join('')}${st.errors.length > 15 ? `<li>و${st.errors.length - 15} أخرى…</li>` : ''}</ul></div>` : ''}
    <details class="more bank-map" ${st.detected ? '' : 'open'}><summary>تعديل الأعمدة${st.detected ? ' (تعرّف النظام عليها تلقائياً)' : ''}</summary>
      <div class="form-grid three">
        ${colSel('bkMapDate', 'التاريخ', st.map.date)}${colSel('bkMapDesc', 'البيان', st.map.desc, true)}${colSel('bkMapAmount', 'المبلغ (بإشارة + / −)', st.map.amount)}
        ${colSel('bkMapDebit', 'مدين / سحب', st.map.debit)}${colSel('bkMapCredit', 'دائن / إيداع', st.map.credit)}
        <div class="field"><label for="bkHeader">سطر العناوين</label><input class="input num" id="bkHeader" inputmode="numeric" value="${st.header + 1}"></div>
      </div>
      <button type="button" class="btn btn-ghost btn-sm" data-action="bk-remap">${icon('restore')}إعادة القراءة</button>
    </details>
    <div class="card">
      ${items.length ? `<div class="table-wrap"><table class="bank-table"><thead><tr>
        <th class="c"><input type="checkbox" id="bkAll" aria-label="تحديد الكل" ${inc.length === items.filter((r) => !r.dup).length && inc.length ? 'checked' : ''}></th>
        <th>التاريخ</th><th>البيان</th><th class="money">سحب</th><th class="money">إيداع</th><th>التصنيف</th><th class="c" title="السعر شامل ضريبة 15% — للمصروفات فقط">ضريبة</th></tr></thead><tbody>
        ${items.map((r, i) => {
          const isExp = r.dir === 'out' && accType.get(r.accountId) === 'Expenses';
          return `<tr class="${r.dup ? 'row-dup' : ''} ${r.include ? '' : 'row-off'}">
          <td class="c"><input type="checkbox" data-bk="inc" data-i="${i}" ${r.include ? 'checked' : ''} ${r.dup ? 'disabled' : ''} aria-label="ترحيل العملية"></td>
          <td class="nowrap num">${fmtDate(r.date)}</td>
          <td class="bank-desc">${esc(r.desc)}${r.dup ? ' <span class="pill neutral">مستوردة سابقاً</span>' : r.learned ? ' <span class="pill ok" title="تصنيف تعلّمه النظام من اختيارك السابق">محفوظ</span>' : ''}</td>
          <td class="money bad-text">${r.dir === 'out' ? M(r.amountH) : ''}</td><td class="money ok-text">${r.dir === 'in' ? M(r.amountH) : ''}</td>
          <td><select class="select sm bank-acc" data-bk="acc" data-i="${i}" aria-label="التصنيف" ${r.dup ? 'disabled' : ''}>${optHtml(r.accountId)}</select></td>
          <td class="c">${isExp ? `<input type="checkbox" data-bk="vat" data-i="${i}" ${r.vat ? 'checked' : ''} ${r.dup ? 'disabled' : ''} aria-label="شامل الضريبة">` : '<span class="faint">—</span>'}</td></tr>`;
        }).join('')}
        </tbody></table></div>` : empty('file', 'لا توجد عمليات مقروءة', 'عدّل الأعمدة من الأعلى ثم اضغط إعادة القراءة.')}
    </div>
    <div class="bank-foot">
      <span class="cell-sub" id="bkProgress">${inc.length ? `سيُرحّل ${inc.length} عملية: ${inc.filter((r) => r.dir === 'out' && accType.get(r.accountId) === 'Expenses').length} مصروفات كفواتير مشتريات، والباقي قيود.` : 'اختر العمليات المراد ترحيلها.'}</span>
      ${btn('bk-post', `ترحيل ${inc.length} عملية`, { ic: 'check', perm: 'bank.import' })}
    </div>
  </form>`;
}
function bankPost(el) {
  const st = S.bank;
  const rows = st.items.filter((r) => r.include && !r.dup).map((r) => ({ date: r.date, desc: r.desc, dir: r.dir, amountH: r.amountH, accountId: r.accountId, vat: r.vat, ref: r.ref }));
  if (!rows.length) { toast('اختر عملية واحدة على الأقل', '', 'error'); return; }
  const prog = $('#bkProgress');
  run(el, () => Services.importBank({ bankAccountId: st.bankAccountId, rows, fileName: st.file }, (d, n) => { if (prog) prog.textContent = `جارٍ الترحيل… ${d} من ${n}`; }), null, { close: false }).then((res) => {
    if (!res) return;
    toast(`رُحّلت ${res.posted} عملية من الكشف`, res.dup ? `${res.dup} عملية كانت مستوردة سابقاً وتُجوهلت` : 'ظهرت في القيود والمشتريات والتقارير');
    S.bank = { ...bankInit(), bankAccountId: st.bankAccountId };
    render();
  });
}

/* =====================================================================
   الموارد البشرية
   ===================================================================== */
const TERM_REASON = { employer: 'إنهاء من المنشأة / انتهاء العقد', resign: 'استقالة', full: 'مستحقة كاملة (م87)' };
const serviceText = (days) => { const y = Math.floor(days / 365), m = Math.floor((days % 365) / 30.42); return [y ? `${y} سنة` : '', m ? `${m} شهر` : ''].filter(Boolean).join(' و') || 'أقل من شهر'; };
const pct = (bp) => (bp / 100).toLocaleString('en', { maximumFractionDigits: 2 }) + '%';
function eosToday(e, reason = 'employer') { return H.endOfService({ wageH: H.fixedWageH(e), hireDate: e.hireDate, endDate: todayISO(), reason }); }

function renderHR() {
  const tab = S.tabs.hr;
  const d = S.data;
  const act = d.employees.filter((e) => e.status === 'active');
  const head = `<div class="toolbar">${btn('new-employee', 'موظف جديد', { perm: 'hr.manage', ic: 'plus' })}${btn('new-advance', 'سلفة', { perm: 'hr.manage', cls: 'btn-ghost', ic: 'wallet' })}
    ${tabs('hr', [['employees', 'الموظفون'], ['payroll', 'مسير الرواتب'], ['advances', 'السلف'], ['eos', 'نهاية الخدمة'], ['settings', 'التأمينات']])}</div>`;
  if (tab === 'payroll') return head + renderPayroll();
  if (tab === 'advances') {
    const l = d.advances;
    return head + `<div class="card">${l.length ? `<div class="table-wrap"><table><thead><tr><th>الرقم</th><th>التاريخ</th><th>الموظف</th><th class="money">المبلغ</th><th class="money hide-sm">القسط</th><th class="money">المسترد</th><th class="money">المتبقي</th><th>الحالة</th></tr></thead><tbody>
      ${l.map((a) => `<tr><td class="num start"><button type="button" class="link" data-action="view-journal" data-id="${esc(a.journalIds?.[0] || '')}">${esc(a.no)}</button></td><td class="nowrap">${fmtDate(a.date)}</td><td><div class="cell-main">${esc(a.empName)}</div>${a.note ? `<div class="cell-sub">${esc(a.note)}</div>` : ''}</td>
        <td class="money">${M(a.amountH)}</td><td class="money hide-sm">${M(a.installmentH)} × ${a.installments}</td><td class="money">${M(a.recoveredH)}</td><td class="money"><b>${M(a.remainingH)}</b></td>
        <td>${a.remainingH ? '<span class="pill warn">قائمة</span>' : '<span class="pill ok">مسددة</span>'}</td></tr>`).join('')}
      <tr class="total-row"><td colspan="6">إجمالي المتبقي على الموظفين</td><td class="money">${M(H.sumInts(l.map((a) => a.remainingH)))}</td><td></td></tr>
      </tbody></table></div>` : empty('wallet', 'لا توجد سلف', 'السلفة تُصرف من الصندوق أو البنك وتُستقطع أقساطها من المسير تلقائياً.')}</div>`;
  }
  if (tab === 'eos') {
    const rows = act.map((e) => ({ e, emp: eosToday(e, 'employer'), res: eosToday(e, 'resign') }));
    const done = d.employees.filter((e) => e.status === 'terminated');
    return head + `<div class="card"><div class="card-head"><h3>المكافأة المستحقة لو انتهت الخدمة اليوم</h3><span class="hint">نظام العمل م84 و م85 — على الأجر الثابت الأخير</span></div>
      ${rows.length ? `<div class="table-wrap"><table><thead><tr><th>الموظف</th><th class="hide-sm">المباشرة</th><th>مدة الخدمة</th><th class="money hide-sm">الأجر</th><th class="money">عند إنهاء العقد</th><th class="money">عند الاستقالة</th><th><span class="sr">إجراءات</span></th></tr></thead><tbody>
      ${rows.map(({ e, emp, res }) => `<tr><td><div class="cell-main">${esc(e.name)}</div><div class="cell-sub">${esc(e.code)}${e.jobTitle ? ' · ' + esc(e.jobTitle) : ''}</div></td><td class="nowrap hide-sm">${fmtDate(e.hireDate)}</td><td class="nowrap">${serviceText(emp.days)}</td>
        <td class="money hide-sm">${M(H.fixedWageH(e))}</td><td class="money"><b>${M(emp.awardH)}</b></td><td class="money">${M(res.awardH)}${res.factor[0] !== res.factor[1] ? ` <span class="cell-sub">(${res.factor[0] ? res.factor.join('/') : 'لا شيء'})</span>` : ''}</td>
        <td>${btn('terminate-employee', 'إنهاء الخدمة', { cls: 'btn-quiet btn-sm', ic: 'logout', data: { id: e.id }, perm: 'hr.manage' })}</td></tr>`).join('')}
      <tr class="total-row"><td colspan="4">الالتزام التقديري لنهاية الخدمة</td><td class="money">${M(H.sumInts(rows.map((r) => r.emp.awardH)))}</td><td class="money">${M(H.sumInts(rows.map((r) => r.res.awardH)))}</td><td></td></tr>
      </tbody></table></div>` : empty('id', 'لا يوجد موظفون نشطون')}</div>
      ${done.length ? `<div class="card mt"><div class="card-head"><h3>انتهت خدمتهم</h3></div><div class="table-wrap"><table><thead><tr><th>الموظف</th><th>تاريخ الانتهاء</th><th>السبب</th><th class="money">المكافأة</th><th class="money hide-sm">خُصم سلف</th><th class="money">الصافي</th></tr></thead><tbody>
      ${done.map((e) => `<tr><td><div class="cell-main">${esc(e.name)}</div><div class="cell-sub">${esc(e.code)} · ${serviceText(e.eosDays || 0)}</div></td><td class="nowrap">${fmtDate(e.termDate)}</td><td>${esc(TERM_REASON[e.termReason] || '')}</td><td class="money">${e.journalIds?.[0] ? `<button type="button" class="link" data-action="view-journal" data-id="${esc(e.journalIds[0])}">${M(e.eosH)}</button>` : M(e.eosH)}</td><td class="money hide-sm">${M(e.eosH - e.eosNetH)}</td><td class="money"><b>${M(e.eosNetH)}</b></td></tr>`).join('')}
      </tbody></table></div></div>` : ''}`;
  }
  if (tab === 'settings') {
    const r = d.hr;
    return head + `<div class="card"><div class="card-head"><h3>نسب التأمينات الاجتماعية</h3><span class="hint">تُطبّق على المسيرات الجديدة</span></div><div class="card-body">
      <form id="hrSetForm" class="form-grid" novalidate style="max-width:720px">
        <div class="field"><label for="gEmpSa">حصة الموظف السعودي %</label><input class="input num" id="gEmpSa" inputmode="decimal" value="${r.empSaudiBp / 100}"></div>
        <div class="field"><label for="gErSa">حصة المنشأة عن السعودي %</label><input class="input num" id="gErSa" inputmode="decimal" value="${r.erSaudiBp / 100}"></div>
        <div class="field"><label for="gErNon">حصة المنشأة عن غير السعودي (أخطار مهنية) %</label><input class="input num" id="gErNon" inputmode="decimal" value="${r.erNonSaudiBp / 100}"></div>
        <div class="field"><label for="gCap">الحد الأعلى للأجر الخاضع (أساسي + سكن)</label><input class="input num" id="gCap" inputmode="decimal" value="${H.moneyInput(r.capH)}"></div>
        <p class="span-2 cell-sub">الوعاء = الراتب الأساسي + بدل السكن. النسب الافتراضية: السعودي 9.75% على الموظف و11.75% على المنشأة، وغير السعودي 2% على المنشأة. نسب التأمينات تتغير بقرارات دورية، فطابقها مع حسابك في «التأمينات الاجتماعية» قبل أول مسير.</p>
        ${can('hr.manage') ? `<div class="span-2"><button class="btn btn-primary" type="submit">${icon('save')}حفظ النسب</button></div>` : ''}
      </form></div></div>`;
  }
  // الموظفون
  const all = d.employees.filter((e) => e.status === 'active' || S.hrShowAll);
  const wageTot = H.sumInts(act.map(H.fixedWageH));
  const saudis = act.filter((e) => e.isSaudi).length;
  return head + `<div class="card kpis-card"><div class="kpis">
      <div class="kpi hero"><div class="kpi-label">الموظفون النشطون</div><div class="kpi-value">${act.length}</div><div class="kpi-meta">${saudis} سعودي · ${act.length - saudis} غير سعودي</div></div>
      <div class="kpi"><div class="kpi-label"><span class="dot navy-bg"></span>الرواتب الثابتة شهرياً</div><div class="kpi-value">${M(wageTot)}<small>ر.س</small></div><div class="kpi-meta">قبل الإضافي والخصومات</div></div>
      <div class="kpi"><div class="kpi-label"><span class="dot ok-bg"></span>نسبة السعودة</div><div class="kpi-value">${act.length ? Math.round((saudis / act.length) * 100) : 0}%</div><div class="kpi-meta">من الموظفين النشطين</div></div>
      <div class="kpi"><div class="kpi-label"><span class="dot warn-bg"></span>سلف قائمة</div><div class="kpi-value">${M(d.recon.advSubH)}<small>ر.س</small></div><div class="kpi-meta">${d.advances.filter((a) => a.remainingH).length} سلفة</div></div>
    </div></div>
    <div class="card mt"><div class="card-head"><h3>ملف الموظفين</h3><label class="check actions"><input type="checkbox" id="hrShowAll" ${S.hrShowAll ? 'checked' : ''}> عرض من انتهت خدمتهم</label></div>
    ${all.length ? `<div class="table-wrap"><table><thead><tr><th>الرقم</th><th>الموظف</th><th class="hide-sm">الجنسية</th><th class="hide-sm">الموقع</th><th class="hide-sm">المباشرة</th><th class="money">الأجر الثابت</th><th>الحالة</th><th><span class="sr">إجراءات</span></th></tr></thead><tbody>
    ${all.map((e) => `<tr><td class="num start">${esc(e.code)}</td><td><div class="cell-main">${esc(e.name)}</div><div class="cell-sub">${esc(e.jobTitle || '')}</div></td>
      <td class="hide-sm">${e.isSaudi ? 'سعودي' : esc(e.nationality || 'غير سعودي')}${e.gosi ? '' : ' <span class="pill neutral">بلا تأمينات</span>'}</td><td class="hide-sm">${esc(e.site || '—')}</td><td class="nowrap hide-sm">${fmtDate(e.hireDate)}</td>
      <td class="money"><b>${M(H.fixedWageH(e))}</b></td><td>${e.status === 'active' ? '<span class="pill ok">على رأس العمل</span>' : `<span class="pill neutral">انتهت ${fmtDate(e.termDate)}</span>`}</td>
      <td><div class="row-actions">${e.status === 'active' ? btn('edit-employee', '', { cls: 'btn-quiet btn-sm icon-btn', ic: 'edit', data: { id: e.id }, title: 'تعديل', perm: 'hr.manage' }) + btn('terminate-employee', '', { cls: 'btn-quiet btn-sm icon-btn', ic: 'logout', data: { id: e.id }, title: 'إنهاء الخدمة', perm: 'hr.manage' }) : ''}</div></td></tr>`).join('')}
    </tbody></table></div>` : empty('id', 'لا يوجد موظفون بعد', 'أضف الموظفين ورواتبهم، ثم جهّز مسير الشهر.', btn('new-employee', 'موظف جديد', { perm: 'hr.manage' }))}</div>`;
}

/* ---------- مسير الرواتب ---------- */
function renderPayroll() {
  const month = S.hrMonth || (S.hrMonth = thisMonth());
  const p = S.data.payrolls.find((x) => x.id === month);
  const bar = `<div class="card pr-bar"><label for="hrMonth">الشهر</label><input class="input" type="month" id="hrMonth" value="${month}">
    ${p ? `<span class="pill ${p.status === 'draft' ? 'warn' : p.status === 'posted' ? 'info' : 'ok'}">${{ draft: 'مسودة', posted: 'معتمد — بانتظار الصرف', paid: 'مصروف' }[p.status]}</span>` : ''}
    <span class="grow"></span>${S.data.payrolls.length ? `<span class="cell-sub">مسيرات سابقة: ${S.data.payrolls.slice(0, 6).map((x) => `<button type="button" class="link" data-action="hr-month" data-m="${x.id}">${esc(fmtMonth(x.id))}</button>`).join(' · ')}</span>` : ''}</div>`;
  if (!p) return bar + `<div class="card">${empty('calc', `لا يوجد مسير لشهر ${fmtMonth(month)}`, 'يُجهَّز المسير من الموظفين النشطين ورواتبهم، ثم تُدخل الإضافي والغياب وتعتمده.', btn('prepare-payroll', 'إعداد مسير الشهر', { perm: 'payroll.run', ic: 'plus' }))}</div>`;
  const draft = p.status === 'draft';
  const edits = (S.prEdits ||= {})[month] ||= {};
  const rows = p.lines.map((l0) => {
    const l = draft ? { ...l0, ...(edits[l0.employeeId] || {}) } : l0;
    let c; try { c = draft ? H.payrollLine(l, l, S.data.hr) : l; } catch { c = { fixedH: 0, grossH: 0, gosiEmpH: 0, gosiErH: 0, netH: 0, absenceH: 0 }; }
    return { l, c };
  });
  const T = (k) => H.sumInts(rows.map((r) => r.c[k] || 0));
  const PR_LABEL = { overtimeH: 'إضافي', bonusH: 'مكافأة', absenceDays: 'أيام غياب', penaltyH: 'جزاءات', advanceH: 'قسط سلفة' };
  const inp = (l, key, v) => `<input class="input num sm" id="pr-${esc(l.employeeId)}-${key}" data-pr="${key}" data-e="${esc(l.employeeId)}" value="${esc(v)}" inputmode="decimal" aria-label="${PR_LABEL[key]} — ${esc(l.name)}">`;
  const table = `<div class="table-wrap"><table class="pr-table"><thead><tr><th>الموظف</th><th class="money">الأجر الثابت</th><th class="money">إضافي</th><th class="money">مكافأة</th><th class="money">أيام غياب</th><th class="money">جزاءات</th><th class="money">قسط سلفة</th><th class="money">تأمينات الموظف</th><th class="money">الصافي</th></tr></thead><tbody>
    ${rows.map(({ l, c }) => `<tr class="${c.netH < 0 ? 'row-warn' : ''}"><td><div class="cell-main">${esc(l.name)}</div><div class="cell-sub">${esc(l.code)}${l.site ? ' · ' + esc(l.site) : ''}</div></td>
      <td class="money">${M(c.fixedH)}</td>
      ${draft ? `<td>${inp(l, 'overtimeH', l.overtimeH ? H.moneyInput(l.overtimeH) : '')}</td><td>${inp(l, 'bonusH', l.bonusH ? H.moneyInput(l.bonusH) : '')}</td><td>${inp(l, 'absenceDays', l.absenceDays || '')}</td><td>${inp(l, 'penaltyH', l.penaltyH ? H.moneyInput(l.penaltyH) : '')}</td><td>${inp(l, 'advanceH', l.advanceH ? H.moneyInput(l.advanceH) : '')}</td>`
        : `<td class="money">${M(l.overtimeH)}</td><td class="money">${M(l.bonusH)}</td><td class="money">${l.absenceDays || 0}${l.absenceH ? ` <span class="cell-sub">(${H.fmtMoney(l.absenceH)})</span>` : ''}</td><td class="money">${M(l.penaltyH)}</td><td class="money">${M(l.advanceH)}</td>`}
      <td class="money">${M(c.gosiEmpH)}</td><td class="money"><b class="${c.netH < 0 ? 'bad-text' : ''}">${M(c.netH)}</b></td></tr>`).join('')}
    <tr class="total-row"><td>الإجمالي (${rows.length})</td><td class="money">${M(T('fixedH'))}</td><td class="money">${M(H.sumInts(rows.map((r) => r.l.overtimeH || 0)))}</td><td class="money">${M(H.sumInts(rows.map((r) => r.l.bonusH || 0)))}</td><td class="money">${M(T('absenceH'))}</td><td class="money">${M(H.sumInts(rows.map((r) => r.l.penaltyH || 0)))}</td><td class="money">${M(H.sumInts(rows.map((r) => r.l.advanceH || 0)))}</td><td class="money">${M(T('gosiEmpH'))}</td><td class="money">${M(T('netH'))}</td></tr>
    </tbody></table></div>`;
  const summary = `<div class="pr-sum"><div><span class="cell-sub">إجمالي الرواتب (مصروف)</span><b>${M(T('grossH'))}</b></div><div><span class="cell-sub">حصة المنشأة في التأمينات</span><b>${M(T('gosiErH'))}</b></div><div><span class="cell-sub">التأمينات المستحقة (الحصتان)</span><b>${M(T('gosiEmpH') + T('gosiErH'))}</b></div><div class="grand"><span class="cell-sub">صافي الرواتب للصرف</span><b>${M(T('netH'))} ر.س</b></div></div>`;
  const actions = draft
    ? `${btn('prepare-payroll', 'تحديث من ملف الموظفين', { cls: 'btn-ghost', ic: 'restore', perm: 'payroll.run' })}${btn('save-payroll', 'حفظ المسودة', { cls: 'btn-ghost', ic: 'save', perm: 'payroll.run' })}${btn('post-payroll', 'اعتماد المسير', { ic: 'check', perm: 'payroll.run' })}`
    : `${p.journalIds?.map((id, k) => `<button type="button" class="btn btn-ghost btn-sm" data-action="view-journal" data-id="${esc(id)}">${icon('book')}${k ? 'قيد الصرف' : 'قيد الاستحقاق'}</button>`).join('') || ''}
       ${btn('export-payroll', 'ملف التحويل البنكي (CSV)', { cls: 'btn-ghost', ic: 'download', perm: 'payroll.run' })}${p.status === 'posted' ? btn('pay-payroll', 'صرف الرواتب', { ic: 'wallet', perm: 'payroll.run' }) : ''}`;
  return bar + `<form id="payrollForm" data-keep novalidate><div class="card">${table}${summary}<div class="pr-actions">${draft ? '<span class="cell-sub">المبالغ بالريال، والغياب بالأيام (يُخصم الأجر الثابت ÷ 30 عن كل يوم).</span>' : `<span class="cell-sub">اعتمده ${esc(userName(p.postedBy))} · ${fmtDateTime(p.postedAt)}${p.paidAt ? ` — صُرف ${fmtDateTime(p.paidAt)}` : ''}</span>`}<div class="actions">${actions}</div></div></div></form>`;
}
/** يقرأ خانات المسودة المعدّلة ويخزنها (بالهللة)، ويعلّم الخانة الخاطئة */
function payrollEditsFromDom() {
  const month = S.hrMonth, edits = (S.prEdits ||= {})[month] ||= {};
  for (const el of $$('[data-pr]')) {
    const e = edits[el.dataset.e] ||= {};
    const v = el.value.trim();
    try { e[el.dataset.pr] = el.dataset.pr === 'absenceDays' ? (v ? H.parseInteger(v, { min: 0, max: 30, label: 'أيام الغياب' }) : 0) : (v ? H.parseMoney(v, { allowZero: true }) : 0); }
    catch (err) { el.classList.add('invalid-input'); el.focus(); throw err; }
  }
  return edits;
}

/* ---------- نوافذ الموارد البشرية ---------- */
function employeeModal(id = '') {
  const e = (id && S.data.employees.find((x) => x.id === id)) || { isSaudi: true, gosi: true, hireDate: todayISO() };
  const mv = (h) => (h ? H.moneyInput(h) : '');
  openModal(id ? `تعديل بيانات ${e.name}` : 'موظف جديد', `<form id="empForm" class="form-grid three" novalidate>
    <div class="field span-2"><label for="eName">الاسم *</label><input class="input" id="eName" maxlength="100" value="${esc(e.name)}"></div>
    <div class="field"><label for="eJob">المهنة</label><input class="input" id="eJob" maxlength="60" value="${esc(e.jobTitle)}" placeholder="مهندس موقع، نجار، سائق…"></div>
    <div class="field"><label for="eSaudi">الجنسية</label><select class="select" id="eSaudi"><option value="1" ${e.isSaudi ? 'selected' : ''}>سعودي</option><option value="0" ${e.isSaudi ? '' : 'selected'}>غير سعودي</option></select></div>
    <div class="field"><label for="eNat">الجنسية (لغير السعودي)</label><input class="input" id="eNat" maxlength="30" value="${esc(e.nationality)}" placeholder="مثال: مصري"></div>
    <div class="field"><label for="eId">رقم الهوية / الإقامة</label><input class="input num" id="eId" maxlength="10" inputmode="numeric" dir="ltr" value="${esc(e.idNumber)}"></div>
    <div class="field"><label for="eHire">تاريخ المباشرة *</label><input class="input" type="date" id="eHire" value="${esc(e.hireDate)}"></div>
    <div class="field"><label for="eSite">الموقع / المشروع</label><input class="input" id="eSite" maxlength="60" value="${esc(e.site)}"></div>
    <div class="field"><label for="ePhone">الجوال</label><input class="input num" id="ePhone" maxlength="13" inputmode="tel" dir="ltr" value="${esc(e.phone)}"></div>
    <div class="field"><label for="eBasic">الراتب الأساسي *</label><input class="input num" id="eBasic" inputmode="decimal" value="${mv(e.basicH)}"></div>
    <div class="field"><label for="eHousing">بدل السكن</label><input class="input num" id="eHousing" inputmode="decimal" value="${mv(e.housingH)}" placeholder="عادة 25% من الأساسي"></div>
    <div class="field"><label for="eTrans">بدل النقل</label><input class="input num" id="eTrans" inputmode="decimal" value="${mv(e.transportH)}"></div>
    <div class="field"><label for="eOther">بدلات أخرى ثابتة</label><input class="input num" id="eOther" inputmode="decimal" value="${mv(e.otherH)}"></div>
    <div class="field"><label for="eBank">البنك</label><input class="input" id="eBank" maxlength="40" value="${esc(e.bankName)}"></div>
    <div class="field"><label for="eIban">الآيبان</label><input class="input" id="eIban" maxlength="34" dir="ltr" value="${esc(e.iban)}" placeholder="SA…"></div>
    <label class="check span-3"><input type="checkbox" id="eGosi" ${e.gosi ? 'checked' : ''}> مسجّل في التأمينات الاجتماعية</label>
    <p class="span-3 cell-sub" id="ePreview"></p>
  </form>`, cancelBtn + submitBtn('empForm', id ? 'حفظ التعديل' : 'إضافة الموظف'), { xwide: true });
  const money = (id2) => { const v = $('#' + id2).value.trim(); return v ? H.parseMoney(v, { allowZero: true }) : 0; };
  const preview = () => {
    try {
      const x = { basicH: money('eBasic'), housingH: money('eHousing'), transportH: money('eTrans'), otherH: money('eOther'), isSaudi: $('#eSaudi').value === '1', gosi: $('#eGosi').checked };
      const g = H.gosiShares(x, S.data.hr);
      $('#ePreview').innerHTML = `الأجر الثابت ${M(H.fixedWageH(x))} ر.س · تأمينات الموظف ${M(g.empH)} · على المنشأة ${M(g.erH)} · الصافي التقريبي ${M(H.fixedWageH(x) - g.empH)}`;
    } catch { $('#ePreview').textContent = ''; }
  };
  $('#empForm').addEventListener('input', preview); $('#empForm').addEventListener('change', preview); preview();
  $('#empForm').addEventListener('submit', formGuard(() => {
    const f = { name: $('#eName').value, jobTitle: $('#eJob').value, isSaudi: $('#eSaudi').value === '1', nationality: $('#eNat').value, idNumber: $('#eId').value,
      hireDate: field('eHire', (v) => H.parseDate(v, 'تاريخ المباشرة')), site: $('#eSite').value, phone: $('#ePhone').value,
      basicH: field('eBasic', (v) => H.parseMoney(v, { label: 'الراتب الأساسي' })), housingH: field('eHousing', (v) => (v.trim() ? H.parseMoney(v, { allowZero: true, label: 'بدل السكن' }) : 0)),
      transportH: field('eTrans', (v) => (v.trim() ? H.parseMoney(v, { allowZero: true, label: 'بدل النقل' }) : 0)), otherH: field('eOther', (v) => (v.trim() ? H.parseMoney(v, { allowZero: true, label: 'البدلات' }) : 0)),
      bankName: $('#eBank').value, iban: $('#eIban').value, gosi: $('#eGosi').checked };
    run(document.querySelector('[form=empForm]'), () => Services.saveEmployee(id, f), [id ? 'حُفظت بيانات الموظف' : 'أُضيف الموظف', (c) => c]);
  }));
}
function advanceModal() {
  const emps = S.data.employees.filter((e) => e.status === 'active');
  if (!emps.length) { toast('أضف موظفاً أولاً', '', 'error'); return; }
  openModal('صرف سلفة لموظف', `<form id="advForm" class="form-grid" novalidate>
    <div class="field span-2"><label for="aEmp">الموظف *</label><select class="select" id="aEmp">${emps.map((e) => `<option value="${esc(e.id)}">${esc(e.code)} — ${esc(e.name)}</option>`).join('')}</select></div>
    <div class="field"><label for="aAmt">مبلغ السلفة *</label><input class="input num" id="aAmt" inputmode="decimal"></div>
    <div class="field"><label for="aInst">عدد الأقساط الشهرية</label><input class="input num" id="aInst" inputmode="numeric" value="1"></div>
    <div class="field"><label for="aDate">التاريخ</label><input class="input" type="date" id="aDate" value="${todayISO()}"></div>
    <div class="field"><label for="aPay">تُصرف من</label><select class="select" id="aPay">${cashOptions(false)}</select></div>
    <div class="field span-2"><label for="aNote">ملاحظة</label><input class="input" id="aNote" maxlength="120"></div>
    <p class="span-2 cell-sub" id="aPrev"></p></form>`, cancelBtn + submitBtn('advForm', 'صرف السلفة'));
  const prev = () => { try { const a = H.parseMoney($('#aAmt').value), n = H.parseInteger($('#aInst').value, { min: 1, max: 36 }); $('#aPrev').innerHTML = `القسط الشهري ${M(Math.ceil(a / n))} ر.س يُستقطع تلقائياً من المسير`; } catch { $('#aPrev').textContent = ''; } };
  $('#advForm').addEventListener('input', prev);
  $('#advForm').addEventListener('submit', formGuard(() => {
    const f = { employeeId: $('#aEmp').value, amountH: field('aAmt', (v) => H.parseMoney(v, { label: 'مبلغ السلفة' })), installments: field('aInst', (v) => H.parseInteger(v, { min: 1, max: 36, label: 'عدد الأقساط' })),
      date: field('aDate', (v) => H.parseDate(v)), payAccountId: $('#aPay').value, note: $('#aNote').value };
    run(document.querySelector('[form=advForm]'), () => Services.createAdvance(f), ['صُرفت السلفة', (n) => n]);
  }));
}
function terminateModal(id) {
  const e = S.data.employees.find((x) => x.id === id); if (!e) return;
  const open = H.sumInts(S.data.advances.filter((a) => a.employeeId === id).map((a) => a.remainingH));
  openModal(`إنهاء خدمة ${e.name}`, `<form id="termForm" class="form-grid" novalidate>
    <div class="field"><label for="tDate">آخر يوم عمل *</label><input class="input" type="date" id="tDate" value="${todayISO()}"></div>
    <div class="field"><label for="tReason">السبب *</label><select class="select" id="tReason">${Object.entries(TERM_REASON).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select></div>
    <div class="field"><label for="tPay">صرف المكافأة</label><select class="select" id="tPay">${cashOptions(false)}<option value="${ACC.salPay}">تُسجّل مستحقة وتُصرف لاحقاً</option></select></div>
    <div class="field"><label for="tNote">ملاحظة</label><input class="input" id="tNote" maxlength="200"></div>
    <div class="span-2 term-box" id="tPrev"></div>
    <p class="span-2 cell-sub">اعتمد مسير الشهر الأخير قبل إنهاء الخدمة؛ الموظف لا يدخل المسيرات بعد الإنهاء. تعويض الإجازات غير المستخدمة لا يُحسب هنا.</p></form>`,
  cancelBtn + submitBtn('termForm', 'إنهاء الخدمة واحتساب المكافأة', 'logout'), { wide: true });
  const prev = () => {
    const date = $('#tDate').value, reason = $('#tReason').value;
    if (!H.isISODate(date) || date < e.hireDate) { $('#tPrev').innerHTML = '<span class="bad-text">تاريخ غير صالح</span>'; return; }
    const r = H.endOfService({ wageH: H.fixedWageH(e), hireDate: e.hireDate, endDate: date, reason });
    const ded = Math.min(open, r.awardH);
    $('#tPrev').innerHTML = `<div><span class="cell-sub">مدة الخدمة</span><b>${serviceText(r.days)}</b></div><div><span class="cell-sub">الأجر المعتمد</span><b>${M(H.fixedWageH(e))}</b></div>
      <div><span class="cell-sub">المكافأة الكاملة</span><b>${M(r.fullH)}</b></div><div><span class="cell-sub">المستحق${r.factor[0] !== r.factor[1] ? ` (${r.factor[0] ? r.factor.join('/') : 'لا شيء'})` : ''}</span><b>${M(r.awardH)}</b></div>
      ${ded ? `<div><span class="cell-sub">يُخصم سلف قائمة</span><b class="bad-text">${M(ded)}</b></div>` : ''}<div class="grand"><span class="cell-sub">الصافي للموظف</span><b>${M(r.awardH - ded)} ر.س</b></div>`;
  };
  $('#termForm').addEventListener('input', prev); $('#termForm').addEventListener('change', prev); prev();
  $('#termForm').addEventListener('submit', formGuard(() => {
    const f = { date: field('tDate', (v) => H.parseDate(v)), reason: $('#tReason').value, payAccountId: $('#tPay').value, note: $('#tNote').value };
    run(document.querySelector('[form=termForm]'), () => Services.terminateEmployee(id, f), ['انتهت خدمة الموظف', (a) => `المكافأة ${H.fmtMoney(a)} ر.س`]);
  }));
}
function payPayrollModal() {
  const p = S.data.payrolls.find((x) => x.id === S.hrMonth); if (!p) return;
  openModal(`صرف رواتب ${fmtMonth(p.id)}`, `<form id="payPrForm" class="form-grid" novalidate>
    <div class="field"><label for="ppAcc">من حساب</label><select class="select" id="ppAcc">${cashOptions(false)}</select></div>
    <div class="field"><label for="ppDate">تاريخ الصرف</label><input class="input" type="date" id="ppDate" value="${todayISO()}"></div>
    <p class="span-2">المبلغ: <b>${M(p.totals.netH)} ر.س</b> لـ ${p.lines.length} موظف. إن كنت ستستورد كشف البنك لاحقاً فلا تصرف من هنا، بل صنّف عملية الرواتب في الكشف على «رواتب مستحقة» حتى لا تتكرر.</p></form>`,
  cancelBtn + submitBtn('payPrForm', 'تسجيل الصرف', 'wallet'));
  $('#payPrForm').addEventListener('submit', formGuard(() => {
    run(document.querySelector('[form=payPrForm]'), () => Services.payPayroll(p.id, $('#ppAcc').value, field('ppDate', (v) => H.parseDate(v))), ['سُجّل صرف الرواتب', '']);
  }));
}

/* =====================================================================
   الأصول الثابتة
   ===================================================================== */
function renderAssets() {
  const l = S.data.assets;
  const pending = pendingDepMonths();
  return `<div class="toolbar">${btn('new-asset', 'أصل جديد', { perm: 'asset.write' })}
      ${pending.length ? btn('run-dep', `احتساب إهلاك ${fmtMonth(pending[0])}`, { cls: 'btn-ghost', ic: 'calc', perm: 'dep.run' }) : ''}
      ${pending.length ? `<span class="pill warn">${pending.length} شهر بانتظار الإهلاك</span>` : l.length ? '<span class="pill ok">الإهلاك محدّث</span>' : ''}</div>
    <div class="card">${l.length ? `<div class="table-wrap"><table><thead><tr><th>الرقم</th><th>الأصل</th><th class="money">التكلفة</th><th class="money hide-sm">الخردة</th><th class="money">القسط الشهري</th><th class="money">مجمع الإهلاك</th><th class="money">القيمة الدفترية</th><th class="hide-sm">المدة</th></tr></thead><tbody>
      ${l.map((a) => `<tr><td class="num start">${esc(a.no)}</td><td><div class="cell-main">${esc(a.name)}</div><div class="cell-sub">من ${esc(fmtMonth(a.startMonth))}</div></td>
        <td class="money">${M(a.costH)}</td><td class="money hide-sm">${M(a.salvageH)}</td><td class="money">${M(Math.floor((a.costH - a.salvageH) / a.lifeMonths))}</td>
        <td class="money">${M(a.accumulatedH)}</td><td class="money"><b>${M(a.bookH)}</b></td><td class="hide-sm"><span class="num">${a.lifeMonths}</span> شهر</td></tr>`).join('')}
      <tr class="total-row"><td colspan="2">الإجمالي</td><td class="money">${M(H.sumInts(l.map((a) => a.costH)))}</td><td class="hide-sm"></td><td></td><td class="money">${M(H.sumInts(l.map((a) => a.accumulatedH)))}</td><td class="money">${M(H.sumInts(l.map((a) => a.bookH)))}</td><td class="hide-sm"></td></tr>
      </tbody></table></div>` : empty('building', 'لا توجد أصول ثابتة', 'سجّل المعدات والسيارات لاحتساب إهلاكها شهرياً.')}</div>`;
}

/* =====================================================================
   القيود
   ===================================================================== */
function renderJournal() {
  const f = S.tabs.journal;
  const all = S.data.journals;
  const list = all.filter((j) => (f === 'all' || j.status === f) && matches('jr', j.no, j.memo));
  const cnt = (k) => (k === 'all' ? all.length : all.filter((j) => j.status === k).length);
  const chips = [['all', 'الكل'], ['draft', 'بانتظار الاعتماد'], ['posted', 'مرحّلة'], ['reversed', 'معكوسة'], ['cancelled', 'ملغاة']]
    .map(([k, l]) => `<button type="button" class="chip ${f === k ? 'active' : ''}" data-action="tab" data-key="journal" data-tab="${k}">${l}<span class="n num">${cnt(k)}</span></button>`).join('');
  return `<div class="toolbar">${btn('new-journal', 'قيد يدوي', { perm: 'journal.create' })}<div class="chips">${chips}</div>${search('jr', 'رقم القيد أو البيان')}
      ${btn('export', 'CSV', { cls: 'btn-ghost btn-sm', ic: 'download', data: { what: 'journal' }, perm: 'reports.export' })}</div>
    <div class="card">${list.length ? `<div class="table-wrap"><table><thead><tr><th>القيد</th><th>التاريخ</th><th>البيان</th><th class="hide-sm">المصدر</th><th class="money">المبلغ</th><th>الحالة</th><th class="hide-sm">أنشأه</th></tr></thead><tbody>
      ${list.slice(0, 400).map((j) => `<tr><td class="num start"><button type="button" class="link" data-action="view-journal" data-id="${esc(j.id)}">${esc(j.no)}</button></td><td class="nowrap">${fmtDate(j.date)}</td>
        <td><div class="cell-main clamp">${esc(j.memo || '—')}</div></td><td class="hide-sm">${esc(SOURCE_LABEL[j.source] || j.source)}</td><td class="money">${M(j.totalDebitH)}</td><td>${pill(J_STATUS, j.status)}</td><td class="hide-sm cell-sub">${esc(userName(j.createdBy))}</td></tr>`).join('')}
      </tbody></table></div>` : empty('book', 'لا توجد قيود', 'القيود تُنشأ آلياً من الفواتير والسندات والمشتريات، أو يدوياً.')}</div>`;
}

/* =====================================================================
   دليل الحسابات
   ===================================================================== */
function renderAccounts() {
  const groups = Object.keys(ACC_TYPES).map((type) => {
    const list = S.data.accounts.filter((a) => a.type === type);
    if (!list.length) return '';
    const sum = H.sumInts(list.map((a) => S.data.accBal.get(a.id) || 0));
    return `<tr class="acc-group"><td colspan="2">${ACC_TYPES[type]}</td><td class="money">${M(sum)}</td></tr>` +
      list.map((a) => { const b = S.data.accBal.get(a.id) || 0; return `<tr><td><button type="button" class="link acc-code num" data-action="ledger" data-id="${esc(a.id)}">${esc(a.number)}</button></td>
        <td><button type="button" class="link plain" data-action="ledger" data-id="${esc(a.id)}">${esc(a.name)}</button>${a.contra ? ' <span class="pill neutral">مقابل</span>' : ''}${a.cash && b < 0 ? ' <span class="pill bad">عجز</span>' : ''}</td><td class="money ${b < 0 && !a.contra ? 'bad-text' : ''}">${M(b)}</td></tr>`; }).join('');
  }).join('');
  return `<div class="toolbar">${btn('new-account', 'حساب جديد', { perm: 'accounts.write' })}<span class="cell-sub">اضغط على أي حساب لعرض كشف الحساب</span></div>
    <div class="card">${S.data.accounts.length ? `<div class="table-wrap"><table><thead><tr><th style="width:110px">الرقم</th><th>الحساب</th><th class="money">الرصيد</th></tr></thead><tbody>${groups}</tbody></table></div>`
      : empty('layers', 'دليل الحسابات غير مهيأ', 'يُهيأ تلقائياً عند أول دخول لمالك النظام (المستخدم 1).')}</div>`;
}

/* =====================================================================
   التقارير
   ===================================================================== */
const REPORTS = [['income', 'قائمة الدخل'], ['balance', 'الميزانية العمومية'], ['trial', 'ميزان المراجعة'], ['vat', 'تقرير الضريبة'], ['aging', 'أعمار الديون'], ['recon', 'المطابقات']];
function reportData(key) {
  const d = S.data, { from, to } = S.period;
  const title = (REPORTS.find((r) => r[0] === key) || REPORTS[0])[1];
  const stRows = (list) => list.map((x) => `<div class="st-row sub"><span>${esc(x.account.name)}</span><span>${M(x.amountH)}</span></div>`).join('');
  if (key === 'income') {
    const r = H.incomeStatement(d.accounts, d.journals, from, to);
    const html = `<div class="statement">
      <div class="st-row total"><span>الإيرادات</span><span>${M(r.totalRevenueH)}</span></div>${stRows(r.revenue)}
      <div class="st-row total"><span>المصروفات</span><span>${M(r.totalExpensesH)}</span></div>${stRows(r.expenses)}
      <div class="st-row grand ${r.netH < 0 ? 'neg' : ''}"><span>${r.netH < 0 ? 'صافي الخسارة' : 'صافي الربح'}</span><span>${M(Math.abs(r.netH))}</span></div></div>`;
    const rows = [['البند', 'المبلغ'], ['الإيرادات', ''], ...r.revenue.map((x) => ['  ' + x.account.name, H.csvMoney(x.amountH)]), ['إجمالي الإيرادات', H.csvMoney(r.totalRevenueH)],
      ['المصروفات', ''], ...r.expenses.map((x) => ['  ' + x.account.name, H.csvMoney(x.amountH)]), ['إجمالي المصروفات', H.csvMoney(r.totalExpensesH)], [r.netH < 0 ? 'صافي الخسارة' : 'صافي الربح', H.csvMoney(r.netH)]];
    return { title, period: `من ${fmtDate(from)} إلى ${fmtDate(to)}`, html, rows, badge: r.netH < 0 ? ['bad', 'خسارة'] : null };
  }
  if (key === 'balance') {
    const r = H.balanceSheet(d.accounts, d.journals, to);
    const sec = (label, list, total) => `<div class="st-row total"><span>${label}</span><span>${M(total)}</span></div>${stRows(list)}`;
    const html = `<div class="statement">${sec('الأصول', r.assets, r.totalAssetsH)}${sec('الخصوم', r.liabilities, r.totalLiabilitiesH)}
      ${sec('حقوق الملكية', r.equity, r.totalEquityH)}<div class="st-row sub"><span>أرباح (خسائر) متراكمة</span><span>${M(r.retainedH)}</span></div>
      <div class="st-row grand"><span>الخصوم + حقوق الملكية</span><span>${M(r.totalLiabilitiesH + r.totalEquityH)}</span></div></div>`;
    const rows = [['البند', 'المبلغ'], ['الأصول', ''], ...r.assets.map((x) => ['  ' + x.account.name, H.csvMoney(x.amountH)]), ['إجمالي الأصول', H.csvMoney(r.totalAssetsH)],
      ['الخصوم', ''], ...r.liabilities.map((x) => ['  ' + x.account.name, H.csvMoney(x.amountH)]), ['إجمالي الخصوم', H.csvMoney(r.totalLiabilitiesH)],
      ['حقوق الملكية', ''], ...r.equity.map((x) => ['  ' + x.account.name, H.csvMoney(x.amountH)]), ['  أرباح متراكمة', H.csvMoney(r.retainedH)], ['إجمالي حقوق الملكية', H.csvMoney(r.totalEquityH)]];
    return { title, period: `كما في ${fmtDate(to)}`, html, rows, badge: r.balanced ? ['ok', 'متوازنة'] : ['bad', 'غير متوازنة'] };
  }
  if (key === 'trial') {
    const r = H.trialBalance(d.accounts, d.journals, to);
    const html = `<div class="table-wrap"><table><thead><tr><th>الحساب</th><th class="money">مجموع المدين</th><th class="money">مجموع الدائن</th><th class="money">رصيد مدين</th><th class="money">رصيد دائن</th></tr></thead><tbody>
      ${r.rows.map((x) => `<tr><td><span class="num">${esc(x.account.number)}</span> ${esc(x.account.name)}</td><td class="money">${M(x.debitH)}</td><td class="money">${M(x.creditH)}</td><td class="money">${x.balDebitH ? M(x.balDebitH) : ''}</td><td class="money">${x.balCreditH ? M(x.balCreditH) : ''}</td></tr>`).join('')}
      <tr class="total-row"><td>الإجمالي</td><td></td><td></td><td class="money">${M(r.totalDebitH)}</td><td class="money">${M(r.totalCreditH)}</td></tr></tbody></table></div>`;
    const rows = [['رقم الحساب', 'الحساب', 'مجموع المدين', 'مجموع الدائن', 'رصيد مدين', 'رصيد دائن'], ...r.rows.map((x) => [x.account.number, x.account.name, H.csvMoney(x.debitH), H.csvMoney(x.creditH), H.csvMoney(x.balDebitH), H.csvMoney(x.balCreditH)]),
      ['', 'الإجمالي', '', '', H.csvMoney(r.totalDebitH), H.csvMoney(r.totalCreditH)]];
    return { title, period: `كما في ${fmtDate(to)}`, html, rows, badge: r.balanced ? ['ok', 'متزن'] : ['bad', 'غير متزن'] };
  }
  if (key === 'vat') {
    const r = H.vatReport(d.invoices, d.purchases, from, to);
    const html = `<div class="table-wrap"><table><thead><tr><th>البيان</th><th class="money">المبلغ الخاضع</th><th class="money">الضريبة</th></tr></thead><tbody>
      <tr><td>المبيعات الخاضعة للنسبة الأساسية 15% — ${r.salesCount} فاتورة${r.voidCount ? ` (مطروح منها ${r.voidCount} ملغاة)` : ''}</td><td class="money">${M(r.outputNetH)}</td><td class="money">${M(r.outputVatH)}</td></tr>
      <tr><td>المشتريات الخاضعة للنسبة الأساسية 15% — ${r.purchaseCount} فاتورة</td><td class="money">${M(r.inputNetH)}</td><td class="money">${M(r.inputVatH)}</td></tr>
      <tr class="total-row"><td>${r.netVatH >= 0 ? 'صافي الضريبة المستحقة للسداد' : 'صافي الضريبة القابلة للاسترداد'}</td><td></td><td class="money">${M(Math.abs(r.netVatH))}</td></tr></tbody></table></div>
      <p class="cell-sub pad">للمساعدة في إعداد الإقرار الضريبي. راجع الأرقام قبل تقديمها لهيئة الزكاة والضريبة والجمارك.</p>`;
    const rows = [['البيان', 'المبلغ الخاضع', 'الضريبة'], ['المبيعات 15%', H.csvMoney(r.outputNetH), H.csvMoney(r.outputVatH)], ['المشتريات 15%', H.csvMoney(r.inputNetH), H.csvMoney(r.inputVatH)], ['صافي الضريبة', '', H.csvMoney(r.netVatH)]];
    return { title, period: `من ${fmtDate(from)} إلى ${fmtDate(to)}`, html, rows };
  }
  if (key === 'aging') {
    const r = H.aging(d.invoices, todayISO());
    const open = d.invoices.filter((i) => i.state.remainingH > 0);
    const html = `<div class="aging">${r.buckets.map((b, k) => `<div><div class="cell-sub">${b.label}</div><div class="v ${k >= 3 ? 'bad-text' : k >= 1 ? 'warn-text' : ''}">${M(b.h)}</div></div>`).join('')}</div>
      ${open.length ? `<div class="table-wrap"><table><thead><tr><th>الفاتورة</th><th>العميل</th><th>الاستحقاق</th><th>أيام التأخير</th><th class="money">المتبقي</th></tr></thead><tbody>
      ${open.map((i) => `<tr><td class="num start">${esc(i.number)}</td><td>${esc(i.customerName)}</td><td class="nowrap">${fmtDate(i.dueDate)}</td><td>${i.state.daysLate > 0 ? `<b class="bad-text num">${i.state.daysLate}</b>` : '—'}</td><td class="money">${M(i.state.remainingH)}</td></tr>`).join('')}</tbody></table></div>` : ''}`;
    const rows = [['الفاتورة', 'العميل', 'الاستحقاق', 'أيام التأخير', 'المتبقي'], ...open.map((i) => [i.number, i.customerName, i.dueDate, Math.max(0, i.state.daysLate), H.csvMoney(i.state.remainingH)])];
    return { title, period: `كما في ${fmtDate(todayISO())}`, html, rows };
  }
  const rc = d.recon;
  const items = [['الفواتير المفتوحة مقابل حساب العملاء 1300', rc.arSubH, rc.arGlH], ['أرصدة الأصناف مقابل حساب المخزون 1400', rc.invSubH, rc.invGlH],
    ['سجل الأصول مقابل حساب الأصول الثابتة 1600', rc.faSubH, rc.faGlH], ['الإهلاك المحتسب مقابل مجمع الإهلاك 1690', rc.depSubH, rc.depGlH], ...(canHR() ? [['أرصدة سلف الموظفين مقابل حساب السلف 1350', rc.advSubH, rc.advGlH]] : [])];
  const tb = H.trialBalance(d.accounts, d.journals, todayISO());
  const seq = sequenceCheck(d.invoices.filter((i) => i.number).map((i) => i.number));
  const allOk = items.every(([, a, b]) => a === b) && tb.balanced && seq.ok;
  const html = `<div class="table-wrap"><table><thead><tr><th>المطابقة</th><th class="money">الدفتر المساعد</th><th class="money">الأستاذ العام</th><th class="money">الفرق</th><th>النتيجة</th></tr></thead><tbody>
    ${items.map(([l, a, b]) => `<tr><td>${esc(l)}</td><td class="money">${M(a)}</td><td class="money">${M(b)}</td><td class="money">${M(a - b)}</td><td>${a === b ? '<span class="pill ok">مطابق</span>' : '<span class="pill bad">غير مطابق</span>'}</td></tr>`).join('')}
    <tr><td>تسلسل أرقام الفواتير (بلا تكرار ولا فجوات)</td><td class="money num">${seq.count}</td><td class="money">${seq.dupes.length ? 'مكرر: ' + esc(seq.dupes.join('، ')) : ''}</td><td class="money">${seq.gaps.length ? 'مفقود: ' + esc(seq.gaps.slice(0, 5).join('، ')) : ''}</td><td>${seq.ok ? '<span class="pill ok">سليم</span>' : '<span class="pill bad">يحتاج مراجعة</span>'}</td></tr>
    <tr><td>ميزان المراجعة (مجموع المدين = مجموع الدائن)</td><td class="money">${M(tb.totalDebitH)}</td><td class="money">${M(tb.totalCreditH)}</td><td class="money">${M(tb.totalDebitH - tb.totalCreditH)}</td><td>${tb.balanced ? '<span class="pill ok">متزن</span>' : '<span class="pill bad">غير متزن</span>'}</td></tr>
    </tbody></table></div><p class="cell-sub pad">عدم المطابقة يعني غالباً قيداً يدوياً على حساب رقابي (1300 أو 1400 أو 1600 أو 1690) بدلاً من المستند الأصلي.</p>`;
  const rows = [['المطابقة', 'الدفتر المساعد', 'الأستاذ العام', 'الفرق'], ...items.map(([l, a, b]) => [l, H.csvMoney(a), H.csvMoney(b), H.csvMoney(a - b)])];
  return { title, period: `كما في ${fmtDate(todayISO())}`, html, rows, badge: allOk ? ['ok', 'كل المطابقات سليمة'] : ['bad', 'توجد فروقات'] };
}

/** يتحقق أن أرقام الفواتير المُصدرة متسلسلة بلا تكرار ولا فجوات */
function sequenceCheck(numbers) {
  const nums = numbers.map((n) => parseInt(String(n).replace(/\D/g, ''), 10)).filter(Number.isFinite).sort((a, b) => a - b);
  const seen = new Set(), dupes = [], gaps = [];
  nums.forEach((n, k) => { if (seen.has(n)) dupes.push('INV-' + pad(n, 5)); seen.add(n); if (k && n - nums[k - 1] > 1) for (let g = nums[k - 1] + 1; g < n && gaps.length < 20; g++) gaps.push('INV-' + pad(g, 5)); });
  if (nums.length && nums[0] > 1) for (let g = 1; g < nums[0] && gaps.length < 20; g++) gaps.unshift('INV-' + pad(g, 5));
  return { ok: !dupes.length && !gaps.length, dupes, gaps, count: nums.length };
}

function renderReports() {
  const key = S.tabs.reports;
  const r = reportData(key);
  const needsFrom = ['income', 'vat'].includes(key), needsTo = !['aging', 'recon'].includes(key);
  return `<div class="toolbar">${tabs('reports', REPORTS)}</div>
    <div class="card">
      <div class="card-head"><h3>${esc(r.title)}</h3><span class="hint">${esc(r.period)}</span>
        <div class="actions">${r.badge ? `<span class="pill ${r.badge[0]}">${esc(r.badge[1])}</span>` : ''}
          ${btn('export', 'Excel (CSV)', { cls: 'btn-ghost btn-sm', ic: 'download', data: { what: 'report', key }, perm: 'reports.export' })}${btn('print', 'PDF / طباعة', { cls: 'btn-ghost btn-sm', ic: 'print', data: { key }, perm: 'reports.export' })}</div></div>
      ${needsTo ? `<form class="period" data-keep id="periodForm" novalidate>
        ${needsFrom ? `<label>من <input class="input" type="date" id="pFrom" value="${esc(S.period.from)}"></label>` : ''}
        <label>${needsFrom ? 'إلى' : 'كما في'} <input class="input" type="date" id="pTo" value="${esc(S.period.to)}"></label>
        <button class="btn btn-ghost btn-sm" type="submit">تحديث</button>
        ${needsFrom ? '<button class="btn btn-quiet btn-sm" type="button" data-action="period" data-p="month">هذا الشهر</button><button class="btn btn-quiet btn-sm" type="button" data-action="period" data-p="year">هذه السنة</button>' : ''}
      </form>` : ''}
      <div>${r.html}</div>
    </div>`;
}

/* =====================================================================
   سجل المراجعة
   ===================================================================== */
const AUDIT_ACTIONS = { create: 'إنشاء', update: 'تعديل', issue: 'إصدار', void: 'إلغاء', cancel: 'إلغاء', post: 'اعتماد', reverse: 'عكس', archive: 'أرشفة', restore: 'استعادة', delete: 'حذف', activate: 'تفعيل', deactivate: 'إيقاف', import: 'استيراد', terminate: 'إنهاء خدمة', pay: 'صرف' };
const AUDIT_ENTITIES = { invoice: 'فاتورة', payment: 'سند قبض', journal: 'قيد', customer: 'عميل', item: 'صنف', purchase: 'مشتريات', asset: 'أصل', depreciation: 'إهلاك', account: 'حساب', user: 'مستخدم', settings: 'إعدادات', system: 'النظام', bank: 'كشف الحساب', employee: 'موظف', advance: 'سلفة', payroll: 'مسير رواتب' };
function filteredAudit() {
  const { user, entity } = S.auditFilter;
  return S.data.audit.filter((a) => (!user || a.actor === user) && (!entity || a.entity === entity) && matches('aud', a.summary));
}
function renderAudit() {
  const list = filteredAudit();
  const users = [...new Set(S.data.audit.map((a) => a.actor))];
  return `<div class="toolbar">
      <select class="select sm" id="audUser" aria-label="المستخدم"><option value="">كل المستخدمين</option>${users.map((u) => `<option value="${esc(u)}" ${S.auditFilter.user === u ? 'selected' : ''}>${esc(userName(u))}</option>`).join('')}</select>
      <select class="select sm" id="audEntity" aria-label="النوع"><option value="">كل الأنواع</option>${Object.entries(AUDIT_ENTITIES).map(([k, v]) => `<option value="${k}" ${S.auditFilter.entity === k ? 'selected' : ''}>${v}</option>`).join('')}</select>
      ${search('aud', 'بحث في التفاصيل')}${btn('export', 'CSV', { cls: 'btn-ghost btn-sm', ic: 'download', data: { what: 'audit' }, perm: 'reports.export' })}</div>
    <div class="card">${list.length ? `<div class="table-wrap"><table><thead><tr><th>الوقت</th><th>المستخدم</th><th>العملية</th><th>النوع</th><th>التفاصيل</th></tr></thead><tbody>
      ${list.slice(0, 500).map((a) => `<tr><td class="nowrap">${fmtDateTime(a.at)}</td><td class="cell-main nowrap">${esc(a.actorName || a.actor)}</td><td><span class="pill ${['void', 'reverse', 'delete', 'deactivate', 'cancel'].includes(a.action) ? 'bad' : ['post', 'issue'].includes(a.action) ? 'ok' : 'info'}">${esc(AUDIT_ACTIONS[a.action] || a.action)}</span></td>
        <td class="nowrap">${esc(AUDIT_ENTITIES[a.entity] || a.entity)}</td><td class="audit-sum">${esc(a.summary)}</td></tr>`).join('')}
      </tbody></table></div>` : empty('shield', 'لا توجد سجلات')}</div>
    <p class="cell-sub pad">السجل للإضافة فقط: لا يمكن تعديل أي سطر أو حذفه، ويُكتب مع العملية نفسها وبوقت الخادم.</p>`;
}

/* =====================================================================
   المستخدمون والصلاحيات
   ===================================================================== */
function renderUsers() {
  const l = S.data.users;
  const roleCols = Object.entries(ROLES).filter(([k]) => k !== 'custom');
  return `<div class="toolbar">${btn('new-user', 'مستخدم جديد', { perm: 'users.manage' })}</div>
    <div class="card"><div class="table-wrap"><table><thead><tr><th>المستخدم</th><th>اسم الدخول</th><th>الدور</th><th class="hide-sm">الصلاحيات</th><th>الحالة</th><th><span class="sr">إجراءات</span></th></tr></thead><tbody>
      ${l.map((u) => `<tr>
        <td><div class="user-cell"><span class="avatar sm">${esc(u.id.slice(0, 2).toUpperCase())}</span><span class="cell-main">${esc(u.name)}</span>${u.id === OWNER ? '<span class="pill info">المالك</span>' : ''}${u.id === S.user.username ? '<span class="pill ok">أنت</span>' : ''}</div></td>
        <td class="num start">${esc(u.id)}</td><td>${esc(roleLabel(u.role))}</td>
        <td class="hide-sm cell-sub">${u.id === OWNER ? 'كل الصلاحيات' : `${(u.perms || []).length} من ${ALL_PERMS.length}`}</td>
        <td>${u.active ? '<span class="pill ok">نشط</span>' : '<span class="pill neutral">موقوف</span>'}</td>
        <td><div class="row-actions">
          ${btn('edit-user', u.id === OWNER ? 'الاسم' : 'الصلاحيات', { cls: 'btn-quiet btn-sm', ic: u.id === OWNER ? 'edit' : 'key', data: { id: u.id } })}
          ${u.id !== OWNER && u.id !== S.user.username ? btn('toggle-user', u.active ? 'إيقاف' : 'تفعيل', { cls: 'btn-quiet btn-sm', ic: u.active ? 'pause' : 'play', data: { id: u.id, active: u.active ? '0' : '1' } }) : ''}
          ${u.id !== OWNER && u.id !== S.user.username ? btn('delete-user', '', { cls: 'btn-quiet btn-sm icon-btn', ic: 'trash', data: { id: u.id }, title: 'حذف المستخدم' }) : ''}
        </div></td></tr>`).join('')}
    </tbody></table></div></div>
    <div class="card"><div class="card-head"><h3>مصفوفة الأدوار الجاهزة</h3><span class="hint">تُطبَّق عند اختيار الدور، ويمكن بعدها تعديل كل صلاحية</span></div>
      <div class="table-wrap"><table class="matrix"><thead><tr><th>الصلاحية</th>${roleCols.map(([, r]) => `<th class="c">${esc(r.label)}</th>`).join('')}</tr></thead><tbody>
      ${ALL_PERMS.map((p) => `<tr><td>${esc(PERM_LABEL[p])}</td>${roleCols.map(([, r]) => `<td class="c">${r.perms.includes(p) ? icon('check', 'i ok-text') : '<span class="faint">—</span>'}</td>`).join('')}</tr>`).join('')}
      </tbody></table></div></div>
    <p class="cell-sub pad">فصل المهام مطبّق دائماً مهما كانت الصلاحيات: لا يعتمد أحد قيداً أنشأه بنفسه. الحذف يوقف الحساب نهائياً ويُبقي تاريخه في سجل المراجعة.</p>`;
}

/* =====================================================================
   الإعدادات
   ===================================================================== */
function renderSettings() {
  const c = S.data.company, ro = !can('settings.write');
  const f = (id, label, val, attrs = '') => `<div class="field"><label for="${id}">${label}</label><input class="input" id="${id}" value="${esc(val || '')}" ${ro ? 'readonly' : ''} ${attrs}></div>`;
  return `<div class="grid-even">
    <div class="card"><div class="card-head"><h3>بيانات المنشأة</h3><span class="hint">تظهر في الفواتير والتقارير</span></div>
      <form class="card-body" id="companyForm" data-keep novalidate><div class="form-grid">
        <div class="span-2">${f('coName', 'اسم المنشأة', c.name, 'maxlength="120" placeholder="الحرف المتكاملة للمقاولات"')}</div>
        ${f('coVat', 'الرقم الضريبي', c.vat, 'inputmode="numeric" maxlength="15" dir="ltr" placeholder="3XXXXXXXXXXXXX3"')}
        ${f('coCr', 'السجل التجاري', c.cr, 'inputmode="numeric" maxlength="20" dir="ltr"')}
        ${f('coPhone', 'الجوال', c.phone, 'inputmode="tel" maxlength="20" dir="ltr"')}
        ${f('coEmail', 'البريد الإلكتروني', c.email, 'type="email" maxlength="80" dir="ltr"')}
        <div class="span-2">${f('coAddress', 'العنوان', c.address, 'maxlength="200"')}</div>
      </div>${ro ? '<p class="cell-sub">للعرض فقط — التعديل يحتاج صلاحية "تعديل بيانات المنشأة".</p>' : `<button class="btn btn-primary" type="submit">${icon('check')}حفظ البيانات</button>`}</form></div>
    <div class="stack">
      <div class="card"><div class="card-head"><h3>حسابي</h3></div><div class="card-body">
        <div class="kv"><span>الاسم</span><b>${esc(S.user.name)}</b><span>اسم الدخول</span><b class="num start">${esc(S.user.username)}</b><span>الدور</span><b>${esc(roleLabel(S.user.role))}</b></div>
        <div class="perm-chips">${(S.user.username === OWNER ? ALL_PERMS : S.user.perms).map((p) => `<span class="pill info">${esc(PERM_LABEL[p] || p)}</span>`).join('') || '<span class="cell-sub">مشاهدة فقط</span>'}</div></div></div>
      <div class="card"><div class="card-head"><h3>تغيير كلمة المرور</h3></div>
        <form class="card-body" id="passForm" data-keep novalidate>
          <div class="field"><label for="pwCur">كلمة المرور الحالية</label><input class="input" id="pwCur" type="password" autocomplete="current-password"></div>
          <div class="field"><label for="pwNew">كلمة المرور الجديدة</label><input class="input" id="pwNew" type="password" autocomplete="new-password" placeholder="8 أحرف على الأقل"></div>
          <div class="field"><label for="pwNew2">تأكيد كلمة المرور</label><input class="input" id="pwNew2" type="password" autocomplete="new-password"></div>
          <button class="btn btn-ghost" type="submit">${icon('lock')}تغيير كلمة المرور</button></form></div>
      <div class="card"><div class="card-head"><h3>قاعدة البيانات</h3></div><div class="card-body">
        ${S.db.mode === 'cloud' ? '<span class="pill ok">أونلاين — مباشر</span><p class="cell-sub mt">البيانات في Firebase، وكل عملية تظهر فوراً عند جميع المستخدمين.</p>'
          : `<span class="pill warn">حفظ محلي</span><p class="cell-sub mt">لم يُربط Firebase بعد؛ البيانات في هذا المتصفح فقط.</p>
             ${S.user.username === OWNER ? btn('wipe-local', 'مسح كل البيانات المحلية', { cls: 'btn-danger btn-sm', ic: 'trash' }) : ''}`}</div></div>
    </div></div>`;
}

/* =====================================================================
   النوافذ المنبثقة
   ===================================================================== */
function openModal(title, body, foot, { wide = false, xwide = false } = {}) {
  $('#modalRoot').innerHTML = `<div class="modal" data-action="modal-bg"><div class="dialog ${wide ? 'wide' : ''} ${xwide ? 'xwide' : ''}" role="dialog" aria-modal="true" aria-label="${esc(title)}">
    <div class="dialog-head"><h3>${esc(title)}</h3><button type="button" class="btn btn-quiet icon-btn" data-action="close-modal" aria-label="إغلاق">${icon('x')}</button></div>
    <div class="dialog-body">${body}</div>${foot ? `<div class="dialog-foot">${foot}</div>` : ''}</div></div>`;
  const first = $('#modalRoot').querySelector('input:not([type=hidden]):not([readonly]):not([type=checkbox]),select,textarea');
  if (first) setTimeout(() => first.focus(), 30);
}
function closeModal() { $('#modalRoot').innerHTML = ''; }
const cancelBtn = '<button class="btn btn-ghost" type="button" data-action="close-modal">إلغاء</button>';
const submitBtn = (form, label, ic = 'check') => `<button class="btn btn-primary" type="submit" form="${form}">${icon(ic)}${esc(label)}</button>`;

function busy(el, on) {
  if (!el) return;
  el.disabled = on;
  if (on) { el.dataset.label = el.innerHTML; el.innerHTML = '<span class="spinner"></span>جارٍ الحفظ…'; }
  else if (el.dataset.label) el.innerHTML = el.dataset.label;
}
/** يشغّل عملية مع مؤشر انتظار ورسالة نجاح أو خطأ واضحة */
async function run(el, fn, ok, { close = true } = {}) {
  busy(el, true);
  try {
    const r = await fn();
    if (close) closeModal(); else busy(el, false);
    if (ok) toast(ok[0], typeof ok[1] === 'function' ? ok[1](r) : ok[1] || '');
    return r;
  } catch (err) {
    if (!(err instanceof H.InputError)) console.error(err);
    toast('تعذّر تنفيذ العملية', err instanceof H.InputError ? err.message : fbError(err), 'error');
    busy(el, false);
    return undefined;
  }
}
/** يقرأ قيمة حقل ويعلّم الحقل عند الخطأ */
function field(id, parse) {
  const el = document.getElementById(id);
  try { return parse(el.value); }
  catch (e) { el.closest('.field')?.classList.add('invalid'); el.focus(); throw e; }
}
function formGuard(fn) {
  return (e) => { e.preventDefault(); try { fn(e); } catch (err) { toast('تحقق من البيانات', err.message, 'error'); } };
}
const optionList = (list, sel, label = (x) => x.name) => list.map((x) => `<option value="${esc(x.id)}" ${x.id === sel ? 'selected' : ''}>${esc(label(x))}</option>`).join('');
const cashOptions = (withAp = false) => `<option value="${ACC.bank}">البنك</option><option value="${ACC.cash}">الصندوق</option>${withAp ? `<option value="${ACC.ap}">آجل (على المورد)</option>` : ''}`;

/* ---------- العميل ---------- */
function customerModal(id = '') {
  const c = (id && S.data.customers.find((x) => x.id === id)) || {};
  openModal(id ? 'تعديل عميل' : 'عميل جديد', `<form id="customerForm" class="form-grid" novalidate>
    <div class="field span-2"><label for="cName">اسم العميل *</label><input class="input" id="cName" maxlength="120" value="${esc(c.name)}"></div>
    <div class="field"><label for="cCompany">المنشأة</label><input class="input" id="cCompany" maxlength="120" value="${esc(c.company)}"></div>
    <div class="field"><label for="cVat">الرقم الضريبي</label><input class="input" id="cVat" inputmode="numeric" maxlength="15" dir="ltr" value="${esc(c.vatNo)}" placeholder="اختياري"></div>
    <div class="field"><label for="cPhone">الجوال</label><input class="input" id="cPhone" inputmode="tel" maxlength="16" dir="ltr" value="${esc(c.phone)}" placeholder="05XXXXXXXX"></div>
    <div class="field"><label for="cEmail">البريد الإلكتروني</label><input class="input" id="cEmail" type="email" maxlength="80" dir="ltr" value="${esc(c.email)}"></div>
    <div class="field"><label for="cCity">المدينة</label><input class="input" id="cCity" maxlength="60" value="${esc(c.city)}"></div>
    <div class="field span-2"><label for="cNotes">ملاحظات</label><textarea class="textarea" id="cNotes" maxlength="500">${esc(c.notes)}</textarea></div>
  </form>`, cancelBtn + submitBtn('customerForm', 'حفظ العميل'));
  $('#customerForm').addEventListener('submit', formGuard(() => {
    const data = { name: $('#cName').value, company: $('#cCompany').value, vatNo: $('#cVat').value, phone: $('#cPhone').value, email: $('#cEmail').value, city: $('#cCity').value, notes: $('#cNotes').value };
    run(document.querySelector('[form=customerForm]'), () => Services.saveCustomer(id, data), ['تم حفظ العميل', (n) => n]);
  }));
}

/* ---------- الفاتورة ---------- */
let draft = null; // { id, lines: [{kind, itemId, description, qty, price}] }
function invoiceModal(customerId = '', invoiceId = '') {
  const customers = S.data.customers.filter((c) => !c.archived);
  if (!customers.length) {
    openModal('فاتورة جديدة', empty('users', 'أضف عميلاً أولاً', 'تحتاج عميلاً واحداً على الأقل.'), cancelBtn + btn('new-customer', 'عميل جديد', { perm: 'customer.write' }));
    return;
  }
  const inv = invoiceId ? S.data.invoices.find((i) => i.id === invoiceId) : null;
  draft = {
    id: invoiceId,
    lines: inv ? inv.lines.map((l) => ({ kind: l.kind, itemId: l.itemId || '', description: l.description, qty: H.qtyInput(l.qtyM), price: H.moneyInput(l.priceH) }))
      : [{ kind: 'service', itemId: '', description: '', qty: '1', price: '' }],
  };
  const issue = inv?.issueDate || todayISO();
  openModal(inv ? 'تعديل مسودة الفاتورة' : 'فاتورة ضريبية جديدة', `<form id="invoiceForm" novalidate>
    <div class="form-grid three">
      <div class="field"><label for="iCustomer">العميل *</label><select class="select" id="iCustomer"><option value="">اختر العميل</option>${optionList(customers, inv?.customerId || customerId)}</select></div>
      <div class="field"><label for="iIssue">تاريخ الفاتورة</label><input class="input" id="iIssue" type="date" value="${esc(issue)}"></div>
      <div class="field"><label for="iDue">تاريخ الاستحقاق</label><input class="input" id="iDue" type="date" value="${esc(inv?.dueDate || addDaysISO(issue, 30))}"></div>
      <div class="field span-3"><label for="iDesc">البيان</label><input class="input" id="iDesc" maxlength="200" value="${esc(inv?.description)}" placeholder="مثال: أعمال خرسانة — المرحلة الأولى"></div>
    </div>
    <div class="lines" id="linesBox"></div>
    <div class="lines-foot"><button type="button" class="btn btn-ghost btn-sm" data-action="add-line">${icon('plus')}إضافة بند</button><div class="totals" id="totalsBox"></div></div>
  </form>`, `${cancelBtn}${btn('save-invoice', 'حفظ كمسودة', { cls: 'btn-ghost', ic: 'save', data: { issue: '0' } })}${btn('save-invoice', 'حفظ وإصدار', { ic: 'send', data: { issue: '1' }, perm: 'invoice.issue' })}`, { xwide: true });
  drawLines();
}
function drawLines() {
  const box = $('#linesBox'); if (!box) return;
  const items = S.data.items.filter((i) => !i.archived);
  box.innerHTML = '<div class="line head"><span>النوع</span><span>البند</span><span>الكمية</span><span>سعر الوحدة</span><span class="lt">الصافي</span><span></span></div>' +
    draft.lines.map((l, k) => `<div class="line">
      <select class="select" data-line="${k}" data-key="kind" aria-label="النوع"><option value="service" ${l.kind !== 'goods' ? 'selected' : ''}>خدمة / أعمال</option><option value="goods" ${l.kind === 'goods' ? 'selected' : ''} ${items.length ? '' : 'disabled'}>صنف مخزون</option></select>
      ${l.kind === 'goods'
        ? `<select class="select" data-line="${k}" data-key="itemId" aria-label="الصنف"><option value="">اختر الصنف</option>${items.map((i) => `<option value="${esc(i.id)}" ${i.id === l.itemId ? 'selected' : ''}>${esc(i.sku)} — ${esc(i.name)} (متوفر ${H.fmtQty(i.qtyM || 0)})</option>`).join('')}</select>`
        : `<input class="input" data-line="${k}" data-key="description" value="${esc(l.description)}" maxlength="150" placeholder="وصف البند" aria-label="وصف البند">`}
      <input class="input num" data-line="${k}" data-key="qty" value="${esc(l.qty)}" inputmode="decimal" aria-label="الكمية">
      <input class="input num" data-line="${k}" data-key="price" value="${esc(l.price)}" inputmode="decimal" placeholder="0.00" aria-label="سعر الوحدة">
      <span class="lt num" data-lt="${k}"></span>
      <button type="button" class="btn btn-quiet icon-btn btn-sm" data-action="remove-line" data-k="${k}" aria-label="حذف البند" ${draft.lines.length === 1 ? 'disabled' : ''}>${icon('trash')}</button>
    </div>`).join('');
  drawTotals();
}
/** يحوّل بنود النموذج إلى أرقام صحيحة؛ strict=true يرمي الخطأ عند الحفظ */
function parseDraftLines(strict) {
  return draft.lines.map((l, k) => {
    const n = k + 1;
    try {
      const qtyM = H.parseQty(l.qty, { label: `كمية البند ${n}` });
      const priceH = H.parseMoney(l.price, { label: `سعر البند ${n}` });
      if (l.kind === 'goods') {
        const it = S.data.items.find((i) => i.id === l.itemId);
        if (!it) throw new H.InputError(`اختر الصنف في البند ${n}`);
        if (strict && qtyM > (it.qtyM || 0)) throw new H.InputError(`البند ${n}: الكمية أكبر من المتوفر (${H.fmtQty(it.qtyM || 0)})`);
        return { kind: 'goods', itemId: it.id, description: `${it.sku} — ${it.name}`, unit: it.unit, qtyM, priceH };
      }
      const description = H.cleanText(l.description, 150);
      if (!description) throw new H.InputError(`اكتب وصف البند ${n}`);
      return { kind: 'service', itemId: '', description, qtyM, priceH };
    } catch (e) { if (strict) throw e; return null; }
  });
}
function drawTotals() {
  const parsed = parseDraftLines(false);
  parsed.forEach((l, k) => { const el = document.querySelector(`[data-lt="${k}"]`); if (el) el.textContent = l ? H.fmtMoney(H.lineNet(l.qtyM, l.priceH)) : '—'; });
  const t = H.invoiceTotals(parsed.filter(Boolean));
  $('#totalsBox').innerHTML = `<div><span class="cell-sub">المجموع قبل الضريبة</span>${M(t.netH)}</div><div><span class="cell-sub">ضريبة القيمة المضافة 15%</span>${M(t.vatH)}</div>
    <div class="grand"><span>الإجمالي</span><span>${M(t.totalH)} ر.س</span></div>${parsed.some((l) => !l) ? '<div class="cell-sub warn-text">أكمل البنود الناقصة</div>' : ''}`;
}
async function saveInvoice(el) {
  try {
    const customerId = field('iCustomer', (v) => { if (!v) throw new H.InputError('اختر العميل'); return v; });
    const issueDate = field('iIssue', (v) => H.parseDate(v, 'تاريخ الفاتورة'));
    const dueDate = field('iDue', (v) => { H.parseDate(v, 'تاريخ الاستحقاق'); if (v < issueDate) throw new H.InputError('الاستحقاق قبل تاريخ الفاتورة'); return v; });
    const issue = el.dataset.issue === '1';
    const lines = parseDraftLines(true);
    if (!lines.length) throw new H.InputError('أضف بنداً واحداً على الأقل');
    if (lines.length > 30) throw new H.InputError('الحد الأقصى 30 بنداً');
    if (new Set(lines.filter((l) => l.kind === 'goods').map((l) => l.itemId)).size > MAX_GOODS_LINES) throw new H.InputError(`الحد الأقصى ${MAX_GOODS_LINES} أصناف مخزون مختلفة في الفاتورة`);
    const f = { customerId, issueDate, dueDate, description: H.cleanText($('#iDesc').value, 200), lines };
    await run(el, async () => {
      const id = await Services.saveInvoiceDraft(draft.id, f);
      if (!issue) return 'مسودة';
      draft.id = id; // لو فشل الإصدار تبقى المسودة ولا تُكرر
      try { return await Services.issueInvoice(id); }
      catch (e) { throw new H.InputError('حُفظت المسودة لكن تعذّر الإصدار: ' + (e instanceof H.InputError ? e.message : fbError(e))); }
    }, [issue ? 'صدرت الفاتورة' : 'حُفظت المسودة', (r) => r]);
  } catch (err) { toast('تحقق من البيانات', err.message, 'error'); }
}

function viewInvoice(id) {
  const inv = S.data.invoices.find((i) => i.id === id); if (!inv) return;
  const cust = S.data.customers.find((c) => c.id === inv.customerId) || {};
  const co = S.data.company;
  const pays = S.data.payments.filter((p) => p.invoiceId === id);
  const st = inv.state;
  const doc = `<div class="doc" id="invoiceDoc">
    <div class="doc-top"><div><div class="doc-title">فاتورة ضريبية</div><div class="cell-main">${esc(co.name || 'الحرف المتكاملة للمقاولات')}</div>
      <div class="cell-sub">${co.vat ? `الرقم الضريبي: <span class="num">${esc(co.vat)}</span>` : 'أضف الرقم الضريبي من الإعدادات'}${co.cr ? ` · س.ت: <span class="num">${esc(co.cr)}</span>` : ''}</div>${co.address ? `<div class="cell-sub">${esc(co.address)}</div>` : ''}</div>
      <dl class="doc-meta"><dt>رقم الفاتورة</dt><dd class="num start">${esc(inv.number || 'مسودة')}</dd><dt>التاريخ</dt><dd>${fmtDate(inv.issueDate)}</dd><dt>الاستحقاق</dt><dd>${fmtDate(inv.dueDate)}</dd><dt>الحالة</dt><dd>${pill(INV_STATUS, st.key)}</dd></dl></div>
    <div class="doc-parties"><div><h4>العميل</h4><div class="cell-main">${esc(cust.name || inv.customerName)}</div><div class="cell-sub">${esc([cust.company, cust.city, cust.phone].filter(Boolean).join(' · '))}</div>${cust.vatNo ? `<div class="cell-sub">الرقم الضريبي: <span class="num">${esc(cust.vatNo)}</span></div>` : ''}</div>
      ${inv.description ? `<div><h4>البيان</h4><div>${esc(inv.description)}</div></div>` : ''}</div>
    <div class="table-wrap bordered"><table><thead><tr><th>البند</th><th class="money">الكمية</th><th class="money">سعر الوحدة</th><th class="money">الصافي</th><th class="money">الضريبة 15%</th><th class="money">الإجمالي</th></tr></thead><tbody>
      ${inv.lines.map((l) => `<tr><td>${esc(l.description)}</td><td class="money">${Q(l.qtyM)}</td><td class="money">${M(l.priceH)}</td><td class="money">${M(l.netH)}</td><td class="money">${M(l.vatH)}</td><td class="money">${M(l.totalH)}</td></tr>`).join('')}
    </tbody></table></div>
    <div class="totals doc-totals"><div><span class="cell-sub">الإجمالي قبل الضريبة</span>${M(inv.netH)}</div><div><span class="cell-sub">ضريبة القيمة المضافة</span>${M(inv.vatH)}</div>
      <div class="grand"><span>الإجمالي شامل الضريبة</span><span>${M(inv.totalH)} ر.س</span></div>
      ${inv.status === 'issued' ? `<div><span class="cell-sub">المدفوع</span><span class="ok-text">${M(inv.paidH || 0)}</span></div><div><b>المتبقي</b><b class="${st.remainingH ? 'warn-text' : 'ok-text'}">${M(st.remainingH)}</b></div>` : ''}
      ${inv.status === 'void' ? `<div class="bad-text"><b>ملغاة: ${esc(inv.voidReason || '')}</b></div>` : ''}</div>
    ${pays.length ? `<h4 class="mt">سندات القبض</h4><div class="table-wrap bordered"><table><tbody>${pays.map((p) => `<tr><td class="num start">${esc(p.no)}</td><td>${fmtDate(p.date)}</td><td>${esc(PAY_METHODS[p.method] || '')}</td><td class="money">${M(p.amountH)}</td><td>${p.status === 'active' ? '' : '<span class="pill neutral">معكوس</span>'}</td></tr>`).join('')}</tbody></table></div>` : ''}
    <p class="cell-sub mt">${esc([inv.createdBy && `أنشأها ${userName(inv.createdBy)}`, inv.issuedBy && `أصدرها ${userName(inv.issuedBy)}`, inv.voidedBy && `ألغاها ${userName(inv.voidedBy)}`].filter(Boolean).join(' · '))}</p>
  </div>`;
  const acts = [
    inv.status === 'draft' ? btn('edit-invoice', 'تعديل', { cls: 'btn-ghost', ic: 'edit', data: { id }, perm: 'invoice.write' }) : '',
    inv.status === 'draft' ? btn('cancel-invoice', 'إلغاء المسودة', { cls: 'btn-ghost', ic: 'x', data: { id }, perm: 'invoice.write' }) : '',
    inv.status === 'draft' ? btn('issue-invoice', 'إصدار', { ic: 'send', data: { id }, perm: 'invoice.issue' }) : '',
    inv.status === 'issued' && !inv.paidH ? btn('void-invoice', 'إلغاء الفاتورة', { cls: 'btn-danger', ic: 'x', data: { id }, perm: 'invoice.void' }) : '',
    st.remainingH > 0 ? btn('new-payment', 'سند قبض', { ic: 'wallet', data: { invoice: id }, perm: 'payment.create' }) : '',
    inv.status !== 'draft' ? btn('print-invoice', 'PDF / طباعة', { cls: 'btn-ghost', ic: 'print', data: { id } }) : '',
  ].join('');
  openModal(`الفاتورة ${inv.number || '(مسودة)'}`, doc, `<button type="button" class="btn btn-ghost" data-action="close-modal">إغلاق</button>${acts}`, { wide: true });
}

/* ---------- سند القبض ---------- */
function paymentModal(invoiceId = '') {
  const open = S.data.invoices.filter((i) => i.status === 'issued' && i.state.remainingH > 0);
  if (!open.length) { openModal('سند قبض', empty('check', 'لا توجد فواتير مستحقة'), '<button type="button" class="btn btn-ghost" data-action="close-modal">حسناً</button>'); return; }
  const sel = open.find((i) => i.id === invoiceId) || open[0];
  openModal('سند قبض', `<form id="paymentForm" class="form-grid" novalidate>
    <div class="field span-2"><label for="pInvoice">الفاتورة *</label><select class="select" id="pInvoice">${open.map((i) => `<option value="${esc(i.id)}" ${i.id === sel.id ? 'selected' : ''}>${esc(i.number)} — ${esc(i.customerName)} (متبقٍ ${H.fmtMoney(i.state.remainingH)})</option>`).join('')}</select></div>
    <div class="field"><label for="pAmount">المبلغ *</label><input class="input num" id="pAmount" inputmode="decimal" value="${H.moneyInput(sel.state.remainingH)}"></div>
    <div class="field"><label for="pDate">التاريخ</label><input class="input" id="pDate" type="date" value="${todayISO()}"></div>
    <div class="field"><label for="pMethod">طريقة الدفع</label><select class="select" id="pMethod">${Object.entries(PAY_METHODS).map(([k, v]) => `<option value="${k}" ${k === 'bank_transfer' ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
    <div class="field"><label for="pAccount">إلى حساب</label><select class="select" id="pAccount">${cashOptions()}</select></div>
    <div class="field span-2"><label for="pRef">المرجع</label><input class="input" id="pRef" maxlength="60" placeholder="رقم الحوالة أو الشيك"></div>
  </form>`, cancelBtn + submitBtn('paymentForm', 'تسجيل السند'));
  $('#pInvoice').addEventListener('change', (e) => { const i = open.find((x) => x.id === e.target.value); $('#pAmount').value = H.moneyInput(i.state.remainingH); });
  $('#pMethod').addEventListener('change', (e) => { $('#pAccount').value = e.target.value === 'cash' ? ACC.cash : ACC.bank; });
  $('#paymentForm').addEventListener('submit', formGuard(() => {
    const inv = open.find((x) => x.id === $('#pInvoice').value);
    const amountH = field('pAmount', (v) => { const h = H.parseMoney(v); if (h > inv.state.remainingH) throw new H.InputError(`المبلغ أكبر من المتبقي (${H.fmtMoney(inv.state.remainingH)})`); return h; });
    const date = field('pDate', (v) => { H.parseDate(v); if (v < inv.issueDate) throw new H.InputError('التاريخ قبل تاريخ الفاتورة'); return v; });
    run(document.querySelector('[form=paymentForm]'), () => Services.recordPayment({ invoiceId: inv.id, amountH, accountId: $('#pAccount').value, method: $('#pMethod').value, date, reference: $('#pRef').value }),
      ['سُجّل سند القبض', (no) => `${no} — ${H.fmtMoney(amountH)} ر.س`]);
  }));
}

/* ---------- القيد اليدوي (متعدد الأسطر) ---------- */
let jdraft = null;
function journalModal(id = '') {
  const j = id ? S.data.journals.find((x) => x.id === id) : null;
  const blank = () => ({ accountId: '', debit: '', credit: '', memo: '' });
  jdraft = { id, lines: j ? j.lines.map((l) => ({ accountId: l.accountId, debit: H.moneyInput(l.debitH), credit: H.moneyInput(l.creditH), memo: l.memo || '' })) : [blank(), blank()] };
  openModal(j ? `تعديل القيد ${j.no}` : 'قيد يومية جديد', `<form id="journalForm" novalidate>
    <div class="form-grid"><div class="field"><label for="jDate">التاريخ</label><input class="input" id="jDate" type="date" value="${esc(j?.date || todayISO())}"></div>
      <div class="field"><label for="jMemo">البيان *</label><input class="input" id="jMemo" maxlength="200" value="${esc(j?.memo)}" placeholder="مثال: سداد إيجار الورشة"></div></div>
    <div class="jlines" id="jLines"></div>
    <div class="lines-foot"><button type="button" class="btn btn-ghost btn-sm" data-action="add-jline">${icon('plus')}سطر</button><div id="jBalance" class="jbalance"></div></div>
    <p class="cell-sub mt">يُحفظ القيد بانتظار اعتماد مستخدم آخر لديه صلاحية "اعتماد وترحيل القيود".</p>
  </form>`, cancelBtn + submitBtn('journalForm', j ? 'حفظ التعديل' : 'حفظ للاعتماد'), { wide: true });
  drawJLines();
  $('#journalForm').addEventListener('submit', formGuard(() => {
    const date = field('jDate', (v) => H.parseDate(v));
    const memo = field('jMemo', (v) => { const s = H.cleanText(v, 200); if (s.length < 3) throw new H.InputError('اكتب بيان القيد'); return s; });
    const lines = parseJLines(true);
    const v = H.validateJournal(lines);
    if (!v.ok) throw new H.InputError(v.errors[0]);
    run(document.querySelector('[form=journalForm]'), () => Services.saveManualJournal(id, { date, memo, lines }), ['حُفظ القيد بانتظار الاعتماد', (no) => no]);
  }));
}
function drawJLines() {
  const accs = S.data.accounts.filter((a) => !a.archived);
  $('#jLines').innerHTML = '<div class="jline head"><span>الحساب</span><span>مدين</span><span>دائن</span><span class="hide-sm">ملاحظة</span><span></span></div>' +
    jdraft.lines.map((l, k) => `<div class="jline">
      <select class="select" data-jl="${k}" data-key="accountId" aria-label="الحساب"><option value="">اختر الحساب</option>${optionList(accs, l.accountId, (a) => `${a.number} — ${a.name}`)}</select>
      <input class="input num" data-jl="${k}" data-key="debit" value="${esc(l.debit)}" inputmode="decimal" placeholder="0.00" aria-label="مدين">
      <input class="input num" data-jl="${k}" data-key="credit" value="${esc(l.credit)}" inputmode="decimal" placeholder="0.00" aria-label="دائن">
      <input class="input hide-sm" data-jl="${k}" data-key="memo" value="${esc(l.memo)}" maxlength="120" aria-label="ملاحظة">
      <button type="button" class="btn btn-quiet icon-btn btn-sm" data-action="remove-jline" data-k="${k}" aria-label="حذف السطر" ${jdraft.lines.length <= 2 ? 'disabled' : ''}>${icon('trash')}</button></div>`).join('');
  drawJBalance();
}
function parseJLines(strict) {
  return jdraft.lines.map((l, k) => {
    try {
      const debitH = l.debit.trim() ? H.parseMoney(l.debit, { allowZero: true, label: `مدين السطر ${k + 1}` }) : 0;
      const creditH = l.credit.trim() ? H.parseMoney(l.credit, { allowZero: true, label: `دائن السطر ${k + 1}` }) : 0;
      return { accountId: l.accountId, debitH, creditH, memo: H.cleanText(l.memo, 120) };
    } catch (e) { if (strict) throw e; return { accountId: l.accountId, debitH: 0, creditH: 0 }; }
  });
}
function drawJBalance() {
  const lines = parseJLines(false);
  const d = H.sumInts(lines.map((l) => l.debitH)), c = H.sumInts(lines.map((l) => l.creditH));
  const v = H.validateJournal(lines);
  $('#jBalance').innerHTML = `<span>مدين ${M(d)}</span><span>دائن ${M(c)}</span>${v.ok ? '<span class="pill ok">متزن</span>' : `<span class="pill ${d !== c ? 'bad' : 'warn'}">${esc(d !== c ? `فرق ${H.fmtMoney(Math.abs(d - c))}` : v.errors[0])}</span>`}`;
  const sub = document.querySelector('[form=journalForm]');
  if (sub) sub.disabled = !v.ok;
}

function viewJournal(id) {
  const j = S.data.journals.find((x) => x.id === id); if (!j) return;
  const acc = (aid) => S.data.accounts.find((a) => a.id === aid);
  const mine = j.createdBy === S.user.username;
  const body = `<div class="kv wide"><span>التاريخ</span><b>${fmtDate(j.date)}</b><span>المصدر</span><b>${esc(SOURCE_LABEL[j.source] || j.source)}</b><span>الحالة</span><b>${pill(J_STATUS, j.status)}</b>
      <span>أنشأه</span><b>${esc(userName(j.createdBy))} · ${fmtDateTime(j.createdAt)}</b>${j.postedBy ? `<span>اعتمده</span><b>${esc(userName(j.postedBy))} · ${fmtDateTime(j.postedAt)}</b>` : ''}
      ${j.reversedBy ? `<span>عكسه</span><b>${esc(userName(j.reversedBy))} · ${fmtDateTime(j.reversedAt)}</b>` : ''}${j.cancelReason ? `<span>سبب الإلغاء</span><b>${esc(j.cancelReason)}</b>` : ''}</div>
    <p class="mt"><b>${esc(j.memo)}</b></p>
    <div class="table-wrap bordered"><table><thead><tr><th>الحساب</th><th class="money">مدين</th><th class="money">دائن</th><th class="hide-sm">ملاحظة</th></tr></thead><tbody>
      ${j.lines.map((l) => `<tr><td><span class="num">${esc(acc(l.accountId)?.number || '')}</span> ${esc(acc(l.accountId)?.name || l.accountId)}</td><td class="money">${l.debitH ? M(l.debitH) : ''}</td><td class="money">${l.creditH ? M(l.creditH) : ''}</td><td class="hide-sm cell-sub">${esc(l.memo || '')}</td></tr>`).join('')}
      <tr class="total-row"><td>الإجمالي</td><td class="money">${M(j.totalDebitH)}</td><td class="money">${M(j.totalCreditH)}</td><td class="hide-sm">${j.totalDebitH === j.totalCreditH ? '<span class="pill ok">متزن</span>' : '<span class="pill bad">غير متزن</span>'}</td></tr>
    </tbody></table></div>
    ${j.status === 'draft' && mine && can('journal.post') ? '<p class="cell-sub mt warn-text">فصل المهام: هذا القيد أنشأته أنت، فيعتمده مستخدم آخر.</p>' : ''}`;
  const acts = [
    j.status === 'draft' && mine ? btn('edit-journal', 'تعديل', { cls: 'btn-ghost', ic: 'edit', data: { id }, perm: 'journal.create' }) : '',
    j.status === 'draft' && (mine || can('journal.post')) ? btn('cancel-journal', mine ? 'إلغاء القيد' : 'رفض', { cls: 'btn-ghost', ic: 'x', data: { id } }) : '',
    j.status === 'draft' && !mine ? btn('post-journal', 'اعتماد وترحيل', { ic: 'check', data: { id }, perm: 'journal.post' }) : '',
    j.status === 'posted' && ['manual', 'bank'].includes(j.source) ? btn('reverse-journal', 'عكس القيد', { cls: 'btn-danger', ic: 'undo', data: { id }, perm: 'journal.reverse' }) : '',
  ].join('');
  openModal(`القيد ${j.no}`, body, `<button type="button" class="btn btn-ghost" data-action="close-modal">إغلاق</button>${acts}`, { wide: true });
}

/** نافذة سبب (للإلغاء والعكس) */
function reasonModal(title, label, onOk, danger = true) {
  openModal(title, `<form id="reasonForm" novalidate><div class="field"><label for="rText">${esc(label)} *</label><textarea class="textarea" id="rText" maxlength="200"></textarea></div></form>`,
    cancelBtn + `<button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" type="submit" form="reasonForm">${icon('check')}تأكيد</button>`);
  $('#reasonForm').addEventListener('submit', formGuard(() => {
    const reason = field('rText', (v) => { const s = H.cleanText(v, 200); if (s.length < 3) throw new H.InputError('اكتب السبب (3 أحرف على الأقل)'); return s; });
    onOk(reason, document.querySelector('[form=reasonForm]'));
  }));
}

/* ---------- كشف حساب ---------- */
function ledgerModal(accountId) {
  const a = S.data.accounts.find((x) => x.id === accountId); if (!a) return;
  const sign = ['Assets', 'Expenses'].includes(a.type) ? 1 : -1;
  const rows = [];
  let bal = 0;
  [...S.data.journals].filter((j) => j.status === 'posted' || j.status === 'reversed')
    .sort((x, y) => String(x.date).localeCompare(String(y.date)) || String(x.no).localeCompare(String(y.no)))
    .forEach((j) => j.lines.forEach((l) => { if (l.accountId !== accountId) return; bal += sign * ((l.debitH || 0) - (l.creditH || 0)); rows.push({ j, l, bal }); }));
  S.ledgerExport = { a, rows };
  openModal(`كشف حساب ${a.number} — ${a.name}`, rows.length ? `<div class="table-wrap bordered"><table><thead><tr><th>التاريخ</th><th>القيد</th><th>البيان</th><th class="money">مدين</th><th class="money">دائن</th><th class="money">الرصيد</th></tr></thead><tbody>
    ${rows.map(({ j, l, bal: b }) => `<tr><td class="nowrap">${fmtDate(j.date)}</td><td class="num start"><button type="button" class="link" data-action="view-journal" data-id="${esc(j.id)}">${esc(j.no)}</button></td><td class="clamp">${esc(j.memo)}</td><td class="money">${l.debitH ? M(l.debitH) : ''}</td><td class="money">${l.creditH ? M(l.creditH) : ''}</td><td class="money ${b < 0 ? 'bad-text' : ''}">${M(b)}</td></tr>`).join('')}
    </tbody></table></div>` : empty('book', 'لا توجد حركات على هذا الحساب'),
  `<button type="button" class="btn btn-ghost" data-action="close-modal">إغلاق</button>${rows.length ? btn('export', 'CSV', { cls: 'btn-ghost', ic: 'download', data: { what: 'ledger' }, perm: 'reports.export' }) : ''}`, { wide: true });
}

/* ---------- الحساب ---------- */
function accountModal() {
  openModal('حساب جديد', `<form id="accountForm" class="form-grid" novalidate>
    <div class="field"><label for="aNum">رقم الحساب *</label><input class="input num" id="aNum" inputmode="numeric" maxlength="8" placeholder="مثال: 5600"></div>
    <div class="field"><label for="aType">النوع *</label><select class="select" id="aType">${Object.entries(ACC_TYPES).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select></div>
    <div class="field span-2"><label for="aName">اسم الحساب *</label><input class="input" id="aName" maxlength="80" placeholder="مثال: مصروفات النقل والمعدات"></div></form>`, cancelBtn + submitBtn('accountForm', 'حفظ الحساب'));
  $('#accountForm').addEventListener('submit', formGuard(() => {
    run(document.querySelector('[form=accountForm]'), () => Services.createAccount({ number: $('#aNum').value, name: $('#aName').value, type: $('#aType').value }), ['أُضيف الحساب', '']);
  }));
}

/* ---------- الصنف ---------- */
function itemModal(id = '') {
  const it = (id && S.data.items.find((i) => i.id === id)) || {};
  const locked = !!id && (it.qtyM || 0) > 0;
  openModal(id ? 'تعديل صنف' : 'صنف جديد', `<form id="itemForm" class="form-grid" novalidate>
    <div class="field"><label for="itSku">الرمز *</label><input class="input" id="itSku" maxlength="30" dir="ltr" value="${esc(it.sku)}" placeholder="CEM-50"></div>
    <div class="field"><label for="itUnit">الوحدة</label><input class="input" id="itUnit" maxlength="20" value="${esc(it.unit)}" placeholder="كيس، م³، طن"></div>
    <div class="field span-2"><label for="itName">اسم الصنف *</label><input class="input" id="itName" maxlength="100" value="${esc(it.name)}" placeholder="أسمنت مقاوم 50 كجم"></div>
    <div class="field"><label for="itMethod">طريقة التقييم</label><select class="select" id="itMethod" ${locked ? 'disabled' : ''}><option value="AVG" ${it.method !== 'FIFO' ? 'selected' : ''}>المتوسط المرجح</option><option value="FIFO" ${it.method === 'FIFO' ? 'selected' : ''}>الوارد أولاً صادر أولاً (FIFO)</option></select>${locked ? '<span class="cell-sub">لا تتغير والصنف عليه رصيد</span>' : ''}</div>
    <div class="field"><label for="itReorder">حد إعادة الطلب</label><input class="input num" id="itReorder" inputmode="decimal" value="${it.reorderM ? H.qtyInput(it.reorderM) : ''}" placeholder="اختياري"></div>
    <div class="field"><label for="itPrice">سعر البيع الافتراضي</label><input class="input num" id="itPrice" inputmode="decimal" value="${H.moneyInput(it.salePriceH || 0)}" placeholder="اختياري"></div>
  </form>`, cancelBtn + submitBtn('itemForm', 'حفظ الصنف'));
  $('#itemForm').addEventListener('submit', formGuard(() => {
    const reorderM = field('itReorder', (v) => (v.trim() ? H.parseQty(v, { label: 'حد إعادة الطلب' }) : 0));
    const salePriceH = field('itPrice', (v) => (v.trim() ? H.parseMoney(v, { label: 'سعر البيع' }) : 0));
    run(document.querySelector('[form=itemForm]'), () => Services.saveItem(id, { sku: $('#itSku').value, name: $('#itName').value, unit: $('#itUnit').value, method: locked ? it.method : $('#itMethod').value, reorderM, salePriceH }), ['حُفظ الصنف', (n) => n]);
  }));
}

/* ---------- فاتورة المشتريات (مبسطة: اكتب الصنف والسعر فقط) ---------- */
let pdraft = null;
const PU_PREF = 'hiraf.puVatMode';
const prefGet = (k, d) => { try { return localStorage.getItem(k) || d; } catch { return d; } };
const prefSet = (k, v) => { try { localStorage.setItem(k, v); } catch { /* تجاهل */ } };
/** تصنيفات المصروف المتاحة: مواد المشاريع أولاً (الافتراضي) ثم باقي حسابات المصروفات */
function expenseAccounts() {
  const list = S.data.accounts.filter((a) => a.type === 'Expenses' && !a.archived && ![ACC.cogs, ACC.depExp].includes(a.id));
  for (const id of [ACC.general, ACC.materials]) if (!list.some((a) => a.id === id)) { const d = DEFAULT_ACCOUNTS.find((x) => 'acc-' + x[0] === id); list.push({ id, number: d[0], name: d[1] }); }
  const rank = (a) => (a.id === ACC.materials ? 0 : a.id === ACC.general ? 1 : 2);
  return list.sort((x, y) => rank(x) - rank(y) || String(x.number).localeCompare(String(y.number)));
}
const newPLine = () => ({ name: '', accountId: ACC.materials, qty: '1', price: '' });
function purchaseModal() {
  pdraft = { lines: [newPLine()] };
  const suppliers = [...new Set(S.data.purchases.map((p) => p.supplier).filter((x) => x && x !== 'مورد نقدي'))].slice(0, 200);
  const mode = prefGet(PU_PREF, 'incl');
  openModal('فاتورة مشتريات', `<form id="purchaseForm" novalidate>
    <div class="form-grid three">
      <div class="field"><label for="puSupplier">المورد</label><input class="input" id="puSupplier" maxlength="120" list="puSuppliers" placeholder="اختياري للشراء النقدي" autocomplete="off"><datalist id="puSuppliers">${suppliers.map((x) => `<option value="${esc(x)}">`).join('')}</datalist></div>
      <div class="field"><label for="puDate">التاريخ</label><input class="input" id="puDate" type="date" value="${todayISO()}"></div>
      <div class="field"><label for="puPay">السداد</label><select class="select" id="puPay"><option value="${ACC.cash}">نقداً (الصندوق)</option><option value="${ACC.bank}">البنك / تحويل / مدى</option><option value="${ACC.ap}">آجل (على المورد)</option></select></div>
      <div class="field span-3"><label>الأسعار المكتوبة</label><div class="seg" role="radiogroup" id="puVatSeg">
        ${Object.entries(VAT_MODE_SHORT).map(([k, v]) => `<label class="seg-opt"><input type="radio" name="puVat" value="${k}" ${k === mode ? 'checked' : ''}><span>${esc(v)}</span></label>`).join('')}</div></div>
    </div>
    <datalist id="puNames">${S.data.catalog.map((c) => `<option value="${esc(c.name)}">`).join('')}</datalist>
    <div class="plines exp" id="puLines"></div>
    <div class="lines-foot"><button type="button" class="btn btn-ghost btn-sm" data-action="add-pline">${icon('plus')}صنف آخر</button><div class="totals" id="puTotals"></div></div>
    <details class="more"><summary>بيانات إضافية (اختياري): الرقم الضريبي ورقم فاتورة المورد</summary><div class="form-grid">
      <div class="field"><label for="puVatNo">الرقم الضريبي للمورد</label><input class="input" id="puVatNo" maxlength="15" dir="ltr" inputmode="numeric"></div>
      <div class="field"><label for="puRef">رقم فاتورة المورد</label><input class="input" id="puRef" maxlength="40" dir="ltr"></div></div></details>
  </form>`, cancelBtn + submitBtn('purchaseForm', 'حفظ الفاتورة'), { xwide: true });
  drawPLines();
  $('#puVatSeg').addEventListener('change', (e) => { prefSet(PU_PREF, e.target.value); drawPTotals(); });
  setTimeout(() => document.querySelector('[data-pl="0"][data-key="name"]')?.focus(), 50);
  $('#purchaseForm').addEventListener('submit', formGuard(() => {
    const date = field('puDate', (v) => H.parseDate(v));
    const vatNo = H.normalizeDigits($('#puVatNo').value);
    if (vatNo && !/^3\d{13}3$/.test(vatNo)) throw new H.InputError('الرقم الضريبي للمورد 15 رقماً يبدأ وينتهي بـ 3');
    const lines = parsePLines(true);
    run(document.querySelector('[form=purchaseForm]'), () => Services.recordPurchase({ supplier: $('#puSupplier').value, supplierVat: vatNo, ref: $('#puRef').value, date, payAccountId: $('#puPay').value, vatMode: puMode(), lines }),
      ['حُفظت فاتورة المشتريات', (no) => no]);
  }));
}
const puMode = () => document.querySelector('input[name=puVat]:checked')?.value || 'incl';
function drawPLines() {
  const accs = expenseAccounts();
  $('#puLines').innerHTML = '<div class="pline head"><span>الصنف</span><span>التصنيف</span><span>الكمية</span><span>السعر</span><span class="lt">المبلغ</span><span></span></div>' +
    pdraft.lines.map((l, k) => `<div class="pline"><input class="input" data-pl="${k}" data-key="name" value="${esc(l.name)}" list="puNames" maxlength="100" placeholder="مثال: أسمنت، ديزل، مسامير…" aria-label="اسم الصنف" autocomplete="off">
      <select class="select" data-pl="${k}" data-key="accountId" aria-label="التصنيف">${optionList(accs, l.accountId, (a) => a.name)}</select>
      <input class="input num" data-pl="${k}" data-key="qty" value="${esc(l.qty)}" inputmode="decimal" aria-label="الكمية">
      <input class="input num" data-pl="${k}" data-key="price" value="${esc(l.price)}" inputmode="decimal" placeholder="0.00" aria-label="سعر الوحدة">
      <span class="lt num" data-plt="${k}"></span>
      <button type="button" class="btn btn-quiet icon-btn btn-sm" data-action="remove-pline" data-k="${k}" aria-label="حذف البند" ${pdraft.lines.length === 1 ? 'disabled' : ''}>${icon('trash')}</button></div>`).join('');
  drawPTotals();
}
/** strict=true عند الحفظ: يرمي الخطأ؛ وإلا يعيد null للبند غير المكتمل. البنود الفارغة تماماً تُتجاهل */
function parsePLines(strict) {
  const out = [];
  pdraft.lines.forEach((l, k) => {
    const blank = !l.name.trim() && !String(l.price).trim();
    if (blank) { out.push(null); return; }
    try {
      const name = H.cleanText(l.name, 100);
      if (!name) throw new H.InputError(`اكتب اسم الصنف في البند ${k + 1}`);
      out.push({ name, accountId: l.accountId, qtyM: H.parseQty(l.qty || '1', { label: `كمية البند ${k + 1}` }), priceH: H.parseMoney(l.price, { label: `سعر البند ${k + 1}` }) });
    } catch (e) { if (strict) throw e; out.push(null); }
  });
  if (strict) { const r = out.filter(Boolean); if (!r.length) throw new H.InputError('اكتب صنفاً واحداً على الأقل مع سعره'); return r; }
  return out;
}
function drawPTotals() {
  const mode = puMode();
  const p = parsePLines(false).map((l) => (l ? { ...l, ...H.purchaseLine(l.qtyM, l.priceH, mode) } : null));
  p.forEach((l, k) => { const el = document.querySelector(`[data-plt="${k}"]`); if (el) el.textContent = l ? H.fmtMoney(l.netH + l.vatH) : '—'; });
  const ok = p.filter(Boolean);
  const net = H.sumInts(ok.map((l) => l.netH)), vat = H.sumInts(ok.map((l) => l.vatH));
  $('#puTotals').innerHTML = `<div><span class="cell-sub">قبل الضريبة</span>${M(net)}</div><div><span class="cell-sub">ضريبة المدخلات</span>${M(vat)}</div><div class="grand"><span>الإجمالي</span><span>${M(net + vat)} ر.س</span></div>`;
}
/** عند كتابة اسم صنف سبق شراؤه: يُكمل التصنيف وآخر سعر تلقائياً */
function autofillPLine(k, el) {
  const c = S.data.catalog.find((x) => x.key === itemKey(pdraft.lines[k].name));
  if (!c) return;
  const line = pdraft.lines[k], row = el.closest('.pline');
  if (c.accountId && expenseAccounts().some((a) => a.id === c.accountId)) { line.accountId = c.accountId; row.querySelector('[data-key="accountId"]').value = c.accountId; }
  if (!String(line.price).trim() && c.lastPriceH && (c.lastVatMode || 'excl') === puMode()) { line.price = H.moneyInput(c.lastPriceH); row.querySelector('[data-key="price"]').value = line.price; }
}
function viewPurchase(id) {
  const p = S.data.purchases.find((x) => x.id === id); if (!p) return;
  const j = S.data.journals.find((x) => x.id === (p.journalIds || [])[0]);
  const rows = (p.lines || []).map((l) => `<tr><td class="cell-main">${esc(l.name || (S.data.items.find((i) => i.id === l.itemId)?.name) || '—')}</td><td class="hide-sm">${esc(l.accountId ? accName(l.accountId) : 'المخزون')}</td><td class="money">${Q(l.qtyM)}</td><td class="money">${M(l.priceH ?? l.unitCostH)}</td><td class="money">${M(l.netH)}</td><td class="money">${M(l.vatH)}</td></tr>`).join('');
  openModal(`فاتورة مشتريات ${p.no}`, `<div class="form-grid three pu-head">
      <div><span class="cell-sub">المورد</span><b>${esc(p.supplier)}</b></div><div><span class="cell-sub">التاريخ</span><b>${fmtDate(p.date)}</b></div><div><span class="cell-sub">السداد</span><b>${esc(PAY_LABEL[p.payAccountId] || '—')}</b></div>
      ${p.ref ? `<div><span class="cell-sub">رقم فاتورة المورد</span><b dir="ltr">${esc(p.ref)}</b></div>` : ''}${p.supplierVat ? `<div><span class="cell-sub">الرقم الضريبي</span><b dir="ltr">${esc(p.supplierVat)}</b></div>` : ''}
      <div><span class="cell-sub">الأسعار</span><b>${esc(VAT_MODE_LABEL[p.vatMode] || 'قبل الضريبة')}</b></div></div>
    <div class="table-wrap bordered"><table><thead><tr><th>الصنف</th><th class="hide-sm">التصنيف</th><th class="money">الكمية</th><th class="money">السعر</th><th class="money">قبل الضريبة</th><th class="money">الضريبة</th></tr></thead><tbody>${rows}
      <tr class="total-row"><td colspan="4">الإجمالي ${M(p.totalH)} ر.س</td><td class="money">${M(p.netH)}</td><td class="money">${M(p.vatH)}</td></tr></tbody></table></div>`,
  `<button type="button" class="btn btn-ghost" data-action="close-modal">إغلاق</button>${j ? `<button type="button" class="btn btn-ghost" data-action="view-journal" data-id="${esc(j.id)}">${icon('book')}القيد ${esc(j.no)}</button>` : ''}`, { wide: true });
}

/* ---------- الأصل الثابت والإهلاك ---------- */
function assetModal() {
  openModal('أصل ثابت جديد', `<form id="assetForm" class="form-grid" novalidate>
    <div class="field span-2"><label for="faName">اسم الأصل *</label><input class="input" id="faName" maxlength="100" placeholder="مثال: خلاطة خرسانة 1 م³"></div>
    <div class="field"><label for="faCost">التكلفة (قبل الضريبة) *</label><input class="input num" id="faCost" inputmode="decimal"></div>
    <div class="field"><label for="faSalvage">قيمة الخردة</label><input class="input num" id="faSalvage" inputmode="decimal" value="0"></div>
    <div class="field"><label for="faLife">العمر الإنتاجي (بالأشهر) *</label><input class="input num" id="faLife" inputmode="numeric" value="60"></div>
    <div class="field"><label for="faStart">بداية الإهلاك</label><input class="input" id="faStart" type="month" value="${thisMonth()}"></div>
    <div class="field span-2"><label for="faPay">السداد</label><select class="select" id="faPay">${cashOptions(true)}</select></div>
    <div class="span-2 cell-sub" id="faPreview"></div></form>`, cancelBtn + submitBtn('assetForm', 'تسجيل الأصل'));
  const preview = () => {
    try {
      const costH = H.parseMoney($('#faCost').value), salvageH = H.parseMoney($('#faSalvage').value || '0', { allowZero: true }), life = H.parseInteger($('#faLife').value, { min: 1, max: 600 });
      const per = Math.floor((costH - salvageH) / life), last = costH - salvageH - per * (life - 1);
      $('#faPreview').innerHTML = costH > salvageH ? `القسط الشهري ${M(per)} ر.س${last !== per ? ` (والشهر الأخير ${M(last)} لإكمال القيمة بالضبط)` : ''}` : '';
    } catch { $('#faPreview').textContent = ''; }
  };
  ['#faCost', '#faSalvage', '#faLife'].forEach((s) => $(s).addEventListener('input', preview));
  $('#assetForm').addEventListener('submit', formGuard(() => {
    const costH = field('faCost', (v) => H.parseMoney(v, { label: 'التكلفة' }));
    const salvageH = field('faSalvage', (v) => H.parseMoney(v || '0', { allowZero: true, label: 'قيمة الخردة' }));
    const lifeMonths = field('faLife', (v) => H.parseInteger(v, { min: 1, max: 600, label: 'العمر الإنتاجي' }));
    const startMonth = field('faStart', (v) => { if (!H.isMonth(v)) throw new H.InputError('شهر البداية غير صالح'); return v; });
    run(document.querySelector('[form=assetForm]'), () => Services.createAsset({ name: $('#faName').value, costH, salvageH, lifeMonths, startMonth, payAccountId: $('#faPay').value }), ['سُجّل الأصل', (no) => no]);
  }));
}
function depModal() {
  const pending = pendingDepMonths();
  if (!pending.length) { toast('لا توجد أشهر مستحقة للإهلاك', ''); return; }
  const month = pending[0];
  const rows = S.data.assets.filter((a) => a.status === 'active').map((a) => ({ a, h: H.monthlyDepreciation(a, month) })).filter((x) => x.h > 0);
  const total = H.sumInts(rows.map((x) => x.h));
  openModal(`إهلاك ${fmtMonth(month)}`, `<div class="table-wrap bordered"><table><thead><tr><th>الأصل</th><th class="money">القسط</th></tr></thead><tbody>
    ${rows.map((x) => `<tr><td>${esc(x.a.no)} — ${esc(x.a.name)}</td><td class="money">${M(x.h)}</td></tr>`).join('')}
    <tr class="total-row"><td>الإجمالي</td><td class="money">${M(total)}</td></tr></tbody></table></div>
    <p class="cell-sub mt">سيُرحّل قيد: من حـ/ مصروف الإهلاك إلى حـ/ مجمع الإهلاك.${pending.length > 1 ? ` يتبقى بعده ${pending.length - 1} شهر.` : ''}</p>`,
  cancelBtn + btn('confirm-dep', 'احتساب وترحيل', { ic: 'check', data: { month } }));
}

/* ---------- المستخدم ---------- */
function userModal(id = '') {
  const u = id ? S.data.users.find((x) => x.id === id) : null;
  const isOwner = id === OWNER;
  const role = u?.role || 'accountant';
  const perms = new Set(u ? u.perms || [] : ROLES[role].perms);
  openModal(u ? `تعديل المستخدم ${u.id}` : 'مستخدم جديد', `<form id="userForm" novalidate>
    <div class="form-grid">
      <div class="field"><label for="uName">الاسم الظاهر *</label><input class="input" id="uName" maxlength="60" value="${esc(u?.name)}" placeholder="مثال: أحمد — المحاسب"></div>
      <div class="field"><label for="uUser">اسم الدخول *</label><input class="input" id="uUser" maxlength="30" dir="ltr" value="${esc(u?.id)}" ${u ? 'readonly' : ''} placeholder="ahmad أو 4" autocomplete="off"></div>
      ${u ? '' : '<div class="field"><label for="uPass">كلمة المرور *</label><input class="input" id="uPass" type="password" autocomplete="new-password" placeholder="8 أحرف على الأقل"></div>'}
      ${isOwner ? '' : `<div class="field"><label for="uRole">الدور</label><select class="select" id="uRole">${Object.entries(ROLES).map(([k, r]) => `<option value="${k}" ${k === role ? 'selected' : ''}>${esc(r.label)}</option>`).join('')}</select></div>`}
    </div>
    ${isOwner ? '<p class="cell-sub">مالك النظام يملك كل الصلاحيات دائماً.</p>' : `<div class="perm-grid" id="permGrid">${PERM_GROUPS.map(([g, list]) => `<fieldset><legend>${esc(g)}</legend>
      ${list.map(([p, l]) => `<label class="check"><input type="checkbox" value="${p}" ${perms.has(p) ? 'checked' : ''}> ${esc(l)}</label>`).join('')}</fieldset>`).join('')}</div>`}
  </form>`, cancelBtn + submitBtn('userForm', u ? 'حفظ' : 'إضافة المستخدم'), { wide: true });
  if (!isOwner) {
    $('#uRole').addEventListener('change', (e) => { const r = ROLES[e.target.value]; if (r.perms) $$('#permGrid input').forEach((c) => { c.checked = r.perms.includes(c.value); }); });
    $('#permGrid').addEventListener('change', (e) => { if (e.target.type === 'checkbox') $('#uRole').value = 'custom'; });
  }
  $('#userForm').addEventListener('submit', formGuard(() => {
    const username = field('uUser', (v) => { const s = normUsername(v.trim()); if (!USERNAME_RE.test(s)) throw new H.InputError('اسم الدخول: حروف إنجليزية صغيرة أو أرقام (بدون مسافات)'); return s; });
    const name = field('uName', (v) => { const s = H.cleanText(v, 60); if (!s) throw new H.InputError('اكتب الاسم الظاهر'); return s; });
    const password = u ? undefined : field('uPass', (v) => { if (v.length < 8) throw new H.InputError('كلمة المرور 8 أحرف على الأقل'); return v; });
    const roleVal = isOwner ? 'admin' : $('#uRole').value;
    const permsVal = isOwner ? ALL_PERMS : $$('#permGrid input:checked').map((c) => c.value);
    run(document.querySelector('[form=userForm]'), () => Services.saveUser({ username, name, role: roleVal, perms: permsVal, password }, !u), [u ? 'حُفظ المستخدم' : 'أُضيف المستخدم', `${name} (${username})`]);
  }));
}

/* =====================================================================
   التصدير والطباعة
   ===================================================================== */
function download(filename, text) {
  const blob = new Blob([text], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function exportPayroll() {
  need('payroll.run');
  const p = S.data.payrolls.find((x) => x.id === S.hrMonth); if (!p) return;
  const rows = [['رقم الموظف', 'الاسم', 'البنك', 'الآيبان', 'الأجر الثابت', 'إضافي', 'مكافأة', 'أيام غياب', 'خصم الغياب', 'جزاءات', 'قسط سلفة', 'تأمينات الموظف', 'الصافي'],
    ...p.lines.map((l) => [l.code, l.name, l.bankName, l.iban, H.csvMoney(l.fixedH), H.csvMoney(l.overtimeH || 0), H.csvMoney(l.bonusH || 0), l.absenceDays || 0, H.csvMoney(l.absenceH || 0), H.csvMoney(l.penaltyH || 0), H.csvMoney(l.advanceH || 0), H.csvMoney(l.gosiEmpH), H.csvMoney(l.netH)]),
    ['', 'الإجمالي', '', '', '', '', '', '', '', '', '', H.csvMoney(p.totals.gosiEmpH), H.csvMoney(p.totals.netH)]];
  download(`مسير-رواتب-${p.id}.csv`, H.toCSV(rows));
}
function exportWhat(what, key) {
  need('reports.export');
  const d = S.data, co = d.company.name || 'الحرف المتكاملة للمقاولات';
  let rows, name;
  if (what === 'report') { const r = reportData(key); rows = [[co], [r.title, r.period], [], ...r.rows]; name = `${r.title}-${todayISO()}`; }
  else if (what === 'invoices') { rows = [['رقم الفاتورة', 'العميل', 'التاريخ', 'الاستحقاق', 'الصافي', 'الضريبة', 'الإجمالي', 'المدفوع', 'المتبقي', 'الحالة'], ...d.invoices.map((i) => [i.number || 'مسودة', i.customerName, i.issueDate, i.dueDate, H.csvMoney(i.netH), H.csvMoney(i.vatH), H.csvMoney(i.totalH), H.csvMoney(i.paidH || 0), H.csvMoney(i.state.remainingH), (INV_STATUS[i.state.key] || [i.state.key])[0]])]; name = 'الفواتير-' + todayISO(); }
  else if (what === 'journal') { rows = [['رقم القيد', 'التاريخ', 'البيان', 'المصدر', 'الحالة', 'رقم الحساب', 'الحساب', 'مدين', 'دائن', 'أنشأه', 'اعتمده']]; d.journals.forEach((j) => j.lines.forEach((l) => { const a = d.accounts.find((x) => x.id === l.accountId) || {}; rows.push([j.no, j.date, j.memo, SOURCE_LABEL[j.source] || j.source, (J_STATUS[j.status] || [j.status])[0], a.number || '', a.name || '', H.csvMoney(l.debitH || 0), H.csvMoney(l.creditH || 0), j.createdBy, j.postedBy || '']); })); name = 'القيود-' + todayISO(); }
  else if (what === 'audit') { rows = [['الوقت', 'المستخدم', 'العملية', 'النوع', 'المعرّف', 'التفاصيل'], ...filteredAudit().map((a) => [a.at, a.actorName || a.actor, AUDIT_ACTIONS[a.action] || a.action, AUDIT_ENTITIES[a.entity] || a.entity, a.entityId, a.summary])]; name = 'سجل-المراجعة-' + todayISO(); }
  else if (what === 'ledger') { const { a, rows: r } = S.ledgerExport; rows = [[`كشف حساب ${a.number} — ${a.name}`], ['التاريخ', 'القيد', 'البيان', 'مدين', 'دائن', 'الرصيد'], ...r.map(({ j, l, bal }) => [j.date, j.no, j.memo, H.csvMoney(l.debitH || 0), H.csvMoney(l.creditH || 0), H.csvMoney(bal)])]; name = `كشف-حساب-${a.number}`; }
  else return;
  download(name.replace(/[\\/:*?"<>|\s]+/g, '-') + '.csv', H.toCSV(rows));
  toast('تم التصدير', 'افتح الملف في Excel');
}
function printHTML(title, sub, html) {
  const co = S.data.company;
  const logo = $('.login-logo')?.getAttribute('src') || '';
  $('#printArea').innerHTML = `<div class="print-head">${logo ? `<img src="${logo}" alt="">` : ''}<div><h1>${esc(title)}</h1><div>${esc(co.name || 'الحرف المتكاملة للمقاولات')}${co.vat ? ` — الرقم الضريبي ${esc(co.vat)}` : ''}</div><div>${esc(sub)}</div></div></div>
    ${html}<div class="print-foot">طُبع بواسطة ${esc(S.user.name)} في ${fmtDateTime(nowISO())}</div>`;
  document.body.classList.add('printing');
  const done = () => { document.body.classList.remove('printing'); $('#printArea').innerHTML = ''; window.removeEventListener('afterprint', done); };
  window.addEventListener('afterprint', done);
  window.print();
  setTimeout(() => { if (document.body.classList.contains('printing')) done(); }, 60000);
}

/* =====================================================================
   الرسائل
   ===================================================================== */
function toast(title, sub = '', type = 'ok') {
  const box = $('#toasts');
  box.innerHTML = '';
  const el = document.createElement('div');
  el.className = 'toast' + (type === 'error' ? ' error' : '');
  el.setAttribute('role', type === 'error' ? 'alert' : 'status');
  el.innerHTML = `<span class="t-ic">${icon(type === 'error' ? 'x' : 'check')}</span><div>${esc(title)}${sub ? `<div class="cell-sub">${esc(sub)}</div>` : ''}</div>`;
  box.appendChild(el);
  setTimeout(() => { el.classList.add('leaving'); setTimeout(() => el.remove(), 300); }, type === 'error' ? 5500 : 3400);
}

/* =====================================================================
   المظهر
   ===================================================================== */
function applyTheme(t) {
  if (t) document.documentElement.setAttribute('data-theme', t); else document.documentElement.removeAttribute('data-theme');
  const dark = t ? t === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
  const ic = $('#themeIcon'); if (ic) ic.innerHTML = `<use href="#i-${dark ? 'sun' : 'moon'}"/>`;
}
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = cur === 'dark' ? 'light' : 'dark';
  local.set('hiraf-theme', next); applyTheme(next);
}

/* =====================================================================
   الأحداث
   ===================================================================== */
const armed = new WeakSet();
function confirmTwice(el, label = 'اضغط مرة أخرى للتأكيد') {
  if (armed.has(el)) return true;
  armed.add(el);
  const old = el.innerHTML;
  el.classList.add('btn-danger'); el.innerHTML = `${icon('alert')}${esc(label)}`;
  setTimeout(() => { armed.delete(el); el.classList.remove('btn-danger'); el.innerHTML = old; }, 3500);
  return false;
}

const ACTIONS = {
  'new-employee': () => employeeModal(), 'edit-employee': (el) => employeeModal(el.dataset.id), 'terminate-employee': (el) => terminateModal(el.dataset.id),
  'new-advance': () => advanceModal(), 'pay-payroll': () => payPayrollModal(),
  'hr-month': (el) => { S.hrMonth = el.dataset.m; render(); },
  'prepare-payroll': (el) => { const m = S.hrMonth; if (S.prEdits?.[m]) try { payrollEditsFromDom(); } catch { /* يُتجاهل */ } run(el, async () => { if (S.prEdits?.[m] && S.data.payrolls.some((p) => p.id === m)) await Services.savePayroll(m, S.prEdits[m]); await Services.preparePayroll(m); }, ['جُهّز المسير', fmtMonth(m)], { close: false }).then(() => render()); },
  'save-payroll': (el) => { let e; try { e = payrollEditsFromDom(); } catch (err) { toast('راجع الخانة المعلّمة', err.message, 'error'); return; } run(el, () => Services.savePayroll(S.hrMonth, e), ['حُفظت المسودة', ''], { close: false }).then(() => render()); },
  'post-payroll': (el) => { let e; try { e = payrollEditsFromDom(); } catch (err) { toast('راجع الخانة المعلّمة', err.message, 'error'); return; } run(el, () => Services.postPayroll(S.hrMonth, e), ['اعتُمد المسير ورُحّل قيده', (no) => no], { close: false }).then((r) => { if (r) { delete S.prEdits[S.hrMonth]; render(); } }); },
  'export-payroll': () => exportPayroll(),
  'bk-reset': () => { S.bank = { ...bankInit(), bankAccountId: S.bank?.bankAccountId || ACC.bank }; render(); },
  'bk-post': (el) => bankPost(el),
  'bk-remap': () => {
    const st = S.bank; const v = (id) => Number($('#' + id).value);
    const hdr = Number(H.normalizeDigits($('#bkHeader').value)) - 1;
    st.map = { date: v('bkMapDate'), desc: v('bkMapDesc') >= 0 ? [v('bkMapDesc')] : [], debit: v('bkMapDebit'), credit: v('bkMapCredit'), amount: v('bkMapAmount'), balance: st.map.balance };
    st.header = Number.isInteger(hdr) && hdr >= -1 && hdr < st.rows.length ? hdr : st.header;
    if (st.map.date < 0 || (st.map.amount < 0 && st.map.debit < 0 && st.map.credit < 0)) { toast('حدّد عمود التاريخ وعمود المبلغ (أو مدين ودائن)', '', 'error'); return; }
    st.detected = true; bankBuild(); render();
  },
  'modal-bg': () => closeModal(), 'close-modal': () => closeModal(),
  logout: () => logout(), theme: () => toggleTheme(),
  'open-nav': () => $('#app').classList.add('nav-open'), 'close-nav': () => $('#app').classList.remove('nav-open'),
  tab: (el) => { S.tabs[el.dataset.key] = el.dataset.tab; render(); },
  period: (el) => { S.period = el.dataset.p === 'month' ? { from: firstOfMonth(), to: todayISO() } : { from: firstOfYear(), to: todayISO() }; render(); },
  'new-customer': () => customerModal(), 'edit-customer': (el) => customerModal(el.dataset.id),
  'archive-customer': (el) => run(el, () => Services.archiveCustomer(el.dataset.id, el.dataset.archived === '1'), [el.dataset.archived === '1' ? 'أُرشف العميل' : 'استُعيد العميل', ''], { close: false }),
  'new-invoice': (el) => invoiceModal(el.dataset.customer || ''),
  'edit-invoice': (el) => { const i = S.data.invoices.find((x) => x.id === el.dataset.id); if (i) invoiceModal(i.customerId, i.id); },
  'view-invoice': (el) => viewInvoice(el.dataset.id), 'save-invoice': (el) => saveInvoice(el),
  'add-line': () => { if (draft.lines.length >= 30) return; draft.lines.push({ kind: 'service', itemId: '', description: '', qty: '1', price: '' }); drawLines(); },
  'remove-line': (el) => { draft.lines.splice(Number(el.dataset.k), 1); drawLines(); },
  'issue-invoice': (el) => run(el, () => Services.issueInvoice(el.dataset.id), ['صدرت الفاتورة', (n) => n]),
  'cancel-invoice': (el) => { if (confirmTwice(el)) run(el, () => Services.cancelDraftInvoice(el.dataset.id), ['أُلغيت المسودة', '']); },
  'void-invoice': (el) => reasonModal('إلغاء فاتورة مُصدرة', 'سبب الإلغاء (يُسجَّل في سجل المراجعة)', (r, b) => run(b, () => Services.voidInvoice(el.dataset.id, r), ['أُلغيت الفاتورة', 'رُحّل قيد عكسي وأُعيد المخزون'])),
  'print-invoice': (el) => { const i = S.data.invoices.find((x) => x.id === el.dataset.id); printHTML(`فاتورة ضريبية ${i.number}`, fmtDate(i.issueDate), $('#invoiceDoc').innerHTML); },
  'new-payment': (el) => paymentModal(el.dataset.invoice || ''),
  'reverse-payment': (el) => reasonModal('عكس سند قبض', 'سبب العكس', (r, b) => run(b, () => Services.reversePayment(el.dataset.id, r), ['عُكس السند', 'رُحّل قيد عكسي'])),
  'new-journal': () => journalModal(), 'edit-journal': (el) => journalModal(el.dataset.id), 'view-journal': (el) => viewJournal(el.dataset.id),
  'add-jline': () => { if (jdraft.lines.length >= 100) return; jdraft.lines.push({ accountId: '', debit: '', credit: '', memo: '' }); drawJLines(); },
  'remove-jline': (el) => { jdraft.lines.splice(Number(el.dataset.k), 1); drawJLines(); },
  'post-journal': (el) => run(el, () => Services.postJournal(el.dataset.id), ['اعتُمد القيد ورُحّل', '']),
  'cancel-journal': (el) => reasonModal('إلغاء / رفض القيد', 'السبب', (r, b) => run(b, () => Services.cancelJournal(el.dataset.id, r), ['أُلغي القيد', '']), false),
  'reverse-journal': (el) => reasonModal('عكس قيد مرحّل', 'سبب العكس', (r, b) => run(b, () => Services.reverseJournal(el.dataset.id, r), ['عُكس القيد', 'رُحّل قيد عكسي'])),
  ledger: (el) => ledgerModal(el.dataset.id), 'new-account': () => accountModal(),
  'new-item': () => itemModal(), 'edit-item': (el) => itemModal(el.dataset.id), 'new-purchase': () => purchaseModal(),
  'add-pline': () => { if (pdraft.lines.length >= 40) return; pdraft.lines.push(newPLine()); drawPLines(); document.querySelector(`[data-pl="${pdraft.lines.length - 1}"][data-key="name"]`)?.focus(); },
  'view-purchase': (el) => viewPurchase(el.dataset.id),
  'remove-pline': (el) => { pdraft.lines.splice(Number(el.dataset.k), 1); drawPLines(); },
  'new-asset': () => assetModal(), 'run-dep': () => depModal(),
  'confirm-dep': (el) => run(el, () => Services.runDepreciation(el.dataset.month), ['رُحّل قيد الإهلاك', (h) => `${H.fmtMoney(h)} ر.س`]),
  'new-user': () => userModal(), 'edit-user': (el) => userModal(el.dataset.id),
  'toggle-user': (el) => run(el, () => Services.setUserActive(el.dataset.id, el.dataset.active === '1'), [el.dataset.active === '1' ? 'فُعّل المستخدم' : 'أُوقف المستخدم', ''], { close: false }),
  'delete-user': (el) => { if (confirmTwice(el, 'تأكيد الحذف')) run(el, () => Services.setUserActive(el.dataset.id, false, true), ['حُذف المستخدم', 'يبقى تاريخه في سجل المراجعة'], { close: false }); },
  export: (el) => exportWhat(el.dataset.what, el.dataset.key),
  print: (el) => { need('reports.export'); const r = reportData(el.dataset.key); printHTML(r.title, r.period, r.html); },
  'wipe-local': (el) => { if (confirmTwice(el)) { local.del(LocalDB.KEY); local.del(LocalDB.AUTH); sess.del('hiraf-local-user'); location.reload(); } },
};

document.addEventListener('click', (e) => {
  const nav = e.target.closest('[data-nav]');
  if (nav) { if (nav.dataset.filter) S.tabs[nav.dataset.nav] = nav.dataset.filter; go(nav.dataset.nav); return; }
  const el = e.target.closest('[data-action]');
  if (!el || el.disabled) return;
  const a = el.dataset.action;
  if (a === 'modal-bg' && e.target !== el) return;
  const fn = ACTIONS[a];
  if (fn) { try { fn(el, e); } catch (err) { toast('تعذّر تنفيذ العملية', err.message, 'error'); } }
});

document.addEventListener('input', (e) => {
  const t = e.target;
  t.closest('.field.invalid')?.classList.remove('invalid');
  if (t.dataset.q) { S.q[t.dataset.q] = t.value; render(); return; }
  if (t.dataset.line !== undefined && draft) {
    const k = Number(t.dataset.line), l = draft.lines[k];
    l[t.dataset.key] = t.value;
    if (t.dataset.key === 'kind') { l.itemId = ''; l.description = ''; drawLines(); return; }
    if (t.dataset.key === 'itemId') { const it = S.data.items.find((i) => i.id === l.itemId); if (it && !l.price && it.salePriceH) l.price = H.moneyInput(it.salePriceH); drawLines(); return; }
    drawTotals(); return;
  }
  if (t.dataset.jl !== undefined && jdraft) {
    const k = Number(t.dataset.jl), key = t.dataset.key, line = jdraft.lines[k];
    line[key] = t.value;
    if ((key === 'debit' || key === 'credit') && t.value.trim()) {
      const other = key === 'debit' ? 'credit' : 'debit';
      line[other] = '';
      const o = t.closest('.jline')?.querySelector(`[data-key="${other}"]`); if (o) o.value = '';
    }
    drawJBalance(); return;
  }
  if (t.dataset.pl !== undefined && pdraft) { const k = Number(t.dataset.pl); pdraft.lines[k][t.dataset.key] = t.value; if (t.dataset.key === 'name') autofillPLine(k, t); drawPTotals(); }
});
document.addEventListener('change', (e) => {
  const t = e.target;
  if (t.id === 'audUser') { S.auditFilter.user = t.value; render(); }
  if (t.id === 'audEntity') { S.auditFilter.entity = t.value; render(); }
  if (t.id === 'hrMonth' && H.isMonth(t.value)) { S.hrMonth = t.value; render(); return; }
  if (t.id === 'hrShowAll') { S.hrShowAll = t.checked; render(); return; }
  // إعادة الرسم بعد انتقال التركيز للخانة التالية حتى لا يضيع مكان الكتابة
  if (t.dataset.pr) { t.classList.remove('invalid-input'); try { payrollEditsFromDom(); setTimeout(() => render(), 0); } catch (err) { toast('قيمة غير صالحة', err.message, 'error'); } return; }
  if (t.id === 'bkFile') { bankReadFile(t.files?.[0]); t.value = ''; return; }
  if (t.id === 'bkAcc') { (S.bank || (S.bank = bankInit())).bankAccountId = t.value; return; }
  if (t.id === 'bkAll' && S.bank?.items) { S.bank.items.forEach((r) => { if (!r.dup) r.include = t.checked; }); render(); return; }
  if (t.dataset.bk && S.bank?.items) {
    const r = S.bank.items[Number(t.dataset.i)]; if (!r) return;
    if (t.dataset.bk === 'inc') r.include = t.checked;
    if (t.dataset.bk === 'vat') r.vat = t.checked;
    if (t.dataset.bk === 'acc') {
      // تطبيق نفس التصنيف على العمليات المشابهة التي لم يغيّرها المستخدم بيده
      r.accountId = t.value; r.touched = true;
      const key = B.descKey(r.desc);
      S.bank.items.forEach((x) => { if (x !== r && !x.touched && !x.dup && x.dir === r.dir && B.descKey(x.desc) === key) x.accountId = t.value; });
    }
    render();
  }
});
// سحب ملف الكشف وإفلاته
document.addEventListener('dragover', (e) => { const z = e.target.closest?.('#bkDrop'); if (z) { e.preventDefault(); z.classList.add('over'); } });
document.addEventListener('dragleave', (e) => { e.target.closest?.('#bkDrop')?.classList.remove('over'); });
document.addEventListener('drop', (e) => { const z = e.target.closest?.('#bkDrop'); if (z) { e.preventDefault(); z.classList.remove('over'); bankReadFile(e.dataTransfer?.files?.[0]); } });

document.addEventListener('submit', async (e) => {
  const f = e.target;
  if (f.id === 'hrSetForm') {
    e.preventDefault();
    try {
      const bp = (id) => H.parseMoney($('#' + id).value, { allowZero: true, label: 'النسبة' });
      const v = { empSaudiBp: bp('gEmpSa'), erSaudiBp: bp('gErSa'), erNonSaudiBp: bp('gErNon'), capH: H.parseMoney($('#gCap').value, { label: 'الحد الأعلى' }) };
      run(f.querySelector('[type=submit]'), () => Services.saveHrSettings(v), ['حُفظت نسب التأمينات', ''], { close: false });
    } catch (err) { toast('قيمة غير صالحة', err.message, 'error'); }
    return;
  }
  if (f.id === 'payrollForm') { e.preventDefault(); return; }
  if (f.id === 'bankForm') { e.preventDefault(); return; }
  if (f.id === 'periodForm') {
    e.preventDefault();
    const from = $('#pFrom')?.value || S.period.from, to = $('#pTo').value;
    if (!H.isISODate(from) || !H.isISODate(to)) { toast('تاريخ غير صالح', '', 'error'); return; }
    if (from > to) { toast('تاريخ البداية بعد النهاية', '', 'error'); return; }
    S.period = { from, to }; document.activeElement?.blur(); render();
  }
  if (f.id === 'companyForm') {
    e.preventDefault();
    const b = f.querySelector('[type=submit]');
    await run(b, () => Services.saveCompany({ name: $('#coName').value, vat: $('#coVat').value, cr: $('#coCr').value, phone: $('#coPhone').value, email: $('#coEmail').value, address: $('#coAddress').value }), ['حُفظت بيانات المنشأة', ''], { close: false });
    document.activeElement?.blur(); render();
  }
  if (f.id === 'passForm') {
    e.preventDefault();
    const cur = $('#pwCur').value, next = $('#pwNew').value;
    if (!cur || !next) { toast('أكمل الحقول', '', 'error'); return; }
    if (next.length < 8) { toast('كلمة المرور قصيرة', 'استخدم 8 أحرف على الأقل', 'error'); return; }
    if (next !== $('#pwNew2').value) { toast('التأكيد غير مطابق', '', 'error'); return; }
    const b = f.querySelector('[type=submit]');
    busy(b, true);
    try { await S.db.changePassword(cur, next); f.reset(); S.weakPassword = false; toast('تم تغيير كلمة المرور', ''); document.activeElement?.blur(); render(); }
    catch (err) { toast('تعذّر التغيير', err.message || fbError(err), 'error'); busy(b, false); }
  }
});

document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closeModal(); $('#app').classList.remove('nav-open'); } });
window.addEventListener('unhandledrejection', (e) => { console.error(e.reason); toast('حدث خطأ غير متوقع', fbError(e.reason), 'error'); });

boot();
