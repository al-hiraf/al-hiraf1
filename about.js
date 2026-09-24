/* =====================================================================
   about.js — الصفحة التعريفية العامة: تقرأ settings/public من Firestore
   بدون تسجيل دخول (القواعد تسمح بقراءة هذا المستند فقط للعامة).
   كل النصوص تُدرج بـ textContent، فلا مجال لحقن HTML.
   ===================================================================== */
(async function () {
  'use strict';
  const FB_VER = '12.18.0';
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const svg = (id) => { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); const u = document.createElementNS('http://www.w3.org/2000/svg', 'use'); u.setAttribute('href', '#' + id); s.appendChild(u); return s; };
  const showSoon = () => { $('page').hidden = true; $('nav').hidden = true; $('soon').hidden = false; };

  const cfg = window.HIRAF_FIREBASE;
  if (!cfg || !cfg.apiKey || String(cfg.apiKey).startsWith('ضع')) { showSoon(); return; }
  let p;
  try {
    const base = `https://www.gstatic.com/firebasejs/${FB_VER}`;
    const [app, fs] = await Promise.all([import(`${base}/firebase-app.js`), import(`${base}/firebase-firestore.js`)]);
    const db = fs.getFirestore(app.initializeApp(cfg));
    const snap = await fs.getDoc(fs.doc(db, 'settings', 'public'));
    p = snap.exists() ? snap.data() : null;
  } catch (e) { console.warn(e); showSoon(); return; }
  if (!p || !p.published) { showSoon(); return; }

  const name = p.companyName || 'الحرف المتكاملة للمقاولات';
  document.title = name;
  $('brandName').textContent = name;
  $('foot').textContent = `© ${new Date().getFullYear()} ${name}`;
  $('city').textContent = p.city ? `مقاولات · ${p.city}` : 'مقاولات';
  $('tagline').textContent = p.tagline || name;
  const aboutLines = String(p.about || '').split('\n').filter(Boolean);
  $('lead').textContent = aboutLines[0] || '';

  // أزرار التواصل في الواجهة
  const ctas = $('ctas');
  if (p.whatsapp) { const a = el('a', 'btn btn-orange'); a.href = `https://wa.me/${encodeURIComponent(p.whatsapp)}`; a.target = '_blank'; a.rel = 'noopener'; a.append(svg('i-chat'), 'راسلنا واتساب'); ctas.append(a); }
  if (p.phone) { const a = el('a', 'btn btn-line'); a.href = `tel:${p.phone}`; a.append(svg('i-phone'), el('span', 'ltr', p.phone)); ctas.append(a); }
  // حقائق نظامية حقيقية فقط (السجل والرقم الضريبي)
  const facts = $('facts');
  if (p.cr) { const s = el('span'); s.append('السجل التجاري ', el('b', 'ltr', p.cr)); facts.append(s); }
  if (p.vat) { const s = el('span'); s.append('الرقم الضريبي ', el('b', 'ltr', p.vat)); facts.append(s); }

  if (aboutLines.length > 1 || (aboutLines.length === 1 && aboutLines[0].length > 160)) { $('aboutText').textContent = p.about; $('about').hidden = false; }
  else document.querySelector('#nav a[href="#about"]').hidden = true;

  const svcs = Array.isArray(p.services) ? p.services.filter(Boolean) : [];
  if (svcs.length) {
    const box = $('svcList');
    svcs.forEach((t) => { const c = el('div', 'svc'); c.append(el('i'), el('span', null, t)); box.append(c); });
    $('services').hidden = false;
  } else document.querySelector('#nav a[href="#services"]').hidden = true;

  const projs = Array.isArray(p.projects) ? p.projects.filter((x) => x && x.name) : [];
  if (projs.length) {
    const box = $('projList');
    projs.forEach((x) => { const r = el('div', 'proj'); r.append(el('b', null, x.name), el('span', null, x.detail || '')); box.append(r); });
    $('projects').hidden = false;
  } else document.querySelector('#nav a[href="#projects"]').hidden = true;

  const cbox = $('contactBox');
  const cell = (label, node) => { const d = el('div'); d.append(el('small', null, label), node); cbox.append(d); };
  const link = (href, text, ltr) => { const a = el('a', ltr ? 'ltr' : null, text); a.href = href; if (href.startsWith('https:')) { a.target = '_blank'; a.rel = 'noopener'; } return a; };
  if (p.phone) cell('الهاتف', link(`tel:${p.phone}`, p.phone, true));
  if (p.whatsapp) cell('واتساب', link(`https://wa.me/${encodeURIComponent(p.whatsapp)}`, '+' + p.whatsapp, true));
  if (p.email) cell('البريد الإلكتروني', link(`mailto:${p.email}`, p.email, true));
  if (p.address || p.city) cell('العنوان', el('b', null, [p.address, p.city].filter(Boolean).join('، ')));
  if (p.mapUrl && /^https:\/\//.test(p.mapUrl)) cell('الموقع', link(p.mapUrl, 'افتح على الخريطة'));
  if (!cbox.children.length) { $('contact').hidden = true; document.querySelector('#nav a[href="#contact"]').hidden = true; }

  $('legal').textContent = [p.cr && `س.ت ${p.cr}`, p.vat && `الرقم الضريبي ${p.vat}`].filter(Boolean).join(' · ');
  $('page').hidden = false;
})();
