---
title: "Preeklamsia Early Recognition Tool (PERT)"
date: 2026-06-24T00:00:00Z
draft: false
description: "Form skrining dini preeklamsia. Isi tanda dan gejala pasien, lalu dapatkan hasil triase: Normal (hijau), Hati-hati (kuning), atau Bahaya/Urgen (merah)."
tags: ["tools", "kesehatan", "preeklamsia", "skrining"]
categories: ["tools"]
---

{{< rawhtml >}}
<style>
    .pert {
        --green: #2e9e5b;
        --yellow: #e0a800;
        --red: #d6336c;
        max-width: 760px;
        margin: 0 auto;
    }
    .pert-card {
        background: #ffffff;
        border-radius: 15px;
        padding: 28px;
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
        color: #333;
    }
    .pert-card h2 {
        color: #333;
        margin: 0 0 6px 0;
        font-size: 26px;
    }
    .pert-sub {
        color: #666;
        margin: 0 0 24px 0;
        font-size: 14px;
    }
    .pert-field {
        margin-bottom: 16px;
    }
    .pert-field > label {
        display: block;
        margin-bottom: 6px;
        color: #444;
        font-weight: 600;
        font-size: 14px;
    }
    .pert-field input[type="text"],
    .pert-field input[type="date"],
    .pert-field input[type="number"],
    .pert-field select {
        width: 100%;
        padding: 11px;
        border: 2px solid #ddd;
        border-radius: 8px;
        font-size: 15px;
        box-sizing: border-box;
        background: #fff;
        color: #333;
        transition: border-color 0.2s;
    }
    .pert-field input:focus,
    .pert-field select:focus {
        outline: none;
        border-color: #764ba2;
    }
    .pert-row {
        display: flex;
        gap: 16px;
        flex-wrap: wrap;
    }
    .pert-row > .pert-field {
        flex: 1 1 200px;
    }
    .pert-section {
        margin: 26px 0 10px 0;
        font-size: 13px;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        color: #764ba2;
        border-bottom: 1px solid #eee;
        padding-bottom: 6px;
    }
    .pert-hint {
        font-weight: 400;
        color: #999;
        font-size: 12px;
        margin-left: 6px;
        text-transform: none;
        letter-spacing: 0;
    }
    .pert-btn {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: #fff;
        border: none;
        padding: 13px 30px;
        font-size: 16px;
        border-radius: 8px;
        cursor: pointer;
        transition: transform 0.2s, box-shadow 0.2s;
        margin: 22px 8px 0 0;
    }
    .pert-btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
    .pert-btn:active { transform: translateY(0); }
    .pert-btn.secondary {
        background: #f1f1f4;
        color: #555;
    }
    .pert-result {
        margin-top: 28px;
        border-radius: 12px;
        padding: 24px;
        color: #fff;
        text-align: center;
    }
    .pert-result.green  { background: var(--green); }
    .pert-result.yellow { background: var(--yellow); color: #3a2e00; }
    .pert-result.red    { background: var(--red); }
    .pert-result h3 {
        margin: 0 0 8px 0;
        font-size: 28px;
        letter-spacing: 0.03em;
    }
    .pert-result .pert-action {
        font-size: 15px;
        line-height: 1.5;
        margin: 0 auto;
        max-width: 600px;
    }
    .pert-flags {
        margin-top: 18px;
        text-align: left;
        background: rgba(255,255,255,0.18);
        border-radius: 8px;
        padding: 14px 16px;
        font-size: 14px;
    }
    .pert-flags strong { display: block; margin-bottom: 6px; }
    .pert-flags ul { margin: 0; padding-left: 20px; }
    .pert-flags li { margin: 3px 0; }
    .pert-badge {
        display: inline-block;
        font-size: 11px;
        font-weight: 700;
        padding: 1px 7px;
        border-radius: 10px;
        margin-left: 6px;
        vertical-align: middle;
        color: #fff;
    }
    .pert-badge.yellow { background: #b58900; }
    .pert-badge.red { background: #b01e54; }
    .pert-summary {
        margin-top: 16px;
        text-align: left;
        font-size: 13px;
        color: #555;
    }
    .pert-disclaimer {
        margin-top: 22px;
        font-size: 12px;
        color: #888;
        line-height: 1.5;
        border-top: 1px solid #eee;
        padding-top: 14px;
    }
    .pert-btn.danger { color: #b01e54; }
    .pert-saverow {
        margin-top: 14px;
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 12px;
    }
    .pert-savemsg {
        font-size: 14px;
        color: #2e9e5b;
        font-weight: 600;
    }
    .pert-history {
        margin-top: 20px;
        padding-top: 16px;
        border-top: 1px solid #eee;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 10px;
    }
    .pert-history-count { font-size: 14px; color: #555; }
    .pert-history-actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .pert-history-actions .pert-btn { margin: 0; padding: 9px 16px; font-size: 14px; }
    .pert-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        transform: none;
        box-shadow: none;
    }
    .hidden { display: none; }
    @media print {
        .pert-btn, .pert-disclaimer, .pert-saverow, .pert-history { display: none; }
    }
</style>

<div class="pert">
  <div class="pert-card">
    <h2>🩺 Preeklamsia Early Recognition Tool</h2>
    <p class="pert-sub">Isi data dan tanda vital pasien, lalu klik <em>Lihat Hasil</em> untuk mendapatkan kategori triase.</p>

    <form id="pertForm" onsubmit="return false;">

      <div class="pert-section">Identitas</div>
      <div class="pert-row">
        <div class="pert-field">
          <label for="tanggal">Tanggal Kunjungan</label>
          <input type="date" id="tanggal">
        </div>
        <div class="pert-field">
          <label for="nama">Nama</label>
          <input type="text" id="nama" placeholder="Nama pasien">
        </div>
      </div>
      <div class="pert-field">
        <label for="alamat">Alamat</label>
        <input type="text" id="alamat" placeholder="Alamat pasien">
      </div>

      <div class="pert-section">Gejala Klinis</div>

      <div class="pert-field">
        <label for="kesadaran">Kesadaran</label>
        <select id="kesadaran" data-param="Kesadaran">
          <option value="">— pilih —</option>
          <option value="0">Sadar</option>
          <option value="1">Gelisah / mengantuk / sulit bicara</option>
          <option value="2">Tidak memberi respon</option>
        </select>
      </div>

      <div class="pert-field">
        <label for="sesak">Sesak Nafas</label>
        <select id="sesak" data-param="Sesak nafas">
          <option value="">— pilih —</option>
          <option value="0">Tidak</option>
          <option value="1">Ya</option>
        </select>
      </div>

      <div class="pert-field">
        <label for="nyerikepala">Nyeri Kepala</label>
        <select id="nyerikepala" data-param="Nyeri kepala">
          <option value="">— pilih —</option>
          <option value="0">Tidak ada</option>
          <option value="1">Ringan – sedang</option>
          <option value="2">Nyeri kepala hebat</option>
        </select>
      </div>

      <div class="pert-field">
        <label for="pandangan">Pandangan</label>
        <select id="pandangan" data-param="Pandangan">
          <option value="">— pilih —</option>
          <option value="0">Normal</option>
          <option value="1">Kabur atau terganggu</option>
          <option value="2">Tidak bisa melihat</option>
        </select>
      </div>

      <div class="pert-field">
        <label for="nyeridada">Nyeri Dada / Abdomen</label>
        <select id="nyeridada" data-param="Nyeri dada/abdomen">
          <option value="">— pilih —</option>
          <option value="0">Tidak ada</option>
          <option value="1">Mual, muntah, nyeri dada / nyeri perut</option>
        </select>
      </div>

      <div class="pert-field">
        <label for="berkemih">Berkemih</label>
        <select id="berkemih" data-param="Berkemih">
          <option value="">— pilih —</option>
          <option value="0">Normal, jernih</option>
          <option value="1">Berkurang, pekat</option>
          <option value="2">Sangat pekat</option>
        </select>
      </div>

      <div class="pert-field">
        <label for="janin">Kondisi Janin</label>
        <select id="janin" data-param="Kondisi janin">
          <option value="">— pilih —</option>
          <option value="0">Gerak aktif</option>
          <option value="1">Gerak janin berkurang / PJT</option>
          <option value="2">Gerak janin meragukan</option>
        </select>
      </div>

      <div class="pert-field">
        <label for="protein">Protein Urine</label>
        <select id="protein" data-param="Protein urine">
          <option value="">— pilih —</option>
          <option value="0">Negatif</option>
          <option value="1">Positif 1 (dipstick ≥ +1)</option>
          <option value="2">Positif &gt; 1 (dipstick ≥ +2)</option>
        </select>
      </div>

      <div class="pert-section">Tanda Vital <span class="pert-hint">isi dengan angka</span></div>
      <div class="pert-row">
        <div class="pert-field">
          <label for="sistole">TD Sistole <span class="pert-hint">mmHg</span></label>
          <input type="number" id="sistole" inputmode="numeric" placeholder="cth. 120">
        </div>
        <div class="pert-field">
          <label for="diastole">TD Diastole <span class="pert-hint">mmHg</span></label>
          <input type="number" id="diastole" inputmode="numeric" placeholder="cth. 80">
        </div>
      </div>
      <div class="pert-row">
        <div class="pert-field">
          <label for="nadi">Nadi <span class="pert-hint">x/menit</span></label>
          <input type="number" id="nadi" inputmode="numeric" placeholder="cth. 88">
        </div>
        <div class="pert-field">
          <label for="nafas">Nafas (RR) <span class="pert-hint">x/menit</span></label>
          <input type="number" id="nafas" inputmode="numeric" placeholder="cth. 20">
        </div>
        <div class="pert-field">
          <label for="saturasi">Saturasi O₂ <span class="pert-hint">%</span></label>
          <input type="number" id="saturasi" inputmode="numeric" placeholder="cth. 98">
        </div>
      </div>

      <button class="pert-btn" onclick="pertEvaluate()">Lihat Hasil</button>
      <button class="pert-btn secondary" onclick="pertReset()">Reset</button>
    </form>

    <div id="pertResult" class="pert-result hidden"></div>

    <div id="pertSaveRow" class="pert-saverow hidden">
      <button class="pert-btn" id="pertSaveBtn" onclick="pertSave()">💾 Simpan ke Riwayat</button>
      <span id="pertSaveMsg" class="pert-savemsg"></span>
    </div>

    <div class="pert-history">
      <span class="pert-history-count">Riwayat tersimpan: <strong id="pertCount">0</strong> entri</span>
      <span class="pert-history-actions">
        <button class="pert-btn secondary" id="pertCsvBtn" onclick="pertDownloadCsv()">⬇️ Unduh CSV</button>
        <button class="pert-btn secondary danger" id="pertClearBtn" onclick="pertClearHistory()">Hapus Riwayat</button>
      </span>
    </div>

    <p class="pert-disclaimer">
      <strong>Disclaimer:</strong> Alat ini adalah bantuan skrining dini (early warning), <em>bukan</em> alat diagnosis.
      Hasil tidak menggantikan penilaian dan keputusan klinis tenaga kesehatan. Selalu lakukan evaluasi langsung
      terhadap pasien. Semua perhitungan dilakukan di perangkat Anda. Riwayat yang Anda <em>simpan</em> tersimpan
      secara lokal di browser perangkat ini (localStorage) — tidak dikirim ke server mana pun. Gunakan tombol
      <em>Hapus Riwayat</em> untuk menghapusnya.
    </p>
  </div>
</div>

<script>
(function () {
  // Severity: 0 = NORMAL (hijau), 1 = HATI-HATI (kuning), 2 = BAHAYA/URGEN (merah)

  // Numeric vital-sign scoring based on the PERT chart.
  function scoreSistole(v) {            // Normal 100–139 | 140–159 | ≥160
    if (v >= 160) return 2;
    if (v >= 140) return 1;
    return 0;
  }
  function scoreDiastole(v) {           // Normal 50–89 | 90–109 | ≥110
    if (v >= 110) return 2;
    if (v >= 90) return 1;
    return 0;
  }
  function scoreNadi(v) {               // Normal 61–110 | 111–120 | >120
    if (v > 120) return 2;
    if (v > 110) return 1;
    return 0;
  }
  function scoreNafas(v) {              // Normal 11–24 | <12 atau 25–30 | <10 atau >30
    if (v < 10 || v > 30) return 2;
    if (v < 12 || v > 24) return 1;
    return 0;
  }
  function scoreSaturasi(v) {           // Normal >95 | <95 | <93
    if (v < 93) return 2;
    if (v < 95) return 1;
    return 0;
  }

  var LABEL = ['NORMAL', 'HATI-HATI', 'BAHAYA / URGEN'];
  var CLS = ['green', 'yellow', 'red'];
  var ACTION = [
    'Lanjutkan pemantauan rutin dan evaluasi oleh dokter sesuai jadwal.',
    'Tingkatkan frekuensi pemantauan. Pertimbangkan pemberian antihipertensi (nifedipine 10 mg) dan MgSO₄ dosis inisial sesuai protokol dan instruksi dokter.',
    'Segera pindahkan ke IGD dengan pemantauan ketat, lakukan evaluasi lebih lanjut, dan persiapkan kemungkinan rujuk ke FKRTL.'
  ];

  var STORAGE_KEY = 'pert-riwayat-v1';
  var lastRecord = null;   // record for the most recent evaluation, awaiting save

  // CSV column order. Keys must match the record object built in pertEvaluate.
  var COLS = [
    'Waktu Simpan', 'Tanggal Kunjungan', 'Nama', 'Alamat',
    'Kesadaran', 'Sesak Nafas', 'Nyeri Kepala', 'Pandangan',
    'Nyeri Dada/Abdomen', 'Berkemih', 'Kondisi Janin', 'Protein Urine',
    'TD Sistole', 'TD Diastole', 'Nadi', 'Nafas (RR)', 'Saturasi O2', 'Hasil'
  ];

  function val(id) { return document.getElementById(id).value; }

  // Selected option text for a <select>, or '' if nothing chosen.
  function selText(id) {
    var el = document.getElementById(id);
    if (!el || el.value === '') return '';
    return el.options[el.selectedIndex].text;
  }

  function pushNum(flags, id, label, scoreFn, unit) {
    var raw = val(id).trim();
    if (raw === '') return null;            // not filled → ignored
    var n = Number(raw);
    if (isNaN(n)) return null;
    var s = scoreFn(n);
    if (s > 0) flags.push({ param: label, detail: n + (unit || ''), sev: s });
    return s;
  }

  function pushSelect(flags, id) {
    var el = document.getElementById(id);
    if (el.value === '') return null;       // not chosen → ignored
    var s = Number(el.value);
    if (s > 0) {
      var txt = el.options[el.selectedIndex].text;
      flags.push({ param: el.getAttribute('data-param'), detail: txt, sev: s });
    }
    return s;
  }

  window.pertEvaluate = function () {
    var flags = [];
    var scores = [];

    ['kesadaran','sesak','nyerikepala','pandangan','nyeridada','berkemih','janin','protein']
      .forEach(function (id) { var s = pushSelect(flags, id); if (s !== null) scores.push(s); });

    [['sistole','TD Sistole',scoreSistole,' mmHg'],
     ['diastole','TD Diastole',scoreDiastole,' mmHg'],
     ['nadi','Nadi',scoreNadi,' x/mnt'],
     ['nafas','Nafas (RR)',scoreNafas,' x/mnt'],
     ['saturasi','Saturasi O₂',scoreSaturasi,'%']
    ].forEach(function (a) { var s = pushNum(flags, a[0], a[1], a[2], a[3]); if (s !== null) scores.push(s); });

    var box = document.getElementById('pertResult');

    if (scores.length === 0) {
      box.className = 'pert-result yellow';
      box.innerHTML = '<h3>Belum ada data</h3><p class="pert-action">Isi minimal satu parameter untuk melihat hasil.</p>';
      box.classList.remove('hidden');
      lastRecord = null;
      document.getElementById('pertSaveRow').classList.add('hidden');
      box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return;
    }

    var overall = Math.max.apply(null, scores);

    // Sort flags worst-first for readability.
    flags.sort(function (a, b) { return b.sev - a.sev; });

    var flagsHtml = '';
    if (flags.length > 0) {
      flagsHtml = '<div class="pert-flags"><strong>Parameter yang menandai:</strong><ul>' +
        flags.map(function (f) {
          var badge = '<span class="pert-badge ' + CLS[f.sev] + '">' + LABEL[f.sev] + '</span>';
          return '<li>' + f.param + ': ' + f.detail + badge + '</li>';
        }).join('') + '</ul></div>';
    } else {
      flagsHtml = '<div class="pert-flags"><strong>Semua parameter yang diisi dalam batas normal.</strong></div>';
    }

    box.className = 'pert-result ' + CLS[overall];
    box.innerHTML =
      '<h3>' + LABEL[overall] + '</h3>' +
      '<p class="pert-action">' + ACTION[overall] + '</p>' +
      flagsHtml;
    box.classList.remove('hidden');

    // Build the record for this evaluation (Waktu Simpan is added on save).
    lastRecord = {
      'Waktu Simpan': '',
      'Tanggal Kunjungan': val('tanggal'),
      'Nama': val('nama'),
      'Alamat': val('alamat'),
      'Kesadaran': selText('kesadaran'),
      'Sesak Nafas': selText('sesak'),
      'Nyeri Kepala': selText('nyerikepala'),
      'Pandangan': selText('pandangan'),
      'Nyeri Dada/Abdomen': selText('nyeridada'),
      'Berkemih': selText('berkemih'),
      'Kondisi Janin': selText('janin'),
      'Protein Urine': selText('protein'),
      'TD Sistole': val('sistole'),
      'TD Diastole': val('diastole'),
      'Nadi': val('nadi'),
      'Nafas (RR)': val('nafas'),
      'Saturasi O2': val('saturasi'),
      'Hasil': LABEL[overall]
    };

    var saveBtn = document.getElementById('pertSaveBtn');
    saveBtn.disabled = false;
    document.getElementById('pertSaveMsg').textContent = '';
    document.getElementById('pertSaveRow').classList.remove('hidden');

    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  window.pertReset = function () {
    document.getElementById('pertForm').reset();
    document.getElementById('pertResult').classList.add('hidden');
    document.getElementById('pertSaveRow').classList.add('hidden');
    lastRecord = null;
  };

  // --- Riwayat (localStorage) + ekspor CSV ---

  function loadHistory() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      var arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr : [];
    } catch (e) {
      return [];
    }
  }

  function saveHistory(arr) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(arr));
      return true;
    } catch (e) {
      return false;
    }
  }

  function pad(n) { return (n < 10 ? '0' : '') + n; }

  function nowStamp() {
    var d = new Date();
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
           ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function updateHistoryUI() {
    var n = loadHistory().length;
    document.getElementById('pertCount').textContent = n;
    document.getElementById('pertCsvBtn').disabled = (n === 0);
    document.getElementById('pertClearBtn').disabled = (n === 0);
  }

  window.pertSave = function () {
    if (!lastRecord) return;
    var rec = {};
    for (var k in lastRecord) { rec[k] = lastRecord[k]; }
    rec['Waktu Simpan'] = nowStamp();

    var hist = loadHistory();
    hist.push(rec);
    var ok = saveHistory(hist);

    var msg = document.getElementById('pertSaveMsg');
    if (ok) {
      msg.style.color = '#2e9e5b';
      msg.textContent = '✓ Tersimpan (' + hist.length + ' entri)';
      document.getElementById('pertSaveBtn').disabled = true;  // prevent duplicate save
      lastRecord = null;                                       // guard against re-save of same entry
    } else {
      msg.style.color = '#d6336c';
      msg.textContent = 'Gagal menyimpan (penyimpanan browser penuh atau diblokir).';
    }
    updateHistoryUI();
  };

  // RFC-4180 style escaping: wrap in quotes and double any inner quotes.
  function csvCell(v) {
    var s = (v === null || v === undefined) ? '' : String(v);
    return '"' + s.replace(/"/g, '""') + '"';
  }

  window.pertDownloadCsv = function () {
    var hist = loadHistory();
    if (hist.length === 0) return;

    var lines = [COLS.map(csvCell).join(',')];
    hist.forEach(function (rec) {
      lines.push(COLS.map(function (c) { return csvCell(rec[c]); }).join(','));
    });
    // CRLF line endings + UTF-8 BOM so Excel reads accents/° correctly.
    var csv = '﻿' + lines.join('\r\n');

    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var d = new Date();
    var fname = 'pert-riwayat-' + d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) + '.csv';

    var a = document.createElement('a');
    a.href = url;
    a.download = fname;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  };

  window.pertClearHistory = function () {
    if (loadHistory().length === 0) return;
    if (!window.confirm('Hapus semua riwayat yang tersimpan di perangkat ini? Tindakan ini tidak dapat dibatalkan.')) return;
    try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
    updateHistoryUI();
  };

  // Initialise history counter on load.
  updateHistoryUI();
})();
</script>
{{< /rawhtml >}}
