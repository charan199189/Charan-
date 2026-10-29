/**
 * ScamShield - Main Application Controller
 * Handles Navigation, Scanning Pipelines, QR Generation & Camera Decoding,
 * LocalStorage History, Interactive Awareness Quiz, Audio Feedback, and Theme Switching.
 */

const App = (function () {
  // Application State
  const state = {
    currentScreen: 'home',
    theme: localStorage.getItem('scamshield_theme') || 'dark',
    soundEnabled: localStorage.getItem('scamshield_sound') !== 'false',
    history: [],
    stats: {
      totalScans: 0,
      scansToday: 0,
      highRiskDetected: 0,
      qrCreated: 0,
      lastDate: new Date().toDateString()
    },
    activeResult: null,
    currentQRType: 'text',
    generatedQRData: null,
    cameraStream: null,
    cameraScanning: false,
    quizIndex: 0,
    quizScore: 0,
    quizAnswered: false,
    historyFilter: 'all'
  };

  // Audio Synth via Web Audio API
  let audioCtx = null;
  function getAudioContext() {
    if (!audioCtx && (window.AudioContext || window.webkitAudioContext)) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      audioCtx = new AudioContextClass();
    }
    return audioCtx;
  }

  function playSound(type) {
    if (!state.soundEnabled) return;
    try {
      const ctx = getAudioContext();
      if (!ctx) return;
      if (ctx.state === 'suspended') {
        ctx.resume();
      }
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      const now = ctx.currentTime;
      if (type === 'scan') {
        // Futuristic cyber blip
        osc.type = 'sine';
        osc.frequency.setValueAtTime(440, now);
        osc.frequency.exponentialRampToValueAtTime(880, now + 0.12);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
        osc.start(now);
        osc.stop(now + 0.15);
      } else if (type === 'high-risk') {
        // Warning buzz
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(220, now);
        osc.frequency.linearRampToValueAtTime(140, now + 0.28);
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
        osc.start(now);
        osc.stop(now + 0.3);
      } else if (type === 'safe') {
        // Harmonic chime
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(523.25, now); // C5
        osc.frequency.setValueAtTime(659.25, now + 0.08); // E5
        gain.gain.setValueAtTime(0.1, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
        osc.start(now);
        osc.stop(now + 0.25);
      }
    } catch (e) {
      // Audio autoplay policy catch
    }
  }

  // LocalStorage Keys
  const STORAGE_KEYS = {
    HISTORY: 'scamshield_history_v1',
    STATS: 'scamshield_stats_v1',
    THEME: 'scamshield_theme',
    SOUND: 'scamshield_sound'
  };

  /**
   * Initialize App
   */
  function init() {
    loadTheme();
    loadStorageData();
    updateStatsDisplay();
    renderRecentHomeScans();
    renderHistoryList();
    initQuiz();
    handleGenerateQR(); // Pre-generate default QR
    setupEventListeners();
  }

  function setupEventListeners() {
    // Keyboard shortcuts or enter key for inputs
    const linkInput = document.getElementById('input-link');
    if (linkInput) {
      linkInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleScanLink();
      });
    }
    const webInput = document.getElementById('input-website');
    if (webInput) {
      webInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleScanWebsite();
      });
    }
  }

  /**
   * Navigation Router
   */
  function navigateTo(screenId) {
    // If navigating away from camera, turn it off
    if (state.currentScreen === 'qrscan' && screenId !== 'qrscan') {
      stopCameraStream();
    }

    state.currentScreen = screenId;

    // Toggle Screen Views
    const views = document.querySelectorAll('.screen-view');
    views.forEach(view => view.classList.remove('active'));

    const targetView = document.getElementById(`view-${screenId}`);
    if (targetView) {
      targetView.classList.add('active');
    }

    // Update Nav Bar active states (Sidebar and Mobile Bottom Nav)
    const allNavLinks = document.querySelectorAll('.nav-link, .mobile-nav-item');
    allNavLinks.forEach(link => {
      if (link.getAttribute('data-target') === screenId) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // View specific hooks
    if (screenId === 'home') {
      updateStatsDisplay();
      renderRecentHomeScans();
    } else if (screenId === 'history') {
      renderHistoryList();
    } else if (screenId === 'awareness') {
      if (state.quizIndex === 0 && !state.quizAnswered) {
        loadQuizQuestion(0);
      }
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  /**
   * Character Counter for textarea
   */
  function updateCharCount(inputId, labelId) {
    const el = document.getElementById(inputId);
    const label = document.getElementById(labelId);
    if (el && label) {
      label.textContent = `${el.value.length} / 1000 characters`;
    }
  }

  /**
   * Clear message input
   */
  function clearMessageInput() {
    const input = document.getElementById('input-message');
    if (input) {
      input.value = '';
      updateCharCount('input-message', 'msg-char-count');
    }
  }

  /**
   * Load Demo Samples
   */
  function loadDemoMessage(sampleId) {
    const sample = ScamAnalyzer.DEMO_SAMPLES.messages.find(m => m.id === sampleId);
    if (sample) {
      const input = document.getElementById('input-message');
      input.value = sample.text;
      updateCharCount('input-message', 'msg-char-count');
      showToast(`Loaded: ${sample.name}`);
    }
  }

  function loadDemoLink(sampleId) {
    const sample = ScamAnalyzer.DEMO_SAMPLES.links.find(l => l.id === sampleId);
    if (sample) {
      const input = document.getElementById('input-link');
      input.value = sample.url;
      showToast(`Loaded: ${sample.name}`);
    }
  }

  function loadDemoWebsite(sampleId) {
    const sample = ScamAnalyzer.DEMO_SAMPLES.websites.find(w => w.id === sampleId);
    if (sample) {
      const input = document.getElementById('input-website');
      input.value = sample.url;
      showToast(`Loaded: ${sample.name}`);
    }
  }

  /**
   * Reusable Scanning Animation Engine
   */
  function runScanningAnimation(callback) {
    const modal = document.getElementById('scanning-modal');
    const steps = [
      document.getElementById('step-1'),
      document.getElementById('step-2'),
      document.getElementById('step-3'),
      document.getElementById('step-4')
    ];

    // Reset steps
    steps.forEach(s => s.classList.remove('completed'));
    modal.classList.add('active');
    playSound('scan');

    // Sequential tick animations over 1.8 seconds
    setTimeout(() => { steps[0].classList.add('completed'); }, 350);
    setTimeout(() => { steps[1].classList.add('completed'); }, 750);
    setTimeout(() => { steps[2].classList.add('completed'); }, 1200);
    setTimeout(() => { steps[3].classList.add('completed'); }, 1600);

    setTimeout(() => {
      modal.classList.remove('active');
      if (typeof callback === 'function') {
        callback();
      }
    }, 1900);
  }

  /**
   * SCAN HANDLERS
   */
  function handleScanMessage() {
    const text = document.getElementById('input-message').value.trim();
    if (!text) {
      showToast('Please paste or type a message first!');
      return;
    }

    runScanningAnimation(() => {
      const result = ScamAnalyzer.analyzeMessage(text);
      displayResult(result);
    });
  }

  function handleScanLink() {
    const url = document.getElementById('input-link').value.trim();
    if (!url) {
      showToast('Please enter a URL to scan!');
      return;
    }

    runScanningAnimation(() => {
      const result = ScamAnalyzer.analyzeLink(url);
      displayResult(result);
    });
  }

  function handleScanWebsite() {
    const url = document.getElementById('input-website').value.trim();
    if (!url) {
      showToast('Please enter a website address!');
      return;
    }

    runScanningAnimation(() => {
      const result = ScamAnalyzer.analyzeWebsite(url);
      displayResult(result);
    });
  }

  /**
   * Display Scan Result
   */
  function displayResult(result) {
    state.activeResult = result;

    // Record in history & update stats
    saveScanResult(result);

    // Play result audio cue
    if (result.score >= 61) {
      playSound('high-risk');
    } else {
      playSound('safe');
    }

    // Populate Header Banner
    const banner = document.getElementById('res-header-banner');
    const catIcon = document.getElementById('res-cat-icon');
    const catText = document.getElementById('res-cat-text');
    const scoreNum = document.getElementById('res-score-number');
    const tagline = document.getElementById('res-tagline-text');

    banner.className = `result-card-header ${result.categoryClass}`;
    scoreNum.textContent = result.score;
    catText.textContent = result.category;

    if (result.category === 'High Risk') {
      catIcon.textContent = '⚠️';
      tagline.textContent = 'High-risk threats or deceptive patterns detected. Do not comply.';
    } else if (result.category === 'Suspicious') {
      catIcon.textContent = '⚡';
      tagline.textContent = 'Suspicious elements were detected. Exercise heightened caution.';
    } else {
      catIcon.textContent = '🛡️';
      tagline.textContent = 'No obvious malicious patterns detected. Stay vigilant.';
    }

    // Issues Count & List
    const issuesCount = document.getElementById('res-issues-count');
    const issuesList = document.getElementById('res-issues-list');
    issuesCount.textContent = (result.issues || []).length;
    issuesList.innerHTML = '';

    if (!result.issues || result.issues.length === 0) {
      issuesList.innerHTML = `
        <div class="issue-card severity-low">
          <div class="issue-header">
            <span class="issue-title">✓ Standard Structure</span>
            <span class="issue-tag">Safe Pattern</span>
          </div>
          <div class="issue-desc">No deceptive urgency, fraud keywords, or abnormal domain patterns were found.</div>
        </div>
      `;
    } else {
      result.issues.forEach(issue => {
        const div = document.createElement('div');
        div.className = `issue-card severity-${issue.severity || 'medium'}`;
        div.innerHTML = `
          <div class="issue-header">
            <span class="issue-title">
              ${issue.severity === 'high' ? '⚠️' : '⚡'} ${escapeHtml(issue.title)}
            </span>
            <span class="issue-tag">${escapeHtml(issue.tag || 'Pattern')}</span>
          </div>
          <div class="issue-desc">${escapeHtml(issue.description)}</div>
          ${issue.matchExcerpt ? `<div class="issue-excerpt">Matched: "${escapeHtml(issue.matchExcerpt)}"</div>` : ''}
        `;
        issuesList.appendChild(div);
      });
    }

    // Extracted Content Preview
    const extType = document.getElementById('res-extracted-type');
    const extVal = document.getElementById('res-extracted-val');
    extType.textContent = result.type === 'QR' ? `QR Payload (${result.qrType})` : `${result.type} Input`;

    const rawContent = result.rawInput || result.rawContent || result.parsedUrl || '';
    extVal.textContent = rawContent.length > 250 ? rawContent.substring(0, 250) + '...' : rawContent;

    // Explanations Tab
    const explanationList = document.getElementById('res-explanation-list');
    explanationList.innerHTML = '';
    (result.reasons || []).forEach(r => {
      const p = document.createElement('div');
      p.innerHTML = `• ${escapeHtml(r)}`;
      explanationList.appendChild(p);
    });

    // Suggestions Tab
    const suggestionsList = document.getElementById('res-suggestions-list');
    suggestionsList.innerHTML = '';
    (result.recommendations || []).forEach(s => {
      const p = document.createElement('div');
      p.innerHTML = `✓ ${escapeHtml(s)}`;
      suggestionsList.appendChild(p);
    });

    // Reset active tab to Details
    switchResultTab('details');

    // Show Modal
    document.getElementById('result-modal').classList.add('active');
  }

  function switchResultTab(tabName) {
    const btns = document.querySelectorAll('.result-tab-btn');
    btns.forEach(b => {
      if (b.getAttribute('data-pane') === tabName) {
        b.classList.add('active');
      } else {
        b.classList.remove('active');
      }
    });

    const panes = document.querySelectorAll('.result-tab-pane');
    panes.forEach(p => p.classList.remove('active'));

    const activePane = document.getElementById(`res-pane-${tabName}`);
    if (activePane) activePane.classList.add('active');
  }

  function closeResultModal() {
    document.getElementById('result-modal').classList.remove('active');
  }

  function copyCurrentResultPayload() {
    if (!state.activeResult) return;
    const text = state.activeResult.rawInput || state.activeResult.rawContent || state.activeResult.parsedUrl || '';
    navigator.clipboard.writeText(text).then(() => {
      showToast('Copied to clipboard!');
    }).catch(() => {
      showToast('Failed to copy');
    });
  }

  function reportScamFeedback() {
    showToast('Report logged locally. Thank you for keeping everyone safe!');
    closeResultModal();
  }

  /**
   * QR CODE SCANNER (Camera + File Upload + Preset Samples)
   */
  async function toggleCameraStream() {
    const label = document.getElementById('camera-btn-label');
    if (state.cameraScanning) {
      stopCameraStream();
    } else {
      await startCameraStream();
    }
  }

  async function startCameraStream() {
    const video = document.getElementById('camera-video');
    const statusText = document.getElementById('scanner-status-text');
    const label = document.getElementById('camera-btn-label');

    try {
      statusText.textContent = 'Requesting camera access...';
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }
      });
      state.cameraStream = stream;
      state.cameraScanning = true;
      video.srcObject = stream;
      await video.play();

      label.textContent = 'Stop Camera';
      statusText.textContent = 'Align QR code within frame';
      requestAnimationFrame(scanVideoFrame);
    } catch (err) {
      statusText.textContent = 'Camera not available. Try Upload Image.';
      label.textContent = 'Start Camera';
      state.cameraScanning = false;
      showToast('Camera access denied or unavailable. Use Image Upload!');
    }
  }

  function stopCameraStream() {
    if (state.cameraStream) {
      state.cameraStream.getTracks().forEach(track => track.stop());
      state.cameraStream = null;
    }
    state.cameraScanning = false;
    const label = document.getElementById('camera-btn-label');
    if (label) label.textContent = 'Start Camera';
    const statusText = document.getElementById('scanner-status-text');
    if (statusText) statusText.textContent = 'Camera stopped';
  }

  function scanVideoFrame() {
    if (!state.cameraScanning) return;
    const video = document.getElementById('camera-video');
    const canvas = document.getElementById('qr-scan-canvas');

    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      if (window.jsQR) {
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'dontInvert'
        });

        if (code && code.data) {
          stopCameraStream();
          document.getElementById('scanner-status-text').textContent = 'QR Code Detected!';
          runScanningAnimation(() => {
            const result = ScamAnalyzer.analyzeQRCode(code.data);
            displayResult(result);
          });
          return;
        }
      }
    }
    requestAnimationFrame(scanVideoFrame);
  }

  function handleImageUpload(input) {
    const file = input.files && input.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
      const img = new Image();
      img.onload = function () {
        const canvas = document.getElementById('qr-scan-canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);

        const imageData = ctx.getImageData(0, 0, img.width, img.height);
        if (window.jsQR) {
          const code = jsQR(imageData.data, imageData.width, imageData.height);
          if (code && code.data) {
            runScanningAnimation(() => {
              const result = ScamAnalyzer.analyzeQRCode(code.data);
              displayResult(result);
            });
          } else {
            showToast('No QR code detected in this image. Try another.');
          }
        }
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  function loadSampleQRScan(sampleType) {
    // Immediate preset QR demo test
    let payload = 'http://paypa1-secure-billing-verify.xyz/login?session=expiring';
    if (sampleType === 'safe') {
      payload = 'https://www.scamshield.app/docs';
    } else if (sampleType === 'wifi') {
      payload = 'WIFI:T:nopass;S:Free_Airport_WiFi_Unsecured;P:;;';
    }

    runScanningAnimation(() => {
      const result = ScamAnalyzer.analyzeQRCode(payload);
      displayResult(result);
    });
  }

  /**
   * QR CODE GENERATOR
   */
  function switchQRType(type) {
    state.currentQRType = type;

    // Tabs
    const tabs = document.querySelectorAll('#qr-create-tabs .tab-btn');
    tabs.forEach(t => {
      if (t.getAttribute('data-type') === type) {
        t.classList.add('active');
      } else {
        t.classList.remove('active');
      }
    });

    // Form Panels
    const panels = document.querySelectorAll('.qr-form-panel');
    panels.forEach(p => p.style.display = 'none');

    const activePanel = document.getElementById(`qr-form-${type}`);
    if (activePanel) activePanel.style.display = 'block';
  }

  function compileQRPayload() {
    const type = state.currentQRType;
    let payload = '';

    if (type === 'text') {
      payload = document.getElementById('qr-input-text').value.trim();
    } else if (type === 'link') {
      payload = document.getElementById('qr-input-link').value.trim();
    } else if (type === 'message') {
      const phone = document.getElementById('qr-input-msg-phone').value.trim();
      const body = document.getElementById('qr-input-msg-body').value.trim();
      payload = `SMSTO:${phone}:${body}`;
    } else if (type === 'wifi') {
      const ssid = document.getElementById('qr-input-wifi-ssid').value.trim() || 'MyNetwork';
      const pass = document.getElementById('qr-input-wifi-pass').value.trim() || '';
      const enc = document.getElementById('qr-input-wifi-type').value;
      payload = `WIFI:T:${enc};S:${ssid};P:${pass};;`;
    } else if (type === 'contact') {
      const name = document.getElementById('qr-input-contact-name').value.trim() || 'Contact';
      const phone = document.getElementById('qr-input-contact-phone').value.trim() || '';
      const email = document.getElementById('qr-input-contact-email').value.trim() || '';
      payload = `BEGIN:VCARD\nVERSION:3.0\nFN:${name}\nTEL:${phone}\nEMAIL:${email}\nEND:VCARD`;
    }

    return payload || 'https://scamshield.app';
  }

  function handleGenerateQR() {
    const payload = compileQRPayload();
    state.generatedQRData = payload;

    const renderArea = document.getElementById('qr-render-area');
    renderArea.innerHTML = '';

    if (window.QRCode) {
      new QRCode(renderArea, {
        text: payload,
        width: 190,
        height: 190,
        colorDark: '#0b0f19',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.H
      });
      state.stats.qrCreated += 1;
      saveStats();
      updateStatsDisplay();
      showToast('QR Code generated!');
    }
  }

  function downloadQRCode() {
    const renderArea = document.getElementById('qr-render-area');
    const canvas = renderArea.querySelector('canvas');
    const img = renderArea.querySelector('img');

    let dataUrl = '';
    if (canvas) {
      dataUrl = canvas.toDataURL('image/png');
    } else if (img && img.src) {
      dataUrl = img.src;
    }

    if (!dataUrl) {
      showToast('Generate a QR code first!');
      return;
    }

    const a = document.createElement('a');
    a.href = dataUrl;
    a.download = `ScamShield_QR_${Date.now()}.png`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast('Download started!');
  }

  function shareQRCode() {
    if (!state.generatedQRData) return;
    if (navigator.share) {
      navigator.share({
        title: 'ScamShield QR Code',
        text: state.generatedQRData
      }).catch(() => {});
    } else {
      navigator.clipboard.writeText(state.generatedQRData).then(() => {
        showToast('QR content copied to clipboard!');
      });
    }
  }

  function scanGeneratedQR() {
    if (!state.generatedQRData) {
      showToast('Generate a QR code first!');
      return;
    }
    runScanningAnimation(() => {
      const result = ScamAnalyzer.analyzeQRCode(state.generatedQRData);
      displayResult(result);
    });
  }

  /**
   * SCAN HISTORY & LOCALSTORAGE
   */
  function loadStorageData() {
    try {
      const storedHistory = localStorage.getItem(STORAGE_KEYS.HISTORY);
      state.history = storedHistory ? JSON.parse(storedHistory) : [];

      const storedStats = localStorage.getItem(STORAGE_KEYS.STATS);
      if (storedStats) {
        state.stats = JSON.parse(storedStats);
        // Reset scansToday if day changed
        if (state.stats.lastDate !== new Date().toDateString()) {
          state.stats.scansToday = 0;
          state.stats.lastDate = new Date().toDateString();
        }
      }
    } catch (e) {
      state.history = [];
    }
  }

  function saveScanResult(result) {
    const item = {
      id: 'scan_' + Date.now(),
      type: result.type,
      title: result.rawInput || result.rawContent || result.parsedUrl || 'Scan',
      score: result.score,
      category: result.category,
      categoryClass: result.categoryClass,
      summary: result.summary,
      timestamp: result.timestamp || new Date().toISOString(),
      fullData: result
    };

    // Prepend
    state.history.unshift(item);
    if (state.history.length > 50) state.history.pop();

    try {
      localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(state.history));
    } catch (e) {}

    // Update Stats
    state.stats.totalScans += 1;
    state.stats.scansToday += 1;
    if (result.score >= 61) {
      state.stats.highRiskDetected += 1;
    }
    saveStats();
    updateStatsDisplay();
  }

  function saveStats() {
    try {
      localStorage.setItem(STORAGE_KEYS.STATS, JSON.stringify(state.stats));
    } catch (e) {}
  }

  function updateStatsDisplay() {
    const todayEl = document.getElementById('stat-scans-today');
    const totalEl = document.getElementById('stat-total-scans');
    const riskEl = document.getElementById('stat-high-risk');
    const qrEl = document.getElementById('stat-qr-created');

    if (todayEl) todayEl.textContent = state.stats.scansToday;
    if (totalEl) totalEl.textContent = state.stats.totalScans;
    if (riskEl) riskEl.textContent = state.stats.highRiskDetected;
    if (qrEl) qrEl.textContent = state.stats.qrCreated;
  }

  function renderRecentHomeScans() {
    const list = document.getElementById('home-recent-scans-list');
    if (!list) return;

    if (state.history.length === 0) {
      list.innerHTML = `
        <div class="empty-state" style="padding: 20px;">
          <p>No recent scans. Try scanning a message or URL above!</p>
        </div>
      `;
      return;
    }

    list.innerHTML = '';
    const recents = state.history.slice(0, 3);
    recents.forEach(item => {
      const card = createHistoryItemCard(item);
      list.appendChild(card);
    });
  }

  function filterHistory(type) {
    state.historyFilter = type;
    const pills = document.querySelectorAll('.history-filter-scroll .filter-pill');
    pills.forEach(p => {
      if (p.getAttribute('data-filter') === type) {
        p.classList.add('active');
      } else {
        p.classList.remove('active');
      }
    });
    renderHistoryList();
  }

  function renderHistoryList() {
    const container = document.getElementById('history-items-container');
    if (!container) return;

    let items = state.history;
    if (state.historyFilter !== 'all') {
      items = items.filter(i => i.type === state.historyFilter);
    }

    if (items.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
          <p>No history records found for "${state.historyFilter}".</p>
        </div>
      `;
      return;
    }

    container.innerHTML = '';
    items.forEach(item => {
      container.appendChild(createHistoryItemCard(item));
    });
  }

  function createHistoryItemCard(item) {
    const card = document.createElement('div');
    card.className = 'history-item-card';
    card.onclick = () => {
      if (item.fullData) {
        displayResult(item.fullData);
      }
    };

    let icon = '💬';
    if (item.type === 'Link') icon = '🔗';
    if (item.type === 'Website') icon = '🌐';
    if (item.type === 'QR') icon = '📷';

    const timeAgo = formatTimeAgo(new Date(item.timestamp));

    card.innerHTML = `
      <div class="history-item-left">
        <div class="history-type-icon">${icon}</div>
        <div class="history-item-info">
          <div class="history-title-preview">${escapeHtml(item.title)}</div>
          <div class="history-item-meta">
            <span>${item.type}</span>
            <span>•</span>
            <span>${timeAgo}</span>
          </div>
        </div>
      </div>
      <div class="history-score-badge ${item.categoryClass}">
        ${item.score}/100 • ${item.category}
      </div>
    `;
    return card;
  }

  function confirmClearHistory() {
    if (confirm('Are you sure you want to clear your scan history and statistics?')) {
      state.history = [];
      state.stats = {
        totalScans: 0,
        scansToday: 0,
        highRiskDetected: 0,
        qrCreated: 0,
        lastDate: new Date().toDateString()
      };
      localStorage.removeItem(STORAGE_KEYS.HISTORY);
      saveStats();
      updateStatsDisplay();
      renderRecentHomeScans();
      renderHistoryList();
      showToast('Scan history and stats reset.');
    }
  }

  function exportHistory() {
    if (state.history.length === 0) {
      showToast('No history to export!');
      return;
    }
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.history, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `ScamShield_History_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast('History exported as JSON!');
  }

  function loadDemoDataset() {
    const demoItems = [
      {
        id: 'demo_1',
        type: 'Message',
        title: 'URGENT: Chase account suspended. Verify OTP immediately: http://chase-update.xyz/login',
        score: 86,
        category: 'High Risk',
        categoryClass: 'high-risk',
        summary: 'High-risk patterns detected. Likely an imitation, insecure, or deceptive link.',
        timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
        fullData: ScamAnalyzer.analyzeMessage('URGENT: Chase account suspended. Verify OTP immediately: http://chase-update.xyz/login')
      },
      {
        id: 'demo_2',
        type: 'Link',
        title: 'https://tinyurl.com/free-gift-card-claim99',
        score: 55,
        category: 'Suspicious',
        categoryClass: 'suspicious',
        summary: 'URL Shortener detected. Destination server is obscured.',
        timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
        fullData: ScamAnalyzer.analyzeLink('https://tinyurl.com/free-gift-card-claim99')
      },
      {
        id: 'demo_3',
        type: 'Website',
        title: 'https://www.wikipedia.org',
        score: 10,
        category: 'Looks Safe',
        categoryClass: 'safe',
        summary: 'Domain structure aligns with standard conventions.',
        timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
        fullData: ScamAnalyzer.analyzeWebsite('https://www.wikipedia.org')
      },
      {
        id: 'demo_4',
        type: 'QR',
        title: 'WIFI:T:nopass;S:Free_Airport_WiFi_Unsecured;P:;;',
        score: 65,
        category: 'High Risk',
        categoryClass: 'high-risk',
        summary: 'Unsecured Open WiFi Network with no encryption.',
        timestamp: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
        fullData: ScamAnalyzer.analyzeQRCode('WIFI:T:nopass;S:Free_Airport_WiFi_Unsecured;P:;;')
      }
    ];

    state.history = demoItems;
    state.stats.totalScans = demoItems.length + 5;
    state.stats.scansToday = demoItems.length;
    state.stats.highRiskDetected = 2;
    state.stats.qrCreated = 3;

    try {
      localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(state.history));
      saveStats();
    } catch (e) {}

    updateStatsDisplay();
    renderRecentHomeScans();
    renderHistoryList();
    showToast('Demo dataset loaded successfully!');
  }

  /**
   * INTERACTIVE AWARENESS QUIZ
   */
  function initQuiz() {
    state.quizIndex = 0;
    state.quizScore = 0;
    state.quizAnswered = false;
    loadQuizQuestion(0);
  }

  function loadQuizQuestion(index) {
    const quizList = ScamAnalyzer.DEMO_SAMPLES.quiz;
    if (index >= quizList.length) {
      // Quiz complete
      renderQuizSummary();
      return;
    }

    state.quizIndex = index;
    state.quizAnswered = false;

    const q = quizList[index];
    const progressEl = document.getElementById('quiz-progress-label');
    const scenarioEl = document.getElementById('quiz-scenario-content');
    const optionsEl = document.getElementById('quiz-options-container');
    const feedbackEl = document.getElementById('quiz-feedback-area');
    const actionRow = document.getElementById('quiz-actions-row');

    if (progressEl) progressEl.textContent = `Question ${index + 1} of ${quizList.length}`;
    if (scenarioEl) scenarioEl.textContent = q.scenario;
    if (feedbackEl) feedbackEl.classList.remove('active');
    if (actionRow) actionRow.style.display = 'none';

    if (optionsEl) {
      optionsEl.innerHTML = '';
      q.options.forEach((optText, optIdx) => {
        const btn = document.createElement('button');
        btn.className = 'quiz-option-btn';
        btn.textContent = optText;
        btn.onclick = () => handleQuizSelection(optIdx, q.correctIndex, q.explanation);
        optionsEl.appendChild(btn);
      });
    }
  }

  function handleQuizSelection(selectedIdx, correctIdx, explanation) {
    if (state.quizAnswered) return;
    state.quizAnswered = true;

    const options = document.querySelectorAll('.quiz-option-btn');
    options.forEach((btn, idx) => {
      btn.disabled = true;
      if (idx === correctIdx) {
        btn.classList.add('correct');
      } else if (idx === selectedIdx) {
        btn.classList.add('wrong');
      }
    });

    const isCorrect = selectedIdx === correctIdx;
    if (isCorrect) {
      state.quizScore += 1;
      playSound('safe');
    } else {
      playSound('high-risk');
    }

    const feedbackEl = document.getElementById('quiz-feedback-area');
    const headlineEl = document.getElementById('feedback-headline-text');
    const explanationEl = document.getElementById('feedback-explanation-text');
    const actionRow = document.getElementById('quiz-actions-row');

    headlineEl.className = `feedback-headline ${isCorrect ? 'correct' : 'wrong'}`;
    headlineEl.textContent = isCorrect ? '✓ Spot on! Correct Answer' : '✕ Careful! That\'s a Scam Trap';
    explanationEl.textContent = explanation;
    feedbackEl.classList.add('active');
    actionRow.style.display = 'flex';
  }

  function nextQuizQuestion() {
    loadQuizQuestion(state.quizIndex + 1);
  }

  function renderQuizSummary() {
    const total = ScamAnalyzer.DEMO_SAMPLES.quiz.length;
    const score = state.quizScore;
    const scenarioEl = document.getElementById('quiz-scenario-content');
    const optionsEl = document.getElementById('quiz-options-container');
    const feedbackEl = document.getElementById('quiz-feedback-area');
    const progressEl = document.getElementById('quiz-progress-label');
    const actionRow = document.getElementById('quiz-actions-row');

    if (progressEl) progressEl.textContent = 'Quiz Completed';
    if (feedbackEl) feedbackEl.classList.remove('active');

    scenarioEl.innerHTML = `
      <div style="text-align: center; padding: 10px 0;">
        <div style="font-size: 2.2rem; margin-bottom: 8px;">${score >= 4 ? '🛡️🎉' : '⚠️📖'}</div>
        <h4 style="font-size: 1.2rem; font-weight: 800; color: #fff; margin-bottom: 6px;">
          You scored ${score} out of ${total}!
        </h4>
        <p style="font-size: 0.85rem; color: var(--text-secondary);">
          ${score >= 4
            ? 'Awesome vigilance! You have sharp cyber instincts.'
            : 'Keep reviewing the awareness cards above to stay alert against phishing!'}
        </p>
      </div>
    `;

    optionsEl.innerHTML = `
      <button class="btn-primary" style="width: 100%;" onclick="App.initQuiz()">
        Retake Quiz
      </button>
    `;
    actionRow.style.display = 'none';
  }

  /**
   * THEME & PREFERENCES
   */
  function loadTheme() {
    document.documentElement.setAttribute('data-theme', state.theme);
    const themeSwitch = document.getElementById('theme-switch');
    if (themeSwitch) {
      themeSwitch.checked = state.theme === 'dark';
    }
  }

  function toggleTheme() {
    const newTheme = state.theme === 'dark' ? 'light' : 'dark';
    handleThemeToggle(newTheme === 'dark');
  }

  function handleThemeToggle(isDark) {
    state.theme = isDark ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', state.theme);
    localStorage.setItem(STORAGE_KEYS.THEME, state.theme);
    const themeSwitch = document.getElementById('theme-switch');
    if (themeSwitch) themeSwitch.checked = isDark;
    showToast(`Switched to ${state.theme} mode`);
  }

  function handleSoundToggle(enabled) {
    state.soundEnabled = enabled;
    localStorage.setItem(STORAGE_KEYS.SOUND, enabled ? 'true' : 'false');
    showToast(enabled ? 'Audio feedback enabled' : 'Audio muted');
  }

  function toggleDrawer(open) {
    const drawer = document.getElementById('notification-drawer');
    if (open) {
      drawer.classList.add('active');
    } else {
      drawer.classList.remove('active');
    }
  }

  /**
   * Toast Notifications
   */
  function showToast(msg) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast-msg';
    toast.innerHTML = `<span>🛡️</span><span>${escapeHtml(msg)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s ease';
      setTimeout(() => {
        if (container.contains(toast)) container.removeChild(toast);
      }, 300);
    }, 2800);
  }

  /**
   * Utilities
   */
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function formatTimeAgo(date) {
    const diffSec = Math.floor((Date.now() - date.getTime()) / 1000);
    if (diffSec < 60) return 'Just now';
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)} min ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} hr ago`;
    return `${Math.floor(diffSec / 86400)} days ago`;
  }

  // Initialize on DOM load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return {
    navigateTo,
    updateCharCount,
    clearMessageInput,
    loadDemoMessage,
    loadDemoLink,
    loadDemoWebsite,
    handleScanMessage,
    handleScanLink,
    handleScanWebsite,
    switchResultTab,
    closeResultModal,
    copyCurrentResultPayload,
    reportScamFeedback,
    toggleCameraStream,
    handleImageUpload,
    loadSampleQRScan,
    switchQRType,
    handleGenerateQR,
    downloadQRCode,
    shareQRCode,
    scanGeneratedQR,
    filterHistory,
    confirmClearHistory,
    exportHistory,
    loadDemoDataset,
    initQuiz,
    nextQuizQuestion,
    toggleTheme,
    handleThemeToggle,
    handleSoundToggle,
    toggleDrawer
  };
})();
