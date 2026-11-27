/**
 * PhishGuard Front-end Client Engine
 * Provides interactive preset loading, live preview analysis, table filtering, and detail modals.
 */

// Sample test scenarios for 1-click evaluation
const SAMPLES = {
  paypal: {
    sender: "billing-security@paypaI-notice.example",
    subject: "Action required: Account suspended immediately",
    body: "Dear Customer,\n\nWe detected unauthorized login attempts. Your account has been suspended to protect your funds.\nVerify your identity immediately at http://paypal-verify.example/login to avoid permanent suspension. Please enter your email and password."
  },
  mailbox: {
    sender: "it-helpdesk@internal-company.example",
    subject: "Urgent: Mailbox storage quota exceeded",
    body: "Your corporate mailbox is 98% full and will stop receiving incoming emails today.\nSign in at http://mailbox-reset.example to expand your quota immediately."
  },
  payroll: {
    sender: "hr-payroll@corporate-service.example",
    subject: "Updated direct deposit payroll form",
    body: "All employees must verify their bank details and routing number before end of day for upcoming salary disbursement.\nPlease review the payroll document and submit your account credentials."
  },
  bank: {
    sender: "alerts@verified-bank.example",
    subject: "Security Alert: New sign-in detected from Chrome on Windows",
    body: "A new sign-in was detected for your online banking profile on Nov 17 at 14:10.\nIf this was you, no action is needed.\nIf this was NOT you, please visit https://bank.example/security using your saved bookmark or mobile app to review recent activity."
  },
  lunch: {
    sender: "maya@company.example",
    subject: "Lunch tomorrow around noon?",
    body: "Hey team,\n\nAre you free to grab tacos tomorrow around noon? Let me know if that works for you!"
  }
};

/**
 * Loads a preset scenario into the scanner form
 */
function loadSample(key) {
  const sample = SAMPLES[key];
  if (!sample) return;

  const senderInput = document.getElementById('sender');
  const subjectInput = document.getElementById('subject');
  const bodyInput = document.getElementById('body');

  if (senderInput && subjectInput && bodyInput) {
    senderInput.value = sample.sender;
    subjectInput.value = sample.subject;
    bodyInput.value = sample.body;

    // Smooth scroll to the scanner form
    const scannerCard = document.getElementById('scanner-card');
    if (scannerCard) {
      scannerCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
      scannerCard.classList.add('scanner-highlight');
      setTimeout(() => scannerCard.classList.remove('scanner-highlight'), 1200);
    }

    // Auto-run live preview for immediate feedback
    performQuickScan();
  }
}

/**
 * Clears scanner form fields and live preview box
 */
function clearForm() {
  const senderInput = document.getElementById('sender');
  const subjectInput = document.getElementById('subject');
  const bodyInput = document.getElementById('body');
  const liveResult = document.getElementById('live-scan-result');

  if (senderInput) senderInput.value = '';
  if (subjectInput) subjectInput.value = '';
  if (bodyInput) bodyInput.value = '';
  if (liveResult) liveResult.classList.add('hidden');
}

/**
 * Performs a real-time AJAX check via /api/analyze without saving to database
 */
async function performQuickScan() {
  const sender = document.getElementById('sender')?.value.trim() || '';
  const subject = document.getElementById('subject')?.value.trim() || '';
  const body = document.getElementById('body')?.value.trim() || '';

  if (!sender && !subject && !body) {
    alert('Please enter a sender, subject, or message body to analyze.');
    return;
  }

  const liveResult = document.getElementById('live-scan-result');
  const verdictBadge = document.getElementById('live-verdict-badge');
  const scoreText = document.getElementById('live-score-text');
  const scoreBar = document.getElementById('live-score-bar');
  const reasonsList = document.getElementById('live-reasons-list');

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender, subject, body })
    });

    if (!response.ok) throw new Error('Analysis request failed');
    const data = await response.json();

    const scorePct = Math.round(data.score * 100);

    if (scoreText) scoreText.textContent = `${scorePct}%`;
    if (scoreBar) {
      scoreBar.style.width = `${scorePct}%`;
      scoreBar.className = 'progress-bar-fill';
      if (scorePct >= 55) {
        scoreBar.classList.add('fill-danger');
      } else if (scorePct >= 35) {
        scoreBar.classList.add('fill-warning');
      } else {
        scoreBar.classList.add('fill-success');
      }
    }

    if (verdictBadge) {
      verdictBadge.className = 'badge';
      if (data.status === 'quarantined') {
        verdictBadge.classList.add('badge-danger');
        verdictBadge.textContent = 'Quarantined (Phishing)';
      } else if (data.status === 'review') {
        verdictBadge.classList.add('badge-warning');
        verdictBadge.textContent = 'Suspicious (Needs Review)';
      } else {
        verdictBadge.classList.add('badge-success');
        verdictBadge.textContent = 'Legitimate (Safe)';
      }
    }

    if (reasonsList) {
      reasonsList.innerHTML = '';
      const reasons = data.reasons || (data.reason ? data.reason.split(';') : []);
      reasons.forEach(r => {
        const span = document.createElement('span');
        span.className = 'reason-pill';
        span.textContent = r.trim();
        reasonsList.appendChild(span);
      });
    }

    if (liveResult) {
      liveResult.classList.remove('hidden');
    }
  } catch (err) {
    console.error('Quick scan error:', err);
  }
}

/**
 * Table Filtering & Search logic
 */
let currentFilter = 'all';

function setFilter(filterType, element) {
  currentFilter = filterType;
  document.querySelectorAll('#filter-pills .filter-pill').forEach(pill => {
    pill.classList.remove('active');
  });
  if (element) element.classList.add('active');
  filterMessages();
}

function clearSearch() {
  const searchInput = document.getElementById('table-search');
  if (searchInput) {
    searchInput.value = '';
    filterMessages();
  }
}

function resetFilters() {
  clearSearch();
  const allPill = document.querySelector('[data-filter="all"]');
  if (allPill) setFilter('all', allPill);
}

function filterMessages() {
  const searchInput = document.getElementById('table-search');
  const clearBtn = document.getElementById('search-clear-btn');
  const query = (searchInput?.value || '').toLowerCase().trim();

  if (clearBtn) {
    if (query.length > 0) clearBtn.classList.remove('hidden');
    else clearBtn.classList.add('hidden');
  }

  const rows = document.querySelectorAll('#messages-tbody tr.message-row');
  let matchCount = 0;

  rows.forEach(row => {
    const status = row.getAttribute('data-status') || '';
    const sender = row.getAttribute('data-sender') || '';
    const subject = row.getAttribute('data-subject') || '';
    const reason = row.getAttribute('data-reason') || '';

    const matchesStatus = (currentFilter === 'all') || (status === currentFilter);
    const matchesQuery = !query || 
      sender.includes(query) || 
      subject.includes(query) || 
      reason.includes(query);

    if (matchesStatus && matchesQuery) {
      row.style.display = '';
      matchCount++;
    } else {
      row.style.display = 'none';
    }
  });

  const noMatchRow = document.getElementById('no-filter-match-row');
  if (noMatchRow) {
    if (rows.length > 0 && matchCount === 0) {
      noMatchRow.classList.remove('hidden');
    } else {
      noMatchRow.classList.add('hidden');
    }
  }
}

/**
 * Inspection Modal
 */
function openDetailModal(id, messageData) {
  const modal = document.getElementById('detail-modal');
  if (!modal) return;

  const scorePct = Math.round(messageData.score * 100);

  document.getElementById('modal-title').textContent = `Message #${id} Inspection`;
  
  const statusBadge = document.getElementById('modal-status-badge');
  if (statusBadge) {
    statusBadge.className = 'badge';
    if (messageData.status === 'quarantined') {
      statusBadge.classList.add('badge-danger');
      statusBadge.textContent = 'Quarantined';
    } else if (messageData.status === 'review') {
      statusBadge.classList.add('badge-warning');
      statusBadge.textContent = 'Needs Review';
    } else {
      statusBadge.classList.add('badge-success');
      statusBadge.textContent = 'Delivered';
    }
  }

  document.getElementById('modal-sender').textContent = messageData.sender;
  document.getElementById('modal-time').textContent = messageData.received_at || 'Just now';
  
  const scoreEl = document.getElementById('modal-score');
  if (scoreEl) {
    scoreEl.textContent = `${scorePct}% (${messageData.verdict.toUpperCase()})`;
    scoreEl.className = 'meta-value font-bold ' + (scorePct >= 55 ? 'text-danger' : (scorePct >= 35 ? 'text-warning' : 'text-success'));
  }

  const statusEl = document.getElementById('modal-status');
  if (statusEl) {
    statusEl.textContent = messageData.status.toUpperCase();
  }

  document.getElementById('modal-subject').textContent = messageData.subject;
  document.getElementById('modal-body').textContent = messageData.body;

  // Render reasons pills
  const reasonsContainer = document.getElementById('modal-reasons');
  if (reasonsContainer) {
    reasonsContainer.innerHTML = '';
    const parts = (messageData.reason || '').split(';');
    parts.forEach(p => {
      const trimmed = p.trim();
      if (trimmed) {
        const pill = document.createElement('span');
        pill.className = 'reason-pill';
        pill.textContent = trimmed;
        reasonsContainer.appendChild(pill);
      }
    });
  }

  // Update form action
  const reviewForm = document.getElementById('modal-review-form');
  if (reviewForm) {
    reviewForm.action = `/review/${id}`;
  }

  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeDetailModal() {
  const modal = document.getElementById('detail-modal');
  if (modal) {
    modal.classList.add('hidden');
    document.body.style.overflow = '';
  }
}

function closeModalOnBackdrop(event) {
  if (event.target.id === 'detail-modal') {
    closeDetailModal();
  }
}

function copyModalBody() {
  const bodyText = document.getElementById('modal-body')?.textContent || '';
  if (bodyText) {
    navigator.clipboard.writeText(bodyText).then(() => {
      alert('Message body copied to clipboard!');
    }).catch(err => {
      console.error('Copy failed:', err);
    });
  }
}

/**
 * Handle CSV file selection in evaluation page
 */
function handleFileSelect(input) {
  const display = document.getElementById('file-name-display');
  if (input.files && input.files[0]) {
    const file = input.files[0];
    if (display) {
      display.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      display.classList.remove('hidden');
    }
  }
}

// Drag & drop file upload support
document.addEventListener('DOMContentLoaded', () => {
  const dropArea = document.getElementById('drop-area');
  const fileInput = document.getElementById('csv-file-input');

  if (dropArea && fileInput) {
    ['dragenter', 'dragover'].forEach(eventName => {
      dropArea.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropArea.classList.add('dragover');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropArea.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropArea.classList.remove('dragover');
      }, false);
    });

    dropArea.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files && files.length > 0) {
        fileInput.files = files;
        handleFileSelect(fileInput);
      }
    }, false);
  }

  // Keyboard shortcut: Escape closes modal
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeDetailModal();
    }
  });

  // Auto-dismiss alert messages after 7 seconds
  setTimeout(() => {
    document.querySelectorAll('.alert').forEach(alert => {
      alert.style.transition = 'opacity 0.4s ease';
      alert.style.opacity = '0';
      setTimeout(() => alert.remove(), 400);
    });
  }, 7000);

  // Background Auto-Sync Engine (Gmail Live Stream)
  initAutoSync();
});

/**
 * Periodically polls /api/auto-sync in the background just like Gmail
 */
function initAutoSync() {
  const syncStatusEl = document.getElementById('auto-sync-status-time');
  const navIndicator = document.getElementById('nav-auto-sync-dot');

  setInterval(async () => {
    try {
      if (navIndicator) navIndicator.classList.add('pulse');
      const res = await fetch('/api/auto-sync');
      if (!res.ok) return;
      const data = await res.json();

      if (data.status === 'success') {
        const timeStr = data.timestamp || new Date().toLocaleTimeString();
        if (syncStatusEl) {
          syncStatusEl.textContent = `(Synced at ${timeStr})`;
        }

        // If new incoming emails were intercepted by auto-sync, show notification & refresh
        if (data.new_emails_count > 0) {
          const banner = document.createElement('div');
          banner.className = 'alert alert-success animate-fade-in';
          banner.style.position = 'fixed';
          banner.style.bottom = '24px';
          banner.style.right = '24px';
          banner.style.zIndex = '99999';
          banner.style.maxWidth = '420px';
          banner.style.boxShadow = '0 10px 30px rgba(0, 255, 157, 0.35)';
          banner.innerHTML = `
            <div class="alert-content">
              <span>⚡ <strong>Auto-Sync Active:</strong> Screened ${data.new_emails_count} new email(s) from Gmail (${data.threats_quarantined} quarantined).</span>
            </div>
          `;
          document.body.appendChild(banner);
          setTimeout(() => {
            banner.remove();
            window.location.reload();
          }, 1600);
        }
      }
    } catch (e) {
      // background silent retry
    }
  }, 15000);
}
