/**
 * UI Rendering and Interaction Component
 */

export class UIManager {
  static formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  static formatDate(isoString) {
    if (!isoString) return 'Just now';
    const d = new Date(isoString);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  static showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <div class="toast-icon">
        ${type === 'success' ? '✓' : type === 'error' ? '✕' : type === 'warning' ? '⚠' : 'ℹ'}
      </div>
      <div class="toast-body">${this.escapeHTML(message)}</div>
      <button class="toast-close" aria-label="Close">&times;</button>
    `;

    toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());
    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('fade-out');
      setTimeout(() => toast.remove(), 400);
    }, duration);
  }

  static escapeHTML(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  static renderStorageStatus(status) {
    const el = document.getElementById('storage-status-badge');
    if (!el) return;

    const { name, isMock, ready, details, fallbackOccurred } = status;

    let badgeClass = 'badge-success';
    let text = name || 'Ready';

    if (isMock) {
      badgeClass = 'badge-warning';
      text = 'Mock Storage (Local)';
    } else if (!ready) {
      badgeClass = 'badge-danger';
      text = `${name} (Disconnected)`;
    }

    el.className = `status-badge ${badgeClass}`;
    el.innerHTML = `
      <span class="status-dot"></span>
      <span class="status-name">${this.escapeHTML(text)}</span>
    `;
    el.title = details || '';

    const detailEl = document.getElementById('storage-status-detail');
    if (detailEl) {
      detailEl.textContent = fallbackOccurred
        ? `Note: ${details} (Fallback active)`
        : details || '';
    }
  }

  static renderDocumentsList(documents, onDecryptClick, onDeleteClick) {
    const tbody = document.getElementById('documents-tbody');
    const emptyState = document.getElementById('vault-empty-state');
    const tableWrapper = document.getElementById('documents-table-wrapper');

    if (!tbody) return;

    if (!documents || documents.length === 0) {
      if (emptyState) emptyState.style.display = 'block';
      if (tableWrapper) tableWrapper.style.display = 'none';
      tbody.innerHTML = '';
      return;
    }

    if (emptyState) emptyState.style.display = 'none';
    if (tableWrapper) tableWrapper.style.display = 'block';

    tbody.innerHTML = documents
      .map(doc => {
        const ext = (doc.originalFilename.split('.').pop() || 'BIN').toUpperCase();
        return `
          <tr data-doc-id="${this.escapeHTML(doc.docId)}">
            <td class="col-file">
              <div class="file-cell">
                <div class="file-icon-badge">${this.escapeHTML(ext.slice(0, 4))}</div>
                <div class="file-meta">
                  <span class="file-name" title="${this.escapeHTML(doc.originalFilename)}">${this.escapeHTML(doc.originalFilename)}</span>
                  <span class="file-subtext">${this.escapeHTML(doc.mimeType)}</span>
                </div>
              </div>
            </td>
            <td>${this.escapeHTML(this.formatDate(doc.createdAt))}</td>
            <td>${this.escapeHTML(this.formatBytes(doc.fileSize))}</td>
            <td>
              <span class="crypto-chip" title="${doc.encryptionAlgorithm} + ${doc.kdfAlgorithm} (${doc.pbkdf2Iterations.toLocaleString()} iter)">
                🔒 AES-256-GCM
              </span>
            </td>
            <td>
              <span class="storage-tag ${doc.storageBackend.includes('Mock') ? 'storage-mock' : 'storage-cloud'}">
                ${this.escapeHTML(doc.storageBackend)}
              </span>
            </td>
            <td class="col-actions">
              <button class="btn btn-sm btn-primary decrypt-btn" data-id="${this.escapeHTML(doc.docId)}" title="Download ciphertext and decrypt locally">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Decrypt
              </button>
              <button class="btn btn-sm btn-danger delete-btn" data-id="${this.escapeHTML(doc.docId)}" title="Permanently delete document">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              </button>
            </td>
          </tr>
        `;
      })
      .join('');

    // Attach event listeners
    tbody.querySelectorAll('.decrypt-btn').forEach(btn => {
      btn.addEventListener('click', () => onDecryptClick(btn.dataset.id));
    });

    tbody.querySelectorAll('.delete-btn').forEach(btn => {
      btn.addEventListener('click', () => onDeleteClick(btn.dataset.id));
    });
  }

  static updateProgress(encryptPercent, uploadPercent, statusText) {
    const bar = document.getElementById('action-progress-bar');
    const label = document.getElementById('action-status-label');
    const container = document.getElementById('progress-section');

    if (container) container.style.display = 'block';
    if (label) label.textContent = statusText || 'Processing...';

    const total = Math.round((encryptPercent + uploadPercent) / 2);
    if (bar) {
      bar.style.width = `${total}%`;
      bar.setAttribute('aria-valuenow', total);
    }
  }

  static resetProgress() {
    const container = document.getElementById('progress-section');
    const bar = document.getElementById('action-progress-bar');
    if (container) container.style.display = 'none';
    if (bar) bar.style.width = '0%';
  }
}

