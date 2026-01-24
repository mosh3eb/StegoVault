const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// Enhanced logging with colors and icons
function log(msg, level = "info") {
  const el = $("#console");
  const now = new Date().toLocaleTimeString();
  const icons = {
    info: "ℹ",
    success: "✓",
    warning: "⚠",
    error: "✗"
  };
  const colors = {
    info: "rgba(230, 234, 242, 0.85)",
    success: "#4CAF50",
    warning: "#FFA726",
    error: "#FF6B6B"
  };
  
  const icon = icons[level] || icons.info;
  const color = colors[level] || colors.info;
  
  el.textContent += `\n[${now}] ${icon} ${msg}`;
  el.scrollTop = el.scrollHeight;
  
  // Flash effect for important messages
  if (level === "success" || level === "error") {
    el.parentElement.classList.add("success-flash");
    setTimeout(() => el.parentElement.classList.remove("success-flash"), 500);
  }
}

function setStatus(kind, text) {
  const dot = $("#status .dot");
  const statusText = $("#statusText");
  
  dot.classList.remove("dot-ok", "dot-warn", "dot-err");
  dot.classList.add(kind === "ok" ? "dot-ok" : kind === "warn" ? "dot-warn" : "dot-err");
  statusText.textContent = text;
  
  // Update tip based on status
  updateStatusTip();
}

function updateStatusTip() {
  const tipEl = $("#statusTip");
  if (!tipEl) return;
  
  const mode = $("select[name='mode']")?.value || "pixel";
  const tips = {
    pixel: "Pixel mode — Higher capacity, lower robustness",
    lsb: "LSB mode — Maximum stealth, lower capacity"
  };
  
  const tipText = tips[mode] || "Select a mode to see tips";
  tipEl.innerHTML = `<span>Tip</span><span class="muted">${tipText}</span>`;
}

function pretty(obj) {
  if (typeof obj === "string") return obj;
  return JSON.stringify(obj, null, 2);
}

// Enhanced form submission with progress
async function postForm(url, formEl, onProgress) {
  const fd = new FormData(formEl);
  setStatus("warn", "Processing…");
  
  // Show progress bar
  const progressContainer = formEl.querySelector(".progress-container") || createProgressBar(formEl);
  progressContainer.classList.add("active");
  const progressBar = progressContainer.querySelector(".progress-bar");
  
  // Simulate progress (since we can't track actual upload progress easily)
  let progress = 0;
  const progressInterval = setInterval(() => {
    progress += Math.random() * 15;
    if (progress > 90) progress = 90;
    progressBar.style.width = progress + "%";
  }, 200);
  
  log(`POST ${url}`, "info");
  
  // Create timeout controller for long operations
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 300000); // 5 minute timeout
  
  try {
    const res = await fetch(url, { 
      method: "POST", 
      body: fd,
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    clearInterval(progressInterval);
    progressBar.style.width = "100%";
    
    let json;
    try {
      const text = await res.text();
      json = text ? JSON.parse(text) : { ok: false, error: "Empty response" };
    } catch (parseErr) {
      json = { ok: false, error: `Invalid server response: ${parseErr.message}` };
    }
    
    setTimeout(() => {
      progressContainer.classList.remove("active");
      progressBar.style.width = "0%";
    }, 500);
    
    if (!res.ok || !json.ok) {
      setStatus("err", "Error");
      const errorMsg = json.error || res.statusText || `HTTP ${res.status}`;
      log(`Error: ${errorMsg}`, "error");
      throw new Error(errorMsg);
    }
    
    setStatus("ok", "Ready");
    if (onProgress) onProgress(json);
    return json;
  } catch (err) {
    clearInterval(progressInterval);
    clearTimeout(timeoutId);
    progressContainer.classList.remove("active");
    progressBar.style.width = "0%";
    setStatus("err", "Error");
    
    // More detailed error messages
    let errorMsg = err.message;
    if (err.name === "AbortError" || err.name === "TimeoutError") {
      errorMsg = "Request timed out. The file may be too large or the server is busy.";
    } else if (err.name === "TypeError" && err.message.includes("fetch")) {
      errorMsg = "Cannot connect to server. Please check if the server is running.";
    } else if (!navigator.onLine) {
      errorMsg = "No internet connection. Please check your network.";
    }
    
    log(`Network error: ${errorMsg}`, "error");
    throw new Error(errorMsg);
  }
}

function createProgressBar(formEl) {
  const container = document.createElement("div");
  container.className = "progress-container";
  container.innerHTML = '<div class="progress-bar"></div>';
  const actions = formEl.querySelector(".actions");
  if (actions) {
    actions.insertBefore(container, actions.firstChild);
  } else {
    formEl.appendChild(container);
  }
  return container;
}

// File preview and drag-and-drop
function setupFileInputs() {
  $$("input[type='file']").forEach(input => {
    const field = input.closest(".field");
    if (!field) return;
    
    // Drag and drop
    field.addEventListener("dragover", (e) => {
      e.preventDefault();
      field.classList.add("drag-over");
    });
    
    field.addEventListener("dragleave", () => {
      field.classList.remove("drag-over");
    });
    
    field.addEventListener("drop", (e) => {
      e.preventDefault();
      field.classList.remove("drag-over");
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        input.files = files;
        updateFilePreview(input);
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
    
    // File preview
    input.addEventListener("change", () => updateFilePreview(input));
  });
}

function updateFilePreview(input) {
  const field = input.closest(".field");
  if (!field) return;
  
  // Remove existing preview
  const existing = field.querySelector(".file-preview");
  if (existing) existing.remove();
  
  if (input.files && input.files.length > 0) {
    const file = input.files[0];
    const preview = document.createElement("div");
    preview.className = "file-preview";
    preview.innerHTML = `
      <strong>${file.name}</strong><br>
      <span>${formatFileSize(file.size)}</span>
    `;
    field.appendChild(preview);
    
    // Update status if it's a cover image or payload
    if (input.name === "cover" || input.name === "payload") {
      updateReadinessStatus();
    }
  }
}

function formatFileSize(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + " " + sizes[i];
}

function updateReadinessStatus() {
  const payload = $("input[name='payload']");
  const cover = $("input[name='cover']");
  
  if (payload?.files?.length > 0 && cover?.files?.length > 0) {
    setStatus("ok", "Ready to embed");
    log("Files selected. Ready to embed.", "success");
  } else if (payload?.files?.length > 0) {
    setStatus("warn", "Cover image recommended");
  } else {
    setStatus("warn", "Select files");
  }
}

// Tab switching with animation
$$(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    $$(".panel").forEach((p) => {
      p.classList.remove("active");
      if (p.id === `tab-${tab}`) {
        setTimeout(() => p.classList.add("active"), 50);
      }
    });
    
    // Update status tip when switching tabs
    if (tab === "embed") {
      updateStatusTip();
    }
  });
});

// Mode change handler
const modeSelect = $("select[name='mode']");
if (modeSelect) {
  modeSelect.addEventListener("change", updateStatusTip);
}

// Embed form
$("#form-embed").addEventListener("submit", async (e) => {
  e.preventDefault();
  const downloadBtn = $("#embed-download");
  downloadBtn.classList.add("hidden");
  
  const submitBtn = e.target.querySelector("button[type='submit']");
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Processing...';
  
  try {
    const json = await postForm("/api/embed", e.target, (result) => {
      if (result.auto_actions?.length) {
        result.auto_actions.forEach((a) => log(a, "info"));
      }
    });
    
    log("Embed complete. Download ready.", "success");
    downloadBtn.href = json.download_url;
    downloadBtn.classList.remove("hidden");
    downloadBtn.classList.add("success-flash");
    setTimeout(() => downloadBtn.classList.remove("success-flash"), 1000);
    
    // Store extract token for direct extraction
    if (json.extract_token) {
      window.lastExtractToken = json.extract_token;
      const directBtn = $("#extract-direct-btn");
      const tokenContainer = $("#extract-token-container");
      if (directBtn) {
        directBtn.classList.remove("hidden");
        log("You can now test extraction directly from the server (no download needed).", "info");
      }
      if (tokenContainer) {
        tokenContainer.classList.remove("hidden");
      }
    }
  } catch (err) {
    // Error already logged
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

// Direct extraction from server (no upload needed)
$("#extract-direct-btn")?.addEventListener("click", async () => {
  if (!window.lastExtractToken) {
    log("No extract token available. Please embed a file first.", "error");
    return;
  }
  
  const downloadBtn = $("#extract-download");
  downloadBtn.classList.add("hidden");
  
  const directBtn = $("#extract-direct-btn");
  const originalText = directBtn.textContent;
  directBtn.disabled = true;
  directBtn.innerHTML = '<span class="spinner"></span> Extracting from server...';
  
  const password = $("input[name='password']")?.value || "";
  
  try {
    const formData = new FormData();
    formData.append("token", window.lastExtractToken);
    if (password) {
      formData.append("password", password);
    }
    
    setStatus("warn", "Extracting from server...");
    log("Extracting directly from server (no upload needed)...", "info");
    
    const res = await fetch("/api/extract-direct", {
      method: "POST",
      body: formData
    });
    
    const json = await res.json().catch(() => ({ ok: false, error: "Invalid response" }));
    
    if (!res.ok || !json.ok) {
      setStatus("err", "Error");
      log(`Error: ${json.error || res.statusText}`, "error");
      return;
    }
    
    setStatus("ok", "Ready");
    log("Extract complete. Download ready.", "success");
    downloadBtn.href = json.download_url;
    downloadBtn.classList.remove("hidden");
    downloadBtn.classList.add("success-flash");
    setTimeout(() => downloadBtn.classList.remove("success-flash"), 1000);
  } catch (err) {
    setStatus("err", "Error");
    log(`Network error: ${err.message}`, "error");
  } finally {
    directBtn.disabled = false;
    directBtn.textContent = originalText;
  }
});

// Extract form
$("#form-extract").addEventListener("submit", async (e) => {
  e.preventDefault();
  const downloadBtn = $("#extract-download");
  downloadBtn.classList.add("hidden");
  
  const submitBtn = e.target.querySelector("button[type='submit']");
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Extracting...';
  
  // Check if file is selected
  const stegoInput = e.target.querySelector("input[name='stego']");
  if (!stegoInput || !stegoInput.files || stegoInput.files.length === 0) {
    log("Please select a stego image file.", "error");
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
    return;
  }
  
  // Warn if file is not PNG
  const fileName = stegoInput.files[0].name.toLowerCase();
  if (!fileName.endsWith('.png')) {
    log("Warning: Only PNG images are supported. The file may not extract correctly.", "warning");
  }
  
  try {
    const json = await postForm("/api/extract", e.target);
    log("Extract complete. Download ready.", "success");
    downloadBtn.href = json.download_url;
    downloadBtn.classList.remove("hidden");
    downloadBtn.classList.add("success-flash");
    setTimeout(() => downloadBtn.classList.remove("success-flash"), 1000);
  } catch (err) {
    // Error already logged by postForm
    // Additional helpful message
    if (err.message && err.message.includes("Not a valid stego image")) {
      log("Tip: Make sure you're using the exact PNG file downloaded from the Embed operation.", "warning");
      log("Tip: If the image was modified, converted, or re-saved, extraction may fail.", "warning");
    }
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

// Detect form
$("#form-detect").addEventListener("submit", async (e) => {
  e.preventDefault();
  const resultEl = $("#detect-result");
  resultEl.textContent = "Analyzing…";
  
  const submitBtn = e.target.querySelector("button[type='submit']");
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Analyzing...';
  
  try {
    const json = await postForm("/api/detect", e.target);
    resultEl.textContent = pretty(json.result);
    log("Detection complete.", "success");
  } catch (err) {
    resultEl.textContent = `Error: ${err.message || err}`;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

// Capacity form
$("#form-capacity").addEventListener("submit", async (e) => {
  e.preventDefault();
  const resultEl = $("#capacity-result");
  resultEl.textContent = "Calculating…";
  
  const submitBtn = e.target.querySelector("button[type='submit']");
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Calculating...';
  
  try {
    const json = await postForm("/api/capacity", e.target);
    let resultText = pretty(json.result);
    
    // Add fit analysis if available
    if (json.result.fit_analysis) {
      const fit = json.result.fit_analysis;
      resultText += "\n\n--- File Fit Analysis ---\n";
      resultText += `File Size: ${formatFileSize(fit.file_size)}\n`;
      resultText += `Capacity: ${formatFileSize(fit.capacity)}\n`;
      resultText += `Fits: ${fit.fits ? "Yes ✓" : "No ✗"}\n`;
      resultText += `Utilization: ${fit.utilization_percent.toFixed(1)}%\n`;
    }
    
    resultEl.textContent = resultText;
    log("Capacity calculation complete.", "success");
  } catch (err) {
    resultEl.textContent = `Error: ${err.message || err}`;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

// Embed Archive form
$("#form-embed-archive").addEventListener("submit", async (e) => {
  e.preventDefault();
  const downloadBtn = $("#embed-archive-download");
  downloadBtn.classList.add("hidden");
  
  const submitBtn = e.target.querySelector("button[type='submit']");
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Processing...';
  
  try {
    const json = await postForm("/api/embed-archive", e.target, (result) => {
      if (result.auto_actions?.length) {
        result.auto_actions.forEach((a) => log(a, "info"));
      }
    });
    
    log("Archive embedded successfully. Download ready.", "success");
    downloadBtn.href = json.download_url;
    downloadBtn.classList.remove("hidden");
    downloadBtn.classList.add("success-flash");
    setTimeout(() => downloadBtn.classList.remove("success-flash"), 1000);
  } catch (err) {
    // Error already logged
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

// Extract Archive form
$("#form-extract-archive").addEventListener("submit", async (e) => {
  e.preventDefault();
  const downloadBtn = $("#extract-archive-download");
  downloadBtn.classList.add("hidden");
  
  const submitBtn = e.target.querySelector("button[type='submit']");
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Extracting...';
  
  try {
    const json = await postForm("/api/extract-archive", e.target);
    log(`Archive extracted: ${json.file_count} file(s), ${formatFileSize(json.total_size)}`, "success");
    if (json.auto_actions?.length) {
      json.auto_actions.forEach((a) => log(a, "info"));
    }
    downloadBtn.href = json.download_url;
    downloadBtn.classList.remove("hidden");
    downloadBtn.classList.add("success-flash");
    setTimeout(() => downloadBtn.classList.remove("success-flash"), 1000);
  } catch (err) {
    // Error already logged
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

// Info form
$("#form-info").addEventListener("submit", async (e) => {
  e.preventDefault();
  const resultEl = $("#info-result");
  resultEl.textContent = "Loading metadata…";
  
  const submitBtn = e.target.querySelector("button[type='submit']");
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Loading...';
  
  try {
    const json = await postForm("/api/info", e.target);
    resultEl.textContent = pretty(json.metadata);
    log("Metadata loaded successfully.", "success");
  } catch (err) {
    resultEl.textContent = `Error: ${err.message || err}`;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

// Privacy form
$("#form-privacy").addEventListener("submit", async (e) => {
  e.preventDefault();
  const resultEl = $("#privacy-result");
  const downloadBtn = $("#privacy-download");
  resultEl.textContent = "Scanning…";
  downloadBtn.classList.add("hidden");
  
  const submitBtn = e.target.querySelector("button[type='submit']");
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Scanning...';
  
  try {
    const json = await postForm("/api/privacy", e.target);
    resultEl.textContent = pretty(json.result);
    if (json.cleaned_download_url) {
      downloadBtn.href = json.cleaned_download_url;
      downloadBtn.classList.remove("hidden");
      log("Cleaned image ready for download.", "success");
    }
    log("Privacy scan complete.", "success");
  } catch (err) {
    resultEl.textContent = `Error: ${err.message || err}`;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  setupFileInputs();
  updateStatusTip();
  log("StegoVault Web ready.", "success");
});
