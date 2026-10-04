/**
 * Dynamic DES Visualizer — Interactive Frontend Engine
 *
 * Implements pure plain text encryption, 16-round Feistel step-by-step playback,
 * S-box coordinate highlighting, dynamic key changing inspection, and verified plain text decryption.
 */

// Global State
const state = {
  currentTrace: null,
  tablesData: null,
  currentStep: 1,
  totalSteps: 11,
  isPlaying: false,
  playTimer: null,
  playSpeedMs: 1500,
  selectedRound: 1,
  selectedSBox: 0,
  activeTab: 'tab-dashboard',
  currentPlaintextInput: 'HELLO WORLD',
  currentKeyInput: 'SECURITY'
};

// Step Meta Information for Step-by-Step Navigation
const STEP_DEFS = [
  { num: 1, title: "Plaintext to 64-bit Binary (8 Characters / Bytes)", tab: "tab-input" },
  { num: 2, title: "Key Parity Inspection & PC-1 Permutation (64b → 56b)", tab: "tab-input" },
  { num: 3, title: "56-bit Key & C0/D0 Split (28 bits each)", tab: "tab-input" },
  { num: 4, title: "16-Round Subkey Schedule (Shifts & PC-2 → 48 bits)", tab: "tab-keys" },
  { num: 5, title: "Initial Permutation (IP) & L0/R0 Formation", tab: "tab-encryption" },
  { num: 6, title: "Feistel Function F: Expansion E & XOR with Ki", tab: "tab-rounds" },
  { num: 7, title: "8 S-Boxes Substitution (Confusion: 48b → 32b)", tab: "tab-rounds" },
  { num: 8, title: "Straight P-Box Permutation (Diffusion: 32b → 32b)", tab: "tab-rounds" },
  { num: 9, title: "16 Feistel Rounds Progression", tab: "tab-encryption" },
  { num: 10, title: "Preoutput 32-bit Swap (R16 || L16)", tab: "tab-encryption" },
  { num: 11, title: "Inverse Initial Permutation (IP⁻¹) → Final Ciphertext", tab: "tab-encryption" }
];

// Document Ready Initialization
document.addEventListener("DOMContentLoaded", async () => {
  setupEventListeners();
  await loadTables();
  await executeEncryption(); // Auto-run initial plain text encryption
});

// Setup All DOM Event Listeners
function setupEventListeners() {
  // Navigation tabs
  document.querySelectorAll(".nav-tab").forEach(tabBtn => {
    tabBtn.addEventListener("click", () => {
      switchTab(tabBtn.dataset.tab);
    });
  });

  // Theme toggle
  document.getElementById("btn-toggle-theme").addEventListener("click", toggleTheme);

  // Playback controller buttons
  document.getElementById("btn-step-first").addEventListener("click", () => goToStep(1));
  document.getElementById("btn-step-prev").addEventListener("click", () => goToStep(state.currentStep - 1));
  document.getElementById("btn-step-next").addEventListener("click", () => goToStep(state.currentStep + 1));
  document.getElementById("btn-step-last").addEventListener("click", () => goToStep(state.totalSteps));
  document.getElementById("btn-step-play").addEventListener("click", startPlayback);
  document.getElementById("btn-step-pause").addEventListener("click", pausePlayback);
  document.getElementById("btn-step-reset").addEventListener("click", resetPlayback);
  document.getElementById("btn-show-all-steps").addEventListener("click", () => switchTab("tab-encryption"));

  // Speed slider
  const speedSlider = document.getElementById("playback-speed");
  speedSlider.addEventListener("input", (e) => {
    state.playSpeedMs = parseInt(e.target.value, 10);
    document.getElementById("speed-display").textContent = (state.playSpeedMs / 1000).toFixed(1) + "s";
    if (state.isPlaying) {
      pausePlayback();
      startPlayback();
    }
  });

  // Action buttons
  document.getElementById("btn-load-test-vector").addEventListener("click", loadTestVector);
  document.getElementById("btn-run-encryption").addEventListener("click", executeEncryption);

  // Enter key in plaintext or key input triggers encryption
  document.getElementById("quick-pt-input").addEventListener("keyup", (e) => {
    if (e.key === "Enter") executeEncryption();
  });
  document.getElementById("quick-key-input").addEventListener("keyup", (e) => {
    if (e.key === "Enter") executeEncryption();
  });

  // Custom S-Box Enter key listener
  document.getElementById("sbox-custom-input").addEventListener("keyup", (e) => {
    if (e.key === "Enter") calculateCustomSBox();
  });
}

// Tab Switching
function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll(".nav-tab").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });
  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("active", pane.id === tabId);
  });
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Dark / Light Theme Toggle
function toggleTheme() {
  const html = document.documentElement;
  const currentTheme = html.getAttribute("data-theme") || "dark";
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  html.setAttribute("data-theme", newTheme);
  document.getElementById("theme-icon").textContent = newTheme === "dark" ? "🌙" : "☀️";
}

// Step-by-Step Playback Controls
function goToStep(stepNum) {
  if (stepNum < 1 || stepNum > state.totalSteps) return;
  state.currentStep = stepNum;
  
  const stepInfo = STEP_DEFS[stepNum - 1];
  document.getElementById("step-counter-badge").textContent = `Step ${stepNum} of ${state.totalSteps}`;
  document.getElementById("step-title-display").textContent = stepInfo.title;
  
  const progressPct = Math.round((stepNum / state.totalSteps) * 100);
  document.getElementById("step-progress-fill").style.width = `${progressPct}%`;
  
  // Switch to the relevant tab for this step
  if (stepInfo.tab && state.activeTab !== stepInfo.tab) {
    switchTab(stepInfo.tab);
  }
}

function startPlayback() {
  state.isPlaying = true;
  document.getElementById("btn-step-play").classList.add("hidden");
  document.getElementById("btn-step-pause").classList.remove("hidden");
  
  if (state.currentStep >= state.totalSteps) {
    goToStep(1);
  }

  state.playTimer = setInterval(() => {
    if (state.currentStep < state.totalSteps) {
      goToStep(state.currentStep + 1);
    } else {
      pausePlayback();
    }
  }, state.playSpeedMs);
}

function pausePlayback() {
  state.isPlaying = false;
  clearInterval(state.playTimer);
  document.getElementById("btn-step-pause").classList.add("hidden");
  document.getElementById("btn-step-play").classList.remove("hidden");
}

function resetPlayback() {
  pausePlayback();
  goToStep(1);
}

// Load Standard Constants & Tables from Backend
async function loadTables() {
  try {
    const res = await fetch("/api/tables");
    state.tablesData = await res.json();
    renderPC1Matrix(state.tablesData.pc1);
    renderShiftBadges(state.tablesData.left_shifts);
    renderRoundSelectorPills();
    renderSBoxMatrix(state.selectedSBox);
  } catch (err) {
    console.error("Failed to load tables:", err);
  }
}

// Load Standard NIST Test Vector
async function loadTestVector() {
  try {
    const res = await fetch("/api/test-vector");
    const data = await res.json();
    
    document.getElementById("quick-pt-input").value = data.plaintext_hex;
    document.getElementById("quick-key-input").value = data.key_hex;
    
    state.currentPlaintextInput = data.plaintext_hex;
    state.currentKeyInput = data.key_hex;

    applyTraceData(data.trace);
    switchTab("tab-encryption");
  } catch (err) {
    console.error("Failed to load test vector:", err);
  }
}

// Execute Encryption via API (Plain Text Native)
async function executeEncryption() {
  const ptVal = document.getElementById("quick-pt-input").value.trim();
  const keyVal = document.getElementById("quick-key-input").value.trim();

  if (!ptVal || !keyVal) {
    alert("Please enter both Plain Text Message and Secret Key!");
    return;
  }

  state.currentPlaintextInput = ptVal;
  state.currentKeyInput = keyVal;

  try {
    const res = await fetch("/api/des/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        plaintext: ptVal,
        key: keyVal,
        input_type: "ascii"
      })
    });

    const data = await res.json();
    if (!res.ok) {
      alert(`Encryption Error: ${data.message}`);
      return;
    }

    applyTraceData(data);
    goToStep(1);
  } catch (err) {
    alert(`Network Error: ${err.message}`);
  }
}

// Populate UI with Structured Trace Data
function applyTraceData(trace) {
  state.currentTrace = trace;

  // 1. Plaintext Tab
  document.getElementById("pt-raw-display").textContent = trace.plaintext_display || trace.raw_plaintext;
  document.getElementById("pt-bin-display").textContent = formatBits(trace.binary_plaintext, 8);
  renderBitsGrid(trace.binary_plaintext);
  renderPlaintextBreakdownTable(trace.plaintext_breakdown || []);

  // Key & Parity
  document.getElementById("key-text-display").textContent = trace.key_display || trace.key_hex;
  renderKeyBinaryWithParity(trace.key_binary);
  renderParityTable(trace.parity_analysis, trace.key_breakdown || []);

  // PC-1 & C0/D0
  document.getElementById("c0-display").textContent = formatBits(trace.C0, 7);
  document.getElementById("d0-display").textContent = formatBits(trace.D0, 7);

  // 2. Key Schedule Tab
  renderKeysTable(trace.round_keys);
  showKeyInspector(0); // Show K1 by default

  // 3. DES Encryption Pipeline Tab
  document.getElementById("ip-input-display").textContent = formatBits(trace.binary_plaintext, 8);
  document.getElementById("ip-output-display").textContent = formatBits(trace.initial_permutation, 8);
  document.getElementById("l0-display").textContent = formatBits(trace.L0, 8);
  document.getElementById("r0-display").textContent = formatBits(trace.R0, 8);

  renderRoundsSummaryTable(trace.rounds, trace.round_keys);

  const lastRound = trace.rounds[15];
  document.getElementById("l16-display").textContent = formatBits(lastRound.L_current, 8);
  document.getElementById("r16-display").textContent = formatBits(lastRound.R_current, 8);
  document.getElementById("preoutput-display").textContent = formatBits(trace.preoutput, 8);
  document.getElementById("final-ct-bin").textContent = formatBits(trace.ciphertext_binary, 8);
  document.getElementById("final-ct-hex").textContent = trace.ciphertext_hex;

  // Automatically configure Decryption tab with current ciphertext and key
  document.getElementById("decrypt-ct-input").value = trace.ciphertext_hex;
  document.getElementById("decrypt-key-input").value = trace.key_display || state.currentKeyInput;

  // 4. Round Details Tab
  showRoundDetails(state.selectedRound);

  // 5. Update Comparison Data with plain text
  loadComparisonData("TESTDATA", trace.key_display || "SECURITY");
}

// Render Character-by-Character ASCII breakdown table for Plaintext
function renderPlaintextBreakdownTable(breakdown) {
  const tbody = document.getElementById("pt-chars-table-body");
  if (!tbody) return;
  tbody.innerHTML = "";

  breakdown.forEach((item, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>Character ${idx + 1}</td>
      <td class="text-cyan font-bold text-lg">'${item.char}'</td>
      <td><strong>${item.ascii}</strong></td>
      <td class="mono">${item.bin}</td>
      <td class="mono text-emerald font-bold">${item.ascii.toString(16).toUpperCase().padStart(2, '0')}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Format Bit Strings with Chunking
function formatBits(bitStr, chunkSize = 8) {
  if (!bitStr) return "";
  const cleaned = bitStr.replace(/\s+/g, '');
  const chunks = [];
  for (let i = 0; i < cleaned.length; i += chunkSize) {
    chunks.push(cleaned.slice(i, i + chunkSize));
  }
  return chunks.join(' ');
}

// Render 64-Bit Interactive Grid
function renderBitsGrid(bitStr) {
  const container = document.getElementById("pt-bits-grid");
  container.innerHTML = "";
  for (let i = 0; i < 64; i++) {
    const bit = bitStr[i] || '0';
    const cell = document.createElement("div");
    cell.className = "bit-cell";
    cell.innerHTML = `<span>${bit}</span><span class="bit-idx">${i + 1}</span>`;
    container.appendChild(cell);
  }
}

// Render 64-bit Key Binary Highlighting 8 Parity Bits
function renderKeyBinaryWithParity(keyBin) {
  const container = document.getElementById("key-bin-display");
  container.innerHTML = "";
  for (let byteIdx = 0; byteIdx < 8; byteIdx++) {
    const byteBits = keyBin.slice(byteIdx * 8, (byteIdx + 1) * 8);
    const dataBits = byteBits.slice(0, 7);
    const parityBit = byteBits[7];
    
    const byteSpan = document.createElement("span");
    byteSpan.innerHTML = `${dataBits}<span class="bit-parity" title="8th parity bit discarded by PC-1">${parityBit}</span> `;
    container.appendChild(byteSpan);
  }
}

// Render Parity Analysis Table with characters
function renderParityTable(parityList, keyChars) {
  const tbody = document.getElementById("parity-table-body");
  tbody.innerHTML = "";
  parityList.forEach((p, idx) => {
    const charInfo = keyChars[idx] ? `'${keyChars[idx].char}'` : '--';
    const asciiCode = keyChars[idx] ? keyChars[idx].ascii : '--';
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>Byte ${p.byte_index}</td>
      <td class="text-amber font-bold text-lg">${charInfo}</td>
      <td><strong>${asciiCode}</strong></td>
      <td class="text-cyan">${p.data_bits}</td>
      <td class="text-rose font-bold">${p.parity_bit} (pos ${p.parity_position})</td>
      <td><span class="badge ${p.is_odd_parity ? 'badge-success' : 'badge-danger'}">${p.is_odd_parity ? 'Odd (Valid)' : 'Even (Adjusted)'}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// Render PC-1 Permutation Matrix
function renderPC1Matrix(pc1Table) {
  const matrixDiv = document.getElementById("pc1-table-matrix");
  if (!matrixDiv || !pc1Table) return;
  matrixDiv.innerHTML = `<div class="table-container"><table class="data-table"><tbody>` +
    [0, 1, 2, 3, 4, 5, 6].map(row => 
      `<tr>` + [0, 1, 2, 3, 4, 5, 6, 7].map(col => {
        const idx = row * 8 + col;
        return `<td>${pc1Table[idx]}</td>`;
      }).join('') + `</tr>`
    ).join('') + `</tbody></table></div>`;
}

// Render Shift Badges
function renderShiftBadges(shifts) {
  const container = document.getElementById("shift-schedule-badges");
  if (!container || !shifts) return;
  container.innerHTML = "";
  shifts.forEach((shift, idx) => {
    const badge = document.createElement("div");
    badge.className = "shift-badge";
    badge.innerHTML = `<span class="round-lbl">R${idx + 1}</span><span class="shift-val">${shift} ${shift === 1 ? 'bit' : 'bits'}</span>`;
    container.appendChild(badge);
  });
}

// Render Keys Table
function renderKeysTable(roundKeys) {
  const tbody = document.getElementById("keys-table-body");
  tbody.innerHTML = "";
  roundKeys.forEach((rk, idx) => {
    const tr = document.createElement("tr");
    tr.className = idx === 0 ? "selected" : "";
    tr.style.cursor = "pointer";
    tr.innerHTML = `
      <td><strong>Round ${rk.round}</strong></td>
      <td><span class="badge">${rk.shift} bit${rk.shift > 1 ? 's' : ''}</span></td>
      <td class="text-cyan">${formatBits(rk.C, 7)}</td>
      <td class="text-emerald">${formatBits(rk.D, 7)}</td>
      <td class="text-rose font-bold">${formatBits(rk.key, 6)}</td>
      <td class="text-amber font-bold">${rk.key_hex}</td>
    `;
    tr.addEventListener("click", () => {
      document.querySelectorAll("#keys-table-body tr").forEach(r => r.classList.remove("selected"));
      tr.classList.add("selected");
      showKeyInspector(idx);
    });
    tbody.appendChild(tr);
  });
}

// Show Subkey Generation Inspector
function showKeyInspector(roundIdx) {
  if (!state.currentTrace) return;
  const rk = state.currentTrace.round_keys[roundIdx];
  document.getElementById("key-detail-title").textContent = `🔍 Subkey K${rk.round} Detailed Generation`;
  
  const container = document.getElementById("key-detail-content");
  container.innerHTML = `
    <div class="data-row"><span class="row-label">Round:</span><span class="row-val font-bold">Round ${rk.round}</span></div>
    <div class="data-row"><span class="row-label">Shift Amount:</span><span class="row-val text-cyan">${rk.shift} position${rk.shift > 1 ? 's' : ''} circular left shift</span></div>
    <div class="data-row"><span class="row-label">C${rk.round} (28 bits):</span><span class="row-val mono text-cyan">${formatBits(rk.C, 7)}</span></div>
    <div class="data-row"><span class="row-label">D${rk.round} (28 bits):</span><span class="row-val mono text-emerald">${formatBits(rk.D, 7)}</span></div>
    <div class="data-row"><span class="row-label">CD Combined (56 bits):</span><span class="row-val mono text-amber">${formatBits(rk.C + rk.D, 7)}</span></div>
    <div class="data-row"><span class="row-label">PC-2 Compression (48 bits):</span><span class="row-val mono text-rose font-bold">${formatBits(rk.key, 6)}</span></div>
    <div class="data-row highlight-box mt-2"><span class="row-label font-bold">Round Key K${rk.round} Hex:</span><span class="row-val mono text-rose font-bold text-lg">${rk.key_hex}</span></div>
  `;
}

// Render Rounds Summary Table in Pipeline Tab
function renderRoundsSummaryTable(rounds, roundKeys) {
  const tbody = document.getElementById("rounds-summary-body");
  tbody.innerHTML = "";
  rounds.forEach((r, idx) => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.innerHTML = `
      <td><strong>Round ${r.round}</strong></td>
      <td class="text-cyan">${binToHex(r.L_previous)}</td>
      <td class="text-emerald">${binToHex(r.R_previous)}</td>
      <td class="text-rose font-bold">${roundKeys[idx].key_hex}</td>
      <td class="text-amber">${binToHex(r.pbox_output)}</td>
      <td class="text-cyan">${binToHex(r.L_current)}</td>
      <td class="text-emerald font-bold">${binToHex(r.R_current)}</td>
    `;
    tr.addEventListener("click", () => {
      state.selectedRound = r.round;
      switchTab("tab-rounds");
      showRoundDetails(r.round);
    });
    tbody.appendChild(tr);
  });
}

// Render Round Selector Pills in Round Details Tab
function renderRoundSelectorPills() {
  const container = document.getElementById("round-pills-bar");
  container.innerHTML = "";
  for (let r = 1; r <= 16; r++) {
    const pill = document.createElement("button");
    pill.className = `round-pill ${r === 1 ? 'active' : ''}`;
    pill.textContent = `Round ${r}`;
    pill.addEventListener("click", () => {
      document.querySelectorAll(".round-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      state.selectedRound = r;
      showRoundDetails(r);
    });
    container.appendChild(pill);
  }
}

// Show Detailed Feistel Round Execution
function showRoundDetails(roundNum) {
  if (!state.currentTrace) return;
  const round = state.currentTrace.rounds[roundNum - 1];
  const rk = state.currentTrace.round_keys[roundNum - 1];

  document.getElementById("current-round-heading").textContent = `Round ${roundNum} Mathematical Execution`;

  // 1. Expansion
  document.getElementById("round-r-input").textContent = formatBits(round.R_previous, 8);
  document.getElementById("round-r-expanded").textContent = formatBits(round.expanded_R, 6);

  // 2. XOR
  document.getElementById("xor-line-r").textContent = formatBits(round.expanded_R, 6);
  document.getElementById("xor-line-k").textContent = formatBits(rk.key, 6);
  document.getElementById("xor-line-res").textContent = formatBits(round.xor_result, 6);

  // 3. S-Boxes
  const sboxTbody = document.getElementById("round-sbox-table-body");
  sboxTbody.innerHTML = "";
  round.sboxes.forEach(sb => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>S${sb.box_num}</strong></td>
      <td class="text-cyan font-bold">${sb.input_bits}</td>
      <td class="text-amber">${sb.row_bits}</td>
      <td>Row ${sb.row}</td>
      <td class="text-emerald">${sb.col_bits}</td>
      <td>Col ${sb.col}</td>
      <td>${sb.value}</td>
      <td class="text-emerald font-bold">${sb.output_bits}</td>
    `;
    sboxTbody.appendChild(tr);
  });
  document.getElementById("round-sbox-combined").textContent = formatBits(round.sbox_output, 4);

  // 4. P-Box
  document.getElementById("round-pbox-in").textContent = formatBits(round.sbox_output, 4);
  document.getElementById("round-pbox-out").textContent = formatBits(round.pbox_output, 4);

  // 5. Final Halves
  document.getElementById("round-final-l").textContent = formatBits(round.L_current, 8) + ` (${binToHex(round.L_current)})`;
  document.getElementById("round-final-r").textContent = formatBits(round.R_current, 8) + ` (${binToHex(round.R_current)})`;
}

// Convert binary string to hex helper
function binToHex(binStr) {
  if (!binStr) return "";
  const cleaned = binStr.replace(/\s+/g, '');
  const hex = parseInt(cleaned, 2).toString(16).toUpperCase();
  return hex.padStart(cleaned.length / 4, '0');
}

// =========================================================
// S-BOX INTERACTIVE ANALYSIS TAB
// =========================================================
function selectSBoxView(boxIdx) {
  state.selectedSBox = boxIdx;
  document.querySelectorAll(".sbox-pill").forEach((btn, idx) => {
    btn.classList.toggle("active", idx === boxIdx);
  });
  document.getElementById("sbox-calculator-title").textContent = `⚡ Interactive S${boxIdx + 1} Tester`;
  document.getElementById("sbox-matrix-title").textContent = `S${boxIdx + 1} Substitution Table (4 Rows × 16 Columns)`;
  renderSBoxMatrix(boxIdx);
  calculateCustomSBox();
}

function renderSBoxMatrix(boxIdx, highlightRow = -1, highlightCol = -1) {
  if (!state.tablesData || !state.tablesData.s_boxes) return;
  const matrix = state.tablesData.s_boxes[boxIdx];

  const header = document.getElementById("sbox-grid-header");
  header.innerHTML = `<th>Row \\ Col</th>` + [...Array(16).keys()].map(c => `<th>${c}</th>`).join('');

  const tbody = document.getElementById("sbox-grid-body");
  tbody.innerHTML = "";

  matrix.forEach((rowValues, rIdx) => {
    const tr = document.createElement("tr");
    let rowHtml = `<th>Row ${rIdx}</th>`;

    rowValues.forEach((val, cIdx) => {
      let cellClass = "";
      if (rIdx === highlightRow && cIdx === highlightCol) {
        cellClass = "highlight-cell";
      } else if (rIdx === highlightRow) {
        cellClass = "highlight-row";
      } else if (cIdx === highlightCol) {
        cellClass = "highlight-col";
      }
      rowHtml += `<td class="${cellClass}">${val}</td>`;
    });

    tr.innerHTML = rowHtml;
    tbody.appendChild(tr);
  });
}

function calculateCustomSBox() {
  const inputBits = document.getElementById("sbox-custom-input").value.trim();
  if (inputBits.length !== 6 || !/^[01]+$/.test(inputBits)) {
    alert("Please enter exactly 6 binary bits (0s and 1s)!");
    return;
  }

  const b1 = inputBits[0];
  const b6 = inputBits[5];
  const rowBits = b1 + b6;
  const row = parseInt(rowBits, 2);

  const colBits = inputBits.slice(1, 5);
  const col = parseInt(colBits, 2);

  const matrix = state.tablesData.s_boxes[state.selectedSBox];
  const val = matrix[row][col];
  const outBin = val.toString(2).padStart(4, '0');
  const outHex = val.toString(16).toUpperCase();

  document.getElementById("scalc-in").textContent = inputBits;
  document.getElementById("scalc-row-bits").textContent = `${b1} + ${b6} = "${rowBits}" (Row ${row})`;
  document.getElementById("scalc-col-bits").textContent = `"${colBits}" = (Col ${col})`;
  document.getElementById("scalc-lookup").textContent = `S${state.selectedSBox + 1}[Row ${row}][Col ${col}] = ${val}`;
  document.getElementById("scalc-out").textContent = `${outBin} (Hex: ${outHex})`;

  // Highlight exact row, col, and cell in the matrix
  renderSBoxMatrix(state.selectedSBox, row, col);
}

// =========================================================
// DYNAMIC DES TAB
// =========================================================
async function runDynamicDESDemo() {
  const masterKey = document.getElementById("dyn-master-key-input").value.trim();
  const dynamicSalt = document.getElementById("dyn-salt-input").value.trim();
  const plaintext = document.getElementById("dyn-pt-input").value.trim();

  if (!masterKey || !plaintext) {
    alert("Master Key and Plaintext are required!");
    return;
  }

  try {
    const res = await fetch("/api/dynamic/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        plaintext: plaintext,
        master_key: masterKey,
        dynamic_salt: dynamicSalt,
        input_type: "ascii"
      })
    });

    const data = await res.json();
    if (!res.ok) {
      alert(`Dynamic DES Error: ${data.message}`);
      return;
    }

    renderDynamicResults(data);
  } catch (err) {
    alert(`Network Error: ${err.message}`);
  }
}

function renderDynamicResults(data) {
  const container = document.getElementById("dynamic-results-area");
  container.innerHTML = `
    <div class="card bg-subtle">
      <div class="card-header">
        <h3 class="text-emerald">⚡ Dynamic DES Multi-Block Execution Results</h3>
        <span class="badge badge-success">${data.total_blocks} Blocks Processed</span>
      </div>
      <div class="card-body">
        <div class="data-row highlight-box">
          <span class="row-label font-bold">Total Dynamic Ciphertext (Hex):</span>
          <span class="row-val mono text-emerald font-bold" style="word-break: break-all;">${data.ciphertext_hex}</span>
        </div>

        <div class="table-container mt-3">
          <table class="data-table">
            <thead>
              <tr>
                <th>Block #</th>
                <th>Dynamic Param</th>
                <th>Rotation</th>
                <th>Derived Session Key (Hex)</th>
                <th>Plaintext Block (Hex)</th>
                <th>Ciphertext Block (Hex)</th>
              </tr>
            </thead>
            <tbody>
              ${data.block_traces.map(b => `
                <tr>
                  <td><strong>Block ${b.block_index}</strong></td>
                  <td class="text-cyan">${b.key_derivation.dynamic_param_hex.slice(0, 12)}...</td>
                  <td>${b.key_derivation.rotation_amount} bits</td>
                  <td class="text-rose font-bold">${b.key_derivation.session_key_hex}</td>
                  <td class="text-muted">${b.plaintext_block_hex}</td>
                  <td class="text-emerald font-bold">${b.ciphertext_hex}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function runDynamicDESDecryptionDemo() {
  const masterKey = document.getElementById("dyn-master-key-input").value.trim();
  const dynamicSalt = document.getElementById("dyn-salt-input").value.trim();

  const ctField = document.querySelector("#dynamic-results-area .text-emerald.font-bold");
  if (!ctField) {
    alert("Please encrypt first to generate dynamic ciphertext!");
    return;
  }
  const ctHex = ctField.textContent.trim();

  try {
    const res = await fetch("/api/dynamic/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ciphertext: ctHex,
        master_key: masterKey,
        dynamic_salt: dynamicSalt
      })
    });

    const data = await res.json();
    if (!res.ok) {
      alert(`Dynamic Decryption Error: ${data.message}`);
      return;
    }

    alert(`🎉 Dynamic Decryption Successful!\n\nRECOVERED PLAIN TEXT:\n"${data.plaintext_ascii}"\n\n(Hex: ${data.plaintext_hex})`);
  } catch (err) {
    alert(`Network Error: ${err.message}`);
  }
}

// =========================================================
// DECRYPTION TAB (100% RELIABLE PLAIN TEXT RESTORATION)
// =========================================================
async function executeDecryption() {
  const ctVal = document.getElementById("decrypt-ct-input").value.trim();
  const keyVal = document.getElementById("decrypt-key-input").value.trim();

  if (!ctVal || !keyVal) {
    alert("Ciphertext and Key are required to decrypt!");
    return;
  }

  try {
    const res = await fetch("/api/des/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext: ctVal, key: keyVal })
    });

    const data = await res.json();
    if (!res.ok) {
      alert(`Decryption Error: ${data.message}`);
      return;
    }

    const recovered = data.recovered_plaintext || data.plaintext_ascii || data.plaintext_hex;

    // 1. Big Prominent Recovered Plain Text Display
    document.getElementById("dec-recovered-main").textContent = recovered;
    
    // Check match with current input
    const isExactMatch = (recovered === state.currentPlaintextInput);
    const indicator = document.getElementById("dec-match-indicator");
    if (isExactMatch) {
      indicator.className = "rec-match-badge mt-2 text-emerald";
      indicator.textContent = `✅ Decryption Verified: 100% Exact Match with Original Input Plaintext ("${recovered}")`;
    } else {
      indicator.className = "rec-match-badge mt-2 text-cyan";
      indicator.textContent = `✅ Successfully Decrypted: "${recovered}"`;
    }

    // 2. Character-by-character table
    const charsTbody = document.getElementById("dec-chars-table-body");
    charsTbody.innerHTML = "";
    if (data.recovered_chars && data.recovered_chars.length > 0) {
      data.recovered_chars.forEach((c, idx) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>Byte ${idx + 1}</td>
          <td class="text-emerald font-bold text-lg">'${c.char}'</td>
          <td><strong>${c.ascii}</strong></td>
          <td class="mono">${c.bin}</td>
        `;
        charsTbody.appendChild(tr);
      });
    }

    // 3. Hex Bytes
    document.getElementById("dec-recovered-hex").textContent = data.plaintext_hex;

    // 4. 16 Reverse Subkeys Table
    const tbody = document.getElementById("decryption-table-body");
    tbody.innerHTML = "";

    data.primary_block.rounds.forEach((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>Round ${r.round}</strong></td>
        <td class="text-rose font-bold">K${r.decryption_key_number} (Reversed)</td>
        <td class="text-cyan">${binToHex(r.L_previous)}</td>
        <td class="text-emerald">${binToHex(r.R_previous)}</td>
        <td class="text-amber">${binToHex(r.pbox_output)}</td>
        <td class="text-cyan">${binToHex(r.L_current)}</td>
        <td class="text-emerald font-bold">${binToHex(r.R_current)}</td>
      `;
      tbody.appendChild(tr);
    });

    // Scroll to results
    document.getElementById("decryption-results-card").scrollIntoView({ behavior: 'smooth' });

  } catch (err) {
    alert(`Decryption Network Error: ${err.message}`);
  }
}

// =========================================================
// COMPARISON TAB
// =========================================================
async function loadComparisonData(blockText = "TESTDATA", keyText = "SECURITY") {
  try {
    const res = await fetch("/api/comparison", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ block_hex: blockText, key: keyText })
    });

    const data = await res.json();
    if (!res.ok) return;

    // Plaintext Labels
    document.getElementById("std-comp-pt1").textContent = blockText;
    document.getElementById("std-comp-pt2").textContent = blockText;
    document.getElementById("dyn-comp-pt1").textContent = blockText;
    document.getElementById("dyn-comp-pt2").textContent = blockText;

    // Keys
    document.getElementById("std-comp-k1").textContent = keyText;
    document.getElementById("std-comp-k2").textContent = `${keyText} (Same Static Key!)`;
    document.getElementById("dyn-comp-k1").textContent = `${keyText} → ${data.dynamic_des.key_block1}`;
    document.getElementById("dyn-comp-k2").textContent = `${keyText} → ${data.dynamic_des.key_block2} (Dynamic Session Key!)`;

    // Standard DES Ciphertexts
    document.getElementById("std-comp-c1").textContent = data.standard_des.cipher_block1;
    document.getElementById("std-comp-c2").textContent = data.standard_des.cipher_block2;

    // Dynamic DES Ciphertexts
    document.getElementById("dyn-comp-c1").textContent = data.dynamic_des.cipher_block1;
    document.getElementById("dyn-comp-c2").textContent = data.dynamic_des.cipher_block2;

    const avalanchePct = data.dynamic_des.ciphertext_hamming_difference.avalanche_percentage;
    document.getElementById("metric-avalanche-pct").textContent = `${avalanchePct}% (${data.dynamic_des.ciphertext_hamming_difference.differing_bits} of 64 bits)`;
  } catch (err) {
    console.error("Comparison load error:", err);
  }
}
