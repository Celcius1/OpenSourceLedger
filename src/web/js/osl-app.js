// OSL: Accounting Suite - Agnostic Core Engine
// ============================================================================
// This core Javascript handles pure UI routing, Core Ledger fetches, and delegates
// specific rendering logic to dynamically loaded Sovereign Plugins via window.pluginHooks.
// ============================================================================

window.pluginHooks = window.pluginHooks || {};

// === [CORE INITIALISATION] ===
async function initSovereign() {
    await loadAndApplyUserPrefs();
    console.log("[SYSTEM] Waking Sovereign Core Node...");
    
    try {
        const res = await fetch('/api/settings/manifest');
        window.oslConfig = await res.json();
        
        if (typeof window.pluginHooks.onAppInit === 'function') {
            await window.pluginHooks.onAppInit();
        }
    } catch (err) {
        console.error("[SYSTEM] Configuration Fetch Failed:", err);
    }
}

// === [LEDGER API & RENDERER] ===
let globalLedgerData = [];
let currentLedgerTab = 'books';
let currentEditSplits = []; 

window.refreshLedger = async function() {
    const mainArea = document.getElementById('main-content');
    try {
        const response = await fetch('/api/ledger/data');
        if (!response.ok) throw new Error("API Connection Error");
        globalLedgerData = await response.json();
        window.renderAgnosticTable(globalLedgerData);
    } catch (err) {
        if(mainArea) mainArea.innerHTML = `<p class="text-red-500 font-bold bg-red-900/20 p-4 rounded border border-red-500">Connection Error: Ensure you are securely logged in.</p>`;
    }
};

window.switchLedgerTab = function(tab) {
    currentLedgerTab = tab;
    window.renderAgnosticTable(globalLedgerData);
};

window.submitTransaction = async function() {
    const toMicros = (val) => Math.round(parseFloat(val || 0) * 1000000);
    const txId = document.getElementById('edit-tx-id').value;
    const isEdit = txId !== '';
    
    let finalCategory = document.getElementById('category').value;
    
    if (typeof window.applyPluginHooks === 'function') {
        finalCategory = window.applyPluginHooks(finalCategory);
    }

    let targetDivision = document.getElementById('osl-context-switcher')?.value || 'global';
    if (isEdit) {
        targetDivision = document.getElementById('edit-tx-division').value;
    }

    const payload = {
        description: document.getElementById('desc').value,
        debit: toMicros(document.getElementById('debit').value),
        credit: toMicros(document.getElementById('credit').value),
        category: finalCategory, 
        division: targetDivision,
        subcategory: "",
        splits: currentEditSplits
    };

    if (isEdit) payload.id = parseInt(txId);

    try {
        const response = await fetch(isEdit ? '/api/ledger/edit' : '/api/ledger/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (response.ok) {
            window.cancelLedgerEdit(); 
            window.refreshLedger();
        } else {
            const errData = await response.json();
            alert("Action failed: " + (errData.error || "Check permissions."));
        }
    } catch (err) {
        console.error("Submission Error", err);
    }
};

window.renderAgnosticTable = function(data, targetContainerId = 'main-content') {
    const activeContext = document.getElementById('osl-context-switcher')?.value || 'global';
    
    let validDivisions = [activeContext];
    
    if (typeof window.pluginHooks.getExpandedContexts === 'function') {
        validDivisions = window.pluginHooks.getExpandedContexts(activeContext);
    }

    let filteredData = data.filter(row => validDivisions.includes(row.division) || activeContext === 'global');
    
    if (targetContainerId === 'main-content') {
        if (currentLedgerTab === 'receipts') {
            filteredData = filteredData.filter(row => row.credit !== '$0.00' && row.credit !== '-');
        } else if (currentLedgerTab === 'payments') {
            filteredData = filteredData.filter(row => row.debit !== '$0.00' && row.debit !== '-');
        }
    }

    let tabHtml = '';
    if (targetContainerId === 'main-content') {
        const activeClass = "text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400 font-black";
        const inactiveClass = "text-gray-500 dark:text-slate-500 hover:text-gray-700 dark:hover:text-slate-300 font-bold";
        
        tabHtml = `
        <div class="flex space-x-8 mb-4 border-b border-gray-200 dark:border-slate-700 px-2">
            <button onclick="switchLedgerTab('books')" class="pb-2 text-xs uppercase tracking-wider transition-colors ${currentLedgerTab === 'books' ? activeClass : inactiveClass}">Company Books</button>
            <button onclick="switchLedgerTab('receipts')" class="pb-2 text-xs uppercase tracking-wider transition-colors ${currentLedgerTab === 'receipts' ? activeClass : inactiveClass}">Company Receipts</button>
            <button onclick="switchLedgerTab('payments')" class="pb-2 text-xs uppercase tracking-wider transition-colors ${currentLedgerTab === 'payments' ? activeClass : inactiveClass}">Company Payments</button>
        </div>`;
    }

    let tableHtml = tabHtml + `
        <table class="w-full text-left text-[11px] border-collapse">
            <thead>
                <tr class="border-b border-gray-300 dark:border-slate-700 text-blue-600 dark:text-blue-400 uppercase font-black tracking-wider">
                    <th class="py-3 px-2">Date</th>
                    <th class="py-3 px-2">Description</th>
                    <th class="py-3 px-2">Category</th>
                    <th class="py-3 px-2">Entity</th>
                    <th class="py-3 px-2 text-right">Debit</th>
                    <th class="py-3 px-2 text-right">Credit</th>
                    <th class="py-3 px-2 text-right">Balance</th>
                    <th class="py-3 px-2 text-center">Audit</th>
                </tr>
            </thead>
            <tbody>`;
            
    filteredData.forEach(row => {
        const auditFailed = row.audit_passed === false;
        let rowClass = auditFailed ? 'bg-red-100 dark:bg-red-900/20 border-l-4 border-red-500' : 'hover:bg-gray-100 dark:hover:bg-slate-800/60';
       
        let actionHtml = auditFailed ? '<span class="text-red-600 dark:text-red-500 font-bold">FAIL</span>' : '<span class="text-green-600 dark:text-green-500 font-bold">OK</span>';
        let clickHandler = '';
        
        if (row.is_editable) {
            const safeData = encodeURIComponent(JSON.stringify(row)).replace(/'/g, "%27");
            actionHtml = `<span class="text-blue-600 font-bold text-[10px] bg-blue-100 dark:bg-blue-900/30 px-2 py-1 rounded transition-colors">EDIT (OPEN)</span>`;
            rowClass = 'hover:bg-blue-50 dark:hover:bg-blue-900/20 cursor-pointer';
            clickHandler = `onclick="editLedgerEntry(JSON.parse(decodeURIComponent('${safeData}')))"`;
        }

        let displayEntity = row.division === 'global' ? 'GLOBAL' : row.division;
        
        if (typeof window.pluginHooks.getEntityName === 'function') {
            displayEntity = window.pluginHooks.getEntityName(row.division) || displayEntity;
        }

        let categoryDisplay = row.category || '-';
        if (row.splits && row.splits.length > 1) {
            categoryDisplay = `<span class="bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300 px-1 rounded text-[9px] font-bold">MULTI</span> ${row.splits.length} Items`;
        } else if (row.splits && row.splits.length === 1) {
            categoryDisplay = row.splits[0].category;
        }

        tableHtml += `
            <tr class="border-b border-gray-200 dark:border-slate-800 transition-colors ${rowClass}" data-txid="${row.id}" ${clickHandler}>
                <td class="py-3 px-2 text-gray-600 dark:text-slate-400">${row.date}</td>
                <td class="py-3 px-2 font-bold text-gray-900 dark:text-white">${row.description}</td>
                <td class="py-3 px-2 text-gray-500 dark:text-slate-500">${categoryDisplay}</td>
                <td class="py-3 px-2 text-purple-600 dark:text-purple-400 font-bold text-[9px] uppercase">${displayEntity}</td>
                <td class="py-3 px-2 text-right text-orange-600 dark:text-orange-400 font-medium">${row.debit === '$0.00' ? '-' : row.debit}</td>
                <td class="py-3 px-2 text-right text-green-600 dark:text-green-400 font-medium">${row.credit === '$0.00' ? '-' : row.credit}</td>
                <td class="py-3 px-2 text-right font-black text-gray-900 dark:text-white">${row.balance}</td>
                <td class="py-3 px-2 text-center">${actionHtml}</td> 
            </tr>`;
    });
    
    tableHtml += `</tbody></table>`;
    document.getElementById(targetContainerId).innerHTML = tableHtml;
};

// === [NAVIGATION CONTROLLERS] ===
window.showLedger = function() {
    document.getElementById('view-users').style.display = 'none';
    document.getElementById('view-settings').style.display = 'none';
    document.getElementById('view-ledger').style.display = 'block';
    window.refreshLedger();
};

window.showUserManagement = function() {
    document.getElementById('view-ledger').style.display = 'none';
    document.getElementById('view-settings').style.display = 'none';
    
    const userView = document.getElementById('view-users');
    userView.style.display = 'block';
    
    if (typeof window.pluginHooks.onUserManagementShow === 'function') {
        window.pluginHooks.onUserManagementShow();
    }
};

window.showSettings = function() {
    document.getElementById('view-ledger').style.display = 'none';
    document.getElementById('view-users').style.display = 'none';
    document.getElementById('view-settings').style.display = 'block';
    window.renderSettingsTab('core');
};

// === [SETTINGS & PREFERENCES] ===
window.renderSettingsTab = async function(tab) {
    const content = document.getElementById('settings-tab-content');
    document.querySelectorAll('.settings-nav-btn').forEach(btn => btn.classList.remove('bg-blue-600/20', 'text-blue-400'));

    if (tab === 'account') {
        const prefsRes = await fetch('/api/user/prefs');
        const prefs = await prefsRes.json();
        const currentTheme = prefs.theme || 'dark';
        const currentScale = prefs.ui_scale || 'normal';

        content.innerHTML = `
            <h3 class="text-green-600 dark:text-green-500 font-bold mb-6 uppercase tracking-wider text-sm">Personal Interface Preferences</h3>
            <div class="space-y-6 max-w-xl">
                <div>
                    <label class="block text-gray-500 dark:text-slate-500 text-[10px] font-black uppercase mb-2 tracking-widest">Display Theme</label>
                    <select id="pref-theme" class="w-full bg-white dark:bg-slate-950 border border-gray-300 dark:border-slate-800 p-3 text-gray-900 dark:text-white rounded font-mono text-sm shadow-sm dark:shadow-none">
                        <option value="light" ${currentTheme === 'light' ? 'selected' : ''}>Light Mode (High Contrast)</option>
                        <option value="dark" ${currentTheme === 'dark' ? 'selected' : ''}>Dark Mode</option>
                    </select>
                </div>
                <div>
                    <label class="block text-gray-500 dark:text-slate-500 text-[10px] font-black uppercase mb-2 tracking-widest">Interface Text Size</label>
                    <select id="pref-scale" class="w-full bg-white dark:bg-slate-950 border border-gray-300 dark:border-slate-800 p-3 text-gray-900 dark:text-white rounded font-mono text-sm shadow-sm dark:shadow-none">
                        <option value="normal" ${currentScale === 'normal' ? 'selected' : ''}>Normal (Default)</option>
                        <option value="large" ${currentScale === 'large' ? 'selected' : ''}>Large</option>
                        <option value="xlarge" ${currentScale === 'xlarge' ? 'selected' : ''}>Extra Large</option>
                    </select>
                </div>
                <button onclick="saveUserPrefs()" class="bg-green-600 hover:bg-green-700 dark:hover:bg-green-500 text-white font-bold py-3 px-6 rounded mt-4 transition-colors shadow-md">Save Preferences</button>
            </div>`;
    }

    if (tab === 'core') {
        content.innerHTML = `<p class="text-blue-400 animate-pulse font-bold">Loading configuration...</p>`;
        const res = await fetch('/api/settings/manifest');
        const data = await res.json();
        window.currentConfig = data; 

        content.innerHTML = `
            <h3 class="text-blue-600 dark:text-blue-400 font-bold mb-6 uppercase tracking-wider text-sm">System Configuration</h3>
            <div class="space-y-4 max-w-xl">
                <div>
                    <label class="block text-slate-500 dark:text-slate-400 text-[10px] font-black uppercase mb-1 tracking-widest">Business Entity Name</label>
                    <input type="text" id="conf-entity-name" value="${data.core.entity_name}" class="w-full bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded p-2 text-gray-900 dark:text-white shadow-sm font-bold">
                </div>
                <button onclick="saveCoreSettings()" class="bg-blue-600 hover:bg-blue-700 dark:hover:bg-blue-500 text-white font-bold py-2 px-6 rounded mt-4 shadow-md transition-colors">Save Configuration</button>
            </div>`;
    } 
    
    if (tab === 'diag') {
        content.innerHTML = `
            <h3 class="text-gray-600 dark:text-gray-400 font-bold mb-4 uppercase tracking-wider text-sm">System Logs</h3>
            <div id="osl-terminal" class="bg-black border border-slate-800 h-96 rounded p-4 font-mono text-[10px] text-green-500 overflow-y-auto mb-4 shadow-inner">
                Loading system activity...
            </div>
            <button onclick="downloadErrorReport()" class="text-[10px] bg-slate-200 dark:bg-slate-800 p-2 rounded uppercase font-black text-slate-700 dark:text-white hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors shadow-sm">Download Full Log Report</button>`;
        window.refreshDiagLogs();
    }
};

window.refreshDiagLogs = async function() {
    const res = await fetch('/api/system/logs');
    const data = await res.json();
    const term = document.getElementById('osl-terminal');
    if (term) term.innerHTML = data.logs.join('<br>');
};

window.saveCoreSettings = async function() {
    window.currentConfig.core.entity_name = document.getElementById('conf-entity-name').value;
    const res = await fetch('/api/settings/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(window.currentConfig)
    });
    if (res.ok) alert("Configuration saved successfully.");
    else alert("Error saving configuration.");
};

window.saveUserPrefs = async function() {
    const payload = {
        theme: document.getElementById('pref-theme').value,
        ui_scale: document.getElementById('pref-scale').value
    };
    const res = await fetch('/api/user/prefs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (res.ok) {
        alert("Preferences saved successfully.");
        window.loadAndApplyUserPrefs(); 
    }
};

window.applyTheme = async function(theme) {
    const htmlTag = document.documentElement;
    if (theme === 'light') htmlTag.classList.remove('dark');
    else htmlTag.classList.add('dark');
};

window.loadAndApplyUserPrefs = async function() {
    try {
        const res = await fetch('/api/user/prefs');
        const prefs = await res.json();
        const htmlElement = document.documentElement; 

        if (prefs.theme === 'light') htmlElement.classList.remove('dark');
        else htmlElement.classList.add('dark');

        if (prefs.ui_scale === 'large') htmlElement.style.fontSize = '18px'; 
        else if (prefs.ui_scale === 'xlarge') htmlElement.style.fontSize = '20px'; 
        else htmlElement.style.fontSize = '16px'; 
    } catch (err) {}
};

window.downloadErrorReport = function() {
    fetch('/api/system/logs')
        .then(res => res.json())
        .then(data => {
            const blob = new Blob([data.logs.join('\n')], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `System_Log_${new Date().getTime()}.txt`;
            a.click();
        });
};

// === [LEDGER EDIT ENGINE] ===
window.editLedgerEntry = function(row) {
    document.getElementById('edit-tx-id').value = row.id;
    document.getElementById('desc').value = row.description;
    document.getElementById('debit').value = row.debit.replace('$', '');
    document.getElementById('credit').value = row.credit.replace('$', '');
    document.getElementById('category').value = row.category;
    
    document.getElementById('edit-tx-division').value = row.division;
    
    currentEditSplits = row.splits || [];
    
    document.getElementById('ledger-submit-text').innerText = 'Update Entry';
    document.getElementById('ledger-submit-btn').classList.replace('bg-blue-600', 'bg-orange-600');
    document.getElementById('ledger-cancel-btn').classList.remove('hidden');
    
    window.scrollTo({ top: 0, behavior: 'smooth' });
};

window.cancelLedgerEdit = function() {
    document.getElementById('ledger-form').reset();
    document.getElementById('edit-tx-id').value = '';
    document.getElementById('edit-tx-division').value = '';
    document.getElementById('ledger-submit-text').innerText = 'Save Entry';
    document.getElementById('ledger-submit-btn').classList.replace('bg-orange-600', 'bg-blue-600');
    document.getElementById('ledger-cancel-btn').classList.add('hidden');
    currentEditSplits = []; 
};