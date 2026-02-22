// OSL: Accounting Suite - Core JS (Cel-Tech-Serv Pty Ltd)

// === [SEARCH: CORE INITIALIZATION] ===
async function initSovereign() {
    await loadAndApplyUserPrefs();
    fetch('/api/user/prefs').then(res => res.json()).then(data => applyTheme(data.theme));
    console.log("[SYSTEM] Initializing Application Context...");
    try {
        const res = await fetch('/api/settings/manifest');
        const data = await res.json();
        window.oslConfig = data;
        
        const switcher = document.getElementById('osl-context-switcher');
        const entryDiv = document.getElementById('entry-division'); 
        
        if (data.core.divisions) {
            let html = `<option value="global">${data.core.entity_name} (GLOBAL)</option>`;
            data.core.divisions.forEach(div => {
                html += `<option value="${div.id}">${div.name.toUpperCase()}</option>`;
            });
            if (switcher) switcher.innerHTML = html;
            if (entryDiv) entryDiv.innerHTML = html; 
            console.log("[SYSTEM] Entity Switchers Ready.");
        }
    } catch (err) {
        console.error("[SYSTEM] Configuration Fetch Failed:", err);
    }
}

// === [SEARCH: LEDGER API & RENDERER] ===
let globalLedgerData = [];
let currentLedgerTab = 'books';

async function refreshLedger() {
    const mainArea = document.getElementById('main-content');
    try {
        const response = await fetch('/api/ledger/data');
        if (!response.ok) throw new Error("API Connection Error");
        globalLedgerData = await response.json();
        renderAgnosticTable(globalLedgerData);
    } catch (err) {
        if(mainArea) mainArea.innerHTML = `<p class="text-red-500 font-bold bg-red-900/20 p-4 rounded border border-red-500">Connection Error: Ensure you are securely logged in.</p>`;
    }
}

function switchLedgerTab(tab) {
    currentLedgerTab = tab;
    renderAgnosticTable(globalLedgerData);
}

async function submitTransaction() {
    const toMicros = (val) => Math.round(parseFloat(val || 0) * 1000000);
    const txId = document.getElementById('edit-tx-id').value;
    const isEdit = txId !== '';
    
    const payload = {
        description: document.getElementById('desc').value,
        debit: toMicros(document.getElementById('debit').value),
        credit: toMicros(document.getElementById('credit').value),
        category: document.getElementById('category').value,
        division: document.getElementById('entry-division').value,
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
            cancelLedgerEdit(); 
            refreshLedger();
        } else {
            const errData = await response.json();
            alert("Action failed: " + (errData.error || "Check permissions."));
        }
    } catch (err) {
        console.error("Submission Error", err);
    }
}

function renderAgnosticTable(data, targetContainerId = 'main-content') {
    // 1. Filter data based on the active tab
    let filteredData = data;
    if (targetContainerId === 'main-content') {
        if (currentLedgerTab === 'receipts') {
            filteredData = data.filter(row => row.credit !== '$0.00' && row.credit !== '-');
        } else if (currentLedgerTab === 'payments') {
            filteredData = data.filter(row => row.debit !== '$0.00' && row.debit !== '-');
        }
    }

    // 2. Draw the Tab Navigation
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

    // 3. Draw the Table
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

        let cleanRowDiv = String(row.division || '').trim().toLowerCase();
        let displayEntity = row.division === 'global' ? 'GLOBAL' : row.division;
        
        if (window.oslConfig && window.oslConfig.core && window.oslConfig.core.divisions) {
            const matchedDiv = window.oslConfig.core.divisions.find(d => 
                String(d.id).trim().toLowerCase() === cleanRowDiv
            );
            if (matchedDiv) displayEntity = matchedDiv.name;
        }

        // === SPLIT-LEDGER VISUAL LOGIC ===
        let categoryDisplay = row.category || '-';
        if (row.splits && row.splits.length > 1) {
            categoryDisplay = `<span class="bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300 px-1 rounded text-[9px] font-bold">MULTI</span> ${row.splits.length} Items`;
        } else if (row.splits && row.splits.length === 1) {
            categoryDisplay = row.splits[0].category;
        }

         tableHtml += `
            <tr class="border-b border-gray-200 dark:border-slate-800 transition-colors ${rowClass}" ${clickHandler}>
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
}

// === [SEARCH: NAVIGATION CONTROLLERS] ===
function showLedger() {
    document.getElementById('view-users').style.display = 'none';
    document.getElementById('view-settings').style.display = 'none';
    document.getElementById('view-archives').style.display = 'none';
    document.getElementById('view-ledger').style.display = 'block';
    refreshLedger();
}

function showUserManagement() {
    document.getElementById('view-ledger').style.display = 'none';
    document.getElementById('view-settings').style.display = 'none';
    document.getElementById('view-archives').style.display = 'none';
    const userView = document.getElementById('view-users');
    userView.style.display = 'block';
    
    // UI generation omitted for brevity, logic remains identical
    fetchActiveUsers();
}

function showSettings() {
    document.getElementById('view-ledger').style.display = 'none';
    document.getElementById('view-users').style.display = 'none';
    document.getElementById('view-archives').style.display = 'none';
    document.getElementById('view-settings').style.display = 'block';
    renderSettingsTab('core');
}

function showArchives() {
    document.getElementById('view-ledger').style.display = 'none';
    document.getElementById('view-users').style.display = 'none';
    document.getElementById('view-settings').style.display = 'none';
    document.getElementById('view-archives').style.display = 'block';
    document.getElementById('archive-content').innerHTML = ''; 
    fetchArchiveList();
}

// === [SEARCH: USER MANAGEMENT ENGINE] ===
async function fetchActiveUsers() {
    console.log("--- USER ENGINE X-RAY START ---");
    try {
        const listContainer = document.getElementById('user-list-container');
        if (!listContainer) {
            console.error("[FATAL ERROR] The HTML element 'user-list-container' is missing from your base.html file!");
            return; 
        }

        console.log("1. Fetching current user identity...");
        const authRes = await fetch('/api/auth/me');
        const authData = await authRes.json();
        const currentUser = authData.user;
        
        console.log("2. Identity confirmed:", currentUser, authData.groups);
        const currentGroups = JSON.stringify(authData.groups || []).toLowerCase();

        const isCurrentAdmin = currentGroups.includes('admin');
        const isCurrentAccountant = currentGroups.includes('accountant');
        const isStandardUser = !isCurrentAdmin && !isCurrentAccountant;

        console.log("3. Fetching user list from backend...");
        const response = await fetch('/api/users/list');
        const data = await response.json();
        
        if (response.ok && data.data && data.data.users) {
            console.log("4. Rendering User Table...");
            const tableHtml = renderUserTable(data.data.users, currentUser, isCurrentAdmin, isCurrentAccountant, isStandardUser);
            
            listContainer.innerHTML = `
                <h3 class="text-blue-400 font-bold mb-4 uppercase tracking-wider text-sm">Active Users</h3>
                ${tableHtml}`;

            console.log("5. Adjusting Form Visibility...");
            const userForm = document.getElementById('user-form');
            
            // Safely check if the form exists before trying to hide/show it
            if (userForm) {
                // Look for any parent div that looks like a container
                const formContainer = userForm.closest('.bg-white, .bg-slate-900, div.rounded-lg, div');
                if (formContainer) {
                    formContainer.style.display = isStandardUser ? 'none' : 'block';
                }
            } else {
                console.warn("[WARNING] The HTML element 'user-form' was not found. Skipping visibility toggle.");
            }
            
            console.log("--- USER ENGINE X-RAY SUCCESS ---");
        } else {
            console.error("API returned an error or missing data:", data);
            listContainer.innerHTML = `<p class="text-red-500 font-bold">Backend Error: ${data.error || "Unknown"}</p>`;
        }
    } catch (err) {
        console.error("--- USER ENGINE CRASHED ---", err); 
        const listContainer = document.getElementById('user-list-container');
        if (listContainer) {
            listContainer.innerHTML = `<p class="text-red-500 font-bold bg-red-900/20 p-4 border border-red-500 rounded">Application UI Exception. Please press F12 and check the Console tab for the exact error.</p>`;
        }
    }
}

function renderUserTable(users, currentUser, isCurrentAdmin, isCurrentAccountant, isStandardUser) {
    let tableHtml = `
        <table class="w-full text-left text-[11px] border-collapse">
            <thead>
                <tr class="border-b border-slate-700 text-blue-400 uppercase font-black tracking-wider">
                    <th class="py-3 px-2">Username</th>
                    <th class="py-3 px-2">Display Name</th>
                    <th class="py-3 px-2">User Role</th>
                    <th class="py-3 px-2 text-center">Action</th>
                </tr>
            </thead>
            <tbody>`;
    
    users.forEach(user => {
        if (user.groups && Array.isArray(user.groups) && user.groups.some(g => String(g.id) === '1' || g.id === 'lldap_admin')) return; 

        let userType = '<span class="text-slate-500 font-bold">[UNASSIGNED]</span>';
        let targetRole = 'user'; 
        let targetRoleId = '6';  
        let primaryGroup = null;

        if (user.groups && Array.isArray(user.groups)) {
            primaryGroup = user.groups.find(g => {
                const gName = String(g.displayName || g.id).toLowerCase();
                return gName.includes('admin') || gName.includes('accountant') || gName.includes('user');
            });
        }

        if (primaryGroup) {
            const gName = String(primaryGroup.displayName || primaryGroup.id).toLowerCase();
            let colour = 'text-slate-300'; 
            targetRoleId = String(primaryGroup.id);
            
            if (gName.includes('admin')) {
                colour = 'text-blue-400 font-black tracking-wide';
                targetRole = 'admin';
            } else if (gName.includes('accountant')) {
                colour = 'text-green-400 font-bold';
                targetRole = 'accountant';
            }

            userType = `<span class="${colour}">[${(primaryGroup.displayName || primaryGroup.id).toString().toUpperCase()}]</span>`;
        }

        if (!isCurrentAdmin) {
            if (isCurrentAccountant) {
                if (user.id !== currentUser && targetRole !== 'user') return;
            } else {
                if (user.id !== currentUser) return;
            }
        }

        tableHtml += `
            <tr class="border-b border-slate-800 hover:bg-blue-900/10 cursor-pointer transition-colors" 
                data-id="${user.id}" 
                data-email="${user.email}" 
                data-display="${user.displayName || ''}" 
                data-first="${user.firstName || ''}" 
                data-last="${user.lastName || ''}"
                data-roleid="${targetRoleId}"
                onclick="editSovereignUser(this.dataset)">
                <td class="py-3 px-2 font-bold text-slate-300">${user.id}</td>
                <td class="py-3 px-2 text-slate-400">${user.displayName || '-'}</td>
                <td class="py-3 px-2">${userType}</td>
                <td class="py-3 px-2 text-center text-blue-500 font-bold">EDIT</td>
            </tr>`;
    });
    
    return tableHtml + `</tbody></table>`;
}

function editSovereignUser(data) {
    document.getElementById('edit-mode').value = 'true';
    document.getElementById('new-username').value = data.id;
    document.getElementById('new-username').readOnly = true; 
    document.getElementById('new-email').value = data.email;
    document.getElementById('new-displayname').value = data.display;
    document.getElementById('new-firstname').value = data.first;
    document.getElementById('new-lastname').value = data.last;
    document.getElementById('new-password').value = ''; 
    document.getElementById('new-role').value = data.roleid;
    
    const submitBtn = document.getElementById('user-submit-btn');
    submitBtn.innerText = 'Update User: ' + data.id;
    submitBtn.classList.replace('bg-blue-600', 'bg-orange-600');
    
    document.getElementById('user-cancel-btn').classList.remove('hidden');
    document.getElementById('user-msg').innerHTML = `<span class="text-orange-400 italic">Editing User: ${data.id}</span>`;
}

function cancelEdit() {
    document.getElementById('user-form').reset();
    document.getElementById('edit-mode').value = 'false';
    document.getElementById('new-username').readOnly = false;
    
    const submitBtn = document.getElementById('user-submit-btn');
    submitBtn.innerText = 'Add User';
    submitBtn.classList.replace('bg-orange-600', 'bg-blue-600');
    
    document.getElementById('user-cancel-btn').classList.add('hidden');
    document.getElementById('user-msg').innerHTML = '';
}

async function submitIdentity() {
    const isEdit = document.getElementById('edit-mode').value === 'true';
    const endpoint = isEdit ? '/api/users/update' : '/api/users/add';
    
    const payload = {
        username: document.getElementById('new-username').value,
        email: document.getElementById('new-email').value,
        displayName: document.getElementById('new-displayname').value,
        firstName: document.getElementById('new-firstname').value,
        lastName: document.getElementById('new-lastname').value,
        password: document.getElementById('new-password').value,
        roleId: document.getElementById('new-role').value 
    };

    if (!isEdit && !payload.password) {
        document.getElementById('user-msg').innerHTML = '<span class="text-red-500">Error: Password is required for new users.</span>';
        return;
    }

    const msgDiv = document.getElementById('user-msg');
    msgDiv.innerHTML = '<span class="text-yellow-400">Processing request...</span>';

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await response.json();
        
        if (response.ok) {
            msgDiv.innerHTML = `<span class="text-green-500">Success: ${data.message}</span>`;
            cancelEdit(); 
            fetchActiveUsers();
        } else {
            msgDiv.innerHTML = `<span class="text-red-500">Error: ${data.error}</span>`;
        }
    } catch (err) {
        msgDiv.innerHTML = '<span class="text-red-500">Connection Error: Failed to update user.</span>';
    }
}

// === [SEARCH: SETTINGS & PREFERENCES] ===
async function renderSettingsTab(tab) {
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
        content.innerHTML = `<p class="text-blue-400 animate-pulse">Loading configuration...</p>`;
        const res = await fetch('/api/settings/manifest');
        const data = await res.json();
        window.currentConfig = data; 

        content.innerHTML = `
            <h3 class="text-blue-400 font-bold mb-6 uppercase tracking-wider text-sm">System Configuration</h3>
            <div class="space-y-4 max-w-xl">
                <div>
                    <label class="block text-slate-400 text-xs mb-1 uppercase">Business Entity Name</label>
                    <input type="text" id="conf-entity-name" value="${data.core.entity_name}" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white font-mono">
                </div>
                <button onclick="saveCoreSettings()" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-6 rounded mt-4">Save Configuration</button>
            </div>`;
    } 
    
    if (tab === 'diag') {
        content.innerHTML = `
            <h3 class="text-gray-500 dark:text-gray-400 font-bold mb-4 uppercase tracking-wider text-sm">System Logs</h3>
            <div id="osl-terminal" class="bg-black border border-slate-800 h-96 rounded p-4 font-mono text-[10px] text-green-500 overflow-y-auto mb-4">
                Loading system activity...
            </div>
            <button onclick="downloadErrorReport()" class="text-[10px] bg-slate-800 p-2 rounded uppercase font-black hover:bg-slate-700 text-white">Download Full Log Report</button>`;
        refreshDiagLogs();
    }

    if (tab === 'danger') {
        content.innerHTML = `
            <h3 class="text-red-500 font-bold mb-6 uppercase tracking-wider text-sm">Data Management (Danger Zone)</h3>
            <div class="border border-red-500/30 bg-red-50 dark:bg-red-900/10 p-6 rounded-lg transition-colors">
                <p class="text-red-600 dark:text-red-400 text-xs font-bold">NOTICE: The End of Financial Year (EOFY) Rollover tool has been relocated. Please navigate to "Historical Archives" in the main sidebar to securely archive and reset the ledger.</p>
            </div>`;
    }
}

async function refreshDiagLogs() {
    const res = await fetch('/api/system/logs');
    const data = await res.json();
    const term = document.getElementById('osl-terminal');
    if (term) term.innerHTML = data.logs.join('<br>');
}

async function saveCoreSettings() {
    window.currentConfig.core.entity_name = document.getElementById('conf-entity-name').value;
    
    const acnField = document.getElementById('conf-acn');
    if (acnField) {
        window.currentConfig.core.acn = acnField.value;
    }

    const res = await fetch('/api/settings/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(window.currentConfig)
    });
    if (res.ok) {
        alert("Configuration saved successfully.");
    } else {
        alert("Error saving configuration.");
    }
}

async function saveUserPrefs() {
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
        loadAndApplyUserPrefs(); 
    } else {
        alert("Failed to save preferences. Please check your connection.");
    }
}

async function applyTheme(theme) {
    const htmlTag = document.documentElement;
    if (theme === 'light') {
        htmlTag.classList.remove('dark');
    } else {
        htmlTag.classList.add('dark');
    }
}

async function loadAndApplyUserPrefs() {
    try {
        const res = await fetch('/api/user/prefs');
        const prefs = await res.json();
        const htmlElement = document.documentElement; 

        if (prefs.theme === 'light') {
            htmlElement.classList.remove('dark');
        } else {
            htmlElement.classList.add('dark');
        }

        if (prefs.ui_scale === 'large') {
            htmlElement.style.fontSize = '18px'; 
        } else if (prefs.ui_scale === 'xlarge') {
            htmlElement.style.fontSize = '20px'; 
        } else {
            htmlElement.style.fontSize = '16px'; 
        }

    } catch (err) {
        console.error("Failed to load user preferences.", err);
    }
}

function downloadErrorReport() {
    fetch('/api/system/logs')
        .then(res => res.json())
        .then(data => {
            const blob = new Blob([data.logs.join('\n')], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `System_Log_${new Date().getTime()}.txt`;
            a.click();
            alert("System log downloaded. Please attach this file if requesting support.");
        });
}

// === [SEARCH: HISTORICAL ARCHIVES & EOFY] ===
async function fetchArchiveList() {
    try {
        const response = await fetch('/api/archives/list');
        if (!response.ok) throw new Error("Failed to fetch archives");
        const archives = await response.json();
        
        const selector = document.getElementById('archive-selector');
        if (archives.length === 0) {
            selector.innerHTML = '<option value="">No Archives Available.</option>';
            return;
        }

        let html = '<option value="">Select an Archive...</option>';
        archives.forEach(arch => {
            html += `<option value="${arch}">${arch.toUpperCase()}</option>`;
        });
        selector.innerHTML = html;
    } catch (err) {
        console.error("Archive List Error", err);
    }
}

async function loadSelectedArchive() {
    const tableName = document.getElementById('archive-selector').value;
    const contentArea = document.getElementById('archive-content');
    
    if (!tableName) {
        contentArea.innerHTML = `<p class="text-orange-500 font-bold text-sm">Please select an archive first.</p>`;
        return;
    }

    contentArea.innerHTML = `<p class="text-blue-500 font-bold animate-pulse text-sm">Decrypting and loading ${tableName}...</p>`;

    try {
        const response = await fetch(`/api/archives/data/${tableName}`);
        if (!response.ok) throw new Error("API Connection Error");
        const data = await response.json();
        
        renderAgnosticTable(data, 'archive-content');
        
    } catch (err) {
        contentArea.innerHTML = `<p class="text-red-500 font-bold bg-red-900/20 p-4 rounded border border-red-500">Failed to load archive data.</p>`;
    }
}

async function executePurge() {
    const confirmInput = document.getElementById('purge-confirm');
    
    if (confirmInput.value !== "EOFY ARCHIVE") {
        alert("Action Aborted: You must type 'EOFY ARCHIVE' exactly to confirm the rollover.");
        return;
    }

    const payload = {
        confirmation: confirmInput.value
    };

    try {
        const response = await fetch('/api/ledger/purge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            const data = await response.json();
            alert(`EOFY Rollover Successful!\n\nAll data has been sealed in database table: ${data.archive_name}\n\nThe active chain is now reset to GENESIS.`);
            confirmInput.value = ""; 
            refreshLedger();
            fetchArchiveList(); 
        } else {
            const data = await response.json();
            alert("Rollover failed: " + (data.error || "Check permissions."));
        }
    } catch (err) {
        console.error("Rollover Error", err);
        alert("Connection error while attempting to archive data.");
    }
}

// === [SEARCH: LEDGER EDIT ENGINE] ===
let currentEditSplits = []; // <-- THE MEMORY BANK

function editLedgerEntry(row) {
    document.getElementById('edit-tx-id').value = row.id;
    document.getElementById('desc').value = row.description;
    document.getElementById('debit').value = row.debit.replace('$', '');
    document.getElementById('credit').value = row.credit.replace('$', '');
    document.getElementById('category').value = row.category;
    document.getElementById('entry-division').value = row.division;
    
    // SAVE THE SPLITS SO THEY AREN'T LOST!
    currentEditSplits = row.splits || [];
    
    document.getElementById('ledger-submit-text').innerText = 'Update Entry';
    document.getElementById('ledger-submit-btn').classList.replace('bg-blue-600', 'bg-orange-600');
    document.getElementById('ledger-cancel-btn').classList.remove('hidden');
    
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function cancelLedgerEdit() {
    document.getElementById('ledger-form').reset();
    document.getElementById('edit-tx-id').value = '';
    document.getElementById('ledger-submit-text').innerText = 'Save Entry';
    document.getElementById('ledger-submit-btn').classList.replace('bg-orange-600', 'bg-blue-600');
    document.getElementById('ledger-cancel-btn').classList.add('hidden');
    
    // CLEAR MEMORY ON CANCEL
    currentEditSplits = []; 
}
