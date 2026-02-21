// OSL: Sovereign Accounting Suite - Core JS (Cel-Tech-Serv Pty Ltd)

async function refreshLedger() {
    const mainArea = document.getElementById('main-content');
    try {
        const response = await fetch('/api/ledger/data');
        if (!response.ok) throw new Error("Unauthorised or API Error");
        const data = await response.json();
        renderAgnosticTable(data);
    } catch (err) {
        if(mainArea) mainArea.innerHTML = `<p class="text-red-500 font-bold bg-red-900/20 p-4 rounded border border-red-500">VAULT SYNC ERROR: Ensure you are logged in via Authelia.</p>`;
    }
}

async function submitTransaction() {
    const toMicros = (val) => Math.round(parseFloat(val || 0) * 1000000);
    const payload = {
        description: document.getElementById('desc').value,
        debit: toMicros(document.getElementById('debit').value),
        credit: toMicros(document.getElementById('credit').value),
        category: document.getElementById('category').value,
        subcategory: ""
    };
    try {
        const response = await fetch('/api/ledger/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (response.ok) {
            document.getElementById('ledger-form').reset();
            document.getElementById('debit').value = "0.00";
            document.getElementById('credit').value = "0.00";
            refreshLedger();
        } else {
            alert("Vault insertion failed. Check permissions.");
        }
    } catch (err) {
        console.error("Submission Error", err);
    }
}

function renderAgnosticTable(data) {
    let tableHtml = `
        <table class="w-full text-left text-[11px] border-collapse">
            <thead>
                <tr class="border-b border-slate-700 text-blue-400 uppercase font-black tracking-wider">
                    <th class="py-3 px-2">Date</th>
                    <th class="py-3 px-2">Description</th>
                    <th class="py-3 px-2">Category</th>
                    <th class="py-3 px-2 text-right">Debit</th>
                    <th class="py-3 px-2 text-right">Credit</th>
                    <th class="py-3 px-2 text-right">Balance</th>
                    <th class="py-3 px-2 text-center">Audit</th>
                </tr>
            </thead>
            <tbody>`;
    data.forEach(row => {
        const auditFailed = row.audit_passed === false;
        const rowClass = auditFailed ? 'bg-red-900/20 border-l-4 border-red-500' : 'hover:bg-slate-800/60';
        const auditIcon = auditFailed ? '<span class="text-red-500 font-bold">FAIL</span>' : '<span class="text-green-500">OK</span>';
        tableHtml += `
            <tr class="border-b border-slate-800 ${rowClass}">
                <td class="py-3 px-2 text-slate-400">${row.date}</td>
                <td class="py-3 px-2 font-bold">${row.description}</td>
                <td class="py-3 px-2 text-slate-500">${row.category || '-'}</td>
                <td class="py-3 px-2 text-right text-orange-400">${row.debit === '$0.00' ? '-' : row.debit}</td>
                <td class="py-3 px-2 text-right text-green-400">${row.credit === '$0.00' ? '-' : row.credit}</td>
                <td class="py-3 px-2 text-right font-black">${row.balance}</td>
                <td class="py-3 px-2 text-center">${auditIcon}</td>
            </tr>`;
    });
    tableHtml += `</tbody></table>`;
    document.getElementById('main-content').innerHTML = tableHtml;
}

function showLedger() {
    document.getElementById('view-users').style.display = 'none';
    document.getElementById('view-ledger').style.display = 'block';
    refreshLedger();
}

function showUserManagement() {
    document.getElementById('view-ledger').style.display = 'none';
    const userView = document.getElementById('view-users');
    userView.style.display = 'block';
    
    // UI Upgrade: Added new fields, removed required tag from password, added a Cancel button
	userView.innerHTML = `
        <div class="bg-slate-800 p-6 rounded-lg border border-slate-700 mb-8">
            <h3 class="text-blue-400 font-bold mb-4 uppercase tracking-wider text-sm">Provision / Update Users</h3>
            <form id="user-form" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-sm" onsubmit="event.preventDefault(); submitIdentity();">
                <input type="hidden" id="edit-mode" value="false">
                
                <div>
                    <label class="block text-slate-400 text-xs mb-1">Username (LDAP ID) *</label>
                    <input type="text" id="new-username" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white" required>
                </div>
                <div>
                    <label class="block text-slate-400 text-xs mb-1">Email Address *</label>
                    <input type="email" id="new-email" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white" required>
                </div>
                <div>
                    <label class="block text-slate-400 text-xs mb-1">Display Name *</label>
                    <input type="text" id="new-displayname" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white" required>
                </div>
                <div>
                    <label class="block text-slate-400 text-xs mb-1">First Name</label>
                    <input type="text" id="new-firstname" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white">
                </div>
                <div>
                    <label class="block text-slate-400 text-xs mb-1">Last Name</label>
                    <input type="text" id="new-lastname" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white">
                </div>
                
                <div>
                    <label class="block text-slate-400 text-xs mb-1">Sovereign Role *</label>
                    <select id="new-role" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white font-bold" required>
                        <option value="6" class="text-slate-300">Standard User</option>
                        <option value="5" class="text-green-400">Accountant</option>
                        <option value="4" class="text-blue-400">Administrator</option>
                    </select>
                </div>

                <div>
                    <label class="block text-slate-400 text-xs mb-1">Password <span class="text-slate-500 text-[10px]">(Leave blank to keep current)</span></label>
                    <input type="password" id="new-password" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white">
                </div>
                
                <div class="md:col-span-2 flex items-end mt-2">
                    <button type="submit" id="user-submit-btn" class="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded transition-colors">
                        Command Core to Provision Identity
                    </button>
                    <button type="button" id="user-cancel-btn" onclick="cancelEdit()" class="hidden w-1/3 ml-4 bg-slate-700 hover:bg-slate-600 text-white font-bold py-2 px-4 rounded transition-colors">
                        Cancel Edit
                    </button>
                </div>
            </form>
            <div id="user-msg" class="mt-4 text-xs font-bold tracking-wide"></div>
        </div>
        
        <div id="user-list-container" class="bg-slate-800 p-6 rounded-lg border border-slate-700">
            <h3 class="text-blue-400 font-bold mb-4 uppercase tracking-wider text-sm">Active Users (Cel-Tech-Serv Pty Ltd)</h3>
            <p class="text-slate-400 text-xs">Synchronising with Vault...</p>
        </div>`;
    fetchActiveUsers();
}

async function fetchActiveUsers() {
    try {
        // 1. Ask the Sovereign Core who is currently holding the mouse
        const authRes = await fetch('/api/auth/me');
        const authData = await authRes.json();
        const currentUser = authData.user;
        
        // Convert the Authelia header to lowercase to ensure safe, case-insensitive string matching
        const currentGroups = (authData.groups || '').toLowerCase();

        // 2. Determine privilege level dynamically using text names (NO HARDCODED LLDAP IDs)
        const isCurrentAdmin = currentGroups.includes('admin');
        const isCurrentAccountant = currentGroups.includes('accountant');
        const isStandardUser = !isCurrentAdmin && !isCurrentAccountant;

        // 3. Fetch the Master List from the Vault
        const response = await fetch('/api/users/list');
        const data = await response.json();
        
        if (response.ok && data.data && data.data.users) {
            // Pass the auth context into the dynamic table renderer
            const tableHtml = renderUserTable(data.data.users, currentUser, isCurrentAdmin, isCurrentAccountant, isStandardUser);
            
            document.getElementById('user-list-container').innerHTML = `
                <h3 class="text-blue-400 font-bold mb-4 uppercase tracking-wider text-sm">Active Users (Cel-Tech-Serv Pty Ltd)</h3>
                ${tableHtml}`;

            // 4. SECURITY ENFORCEMENT: Hide the Provisioning form if they are a standard User
            const formContainer = document.getElementById('user-form').closest('.bg-slate-800');
            if (formContainer) {
                if (isStandardUser) {
                    formContainer.style.display = 'none';
                } else {
                    formContainer.style.display = 'block';
                }
            }
        }
    } catch (err) {
        console.error("Sovereign UI Exception:", err); // <--- This will print the real error to F12!
        document.getElementById('user-list-container').innerHTML = `<p class="text-red-500 font-bold">CRITICAL: Identity API Unreachable.</p>`;
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
        // 1. Hide the infrastructure Sysadmin (Group 1 or lldap_admin) from EVERYONE
        if (user.groups && Array.isArray(user.groups) && user.groups.some(g => String(g.id) === '1' || g.id === 'lldap_admin')) return; 

        let userType = '<span class="text-slate-500 font-bold">[UNASSIGNED]</span>';
        let targetRole = 'user'; // Default text role
        let targetRoleId = '6';  // Default numeric ID (Standard User) for the Edit dropdown
        let primaryGroup = null;

        // 2. Extract the primary group using a safe string conversion
        if (user.groups && Array.isArray(user.groups)) {
            primaryGroup = user.groups.find(g => {
                // FORCE into a string before converting to lowercase
                const gName = String(g.displayName || g.id).toLowerCase();
                return gName.includes('admin') || gName.includes('accountant') || gName.includes('user');
            });
        }

        // 3. Dynamically assign colours, roles, and target IDs based on the extracted name
        if (primaryGroup) {
            // FORCE into a string before converting to lowercase
            const gName = String(primaryGroup.displayName || primaryGroup.id).toLowerCase();
            let colour = 'text-slate-300'; 
            
            // Capture the exact ID from LLDAP to feed back into the Edit dropdown
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

        // 4. --- CEL-TECH-SERV VIEWING RULES (Using dynamic roles) ---
        if (!isCurrentAdmin) {
            if (isCurrentAccountant) {
                // Accountants can only see themselves AND standard users
                if (user.id !== currentUser && targetRole !== 'user') return;
            } else {
                // Standard Users can ONLY see themselves
                if (user.id !== currentUser) return;
            }
        }
        // ------------------------------------------------------------

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
    // NEW: Set the dropdown to match their current Sovereign Role
    document.getElementById('new-role').value = data.roleid;
    
    const submitBtn = document.getElementById('user-submit-btn');
    submitBtn.innerText = 'Update Identity: ' + data.id;
    submitBtn.classList.replace('bg-blue-600', 'bg-orange-600');
    
    document.getElementById('user-cancel-btn').classList.remove('hidden');
    document.getElementById('user-msg').innerHTML = `<span class="text-orange-400 italic">MODIFICATION MODE: Updating ${data.id} (Cel-Tech-Serv Pty Ltd)</span>`;
}

function cancelEdit() {
    document.getElementById('user-form').reset();
    document.getElementById('edit-mode').value = 'false';
    document.getElementById('new-username').readOnly = false;
    
    const submitBtn = document.getElementById('user-submit-btn');
    submitBtn.innerText = 'Command Core to Provision Identity';
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
        roleId: document.getElementById('new-role').value // Extract the selected LLDAP group ID
    };

    // Client-side guard: New users must have a password
    if (!isEdit && !payload.password) {
        document.getElementById('user-msg').innerHTML = '<span class="text-red-500">DENIED: Password is required for provisioning new identities.</span>';
        return;
    }

    const msgDiv = document.getElementById('user-msg');
    msgDiv.innerHTML = '<span class="text-yellow-400">Transmitting to Identity Gateway...</span>';

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await response.json();
        
        if (response.ok) {
            msgDiv.innerHTML = `<span class="text-green-500">SUCCESS: ${data.message}</span>`;
            cancelEdit(); 
            fetchActiveUsers();
        } else {
            msgDiv.innerHTML = `<span class="text-red-500">DENIED: ${data.error}</span>`;
        }
    } catch (err) {
        msgDiv.innerHTML = '<span class="text-red-500">CRITICAL: Failed to contact the C++ Core.</span>';
    }
}
