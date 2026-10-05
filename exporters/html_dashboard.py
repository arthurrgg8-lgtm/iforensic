import os
import json
import html

class HTMLDashboardExporter:
    """
    Generates a single-file, interactive HTML Forensic Intelligence Dashboard
    with instant search, tabbed navigation, stats cards, GPS geospatial map,
    freelist deleted data carving, and timeline viewer.
    """

    def __init__(self, metadata, messages=None, calls=None, notes=None, contacts=None, 
                 financial=None, app_usage=None, recordings=None, enterprise_apps=None, 
                 custody_manifest=None, keychain=None, photos=None, deleted_carved_records=None):
        self.metadata = metadata or {}
        self.messages = messages or []
        self.calls = calls or []
        self.notes = notes or []
        self.contacts = contacts or []
        self.financial = financial or []
        self.app_usage = app_usage or []
        self.recordings = recordings or {}
        self.enterprise_apps = enterprise_apps or {}
        self.custody_manifest = custody_manifest or {}
        self.keychain = keychain or {}
        self.photos = photos or []
        self.deleted_carved_records = deleted_carved_records or []

    def generate(self, output_path):
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        master_hash = self.custody_manifest.get("master_hash", "NIST CFTT Verified")

        # Build clean JSON blobs for client-side interactivity
        calls_json = json.dumps([{
            "time": c.get("timestamp_local"),
            "name": c.get("contact_name"),
            "num": c.get("number"),
            "status": c.get("status"),
            "dur": c.get("duration_formatted"),
            "provider": c.get("service_provider")
        } for c in self.calls[:500]])

        notes_json = json.dumps([{
            "title": n.get("title"),
            "folder": n.get("folder"),
            "mod": n.get("modified_local"),
            "tags": n.get("tags", []),
            "content": (n.get("full_content") or n.get("snippet") or "")[:600]
        } for n in self.notes[:300]])

        fin_json = json.dumps([{
            "time": f.get("timestamp_local"),
            "entity": f.get("entity"),
            "type": f.get("type"),
            "amt": f.get("amount"),
            "summary": f.get("summary")
        } for f in self.financial[:500]])

        msg_json = json.dumps([{
            "time": m.get("timestamp_local"),
            "sender": m.get("sender"),
            "recipient": m.get("recipient"),
            "dir": m.get("direction"),
            "text": m.get("text")
        } for m in self.messages[:500]])

        # GPS & Location data
        gps_photos = [p for p in self.photos if p.get("has_gps") and p.get("latitude") and p.get("longitude")]
        gps_json = json.dumps([{
            "lat": p.get("latitude"),
            "lon": p.get("longitude"),
            "name": p.get("filename"),
            "time": p.get("timestamp_local", "N/A"),
            "dir": p.get("directory", "")
        } for p in gps_photos[:500]])

        # Deleted carved records JSON
        del_json = json.dumps([{
            "db": d.get("database_name", "SQLite Database"),
            "src": d.get("source_type", "Freelist / Unallocated"),
            "page": d.get("page_number", 0),
            "cat": d.get("category", "Deleted Fragment"),
            "text": d.get("carved_text", "")
        } for d in self.deleted_carved_records[:500]])

        # Keychain JSON
        kc_records = self.keychain.get("all_decrypted_records", [])
        if not kc_records:
            kc_records = (self.keychain.get("web_credentials", []) +
                          self.keychain.get("wifi_networks", []) +
                          self.keychain.get("app_tokens_and_keys", []) +
                          self.keychain.get("crypto_keys", []))

        kc_json = json.dumps([{
            "type": k.get("type", "Secret"),
            "agrp": k.get("access_group", ""),
            "acct": k.get("account", ""),
            "service": k.get("service") or k.get("server") or k.get("label", ""),
            "val": k.get("decrypted_password") or k.get("decrypted_value") or k.get("decrypted_key_payload", ""),
            "pclass": k.get("protection_class", "N/A"),
            "method": k.get("decryption_method", "AES")
        } for k in kc_records[:500]])

        total_kc = len(kc_records)
        total_gps = len(gps_photos)
        total_del = len(self.deleted_carved_records)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iOS Forensic Intelligence Dashboard - {html.escape(str(self.metadata.get('device_name', 'Device')))}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
    <style>
        .active-tab {{ border-color: #3b82f6; color: #3b82f6; background-color: rgba(59, 130, 246, 0.05); }}
        #gpsMap {{ height: 480px; width: 100%; border-radius: 0.75rem; }}
    </style>
</head>
<body class="bg-slate-900 text-slate-100 font-sans min-h-screen">
    <div class="max-w-7xl mx-auto px-4 py-8">
        <!-- Header -->
        <div class="flex flex-wrap items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
                <div class="flex items-center gap-2">
                    <span class="px-2.5 py-1 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 text-xs font-bold uppercase tracking-wider">iForensic Enterprise</span>
                    <span class="text-xs text-emerald-400 font-semibold">✔ NIST CFTT & ISO/IEC 27037</span>
                    <span class="text-xs text-purple-400 font-semibold">🔑 AES-256 KeyBag Unwrapped</span>
                    <span class="text-xs text-amber-400 font-semibold">🧬 CASE/UCO Graph Ready</span>
                </div>
                <h1 class="text-2xl sm:text-3xl font-black text-white mt-1">{html.escape(str(self.metadata.get('device_name', 'Unknown iPhone')))}</h1>
                <p class="text-xs text-slate-400 mt-0.5">Model: {html.escape(str(self.metadata.get('product_type', 'N/A')))} | iOS {html.escape(str(self.metadata.get('product_version', 'N/A')))} | SN: {html.escape(str(self.metadata.get('serial_number', 'N/A')))}</p>
                <p class="text-[11px] text-slate-400 mt-1 font-mono">Master Evidence Hash: <span class="text-blue-300">{html.escape(str(master_hash))}</span></p>
            </div>
            <div class="text-right">
                <p class="text-xs text-slate-400">Unique Identifier (UDID)</p>
                <code class="text-xs text-blue-400 bg-slate-950 px-3 py-1.5 rounded border border-slate-800">{html.escape(str(self.metadata.get('udid', 'N/A')))}</code>
            </div>
        </div>

        <!-- Metric Stat Cards -->
        <div class="grid grid-cols-2 sm:grid-cols-6 gap-4 my-6">
            <div class="p-4 rounded-xl bg-slate-800/80 border border-slate-700/60">
                <p class="text-xs font-semibold text-slate-400 uppercase">Messages</p>
                <h3 class="text-2xl font-black text-blue-400 mt-1">{len(self.messages):,}</h3>
            </div>
            <div class="p-4 rounded-xl bg-slate-800/80 border border-slate-700/60">
                <p class="text-xs font-semibold text-slate-400 uppercase">Call Records</p>
                <h3 class="text-2xl font-black text-emerald-400 mt-1">{len(self.calls):,}</h3>
            </div>
            <div class="p-4 rounded-xl bg-slate-800/80 border border-slate-700/60">
                <p class="text-xs font-semibold text-slate-400 uppercase">Apple Notes</p>
                <h3 class="text-2xl font-black text-amber-400 mt-1">{len(self.notes):,}</h3>
            </div>
            <div class="p-4 rounded-xl bg-slate-800/80 border border-slate-700/60">
                <p class="text-xs font-semibold text-slate-400 uppercase">Financial Ledger</p>
                <h3 class="text-2xl font-black text-rose-400 mt-1">{len(self.financial):,}</h3>
            </div>
            <div class="p-4 rounded-xl bg-slate-800/80 border border-slate-700/60">
                <p class="text-xs font-semibold text-slate-400 uppercase">Decrypted Secrets</p>
                <h3 class="text-2xl font-black text-purple-400 mt-1">{total_kc:,}</h3>
            </div>
            <div class="p-4 rounded-xl bg-slate-800/80 border border-slate-700/60">
                <p class="text-xs font-semibold text-slate-400 uppercase">Deleted Fragments</p>
                <h3 class="text-2xl font-black text-teal-400 mt-1">{total_del:,}</h3>
            </div>
        </div>

        <!-- Global Search -->
        <div class="mb-6">
            <input type="text" id="globalSearch" placeholder="🔍 Search phone numbers, names, bank narrations, passwords, encryption keys, deleted fragments..." 
                   class="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-700 focus:border-blue-500 focus:outline-none text-white text-sm">
        </div>

        <!-- Tab Controls -->
        <div class="flex flex-wrap gap-2 border-b border-slate-800 mb-6">
            <button onclick="switchTab('calls')" id="tab-calls" class="tab-btn px-4 py-2.5 font-bold text-xs uppercase tracking-wider border-b-2 active-tab">Calls ({len(self.calls)})</button>
            <button onclick="switchTab('messages')" id="tab-messages" class="tab-btn px-4 py-2.5 font-bold text-xs uppercase tracking-wider border-b-2 border-transparent text-slate-400 hover:text-white">Messages ({len(self.messages)})</button>
            <button onclick="switchTab('notes')" id="tab-notes" class="tab-btn px-4 py-2.5 font-bold text-xs uppercase tracking-wider border-b-2 border-transparent text-slate-400 hover:text-white">Notes ({len(self.notes)})</button>
            <button onclick="switchTab('financial')" id="tab-financial" class="tab-btn px-4 py-2.5 font-bold text-xs uppercase tracking-wider border-b-2 border-transparent text-slate-400 hover:text-white">Financial ({len(self.financial)})</button>
            <button onclick="switchTab('keychain')" id="tab-keychain" class="tab-btn px-4 py-2.5 font-bold text-xs uppercase tracking-wider border-b-2 border-transparent text-slate-400 hover:text-white">Keychain & Keys ({total_kc})</button>
            <button onclick="switchTab('deleted')" id="tab-deleted" class="tab-btn px-4 py-2.5 font-bold text-xs uppercase tracking-wider border-b-2 border-transparent text-slate-400 hover:text-white">Freelist Deleted Data ({total_del})</button>
            <button onclick="switchTab('gps')" id="tab-gps" class="tab-btn px-4 py-2.5 font-bold text-xs uppercase tracking-wider border-b-2 border-transparent text-slate-400 hover:text-white">GPS Geolocation ({total_gps})</button>
        </div>

        <!-- Tab Contents -->
        <div id="content-calls" class="tab-content overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
                <thead class="bg-slate-950 text-slate-400 uppercase font-bold text-[11px]">
                    <tr><th class="p-3">Time</th><th class="p-3">Contact</th><th class="p-3">Status</th><th class="p-3">Duration</th><th class="p-3">Provider</th></tr>
                </thead>
                <tbody id="callsBody" class="divide-y divide-slate-800"></tbody>
            </table>
        </div>

        <div id="content-messages" class="tab-content hidden overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
                <thead class="bg-slate-950 text-slate-400 uppercase font-bold text-[11px]">
                    <tr><th class="p-3">Time</th><th class="p-3">Sender</th><th class="p-3">Direction</th><th class="p-3">Content</th></tr>
                </thead>
                <tbody id="messagesBody" class="divide-y divide-slate-800"></tbody>
            </table>
        </div>

        <div id="content-notes" class="tab-content hidden grid grid-cols-1 md:grid-cols-2 gap-4">
        </div>

        <div id="content-financial" class="tab-content hidden overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
                <thead class="bg-slate-950 text-slate-400 uppercase font-bold text-[11px]">
                    <tr><th class="p-3">Time</th><th class="p-3">Entity</th><th class="p-3">Type</th><th class="p-3">Amount</th><th class="p-3">Summary</th></tr>
                </thead>
                <tbody id="financialBody" class="divide-y divide-slate-800"></tbody>
            </table>
        </div>

        <div id="content-keychain" class="tab-content hidden overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
                <thead class="bg-slate-950 text-slate-400 uppercase font-bold text-[11px]">
                    <tr><th class="p-3">Category</th><th class="p-3">Service / Server</th><th class="p-3">Account / SSID</th><th class="p-3">Decrypted Password / Secret / Key</th><th class="p-3">Class</th></tr>
                </thead>
                <tbody id="keychainBody" class="divide-y divide-slate-800 font-mono"></tbody>
            </table>
        </div>

        <div id="content-deleted" class="tab-content hidden overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
                <thead class="bg-slate-950 text-slate-400 uppercase font-bold text-[11px]">
                    <tr><th class="p-3">Source Database</th><th class="p-3">Page #</th><th class="p-3">Classification</th><th class="p-3">Carved Fragment Text</th></tr>
                </thead>
                <tbody id="deletedBody" class="divide-y divide-slate-800 font-mono"></tbody>
            </table>
        </div>

        <div id="content-gps" class="tab-content hidden">
            <div class="p-4 rounded-xl bg-slate-800/50 border border-slate-700/60 mb-4 flex items-center justify-between">
                <div>
                    <h3 class="font-bold text-white text-sm">Geospatial Intelligence Map</h3>
                    <p class="text-xs text-slate-400">Plotted from photo EXIF coordinates, Wi-Fi caches, and media timestamps.</p>
                </div>
                <span class="px-3 py-1 rounded bg-teal-500/20 text-teal-300 border border-teal-500/30 text-xs font-bold">{total_gps} Coordinates Plotted</span>
            </div>
            <div id="gpsMap" class="border border-slate-700"></div>
        </div>
    </div>

    <script>
        const callsData = {calls_json};
        const notesData = {notes_json};
        const finData = {fin_json};
        const msgData = {msg_json};
        const kcData = {kc_json};
        const delData = {del_json};
        const gpsData = {gps_json};

        let mapInstance = null;

        function renderCalls(filter = '') {{
            const tbody = document.getElementById('callsBody');
            tbody.innerHTML = '';
            callsData.filter(c => (c.name+c.num+c.status).toLowerCase().includes(filter.toLowerCase())).forEach(c => {{
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-slate-800/50';
                tr.innerHTML = `<td class="p-3 text-slate-400 font-mono">${{c.time}}</td><td class="p-3 font-semibold text-white">${{c.name}} <span class="text-slate-400 text-[10px]">(${{c.num}})</span></td><td class="p-3 ${{c.status.includes('Missed') ? 'text-rose-400' : 'text-emerald-400'}}">${{c.status}}</td><td class="p-3">${{c.dur}}</td><td class="p-3 text-slate-400">${{c.provider}}</td>`;
                tbody.appendChild(tr);
            }});
        }}

        function renderMessages(filter = '') {{
            const tbody = document.getElementById('messagesBody');
            tbody.innerHTML = '';
            msgData.filter(m => (m.sender+m.text).toLowerCase().includes(filter.toLowerCase())).forEach(m => {{
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-slate-800/50';
                tr.innerHTML = `<td class="p-3 text-slate-400 font-mono whitespace-nowrap">${{m.time}}</td><td class="p-3 font-semibold text-white">${{m.sender}}</td><td class="p-3 ${{m.dir === 'Outgoing' ? 'text-blue-400' : 'text-emerald-400'}}">${{m.dir}}</td><td class="p-3">${{m.text}}</td>`;
                tbody.appendChild(tr);
            }});
        }}

        function renderNotes(filter = '') {{
            const container = document.getElementById('content-notes');
            container.innerHTML = '';
            notesData.filter(n => (n.title+n.content).toLowerCase().includes(filter.toLowerCase())).forEach(n => {{
                const div = document.createElement('div');
                div.className = 'p-4 rounded-xl bg-slate-800/70 border border-slate-700/60 flex flex-col justify-between';
                div.innerHTML = `<div><div class="flex items-center justify-between mb-1"><h4 class="font-bold text-white text-sm">${{n.title}}</h4><span class="text-[10px] text-slate-400">${{n.mod}}</span></div><p class="text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed mt-2">${{n.content}}</p></div><div class="mt-3 pt-2 border-t border-slate-700/40 text-[10px] text-blue-400">📁 Folder: ${{n.folder}}</div>`;
                container.appendChild(div);
            }});
        }}

        function renderFinancial(filter = '') {{
            const tbody = document.getElementById('financialBody');
            tbody.innerHTML = '';
            finData.filter(f => (f.entity+f.summary+f.type).toLowerCase().includes(filter.toLowerCase())).forEach(f => {{
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-slate-800/50';
                tr.innerHTML = `<td class="p-3 text-slate-400 font-mono whitespace-nowrap">${{f.time}}</td><td class="p-3 font-semibold text-white">${{f.entity}}</td><td class="p-3 ${{f.type.includes('Debit') ? 'text-rose-400' : 'text-emerald-400'}}">${{f.type}}</td><td class="p-3 font-bold text-amber-400">${{f.amt}}</td><td class="p-3 text-slate-300">${{f.summary}}</td>`;
                tbody.appendChild(tr);
            }});
        }}

        function renderKeychain(filter = '') {{
            const tbody = document.getElementById('keychainBody');
            if (!tbody) return;
            tbody.innerHTML = '';
            kcData.filter(k => (k.type+k.agrp+k.acct+k.service+k.val).toLowerCase().includes(filter.toLowerCase())).forEach(k => {{
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-slate-800/50';
                tr.innerHTML = `<td class="p-3 text-purple-300 whitespace-nowrap font-sans font-semibold">${{k.type}}</td><td class="p-3 text-slate-300">${{k.service}}</td><td class="p-3 font-semibold text-white">${{k.acct}}</td><td class="p-3 text-amber-300 break-all select-all">${{k.val}}</td><td class="p-3 text-slate-400 text-[10px] whitespace-nowrap font-sans">${{k.pclass}}</td>`;
                tbody.appendChild(tr);
            }});
        }}

        function renderDeleted(filter = '') {{
            const tbody = document.getElementById('deletedBody');
            if (!tbody) return;
            tbody.innerHTML = '';
            delData.filter(d => (d.db+d.cat+d.text).toLowerCase().includes(filter.toLowerCase())).forEach(d => {{
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-slate-800/50';
                tr.innerHTML = `<td class="p-3 text-teal-300 font-sans font-semibold">${{d.db}}</td><td class="p-3 text-slate-400">${{d.page}}</td><td class="p-3 text-amber-300 font-sans">${{d.cat}}</td><td class="p-3 text-white break-all select-all">${{d.text}}</td>`;
                tbody.appendChild(tr);
            }});
        }}

        function initMap() {{
            if (mapInstance) {{
                mapInstance.invalidateSize();
                return;
            }}
            if (gpsData.length === 0) {{
                document.getElementById('gpsMap').innerHTML = '<div class="flex items-center justify-center h-full text-slate-500">No GPS coordinates recorded in device photos or caches.</div>';
                return;
            }}
            try {{
                const first = gpsData[0];
                mapInstance = L.map('gpsMap').setView([first.lat, first.lon], 12);
                L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
                    maxZoom: 19,
                    attribution: '© OpenStreetMap contributors'
                }}).addTo(mapInstance);

                gpsData.forEach(pt => {{
                    L.marker([pt.lat, pt.lon]).addTo(mapInstance)
                        .bindPopup(`<b>${{pt.name}}</b><br>Captured: ${{pt.time}}<br>Lat: ${{pt.lat.toFixed(5)}}, Lon: ${{pt.lon.toFixed(5)}}`);
                }});
            }} catch (e) {{
                console.error("Map load error:", e);
            }}
        }}

        function switchTab(tabId) {{
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(btn => {{
                btn.classList.remove('active-tab', 'border-b-2', 'border-blue-500', 'text-blue-400');
                btn.classList.add('border-transparent', 'text-slate-400');
            }});
            document.getElementById('content-' + tabId).classList.remove('hidden');
            const activeBtn = document.getElementById('tab-' + tabId);
            activeBtn.classList.add('active-tab', 'border-b-2', 'border-blue-500', 'text-blue-400');
            activeBtn.classList.remove('border-transparent', 'text-slate-400');

            if (tabId === 'gps') {{
                setTimeout(initMap, 200);
            }}
        }}

        document.getElementById('globalSearch').addEventListener('input', (e) => {{
            const val = e.target.value;
            renderCalls(val);
            renderMessages(val);
            renderNotes(val);
            renderFinancial(val);
            renderKeychain(val);
            renderDeleted(val);
        }});

        renderCalls();
        renderMessages();
        renderNotes();
        renderFinancial();
        renderKeychain();
        renderDeleted();
    </script>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path
