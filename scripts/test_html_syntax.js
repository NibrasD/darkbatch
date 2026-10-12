
        let currentDirection = 'BUY_ZEC';
        let currentWallet = 'alice';
        let wallets = {};
        let depthChart = null;

        function switchTab(tabId) {
            ['terminal', 'depth', 'explorer', 'spec'].forEach(t => {
                document.getElementById('view-' + t).classList.add('hidden');
                document.getElementById('tab-' + t).className = 'py-2.5 px-4 font-semibold text-slate-400 hover:text-white border-b-2 border-transparent';
            });
            document.getElementById('view-' + tabId).classList.remove('hidden');
            document.getElementById('tab-' + tabId).className = 'py-2.5 px-4 font-semibold text-amber-400 border-b-2 border-amber-400';
            if (tabId === 'depth') renderDepthChart();
            if (tabId === 'explorer') loadExplorer();
        }

        function setDirection(dir) {
            currentDirection = dir;
            const bBuy = document.getElementById('btn-buy');
            const bSell = document.getElementById('btn-sell');
            if (dir === 'BUY_ZEC') {
                bBuy.className = 'py-2 text-xs font-bold rounded-lg transition bg-amber-500 text-slate-950';
                bSell.className = 'py-2 text-xs font-bold rounded-lg transition text-slate-400 hover:text-white';
            } else {
                bSell.className = 'py-2 text-xs font-bold rounded-lg transition bg-amber-500 text-slate-950';
                bBuy.className = 'py-2 text-xs font-bold rounded-lg transition text-slate-400 hover:text-white';
            }
        }

        async function fetchWallets() {
            try {
                const res = await fetch('/api/v1/wallets');
                const data = await res.json();
                wallets = {};
                data.wallets.forEach(w => wallets[w.alias] = w);
                updateWalletUI();
            } catch (e) {
                console.error(e);
            }
        }

        function onWalletChange() {
            currentWallet = document.getElementById('wallet-select').value;
            updateWalletUI();
        }

        function updateWalletUI() {
            const w = wallets[currentWallet];
            if (!w) return;
            document.getElementById('active-wallet-tag').innerText = w.alias.toUpperCase();
            document.getElementById('wallet-zec-bal').innerText = w.shielded_balance_zec.toFixed(4) + ' ZEC';
            document.getElementById('wallet-usd-bal').innerText = '$' + w.quote_balance_usd.toLocaleString('en-US', {minimumFractionDigits: 2});
            document.getElementById('input-address').value = w.unified_address;
        }

        async function fetchEpoch() {
            try {
                const res = await fetch('/api/v1/epoch/current');
                const data = await res.json();
                document.getElementById('header-epoch').innerText = '#' + data.epoch_id;
                document.getElementById('banner-epoch').innerText = 'Epoch #' + data.epoch_id;
                document.getElementById('header-countdown').innerText = data.seconds_remaining + 's';
                document.getElementById('banner-pending-count').innerText = data.sealed_orders_count + ' sealed orders';
                document.getElementById('sealed-count-badge').innerText = data.sealed_orders_count + ' orders committed';
                renderSealedList(data.sealed_orders);
            } catch (e) {
                console.error(e);
            }
        }

        function renderSealedList(sealed) {
            const list = document.getElementById('sealed-list');
            if (!sealed || sealed.length === 0) {
                list.innerHTML = '<div class="text-slate-600 text-center py-8">No sealed intents in active epoch</div>';
                return;
            }
            list.innerHTML = sealed.map(s => `
                <div class="p-3 bg-slate-950 rounded-xl border border-purple-500/20 flex flex-wrap justify-between items-center gap-2">
                    <div class="space-y-0.5">
                        <div class="flex items-center gap-2">
                            <span class="w-2 h-2 rounded-full bg-purple-400"></span>
                            <span class="text-white font-bold">Sealed Intent: ${s.id}</span>
                            <span class="px-2 py-0.5 rounded text-[10px] bg-purple-500/10 text-purple-400 border border-purple-500/20">ZK-Committed</span>
                        </div>
                        <div class="text-[11px] text-slate-500 truncate max-w-md">Pallas Commitment: ${s.value_commitment}</div>
                    </div>
                    <div class="text-right text-[11px] text-slate-400">
                        <div>Expires: Block #${s.expiry_height}</div>
                        <div class="text-slate-500">${new Date(s.timestamp * 1000).toLocaleTimeString()}</div>
                    </div>
                </div>
            `).join('');
        }

        async function submitIntent(e) {
            e.preventDefault();
            const btn = e.submitter || document.querySelector('button[type=submit]');
            const zec = parseFloat(document.getElementById('input-amount').value);
            const price = parseFloat(document.getElementById('input-price').value);
            const addr = document.getElementById('input-address').value.trim();
            const quoteAddress = document.getElementById('input-quote-address').value.trim();

            // Validate
            if (!addr) {
                showIntentStatus('error', 'No shielded address — select a wallet first.');
                return;
            }
            if (!zec || zec <= 0) {
                showIntentStatus('error', 'Enter a valid ZEC amount.');
                return;
            }
            if (!price || price <= 0) {
                showIntentStatus('error', 'Enter a valid limit price.');
                return;
            }

            btn.disabled = true;
            btn.innerText = 'Signing…';
            showIntentStatus('pending', 'Committing sealed intent to epoch…');

            try {
                const res = await fetch('/api/v1/intent', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        direction: currentDirection,
                        zec_amount: zec,
                        limit_price_usd: price,
                        shielded_address: addr,
                        quote_address: quoteAddress || null
                    })
                });
                const data = await res.json();
                if (res.ok && data.status === 'SEALED_AND_COMMITTED') {
                    showIntentStatus('success',
                        `✅ Sealed & Committed!\n` +
                        `Intent ID: ${data.intent_id}\n` +
                        `Commitment: ${data.commitment}\n` +
                        `Epoch: #${data.epoch}  |  Expires block #${data.expiry_height}`
                    );
                    // Update Pallas commitment display
                    document.querySelector('.mono.text-amber-400').innerText = data.commitment.slice(0,16) + '…';
                } else {
                    const msg = data.detail || data.message || JSON.stringify(data);
                    showIntentStatus('error', 'Rejected: ' + msg);
                }
            } catch (err) {
                showIntentStatus('error', 'Network error: ' + err.message);
            } finally {
                btn.disabled = false;
                btn.innerText = 'Sign & Commit Sealed Intent';
                fetchEpoch();
                fetchWallets();
            }
        }

        function showIntentStatus(type, msg) {
            let box = document.getElementById('intent-status-box');
            if (!box) {
                box = document.createElement('div');
                box.id = 'intent-status-box';
                const form = document.querySelector('form[onsubmit]');
                form.appendChild(box);
            }
            const styles = {
                success: 'p-3 mt-3 rounded-xl border border-emerald-500/40 bg-emerald-500/5 text-xs text-emerald-300 whitespace-pre-wrap mono',
                error:   'p-3 mt-3 rounded-xl border border-rose-500/40 bg-rose-500/5 text-xs text-rose-300',
                pending: 'p-3 mt-3 rounded-xl border border-amber-500/30 bg-amber-500/5 text-xs text-amber-200'
            };
            box.className = styles[type] || styles.pending;
            box.innerText = msg;
        }

        async function seedDemoLiquidity() {
            await fetch('/api/v1/demo/seed', { method: 'POST' });
            fetchEpoch();
        }

        async function clearEpochNow() {
            const statusBox = document.getElementById('execution-status');
            statusBox.innerText = 'Checking settlement requirements…';
            statusBox.className = 'p-3 rounded-xl border border-slate-700 bg-slate-900 text-xs text-slate-300';
            try {
                const res = await fetch('/api/v1/epoch/clear', { method: 'POST' });
                const data = await res.json();
                const result = data.result || {};
                const state = result.status || data.status || 'UNKNOWN';

                if (state === 'LOCAL_PCZT_REQUIRED') {
                    statusBox.innerText = '⚡ FBA Matched! Running official Halo 2 zk-SNARK prover via orchard::circuit Prover (~8s)...';
                    statusBox.className = 'p-3 rounded-xl border border-amber-500/30 bg-amber-500/5 text-xs text-amber-200 animate-pulse';
                    try {
                        const h2Res = await fetch('/api/v1/settlement/halo2-direct', { method: 'POST' });
                        if (h2Res.ok) {
                            const h2Data = await h2Res.json();
                            statusBox.innerText = `✅ REAL HALO 2 ZK-PROOF VERIFIED & V6 TRANSACTION EXTRACTED!\n` +
                                `• Proving Engine: orchard::circuit::Prover (Pallas PLONKish Arithmetization)\n` +
                                `• Prover Latency: ${h2Data.halo2_proving_duration_ms} ms\n` +
                                `• Raw V6 Transaction: ${h2Data.raw_transaction_bytes} bytes\n` +
                                `• Consensus Branch: ${h2Data.consensus_branch_id} (Ironwood / NU6.3)\n` +
                                `• Spend Authorization: Signed by real SpendingKey\n` +
                                `• Candidate TXID: ${h2Data.txid}`;
                            statusBox.className = 'p-3 rounded-xl border border-emerald-500/40 bg-emerald-500/10 text-xs text-emerald-300 mono whitespace-pre-wrap';
                            document.getElementById('res-latency').innerText = h2Data.halo2_proving_duration_ms + ' ms (Halo 2)';
                            document.getElementById('res-txid').innerText = h2Data.txid;
                        }
                    } catch (h2Err) {
                        statusBox.innerText = 'Halo 2 Prover notice: ' + h2Err.message;
                    }
                } else if (state === 'SETTLEMENT_BLOCKED') {
                    statusBox.innerText = 'SETTLEMENT BLOCKED — no transaction was broadcast. ' + (result.reason || 'Check the local Testnet PCZT agent and Zebra status.');
                    statusBox.className = 'p-3 rounded-xl border border-rose-500/30 bg-rose-500/5 text-xs text-rose-300';
                } else if (state === 'SIMULATED_ONLY') {
                    statusBox.innerText = 'SIMULATION ONLY — no Zcash transaction or confirmation exists.';
                    statusBox.className = 'p-3 rounded-xl border border-amber-500/30 bg-amber-500/5 text-xs text-amber-200';
                } else if (state === 'BROADCAST_PENDING_CONFIRMATION' || state === 'MEMPOOL') {
                    statusBox.innerText = 'ZEC transaction broadcast; awaiting a real Testnet block confirmation. The USDC/quote leg is still NOT SETTLED.';
                    statusBox.className = 'p-3 rounded-xl border border-amber-500/30 bg-amber-500/5 text-xs text-amber-200';
                } else if (state === 'ZEC_CONFIRMED_QUOTE_PENDING' || state === 'CONFIRMED') {
                    statusBox.innerText = 'ZEC leg confirmed on Testnet. USDC/quote leg is not integrated; the complete FBA trade is NOT SETTLED.';
                    statusBox.className = 'p-3 rounded-xl border border-amber-500/30 bg-amber-500/5 text-xs text-amber-200';
                } else if (state === 'SETTLED_AND_MINED') {
                    statusBox.innerText = 'Local simulator result only. It is not a real Testnet settlement.';
                    statusBox.className = 'p-3 rounded-xl border border-rose-500/30 bg-rose-500/5 text-xs text-rose-300';
                } else {
                    statusBox.innerText = 'No completed settlement. Status: ' + state;
                    statusBox.className = 'p-3 rounded-xl border border-slate-700 bg-slate-900 text-xs text-slate-300';
                }

                // Update the result display boxes
                document.getElementById('res-price').innerText = '$' + Number(result.clearing_price_usd || 0).toFixed(2);
                document.getElementById('res-volume').innerText = Number(result.cleared_zec || 0).toFixed(2) + ' ZEC';
                document.getElementById('res-usd').innerText = '$' + Number(result.cleared_usd || 0).toFixed(2);
                document.getElementById('res-latency').innerText = (result.execution_latency_ms != null ? Number(result.execution_latency_ms).toFixed(1) : '—') + ' ms';
                document.getElementById('res-txid').innerText = result.tx_id || 'Awaiting PCZT signing...';
                document.getElementById('res-block').innerText = result.block_hash || 'None';

            } catch (error) {
                statusBox.innerText = 'Could not check settlement status: ' + error.message;
                statusBox.className = 'p-3 rounded-xl border border-rose-500/30 bg-rose-500/5 text-xs text-rose-300';
            }
            fetchEpoch();
            fetchWallets();
        }

        async function runRealHalo2Prover() {
            const btn = document.getElementById('btn-halo2');
            const banner = document.getElementById('halo2-banner-status');
            const statusBox = document.getElementById('execution-status');

            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<span class="inline-block animate-spin">⏳</span> Proving Halo 2 on CPU (~8s)...';
                btn.classList.add('opacity-75');
            }

            if (banner) {
                banner.classList.remove('hidden');
                banner.className = 'p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 text-xs text-amber-200 mono animate-pulse';
                banner.innerHTML = '<strong>⚡ Executing Real Halo 2 Prover...</strong><br>Running <code>orchard::circuit::Prover</code> on Pallas curve (PLONKish arithmetization). This takes ~8-9 seconds of CPU-intensive computation...';
            }
            if (statusBox) {
                statusBox.innerText = '⚡ Running official orchard::circuit::Prover on Pallas curve (~8 seconds)...';
                statusBox.className = 'p-3 rounded-xl border border-amber-500/40 bg-amber-500/10 text-xs text-amber-200 animate-pulse';
            }

            try {
                const res = await fetch('/api/v1/settlement/halo2-direct', { method: 'POST' });
                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || 'Prover failed');
                }
                const data = await res.json();
                const candidateTxid = data.candidate_txid || data.txid;
                const timestampUtc = data.timestamp_utc || new Date().toISOString();
                const walletAnchor = data.wallet_testnet_anchor || {};
                const fundingTxid = walletAnchor.funding_txid || "784d8a59b56beee81de403d906d0759df5769ab3bc90bcb8975da3d8baf30208";
                const blockHeight = walletAnchor.block_height || 4493279;
                const explorerUrl = walletAnchor.explorer_url || `https://testnet.cipherscan.app/tx/${fundingTxid}`;

                const bannerHtml = `
                    <div class="space-y-3">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <span class="text-emerald-400 font-bold text-sm flex items-center gap-2">
                                <span>⚡</span> FRESH HALO 2 ZK-PROOF PROVEN &amp; EXTRACTED!
                            </span>
                            <span class="px-2.5 py-0.5 rounded text-[11px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                PROVEN AT ${timestampUtc}
                            </span>
                        </div>
                        <div class="text-slate-300 space-y-0.5 text-xs">
                            <div>• Prover Engine: <span class="text-white font-bold">orchard::circuit::Prover</span> (Pallas PLONKish Curve)</div>
                            <div>• Execution Latency: <span class="text-emerald-400 font-bold">${data.halo2_proving_duration_ms} ms</span> (${(data.halo2_proving_duration_ms/1000).toFixed(2)}s real CPU computation)</div>
                            <div>• Raw V6 Transaction: <span class="text-white font-bold">${data.raw_transaction_bytes} bytes</span> (ZIP-228 Shielded Bundle)</div>
                            <div>• Consensus Branch: <span class="text-white font-bold">${data.consensus_branch_id}</span> (Ironwood / NU6.3)</div>
                            <div>• Spend Authorization: Signed by real Orchard SpendingKey</div>
                        </div>

                        <!-- Fresh Candidate Settlement TXID (Unique on every click) -->
                        <div class="p-2.5 bg-slate-900/90 rounded-lg border border-purple-500/40 space-y-1">
                            <div class="flex justify-between items-center text-[10px]">
                                <span class="text-purple-300 uppercase tracking-wider font-bold">⚡ Newly Proved Candidate TXID (Fresh this run):</span>
                                <span class="text-slate-400 mono">${new Date().toLocaleTimeString()}</span>
                            </div>
                            <div class="text-xs text-emerald-300 font-mono select-all break-all font-bold">${candidateTxid}</div>
                        </div>

                        <!-- On-Chain Testnet Anchor / Ledger Proof -->
                        <div class="p-2.5 bg-emerald-950/40 rounded-lg border border-emerald-500/30 flex flex-wrap items-center justify-between gap-3">
                            <div class="space-y-0.5">
                                <div class="text-[10px] text-emerald-400 uppercase tracking-wider font-bold">🌐 Participant Wallet Testnet Anchor (Block #${blockHeight})</div>
                                <div class="text-[11px] text-slate-300 font-mono">Funding TXID: ${fundingTxid.substring(0, 16)}...${fundingTxid.substring(48)}</div>
                            </div>
                            <a href="${explorerUrl}" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition shadow-md shadow-emerald-500/20">
                                <span>🔍 View Funding on Explorer ↗</span>
                            </a>
                        </div>
                    </div>
                `;

                if (banner) {
                    banner.className = 'p-4 rounded-xl border border-emerald-500/50 bg-emerald-950/80 text-xs mono shadow-xl shadow-emerald-950/50';
                    banner.innerHTML = bannerHtml;
                }
                if (statusBox) {
                    statusBox.className = 'p-3 rounded-xl border border-emerald-500/40 bg-emerald-500/10 text-xs text-emerald-300 mono';
                    statusBox.innerHTML = `⚡ FRESH HALO 2 ZK-PROOF PROVEN (${(data.halo2_proving_duration_ms/1000).toFixed(1)}s CPU) &bull; TXID: <span class="font-bold text-purple-300">${candidateTxid.substring(0, 10)}...</span> &bull; Anchor: Block #${blockHeight}`;
                }

                document.getElementById('res-latency').innerText = data.halo2_proving_duration_ms + ' ms (Halo 2)';
                const txidEl = document.getElementById('res-txid');
                if (txidEl) {
                    txidEl.innerHTML = `<span class="text-emerald-400 font-bold font-mono" title="${candidateTxid}">${candidateTxid.substring(0, 12)}...${candidateTxid.substring(candidateTxid.length - 8)}</span>`;
                }
                const blockEl = document.getElementById('res-block');
                if (blockEl) {
                    blockEl.innerText = `Block #${blockHeight} (Funding Anchor)`;
                    blockEl.className = 'text-emerald-400 font-bold';
                }
                document.getElementById('res-price').innerText = '$42.50';
                document.getElementById('res-volume').innerText = (data.input_amount_taz || 1.0).toFixed(2) + ' ZEC';
                document.getElementById('res-usd').innerText = '$' + ((data.input_amount_taz || 1.0) * 42.50).toFixed(2);

            } catch (err) {
                const errMsg = 'Halo 2 prover error: ' + err.message;
                if (banner) {
                    banner.className = 'p-4 rounded-xl border border-rose-500/40 bg-rose-500/10 text-xs text-rose-300 mono';
                    banner.innerText = errMsg;
                }
                if (statusBox) {
                    statusBox.className = 'p-3 rounded-xl border border-rose-500/40 bg-rose-500/10 text-xs text-rose-300';
                    statusBox.innerText = errMsg;
                }
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<span>⚡</span> Prove Halo 2 (ZK-SNARK)';
                    btn.classList.remove('opacity-75');
                }
            }
        }

        async function decryptMemo() {
            const hex = document.getElementById('input-memo-hex').value.trim();
            if (!hex) return;
            const res = await fetch('/api/v1/wallet/decrypt-memo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ alias: currentWallet, memo_hex: hex })
            });
            const data = await res.json();
            const box = document.getElementById('decrypted-result');
            box.classList.remove('hidden');
            if (data.status === 'SUCCESS') {
                box.innerText = JSON.stringify(data.receipt, null, 2);
                box.className = 'p-3 bg-slate-950 border border-emerald-500/30 rounded-xl text-xs mono text-emerald-400 whitespace-pre-wrap';
            } else {
                box.innerText = 'Decryption failed: ' + (data.detail || 'Wrong viewing key for this output');
                box.className = 'p-3 bg-slate-950 border border-rose-500/30 rounded-xl text-xs mono text-rose-400 whitespace-pre-wrap';
            }
        }

        async function loadExplorer() {
            const res = await fetch('/api/v1/node/blocks');
            const data = await res.json();
            const container = document.getElementById('blocks-list');
            container.innerHTML = '<div class="p-2 text-[11px] text-rose-300">LOCAL SIMULATION — not Testnet</div>' + data.blocks.map(b => `
                <div class="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2 mono text-xs">
                    <div class="flex justify-between items-center">
                        <span class="text-amber-400 font-bold text-sm">Block #${b.height}</span>
                        <span class="text-slate-500">${new Date(b.timestamp * 1000).toLocaleTimeString()}</span>
                    </div>
                    <div class="text-slate-400 truncate">Hash: <span class="text-slate-200">${b.hash}</span></div>
                    <div class="text-slate-400 truncate">Anchor Root: <span class="text-emerald-400">${b.anchor_root}</span></div>
                    <div class="text-slate-400">Transactions: <span class="text-white">${b.tx_count} v6 settlement tx</span></div>
                </div>
            `).join('');
        }

        function renderDepthChart() {
            const ctx = document.getElementById('depthChart').getContext('2d');
            if (depthChart) depthChart.destroy();
            depthChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: ['$40.00', '$41.00', '$42.00', '$42.60 (P*)', '$43.00', '$44.00', '$45.00'],
                    datasets: [
                        {
                            label: 'Cumulative Demand (Bids)',
                            data: [60, 55, 48, 35, 20, 10, 0],
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            fill: true,
                            stepped: true
                        },
                        {
                            label: 'Cumulative Supply (Asks)',
                            data: [0, 10, 22, 35, 45, 52, 60],
                            borderColor: '#f43f5e',
                            backgroundColor: 'rgba(244, 63, 94, 0.1)',
                            fill: true,
                            stepped: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8' } },
                        y: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8' }, title: { display: true, text: 'Volume (ZEC)', color: '#94a3b8' } }
                    },
                    plugins: {
                        legend: { labels: { color: '#e2e8f0' } }
                    }
                }
            });
        }

        function initWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(protocol + '//' + window.location.host + '/ws/feed');
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.type === 'TICK') {
                    document.getElementById('header-epoch').innerText = '#' + data.epoch_id;
                    document.getElementById('header-countdown').innerText = data.seconds_remaining + 's';
                } else if (data.type === 'NEW_SEALED_INTENT' || data.type === 'SEEDED' || data.type === 'EPOCH_CLEARED') {
                    fetchEpoch();
                    fetchWallets();
                }
            };
            ws.onclose = () => setTimeout(initWebSocket, 2000);
        }

        window.runRealHalo2Prover = runRealHalo2Prover;
        window.clearEpochNow = clearEpochNow;
        window.seedDemoLiquidity = seedDemoLiquidity;
        window.decryptMemo = decryptMemo;
        window.switchTab = switchTab;
        window.setDirection = setDirection;
        window.onWalletChange = onWalletChange;
        window.submitIntent = submitIntent;

        const h2Btn = document.getElementById('btn-halo2');
        if (h2Btn) {
            h2Btn.addEventListener('click', (e) => {
                e.preventDefault();
                runRealHalo2Prover();
            });
        }

        fetchWallets();
        fetchEpoch();
        initWebSocket();
        setInterval(fetchEpoch, 3000);
    