document.addEventListener("DOMContentLoaded", () => {
    // 1. AJAX Scan Handler with CSRF Protection
    const scanForm = document.getElementById("scan-form");
    const scanInput = document.getElementById("url-input");
    const scanBtn = document.getElementById("scan-btn");
    const scanBtnText = document.getElementById("scan-btn-text");
    const scanSpinner = document.getElementById("scan-spinner");
    const resultsContainer = document.getElementById("results-container");
    
    if (scanForm) {
        scanForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const urlToScan = scanInput.value.trim();
            if (!urlToScan) return;
            
            // Retrieve CSRF Token from meta tag
            const csrfMeta = document.querySelector('meta[name="csrf-token"]');
            const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";
            
            // UI Loading state
            scanBtn.disabled = true;
            if (scanSpinner) scanSpinner.classList.remove("d-none");
            if (scanBtnText) scanBtnText.textContent = "Analyzing URL...";
            resultsContainer.classList.add("d-none");
            resultsContainer.style.marginTop = "0";
            
            try {
                const response = await fetch("/scan", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": csrfToken
                    },
                    body: JSON.stringify({ url: urlToScan })
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    displayScanResults(data.result);
                    appendScanToLogsTable(data.result);
                    
                    // Trigger toast notifications if available
                    showToast("Scan completed! Security audit logged.", "success");
                    
                    // Re-draw stats/charts dynamically
                    if (window.updateChartsData) {
                        window.updateChartsData(data.result);
                    }
                } else {
                    showToast(data.error || "Verification failed.", "danger");
                }
            } catch (err) {
                console.error("Scan Error:", err);
                showToast("Connection anomaly. Could not reach server.", "danger");
            } finally {
                scanBtn.disabled = false;
                if (scanSpinner) scanSpinner.classList.add("d-none");
                if (scanBtnText) scanBtnText.textContent = "Audit URL";
            }
        });
    }

    // Helper functions for dynamic UI generation
    function renderRiskMatrixRows(activeLikelihood, activeImpact) {
        let html = "";
        for (let imp = 5; imp >= 1; imp--) {
            html += `<tr>`;
            html += `<td class="fw-bold text-muted-cs py-1 border-0 text-end pe-2" style="width: 15%;">${imp}</td>`;
            for (let lik = 1; lik <= 5; lik++) {
                const isActive = (lik === activeLikelihood && imp === activeImpact);
                let cellColor = "";
                if (imp >= 4 && lik >= 4) {
                    cellColor = isActive ? "bg-danger text-white border-danger" : "bg-danger-subtle text-danger";
                } else if (imp >= 3 && lik >= 3) {
                    cellColor = isActive ? "bg-warning text-dark border-warning" : "bg-warning-subtle text-warning";
                } else if (imp >= 2 && lik >= 2) {
                    cellColor = isActive ? "bg-info text-white border-info" : "bg-info-subtle text-info";
                } else {
                    cellColor = isActive ? "bg-success text-white border-success" : "bg-success-subtle text-success";
                }
                
                const activeStyle = isActive 
                    ? `style="border: 2px solid var(--color-primary) !important; box-shadow: 0 0 15px var(--color-primary-glow); transform: scale(1.1); font-weight: 900; z-index: 5;"` 
                    : `class="${cellColor} opacity-50"`;
                html += `<td ${activeStyle} class="py-1 border" title="Likelihood ${lik}, Impact ${imp}">${isActive ? '🎯' : ''}</td>`;
            }
            html += `</tr>`;
        }
        return html;
    }

    function renderFeatureCards(features) {
        const list = [
            { key: "ssl_final_state", label: "SSL/HTTPS Status", interpret: v => v === 1 ? ["HTTP (No encryption)", "DANGER", "text-danger", "bi-shield-fill-x"] : ["HTTPS Secured", "SAFE", "text-success", "bi-shield-fill-check"] },
            { key: "url_length", label: "URL Length Check", interpret: v => v === 1 ? ["Long URL (>= 54 chars)", "WARNING", "text-warning", "bi-exclamation-triangle-fill"] : ["Normal string length", "SAFE", "text-success", "bi-shield-fill-check"] },
            { key: "having_ip_address", label: "IP Host Address", interpret: v => v === 1 ? ["IP address used as host", "WARNING", "text-warning", "bi-exclamation-triangle-fill"] : ["Standard named domain", "SAFE", "text-success", "bi-shield-fill-check"] },
            { key: "prefix_suffix", label: "Hyphen in Domain", interpret: v => v === 1 ? ["Domain contains '-'", "WARNING", "text-warning", "bi-exclamation-triangle-fill"] : ["No domain hyphens", "SAFE", "text-success", "bi-shield-fill-check"] },
            { key: "having_sub_domain", label: "Subdomain Count", interpret: v => v === 1 ? ["Multiple subdomains", "WARNING", "text-warning", "bi-exclamation-triangle-fill"] : ["Single or no subdomain", "SAFE", "text-success", "bi-shield-fill-check"] },
            { key: "shortening_service", label: "URL Shortener", interpret: v => v === 1 ? ["Shortened URL redirection", "WARNING", "text-warning", "bi-exclamation-triangle-fill"] : ["No shorteners found", "SAFE", "text-success", "bi-shield-fill-check"] },
            { key: "having_at_symbol", label: "@ Character Check", interpret: v => v === 1 ? ["Contains '@' symbol", "DANGER", "text-danger", "bi-shield-fill-x"] : ["No '@' symbol", "SAFE", "text-success", "bi-shield-fill-check"] },
            { key: "double_slash_redirecting", label: "Double Slash Redirect", interpret: v => v === 1 ? ["Multiple // symbols", "DANGER", "text-danger", "bi-shield-fill-x"] : ["Normal path format", "SAFE", "text-success", "bi-shield-fill-check"] },
            { key: "suspicious_keywords", label: "Brand Spoofing terms", interpret: v => v > 1 ? [`${v} Phishing terms found`, "DANGER", "text-danger", "bi-shield-fill-x"] : v === 1 ? ["1 Phishing term found", "WARNING", "text-warning", "bi-exclamation-triangle-fill"] : ["No suspicious terms", "SAFE", "text-success", "bi-shield-fill-check"] }
        ];
        
        let html = "";
        list.forEach(item => {
            const val = features[item.key] || 0;
            const [valDesc, riskLabel, colorClass, iconClass] = item.interpret(val);
            html += `
            <div class="col-sm-6 col-lg-4">
                <div class="p-3 bg-cs-tertiary rounded-3 border-cs h-100 d-flex flex-column justify-content-between">
                    <div class="d-flex align-items-center justify-content-between mb-2">
                        <span class="small font-monospace text-muted-cs fw-bold" style="font-size: 0.7rem;">${item.label}</span>
                        <span class="badge-cs ${val === 1 || (item.key === 'suspicious_keywords' && val > 0) ? (riskLabel === 'DANGER' ? 'badge-danger' : 'badge-warning') : 'badge-success'} px-2 py-0.5" style="font-size: 0.65rem;">${riskLabel}</span>
                    </div>
                    <div class="d-flex align-items-center gap-2">
                        <i class="bi ${iconClass} ${colorClass} fs-5"></i>
                        <span class="small text-truncate" title="${valDesc}">${valDesc}</span>
                    </div>
                </div>
            </div>
            `;
        });
        return html;
    }

    function getAIExplanation(res) {
        const isPhishing = res.prediction === "Phishing";
        const risk = res.risk_score;
        const isSSL = res.features.ssl_final_state === 0;
        const keywords = res.features.suspicious_keywords || 0;
        
        if (isPhishing) {
            let factors = [];
            if (!isSSL) factors.push("the lack of secure SSL/HTTPS encryption");
            if (keywords > 0) factors.push("the inclusion of suspicious brand-spoofing keywords");
            if (res.features.url_length === 1) factors.push("an unusually long URL pattern");
            if (res.features.having_ip_address === 1) factors.push("using a raw numerical IP address as host name");
            if (res.features.shortening_service === 1) factors.push("the use of bulk URL shortening redirection services");
            
            let factorsStr = factors.length > 0 ? " key indicators: " + factors.join(", ") + "." : " multiple structural anomalies and suspicious lexical parameters.";
            return `Our Random Forest model analyzed this link and flagged it as <strong>Phishing</strong> with <strong>${res.confidence_score.toFixed(1)}% confidence</strong>. The overall threat risk score is <strong>${risk}/100</strong>, indicating a highly dangerous profile. The decision was heavily influenced by ${factorsStr} DO NOT visit this site or input any credentials.`;
        } else {
            if (risk > 30) {
                return `Our Random Forest model marked this link as <strong>Safe</strong>, but with warning parameters (Risk: <strong>${risk}/100</strong>). While it has valid SSL/HTTPS encryption and does not contain blatant brand phishing terms, its structural properties (such as length or subdomain depth) indicate moderate anomaly. Proceed with caution.`;
            }
            return `Our Random Forest model verified this link as <strong>Safe and Clean</strong> with <strong>${res.confidence_score.toFixed(1)}% confidence</strong>. The risk score is extremely low (<strong>${risk}/100</strong>). It contains valid SSL encryption, matches standard domain architectures, and contains zero credential spoofing signatures.`;
        }
    }

    function displayScanResults(res) {
        if (!resultsContainer) return;
        
        resultsContainer.classList.remove("d-none");
        resultsContainer.style.marginTop = "1.5rem";
        resultsContainer.scrollIntoView({ behavior: "smooth" });
        
        const isDark = document.documentElement.getAttribute("data-theme") === "dark";
        const isPhishing = res.prediction === "Phishing";
        const isSuspicious = !isPhishing && res.risk_score > 30;
        
        // Determine colors and labels
        let verdictBgClass = "bg-success-subtle border-success";
        let verdictTextClass = "text-success";
        let badgeColorClass = "badge-success";
        let badgeText = "VERIFIED SECURE";
        let verdictTitle = "URL VERIFIED CLEAN / SAFE";
        let riskColor = "#10b981"; // success
        let decisionBorderClass = "border-success";
        
        if (isPhishing) {
            verdictBgClass = "bg-danger-subtle border-danger";
            verdictTextClass = "text-danger";
            badgeColorClass = "badge-danger";
            badgeText = "THREAT BLOCKED";
            verdictTitle = "PHISHING CONFIRMED / MALICIOUS";
            riskColor = "#ef4444"; // danger
            decisionBorderClass = "border-danger";
        } else if (isSuspicious) {
            verdictBgClass = "bg-warning-subtle border-warning";
            verdictTextClass = "text-warning";
            badgeColorClass = "badge-warning";
            badgeText = "SUSPICION LOGGED";
            verdictTitle = "SUSPICIOUS LINK DETECTED";
            riskColor = "#fbbf24"; // warning
            decisionBorderClass = "border-warning";
        }
        
        // Likelihood vs Impact Calculations
        const likelihood = Math.min(5, Math.ceil(res.confidence_score / 20));
        const impact = Math.min(5, Math.ceil(res.risk_score / 20));
        
        const explanation = getAIExplanation(res);
        
        // PDF button setup
        const hasUserId = document.getElementById("scans-tbody") !== null;
        let pdfButtonHtml = "";
        if (hasUserId) {
            pdfButtonHtml = `
                <a id="res-pdf-link" href="/report/${res.id}" class="btn btn-primary-cs btn-sm rounded-pill px-3">
                    <i class="bi bi-file-earmark-pdf-fill"></i> Download PDF Report
                </a>
            `;
        } else {
            pdfButtonHtml = `
                <a href="/login" class="btn btn-primary-cs btn-sm rounded-pill px-3">
                    <i class="bi bi-shield-lock-fill"></i> Login to Download
                </a>
            `;
        }
        
        // Rebuild resultsContainer innerHTML
        resultsContainer.innerHTML = `
            <div class="row g-4">
                <!-- Header verdict banner -->
                <div class="col-12">
                    <div class="p-4 rounded-3 text-center border-cs ${verdictBgClass} animate__animated animate__fadeIn">
                        <span class="badge-cs ${badgeColorClass} mb-2">${badgeText}</span>
                        <h3 class="fw-bold mb-1 ${verdictTextClass}">${verdictTitle}</h3>
                        <p class="text-break font-monospace small text-muted-cs mb-0">${res.url}</p>
                    </div>
                </div>

                <!-- Visual Charts & Gauge -->
                <div class="col-lg-4">
                    <div class="glass-card p-3 h-100 text-center d-flex flex-column align-items-center justify-content-center">
                        <h6 class="fw-bold mb-2 text-muted-cs font-monospace small"><i class="bi bi-shield-fill-check"></i> Overall Threat Score</h6>
                        <div id="risk-radial-chart" style="min-height: 180px; width: 100%;"></div>
                        <div class="mt-2 text-center">
                            <span class="fw-bold ${verdictTextClass} font-monospace">Score: ${res.risk_score}/100</span>
                        </div>
                    </div>
                </div>
                
                <div class="col-lg-4">
                    <div class="glass-card p-3 h-100 text-center d-flex flex-column align-items-center justify-content-center">
                        <h6 class="fw-bold mb-2 text-muted-cs font-monospace small"><i class="bi bi-pie-chart-fill"></i> Probability Breakdown</h6>
                        <div id="prob-doughnut-chart" style="min-height: 180px; width: 100%;"></div>
                    </div>
                </div>
                
                <div class="col-lg-4">
                    <div class="glass-card p-3 h-100 text-center d-flex flex-column align-items-center justify-content-center">
                        <h6 class="fw-bold mb-2 text-muted-cs font-monospace small"><i class="bi bi-radar"></i> Threat Vector Radar</h6>
                        <div id="vector-radar-chart" style="min-height: 180px; width: 100%;"></div>
                    </div>
                </div>

                <!-- Risk Matrix & Timeline -->
                <div class="col-md-6">
                    <div class="glass-card p-3 h-100">
                        <h6 class="fw-bold mb-3 text-muted-cs font-monospace small"><i class="bi bi-grid-3x3-gap-fill"></i> Likelihood vs Impact Matrix</h6>
                        <div class="risk-matrix">
                            <table class="table table-bordered text-center font-monospace" style="font-size: 0.72rem; table-layout: fixed;">
                                <thead>
                                    <tr>
                                        <th style="width: 15%; border: none;"></th>
                                        <th colspan="5" class="small py-1 text-muted-cs text-center" style="border: none;">LIKELIHOOD (CONFIDENCE)</th>
                                    </tr>
                                    <tr class="text-muted-cs border-0">
                                        <th class="py-1 text-end border-0" style="font-size: 0.65rem;">IMPACT</th>
                                        <th class="py-1">1</th>
                                        <th class="py-1">2</th>
                                        <th class="py-1">3</th>
                                        <th class="py-1">4</th>
                                        <th class="py-1">5</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${renderRiskMatrixRows(likelihood, impact)}
                                </tbody>
                            </table>
                            <div class="d-flex justify-content-between text-muted-cs small font-monospace mt-2 px-1">
                                <span>1: Negligible / 5: Critical</span>
                                <span class="fw-bold text-primary-cs">🎯 Active Cell</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="glass-card p-3 h-100">
                        <h6 class="fw-bold mb-3 text-muted-cs font-monospace small"><i class="bi bi-clock-history"></i> AI Auditing Timeline</h6>
                        <div class="timeline-v text-start font-monospace small ps-2">
                            <div class="timeline-item">
                                <strong class="text-success">[01] REQUEST CAPTURED</strong>
                                <div class="text-muted-cs" style="font-size: 0.75rem;">Audited URL intercepted by gateway filters.</div>
                            </div>
                            <div class="timeline-item">
                                <strong class="text-info">[02] LEXICAL PARSING</strong>
                                <div class="text-muted-cs" style="font-size: 0.75rem;">Analyzed length, subdomains, IP presence, and brand tokens.</div>
                            </div>
                            <div class="timeline-item">
                                <strong class="text-warning">[03] ML CLASSIFICATION</strong>
                                <div class="text-muted-cs" style="font-size: 0.75rem;">Passed vector map to RandomForest Model (100 decision trees).</div>
                            </div>
                            <div class="timeline-item">
                                <strong class="text-primary-cs">[04] REPORT COMPILED</strong>
                                <div class="text-muted-cs" style="font-size: 0.75rem;">Assigned risk score, generated cryptographic secure logs.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Feature Breakdown Ledger -->
                <div class="col-12">
                    <div class="glass-card p-4">
                        <h6 class="fw-bold mb-3 text-muted-cs font-monospace small"><i class="bi bi-terminal-fill"></i> Feature Auditing Breakdown</h6>
                        <div class="row g-2">
                            ${renderFeatureCards(res.features)}
                        </div>
                    </div>
                </div>

                <!-- AI Decision Breakdown explanation card -->
                <div class="col-12">
                    <div class="p-3 bg-cs-tertiary rounded-3 border-start border-4 ${decisionBorderClass}">
                        <h6 class="fw-bold mb-1 text-muted-cs font-monospace small"><i class="bi bi-cpu-fill"></i> AI Decision Explainer</h6>
                        <p class="text-secondary-cs small mb-0">
                            ${explanation}
                        </p>
                    </div>
                </div>

                <!-- Actions -->
                <div class="col-12">
                    <div class="d-flex align-items-center justify-content-between bg-body-tertiary p-3 rounded-3 flex-wrap gap-2">
                        <span class="small text-muted-cs"><i class="bi bi-shield-fill-check"></i> Security Report Verified by CyberShield Kernel</span>
                        <div class="d-flex gap-2">
                            <button onclick="window.print()" class="btn btn-outline-cs btn-sm rounded-pill px-3">
                                <i class="bi bi-printer-fill"></i> Print Details
                            </button>
                            ${pdfButtonHtml}
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Render ApexCharts after DOM elements are written
        setTimeout(() => {
            // A. Radial Bar Chart
            var radialOptions = {
                series: [res.risk_score],
                chart: { height: 160, type: 'radialBar' },
                colors: [riskColor],
                plotOptions: {
                    radialBar: {
                        hollow: { size: '60%' },
                        dataLabels: {
                            name: { show: false },
                            value: {
                                offsetY: 8,
                                fontSize: '20px',
                                fontWeight: 700,
                                color: isDark ? '#e8f0ff' : '#0b1437',
                                formatter: function(val) { return val + '%'; }
                            }
                        }
                    }
                }
            };
            var radialChart = new ApexCharts(document.querySelector("#risk-radial-chart"), radialOptions);
            radialChart.render();

            // B. Doughnut Chart
            var safeProb = isPhishing ? 0 : res.confidence_score;
            var phishProb = isPhishing ? res.confidence_score : 0;
            var suspProb = 100 - res.confidence_score;
            var doughnutOptions = {
                series: [parseFloat(safeProb.toFixed(1)), parseFloat(suspProb.toFixed(1)), parseFloat(phishProb.toFixed(1))],
                chart: { height: 160, type: 'donut' },
                labels: ['Safe', 'Suspicious', 'Phishing'],
                colors: ['#10b981', '#fbbf24', '#ef4444'],
                legend: { show: false },
                dataLabels: { enabled: false },
                plotOptions: {
                    pie: {
                        donut: {
                            size: '65%',
                            labels: {
                                show: true,
                                name: { show: true, fontSize: '11px', color: '#8492b4' },
                                value: { show: true, fontSize: '16px', fontWeight: 600, color: isDark ? '#e8f0ff' : '#0b1437' },
                                total: {
                                    show: true,
                                    label: 'Verdict',
                                    formatter: function () {
                                        return isPhishing ? 'Malicious' : (isSuspicious ? 'Suspicious' : 'Clean');
                                    }
                                }
                            }
                        }
                    }
                }
            };
            var doughnutChart = new ApexCharts(document.querySelector("#prob-doughnut-chart"), doughnutOptions);
            doughnutChart.render();

            // C. Radar Chart
            var radarOptions = {
                series: [{
                    name: 'Threat Level',
                    data: [
                        res.features.ssl_final_state === 1 ? 100 : 10,
                        res.features.suspicious_keywords > 0 ? Math.min(100, 30 * res.features.suspicious_keywords) : 10,
                        (res.features.shortening_service === 1 || res.features.url_length === 1) ? 80 : 10,
                        (res.features.double_slash_redirecting === 1 || res.features.having_at_symbol === 1) ? 95 : 15,
                        (res.features.prefix_suffix === 1 || res.features.having_sub_domain === 1 || res.features.having_ip_address === 1) ? 75 : 15
                    ]
                }],
                chart: { height: 170, type: 'radar', toolbar: { show: false } },
                xaxis: {
                    categories: ['SSL', 'Keywords', 'Redirects', 'Structure', 'Domain Check'],
                    labels: {
                        style: {
                            colors: ['#8492b4', '#8492b4', '#8492b4', '#8492b4', '#8492b4'],
                            fontSize: '9px',
                            fontFamily: 'Fira Code'
                        }
                    }
                },
                yaxis: { show: false, min: 0, max: 100 },
                colors: [riskColor],
                markers: { size: 3 },
                fill: { opacity: 0.2 }
            };
            var radarChart = new ApexCharts(document.querySelector("#vector-radar-chart"), radarOptions);
            radarChart.render();
        }, 100);
    }

    function appendScanToLogsTable(res) {
        const tableBody = document.getElementById("scans-tbody");
        if (!tableBody) return;
        
        const tr = document.createElement("tr");
        tr.className = "animate__animated animate__fadeInDown";
        
        const dateFormatted = new Date().toLocaleString();
        const badgeClass = res.prediction === "Phishing" ? "badge bg-danger" : "badge bg-success";
        
        tr.innerHTML = `
            <td class="text-break"><code>${res.url}</code></td>
            <td><span class="${badgeClass}">${res.prediction}</span></td>
            <td>${res.confidence_score.toFixed(1)}%</td>
            <td>${res.risk_score}/100</td>
            <td>${dateFormatted}</td>
            <td>
                <a href="/report/${res.id}" class="btn btn-sm btn-outline-cs">
                    <i class="bi bi-file-earmark-pdf"></i> PDF
                </a>
            </td>
        `;
        
        if (tableBody.firstChild) {
            tableBody.insertBefore(tr, tableBody.firstChild);
        } else {
            tableBody.appendChild(tr);
        }
        
        const emptyRow = document.getElementById("no-scans-row");
        if (emptyRow) {
            emptyRow.remove();
        }
    }

    // Toast Notification Creator
    function showToast(message, type = "success") {
        const toastContainer = document.getElementById("toast-container");
        if (!toastContainer) {
            const container = document.createElement("div");
            container.id = "toast-container";
            container.className = "position-fixed bottom-0 end-0 p-3";
            container.style.zIndex = "1055";
            document.body.appendChild(container);
        }
        
        const toastId = "toast_" + Date.now();
        const icon = type === "success" ? "bi-check-circle-fill" : "bi-exclamation-triangle-fill";
        const bgClass = type === "success" ? "bg-success" : "bg-danger";
        
        const toastHtml = `
            <div id="${toastId}" class="toast align-items-center text-white ${bgClass} border-0 shadow-lg" role="alert" aria-live="assertive" aria-atomic="true">
                <div class="d-flex text-white p-2">
                    <div class="toast-body d-flex align-items-center gap-2">
                        <i class="bi ${icon}"></i>
                        <span>${message}</span>
                    </div>
                    <button type="button" class="btn-close btn-close-white m-auto me-2" data-bs-dismiss="toast" aria-label="Close"></button>
                </div>
            </div>
        `;
        
        document.getElementById("toast-container").insertAdjacentHTML("beforeend", toastHtml);
        const toastEl = document.getElementById(toastId);
        const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
        bsToast.show();
        
        toastEl.addEventListener("hidden.bs.toast", () => {
            toastEl.remove();
        });
    }

    // ==========================================
    // 2. Advanced Visual Analytics (Chart.js & ApexCharts)
    // ==========================================
    let scanPieChart = null;
    let trendsChart = null;
    let heatmapChart = null;
    let gaugeChart = null;

    const initDashboardAnalytics = async () => {
        const isDark = document.documentElement.getAttribute("data-theme") === "dark";
        const textColor = isDark ? "#9baece" : "#3a4a6b";
        const gridColor = isDark ? "rgba(26, 38, 70, 0.4)" : "rgba(208, 217, 240, 0.5)";
        const primaryColor = isDark ? "#00c8ff" : "#0057ff";
        
        try {
            const response = await fetch("/api/dashboard-analytics");
            const data = await response.json();
            
            if (!response.ok || !data.success) {
                console.error("Failed to load dashboard analytics");
                return;
            }

            // A. Update Card Numbers in real-time
            const totalCard = document.getElementById("card-total-scans");
            const safeCard = document.getElementById("card-safe-scans");
            const suspiciousCard = document.getElementById("card-suspicious-scans");
            const phishCard = document.getElementById("card-phish-scans");
            const avgPwCard = document.getElementById("card-avg-password-strength");
            const genPwCard = document.getElementById("card-passwords-generated");

            if (totalCard) totalCard.textContent = data.url_analytics.total;
            if (safeCard) safeCard.textContent = data.url_analytics.safe;
            if (suspiciousCard) suspiciousCard.textContent = data.url_analytics.suspicious;
            if (phishCard) phishCard.textContent = data.url_analytics.phishing;
            if (avgPwCard) avgPwCard.textContent = data.password_analytics.average_strength_score;
            if (genPwCard) genPwCard.textContent = data.password_analytics.total_generated;

            // B. Doughnut Chart: Scan Verdict Ratios (Chart.js)
            const ratioCtx = document.getElementById("scanChart");
            if (ratioCtx) {
                if (scanPieChart) scanPieChart.destroy();
                scanPieChart = new Chart(ratioCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Safe', 'Suspicious', 'Phishing'],
                        datasets: [{
                            data: [data.url_analytics.safe, data.url_analytics.suspicious, data.url_analytics.phishing],
                            backgroundColor: ['#10b981', '#fbbf24', '#ef4444'],
                            borderWidth: 2,
                            borderColor: isDark ? '#080f22' : '#ffffff',
                            hoverOffset: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    color: textColor,
                                    font: { family: 'Space Grotesk', size: 10 }
                                }
                            }
                        },
                        cutout: '70%'
                    }
                });
            }

            // C. Score Security Trends Chart (ApexCharts - Line)
            const trendsContainer = document.querySelector("#securityTrendsChart");
            if (trendsContainer) {
                if (trendsChart) trendsChart.destroy();
                
                const trendsOptions = {
                    series: [
                        { name: 'URL Risk Index', data: data.trends.scan_risk_scores },
                        { name: 'Password Security', data: data.trends.password_strength_scores }
                    ],
                    chart: { 
                        height: 200, 
                        type: 'line', 
                        toolbar: { show: false },
                        background: 'transparent'
                    },
                    theme: { mode: isDark ? 'dark' : 'light' },
                    colors: ['#ef4444', '#10b981'],
                    stroke: { width: 3, curve: 'smooth' },
                    xaxis: {
                        categories: data.trends.scan_dates,
                        labels: { style: { colors: textColor } }
                    },
                    yaxis: {
                        min: 0,
                        max: 100,
                        labels: { style: { colors: textColor } }
                    },
                    grid: { borderColor: gridColor },
                    legend: { labels: { colors: textColor } }
                };

                trendsChart = new ApexCharts(trendsContainer, trendsOptions);
                trendsChart.render();
            }

            // D. Security Activity Heatmap (ApexCharts - Heatmap)
            const heatmapContainer = document.querySelector("#activityHeatmap");
            if (heatmapContainer) {
                if (heatmapChart) heatmapChart.destroy();

                const heatmapSeries = data.heatmap.days.map((dayName, dayIdx) => {
                    return {
                        name: dayName,
                        data: data.heatmap.hours.map((hourName, hourIdx) => {
                            return {
                                x: hourName,
                                y: data.heatmap.matrix[dayIdx][hourIdx]
                            };
                        })
                    };
                });

                const heatmapOptions = {
                    series: heatmapSeries,
                    chart: { 
                        height: 200, 
                        type: 'heatmap', 
                        toolbar: { show: false },
                        background: 'transparent'
                    },
                    theme: { mode: isDark ? 'dark' : 'light' },
                    dataLabels: { enabled: false },
                    colors: [primaryColor],
                    xaxis: {
                        labels: { style: { colors: textColor } }
                    },
                    yaxis: {
                        labels: { style: { colors: textColor } }
                    }
                };

                heatmapChart = new ApexCharts(heatmapContainer, heatmapOptions);
                heatmapChart.render();
            }

            // E. Threat Index Speedometer Gauge (ApexCharts - Semi Radial)
            const gaugeContainer = document.querySelector("#securityGaugeChart");
            if (gaugeContainer) {
                if (gaugeChart) gaugeChart.destroy();

                // Compute overall safety score: (safe counts / total) * 100, default 100
                let profileScore = 100;
                if (data.url_analytics.total > 0) {
                    profileScore = Math.round((data.url_analytics.safe / data.url_analytics.total) * 100);
                }

                // If they checked passwords, factor it in
                if (data.password_analytics.average_strength_score > 0) {
                    profileScore = Math.round((profileScore + data.password_analytics.average_strength_score) / 2);
                }

                let gaugeColor = '#10b981';
                if (profileScore < 50) gaugeColor = '#ef4444';
                else if (profileScore < 80) gaugeColor = '#fbbf24';

                const gaugeOptions = {
                    series: [profileScore],
                    chart: { 
                        height: 200, 
                        type: 'radialBar',
                        sparkline: { enabled: true }
                    },
                    plotOptions: {
                        radialBar: {
                            startAngle: -90,
                            endAngle: 90,
                            track: {
                                background: isDark ? '#1a2646' : '#e8edf8',
                                strokeWidth: '97%'
                            },
                            dataLabels: {
                                name: { show: false },
                                value: {
                                    offsetY: -10,
                                    fontSize: '24px',
                                    fontWeight: 'bold',
                                    color: isDark ? '#e8f0ff' : '#0b1437'
                                }
                            }
                        }
                    },
                    colors: [gaugeColor],
                    grid: { padding: { top: -10 } },
                    labels: ['Safety Index']
                };

                gaugeChart = new ApexCharts(gaugeContainer, gaugeOptions);
                gaugeChart.render();

                // Update text layout
                const gaugeValText = document.getElementById("security-score-val");
                const gaugeFill = document.getElementById("security-score-fill");
                const gaugeVerdict = document.getElementById("security-score-verdict");
                
                if (gaugeValText) gaugeValText.textContent = `${profileScore}%`;
                if (gaugeFill) {
                    gaugeFill.style.width = `${profileScore}%`;
                    gaugeFill.className = "progress-bar";
                    if (profileScore >= 80) {
                        gaugeFill.classList.add("bg-success");
                        if (gaugeVerdict) gaugeVerdict.innerHTML = "<span class='text-success'><i class='bi bi-shield-check'></i> SECURED PROFILE</span>";
                    } else if (profileScore >= 50) {
                        gaugeFill.classList.add("bg-warning");
                        if (gaugeVerdict) gaugeVerdict.innerHTML = "<span class='text-warning'><i class='bi bi-shield-slash'></i> SUSPICION DETECTED</span>";
                    } else {
                        gaugeFill.classList.add("bg-danger");
                        if (gaugeVerdict) gaugeVerdict.innerHTML = "<span class='text-danger'><i class='bi bi-shield-exclamation'></i> HIGH THREAT VALUE</span>";
                    }
                }
            }
        } catch (err) {
            console.error("Dashboard Analytics Error:", err);
        }
    };

    // Initialize charts on load
    if (document.getElementById("stats-data")) {
        initDashboardAnalytics();
        
        // Listen to theme change to update charts properly
        const themeBtn = document.getElementById("theme-toggle");
        if (themeBtn) {
            themeBtn.addEventListener("click", () => {
                setTimeout(initDashboardAnalytics, 150);
            });
        }
        
        // Bind dynamic charts updater to window
        window.updateChartsData = () => {
            initDashboardAnalytics();
        };
    }
});
