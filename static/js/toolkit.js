document.addEventListener("DOMContentLoaded", () => {
    // CSRF Token utility
    const getCsrfToken = () => {
        const csrfMeta = document.querySelector('meta[name="csrf-token"]');
        return csrfMeta ? csrfMeta.getAttribute("content") : "";
    };

    // Show Toast Notification
    const showToast = (message, type = "success") => {
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
    };

    // ==========================================
    // 1. URL SCANNER
    // ==========================================
    const scanForm = document.getElementById("toolkit-scan-form");
    const scanInput = document.getElementById("toolkit-url-input");
    const scanBtn = document.getElementById("toolkit-scan-btn");
    const scanBtnText = document.getElementById("toolkit-scan-btn-text");
    const scanSpinner = document.getElementById("toolkit-scan-spinner");
    const resultsContainer = document.getElementById("toolkit-results-container");

    if (scanForm) {
        scanForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const urlToScan = scanInput.value.trim();
            if (!urlToScan) return;

            scanBtn.disabled = true;
            if (scanSpinner) scanSpinner.classList.remove("d-none");
            if (scanBtnText) scanBtnText.textContent = "Analyzing structure...";
            resultsContainer.classList.add("d-none");

            try {
                const response = await fetch("/scan", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": getCsrfToken()
                    },
                    body: JSON.stringify({ url: urlToScan })
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    displayScanResults(data.result);
                    appendScanToLogsTable(data.result);
                    showToast("Vulnerability audit complete!", "success");
                } else {
                    showToast(data.error || "URL Analysis failed.", "danger");
                }
            } catch (err) {
                console.error("URL Scan Error:", err);
                showToast("Connection anomaly. Server unreachable.", "danger");
            } finally {
                scanBtn.disabled = false;
                if (scanSpinner) scanSpinner.classList.add("d-none");
                if (scanBtnText) scanBtnText.textContent = "Scan Destination";
            }
        });
    }

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
            { key: "suspicious_keywords", label: "Brand Spoofing terms", interpret: v => v > 1 ? [`${v} Phishing terms found`, "DANGER", "text-danger", "bi-shield-fill-x"] : v === 1 ? ["1 Phishing term found", "WARNING", "text-warning", "bi-exclamation-triangle-fill"] : ["No suspicious terms", "SAFE", "text-success", "bi-shield-fill-check"] },
            { key: "excessive_special_chars", label: "Special Characters", interpret: v => v === 1 ? ["Excessive special characters", "WARNING", "text-warning", "bi-exclamation-triangle-fill"] : ["Standard character ratio", "SAFE", "text-success", "bi-shield-fill-check"] }
        ];
        
        let html = "";
        list.forEach(item => {
            const val = features[item.key] || 0;
            const [valDesc, riskLabel, colorClass, iconClass] = item.interpret(val);
            html += `
            <div class="col-sm-6 col-md-4">
                <div class="p-3 bg-cs-tertiary rounded-3 border-cs h-100 d-flex flex-column justify-content-between">
                    <div class="d-flex align-items-center justify-content-between mb-2">
                        <span class="small font-monospace text-muted-cs fw-bold" style="font-size: 0.7rem;">${item.label}</span>
                        <span class="badge-cs ${val === 1 || (item.key === 'suspicious_keywords' && val > 0) ? (riskLabel === 'DANGER' ? 'badge-danger' : 'badge-warning') : 'badge-success'} px-2 py-0.5" style="font-size: 0.65rem;">${riskLabel}</span>
                    </div>
                    <div class="d-flex align-items-center gap-2">
                        <i class="bi ${iconClass} ${colorClass} fs-5"></i>
                        <span class="small text-truncate text-secondary-cs" title="${valDesc}">${valDesc}</span>
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
            if (res.features.excessive_special_chars === 1) factors.push("an excessive amount of query symbols and special characters");
            
            let factorsStr = factors.length > 0 ? " key indicators: " + factors.join(", ") + "." : " multiple structural anomalies and suspicious lexical parameters.";
            return `Our model analyzed this link and flagged it as <strong>Phishing</strong> with <strong>${res.confidence_score.toFixed(1)}% confidence</strong>. The overall threat risk score is <strong>${risk}/100</strong>, indicating a highly dangerous profile. The decision was heavily influenced by ${factorsStr} DO NOT visit this site or input any credentials.`;
        } else {
            if (risk > 30) {
                return `Our model marked this link as <strong>Safe</strong>, but with warning parameters (Risk: <strong>${risk}/100</strong>). While it has valid SSL/HTTPS encryption and does not contain blatant brand phishing terms, its structural properties (such as length or subdomain depth) indicate moderate anomaly. Proceed with caution.`;
            }
            return `Our model verified this link as <strong>Safe and Clean</strong> with <strong>${res.confidence_score.toFixed(1)}% confidence</strong>. The risk score is extremely low (<strong>${risk}/100</strong>). It contains valid SSL encryption, matches standard domain architectures, and contains zero credential spoofing signatures.`;
        }
    }

    function displayScanResults(res) {
        if (!resultsContainer) return;
        
        resultsContainer.classList.remove("d-none");
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
        const reputationScore = 100 - res.risk_score;
        
        // PDF button setup
        let pdfButtonHtml = `
            <a id="res-pdf-link" href="/report/${res.id}" class="btn btn-primary-cs btn-sm rounded-pill px-3">
                <i class="bi bi-file-earmark-pdf-fill"></i> Download PDF Report
            </a>
        `;
        
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

                <!-- Risk Matrix & Details -->
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
                        <h6 class="fw-bold mb-3 text-muted-cs font-monospace small"><i class="bi bi-shield-lock-fill"></i> Reputation & Special Indicators</h6>
                        <div class="d-flex flex-column gap-3 justify-content-center h-75 px-2">
                            <div>
                                <div class="d-flex justify-content-between mb-1">
                                    <span class="small font-monospace text-secondary-cs">Domain Reputation Score:</span>
                                    <span class="small font-monospace fw-bold ${reputationScore > 70 ? 'text-success' : reputationScore > 40 ? 'text-warning' : 'text-danger'}">${reputationScore}/100</span>
                                </div>
                                <div class="progress" style="height: 10px;">
                                    <div class="progress-bar ${reputationScore > 70 ? 'bg-success' : reputationScore > 40 ? 'bg-warning' : 'bg-danger'}" role="progressbar" style="width: ${reputationScore}%"></div>
                                </div>
                            </div>
                            <div class="border-top border-cs pt-2">
                                <div class="small text-muted-cs font-monospace mb-1">Vulnerability Checks:</div>
                                <div class="d-flex flex-wrap gap-2">
                                    <span class="badge-cs ${res.features.having_ip_address === 1 ? 'badge-danger' : 'badge-success'}">
                                        <i class="bi ${res.features.having_ip_address === 1 ? 'bi-shield-x' : 'bi-shield-check'}"></i> IP-based host
                                    </span>
                                    <span class="badge-cs ${res.features.shortening_service === 1 ? 'badge-danger' : 'badge-success'}">
                                        <i class="bi ${res.features.shortening_service === 1 ? 'bi-shield-x' : 'bi-shield-check'}"></i> Shortener
                                    </span>
                                    <span class="badge-cs ${res.features.excessive_special_chars === 1 ? 'badge-danger' : 'badge-success'}">
                                        <i class="bi ${res.features.excessive_special_chars === 1 ? 'bi-shield-x' : 'bi-shield-check'}"></i> Special Char Ratio
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Feature Breakdown Ledger -->
                <div class="col-12">
                    <div class="glass-card p-4">
                        <h6 class="fw-bold mb-3 text-muted-cs font-monospace small"><i class="bi bi-terminal-fill"></i> Structure Auditing Breakdown</h6>
                        <div class="row g-2">
                            ${renderFeatureCards(res.features)}
                        </div>
                    </div>
                </div>

                <!-- AI Decision Explainer -->
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
                        (res.features.prefix_suffix === 1 || res.features.having_sub_domain === 1 || res.features.having_ip_address === 1 || res.features.excessive_special_chars === 1) ? 75 : 15
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
        const tableBody = document.getElementById("toolkit-scans-tbody");
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

        const emptyRow = document.getElementById("toolkit-no-scans-row");
        if (emptyRow) {
            emptyRow.remove();
        }
    }


    // ==========================================
    // 2. PASSWORD STRENGTH ANALYZER
    // ==========================================
    const passwordInput = document.getElementById("pw-analyzer-input");
    const toggleVisibleBtn = document.getElementById("pw-toggle-visible");
    const meterFill = document.getElementById("pw-meter-fill");
    const scoreVal = document.getElementById("pw-score-val");
    const ratingLabel = document.getElementById("pw-rating-label");
    const crackTimeVal = document.getElementById("pw-crack-time");
    const entropyVal = document.getElementById("pw-entropy-val");
    const feedbackList = document.getElementById("pw-feedback-list");
    const logCheckBtn = document.getElementById("pw-log-check-btn");
    
    // Checklist checkmarks
    const reqLength = document.getElementById("req-length");
    const reqUpper = document.getElementById("req-upper");
    const reqLower = document.getElementById("req-lower");
    const reqDigit = document.getElementById("req-digit");
    const reqSpecial = document.getElementById("req-special");
    const reqUnique = document.getElementById("req-unique");

    let currentCheckResult = null;

    if (toggleVisibleBtn && passwordInput) {
        toggleVisibleBtn.addEventListener("click", () => {
            const isPassword = passwordInput.type === "password";
            passwordInput.type = isPassword ? "text" : "password";
            toggleVisibleBtn.innerHTML = isPassword ? `<i class="bi bi-eye-slash"></i>` : `<i class="bi bi-eye"></i>`;
        });
    }

    const analyzePassword = (password) => {
        let score = 0;
        let feedback = [];
        
        if (!password) {
            return { score: 0, strength: "Very Weak", feedback: [], checks: {} };
        }
        
        // 1. Length check
        const len = password.length;
        if (len >= 16) score += 30;
        else if (len >= 12) score += 20;
        else if (len >= 8) score += 10;
        else {
            score += 5;
            feedback.push("Make the password longer (at least 8 characters).");
        }
        
        // 2. Character varieties
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasDigit = /[0-9]/.test(password);
        const hasSpecial = /[^A-Za-z0-9]/.test(password);
        
        if (hasLower) score += 15;
        else feedback.push("Add lowercase letters.");
        
        if (hasUpper) score += 15;
        else feedback.push("Add uppercase letters.");
        
        if (hasDigit) score += 15;
        else feedback.push("Add numbers.");
        
        if (hasSpecial) score += 15;
        else feedback.push("Add special characters.");
        
        // 3. Repeated characters check (e.g. "aaa", "111")
        const hasRepeats = /(.)\1\1/.test(password);
        if (hasRepeats) {
            score -= 15;
            feedback.push("Remove repeated consecutive characters (e.g., 'aaa').");
        }
        
        // 4. Common patterns (like 12345, qwerty, password)
        const commonPatterns = ['123456', 'abcdef', 'password', 'qwerty', 'admin', 'welcome', 'p@ssword'];
        let hasCommon = false;
        for (const pat of commonPatterns) {
            if (password.toLowerCase().includes(pat)) {
                hasCommon = true;
                break;
            }
        }
        if (hasCommon) {
            score -= 20;
            feedback.push("Avoid common sequence patterns (like '123456').");
        }
        
        // Clamp score
        score = Math.max(0, Math.min(100, score));
        
        // Determine strength rating
        let strength = "Very Weak";
        if (score >= 80) strength = "Very Strong";
        else if (score >= 60) strength = "Strong";
        else if (score >= 40) strength = "Medium";
        else if (score >= 20) strength = "Weak";
        
        // Compute entropy
        let poolSize = 0;
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSpecial) poolSize += 32;
        if (poolSize === 0) poolSize = 1;
        
        const entropy = len * Math.log2(poolSize);
        
        // Compute estimated offline crack time
        const guessesPerSec = 1e10; // GPU Brute Force offline speed
        const seconds = Math.pow(2, entropy - 1) / guessesPerSec;
        let crackTime = "Instantly";
        
        if (seconds > 31536000 * 1e9) crackTime = "Trillions of years";
        else if (seconds > 31536000 * 1e6) crackTime = Math.round(seconds / (31536000 * 1e6)) + " Million years";
        else if (seconds > 31536000) crackTime = Math.round(seconds / 31536000) + " Years";
        else if (seconds > 86400) crackTime = Math.round(seconds / 86400) + " Days";
        else if (seconds > 3600) crackTime = Math.round(seconds / 3600) + " Hours";
        else if (seconds > 60) crackTime = Math.round(seconds / 60) + " Minutes";
        else if (seconds > 0.1) crackTime = seconds.toFixed(1) + " Seconds";
        
        return {
            score: score,
            strength: strength,
            feedback: feedback,
            entropy: entropy,
            crackTime: crackTime,
            checks: {
                length: len >= 12,
                lower: hasLower,
                upper: hasUpper,
                digit: hasDigit,
                special: hasSpecial,
                unique: !hasRepeats && !hasCommon
            }
        };
    };

    const updateChecklistUI = (checks) => {
        const toggleCheck = (el, passed) => {
            if (!el) return;
            const icon = el.querySelector("i");
            if (passed) {
                el.className = "small font-monospace text-success d-flex align-items-center gap-1";
                if (icon) icon.className = "bi bi-check-circle-fill";
            } else {
                el.className = "small font-monospace text-muted-cs d-flex align-items-center gap-1";
                if (icon) icon.className = "bi bi-circle";
            }
        };

        toggleCheck(reqLength, checks.length);
        toggleCheck(reqUpper, checks.upper);
        toggleCheck(reqLower, checks.lower);
        toggleCheck(reqDigit, checks.digit);
        toggleCheck(reqSpecial, checks.special);
        toggleCheck(reqUnique, checks.unique);
    };

    if (passwordInput) {
        passwordInput.addEventListener("input", (e) => {
            const password = e.target.value;
            const res = analyzePassword(password);
            currentCheckResult = res;

            // Update score values
            if (scoreVal) scoreVal.textContent = `${res.score}/100`;
            if (ratingLabel) {
                ratingLabel.textContent = res.strength;
                // Set color class
                ratingLabel.className = "fw-bold small px-2 py-0.5 rounded badge-cs";
                if (res.strength === "Very Strong") ratingLabel.classList.add("badge-success");
                else if (res.strength === "Strong") ratingLabel.classList.add("badge-success");
                else if (res.strength === "Medium") ratingLabel.classList.add("badge-warning");
                else if (res.strength === "Weak") ratingLabel.classList.add("badge-danger");
                else ratingLabel.classList.add("badge-danger");
            }

            // Update animated meter
            if (meterFill) {
                meterFill.style.width = `${res.score}%`;
                meterFill.className = "progress-bar";
                if (res.score >= 80) meterFill.classList.add("bg-success");
                else if (res.score >= 60) meterFill.classList.add("bg-success");
                else if (res.score >= 40) meterFill.classList.add("bg-warning");
                else meterFill.classList.add("bg-danger");
            }

            // Update stats
            if (crackTimeVal) crackTimeVal.textContent = password ? res.crackTime : "--";
            if (entropyVal) entropyVal.textContent = password ? `${res.entropy.toFixed(1)} bits` : "--";

            // Update checklist
            updateChecklistUI(res.checks);

            // Update feedback suggestions
            if (feedbackList) {
                feedbackList.innerHTML = "";
                if (password && res.feedback.length > 0) {
                    res.feedback.forEach(item => {
                        const li = document.createElement("li");
                        li.className = "text-warning small mb-1";
                        li.innerHTML = `<i class="bi bi-info-circle-fill"></i> ${item}`;
                        feedbackList.appendChild(li);
                    });
                } else if (password && res.feedback.length === 0) {
                    const li = document.createElement("li");
                    li.className = "text-success small mb-1";
                    li.innerHTML = `<i class="bi bi-shield-check"></i> Ideal password complexity met!`;
                    feedbackList.appendChild(li);
                }
            }

            // Enable log button
            if (logCheckBtn) {
                logCheckBtn.disabled = !password;
            }
        });
    }

    if (logCheckBtn) {
        logCheckBtn.addEventListener("click", async () => {
            if (!currentCheckResult || !passwordInput.value) return;

            logCheckBtn.disabled = true;
            try {
                const response = await fetch("/api/log-password-check", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": getCsrfToken()
                    },
                    body: JSON.stringify({
                        score: currentCheckResult.score,
                        strength: currentCheckResult.strength
                    })
                });

                const data = await response.json();
                if (response.ok && data.success) {
                    showToast("Password integrity logged in Ledger!", "success");
                    passwordInput.value = "";
                    passwordInput.dispatchEvent(new Event("input"));
                } else {
                    showToast("Failed to log assessment.", "danger");
                    logCheckBtn.disabled = false;
                }
            } catch (err) {
                console.error("Log PW Error:", err);
                showToast("Connection anomaly.", "danger");
                logCheckBtn.disabled = false;
            }
        });
    }


    // ==========================================
    // 3. SECURE PASSWORD GENERATOR
    // ==========================================
    const genLengthSlider = document.getElementById("gen-length");
    const genLengthVal = document.getElementById("gen-length-val");
    const genUpper = document.getElementById("gen-upper");
    const genLower = document.getElementById("gen-lower");
    const genDigits = document.getElementById("gen-digits");
    const genSpecial = document.getElementById("gen-special");
    const genOutput = document.getElementById("gen-output-field");
    const genBtn = document.getElementById("generate-btn");
    const copyBtn = document.getElementById("gen-copy-btn");

    const genEntropyVal = document.getElementById("gen-entropy-val");
    const genRatingVal = document.getElementById("gen-rating-val");
    const genCrackVal = document.getElementById("gen-crack-val");
    const genEntropyGauge = document.getElementById("gen-entropy-gauge");

    if (genLengthSlider && genLengthVal) {
        genLengthSlider.addEventListener("input", (e) => {
            genLengthVal.textContent = e.target.value;
        });
    }

    const calculatePoolSize = (upper, lower, digits, special) => {
        let size = 0;
        if (lower) size += 26;
        if (upper) size += 26;
        if (digits) size += 10;
        if (special) size += 32;
        return size;
    };

    const getEntropyRating = (entropy) => {
        if (entropy >= 100) return ["Very Strong", "badge-success"];
        if (entropy >= 80) return ["Strong", "badge-success"];
        if (entropy >= 60) return ["Medium", "badge-warning"];
        if (entropy >= 40) return ["Weak", "badge-danger"];
        return ["Very Weak", "badge-danger"];
    };

    const getEstimatedCrackTime = (entropy) => {
        if (entropy === 0) return "Instantly";
        const guessesPerSec = 1e10; // offline GPU speed
        const seconds = Math.pow(2, entropy - 1) / guessesPerSec;
        
        if (seconds > 31536000 * 1e9) return "Trillions of years";
        if (seconds > 31536000 * 1e6) return Math.round(seconds / (31536000 * 1e6)) + " Million years";
        if (seconds > 31536000) return Math.round(seconds / 31536000) + " Years";
        if (seconds > 86400) return Math.round(seconds / 86400) + " Days";
        if (seconds > 3600) return Math.round(seconds / 3600) + " Hours";
        if (seconds > 60) return Math.round(seconds / 60) + " Minutes";
        return Math.round(seconds) + " Seconds";
    };

    const generatePassword = () => {
        const length = parseInt(genLengthSlider.value);
        const upper = genUpper.checked;
        const lower = genLower.checked;
        const digits = genDigits.checked;
        const special = genSpecial.checked;

        const poolSize = calculatePoolSize(upper, lower, digits, special);
        if (poolSize === 0) {
            showToast("Select at least one complexity filter", "danger");
            return;
        }

        // Generate logic — use named constants to prevent index out-of-bounds
        const CHARS_LOWER = "abcdefghijklmnopqrstuvwxyz";
        const CHARS_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const CHARS_DIGITS = "0123456789";
        const CHARS_SPECIAL = "!@#$%^&*()_+-=[]{}|;:',.<>/?~";

        let pool = "";
        const mandatory = [];
        if (lower) { pool += CHARS_LOWER; mandatory.push(CHARS_LOWER[Math.floor(Math.random() * CHARS_LOWER.length)]); }
        if (upper) { pool += CHARS_UPPER; mandatory.push(CHARS_UPPER[Math.floor(Math.random() * CHARS_UPPER.length)]); }
        if (digits) { pool += CHARS_DIGITS; mandatory.push(CHARS_DIGITS[Math.floor(Math.random() * CHARS_DIGITS.length)]); }
        if (special) { pool += CHARS_SPECIAL; mandatory.push(CHARS_SPECIAL[Math.floor(Math.random() * CHARS_SPECIAL.length)]); }

        let password = "";
        for (let i = 0; i < length - mandatory.length; i++) {
            password += pool[Math.floor(Math.random() * pool.length)];
        }

        mandatory.forEach(char => {
            const idx = Math.floor(Math.random() * (password.length + 1));
            password = password.slice(0, idx) + char + password.slice(idx);
        });

        // Letter scrambling animation effect in UI
        let iter = 0;
        const originalText = password;
        const scrambleInterval = setInterval(() => {
            let scrambled = "";
            for (let k = 0; k < originalText.length; k++) {
                if (k < iter) {
                    scrambled += originalText[k];
                } else {
                    scrambled += pool[Math.floor(Math.random() * pool.length)];
                }
            }
            genOutput.value = scrambled;
            iter += 2;
            if (iter >= originalText.length + 2) {
                clearInterval(scrambleInterval);
                genOutput.value = originalText;
                
                // Trigger stats update
                const entropy = length * Math.log2(poolSize);
                const [rating, badgeClass] = getEntropyRating(entropy);
                const crackTime = getEstimatedCrackTime(entropy);

                if (genEntropyVal) genEntropyVal.textContent = `${entropy.toFixed(1)} bits`;
                if (genRatingVal) {
                    genRatingVal.textContent = rating;
                    genRatingVal.className = `badge-cs ${badgeClass} small fw-bold px-2 py-0.5 rounded`;
                }
                if (genCrackVal) genCrackVal.textContent = crackTime;
                
                // Entropy gauge fill
                if (genEntropyGauge) {
                    const percent = Math.min(100, Math.round((entropy / 128) * 100));
                    genEntropyGauge.style.width = `${percent}%`;
                    genEntropyGauge.className = "progress-bar";
                    if (percent >= 70) genEntropyGauge.classList.add("bg-success");
                    else if (percent >= 50) genEntropyGauge.classList.add("bg-warning");
                    else genEntropyGauge.classList.add("bg-danger");
                }

                // Log generation event
                logPasswordGenerationEvent(length, entropy);
            }
        }, 30);
    };

    const logPasswordGenerationEvent = async (length, entropy) => {
        try {
            await fetch("/api/log-password-generation", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": getCsrfToken()
                },
                body: JSON.stringify({ length, entropy })
            });
        } catch (err) {
            console.error("Logging generation failed:", err);
        }
    };

    if (genBtn) {
        genBtn.addEventListener("click", generatePassword);
        // Generate once on load
        generatePassword();
    }

    if (copyBtn) {
        copyBtn.addEventListener("click", () => {
            if (!genOutput.value) return;
            navigator.clipboard.writeText(genOutput.value);
            showToast("Password copied to clipboard!", "success");
            
            const icon = copyBtn.querySelector("i");
            if (icon) {
                icon.className = "bi bi-check-all text-success";
                setTimeout(() => {
                    icon.className = "bi bi-copy";
                }, 2000);
            }
        });
    }
});
