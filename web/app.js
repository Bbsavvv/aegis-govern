(function () {
  const LICENSE_STORE = "aegis.licenses";

  function $(id) {
    return document.getElementById(id);
  }

  function log(message) {
    const el = $("log");
    const line = document.createElement("div");
    line.textContent = new Date().toISOString() + "  " + message;
    el.prepend(line);
  }

  async function api(path, options) {
    const response = await fetch(path, options);
    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (err) {
      throw new Error(text || "Invalid JSON from " + path);
    }
    if (!response.ok) {
      const detail = data && data.detail ? JSON.stringify(data.detail) : text;
      throw new Error(response.status + " " + detail);
    }
    return data;
  }

  function euro(n) {
    return new Intl.NumberFormat("en-IE", {
      style: "currency",
      currency: "EUR",
      maximumFractionDigits: 0,
    }).format(Number(n || 0));
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function licenses() {
    try {
      return JSON.parse(sessionStorage.getItem(LICENSE_STORE) || "{}");
    } catch (err) {
      return {};
    }
  }

  function rememberLicense(packageId, key) {
    if (!packageId || !key) return;
    const map = licenses();
    map[packageId] = key;
    sessionStorage.setItem(LICENSE_STORE, JSON.stringify(map));
  }

  function table(headers, rows) {
    if (!rows.length) {
      return '<p class="empty">No rows.</p>';
    }
    const head = headers
      .map(function (h) {
        return "<th>" + escapeHtml(h) + "</th>";
      })
      .join("");
    const body = rows
      .map(function (row) {
        const cls = row.onClickId ? ' class="clickable" data-id="' + escapeHtml(row.onClickId) + '"' : "";
        return (
          "<tr" +
          cls +
          ">" +
          row.cells
            .map(function (c) {
              return "<td>" + c + "</td>";
            })
            .join("") +
          "</tr>"
        );
      })
      .join("");
    return "<table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>";
  }

  function bindRowClicks(container, handler) {
    container.querySelectorAll("tr[data-id]").forEach(function (row) {
      row.addEventListener("click", function () {
        handler(row.getAttribute("data-id"));
      });
    });
  }

  function kindOf(value) {
    if (value == null) return "";
    if (typeof value === "string") return value;
    return String(value);
  }

  async function refreshHealth() {
    const health = await api("/health");
    const pill = $("health-pill");
    pill.textContent = health.status;
    pill.className = "pill " + (health.status === "ok" ? "ok" : "warn");
    $("env-pill").textContent = health.environment;
    const stats = health.store || {};
    $("stats-row").innerHTML = Object.keys(stats)
      .map(function (key) {
        return (
          '<div class="stat"><b>' +
          escapeHtml(stats[key]) +
          "</b><span>" +
          escapeHtml(key.replace(/_/g, " ")) +
          "</span></div>"
        );
      })
      .join("");
  }

  async function runAudit(event) {
    event.preventDefault();
    const target = $("audit-target").value.trim();
    const turnover = $("audit-turnover").value;
    const sweep = $("audit-sweep").value;
    const body = { target: target };
    if (turnover) body.annual_turnover_eur = Number(turnover);
    if (sweep) body.sweep_size = Number(sweep);
    log("POST /acquisition/audit " + target);
    const report = await api("/acquisition/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    $("package-report-id").value = report.report_id;
    $("verify-id").value = report.report_id;
    renderAudit(report);
    await refreshHealth();
    await refreshProofs();
  }

  function renderAudit(report) {
    const seal = report.integrity || {};
    $("audit-result").innerHTML =
      "<p><strong>" +
      escapeHtml(report.report_id) +
      "</strong> · " +
      escapeHtml(report.target_host) +
      "</p><p>Findings " +
      escapeHtml((report.findings || []).length) +
      " · Weighted " +
      euro(report.expected_exposure_eur) +
      " · Statutory max " +
      euro(report.statutory_maximum_eur) +
      "</p><p class=\"mono\">merkle " +
      escapeHtml(seal.merkle_root) +
      "</p><p class=\"mono\">hmac " +
      escapeHtml(seal.signature) +
      "</p><p>" +
      escapeHtml(report.disclaimer) +
      "</p>";
  }

  async function refreshProofs() {
    const data = await api("/acquisition/reports?limit=50");
    const rows = (data.reports || []).map(function (r) {
      return {
        onClickId: r.report_id,
        cells: [
          '<span class="mono">' + escapeHtml(r.report_id) + "</span>",
          escapeHtml(r.target_host),
          String((r.findings || []).length),
          euro(r.expected_exposure_eur),
          euro(r.statutory_maximum_eur),
        ],
      };
    });
    $("proof-list").innerHTML = table(
      ["Report", "Host", "Findings", "Weighted", "Statutory max"],
      rows
    );
    bindRowClicks($("proof-list"), loadReport);
  }

  async function loadReport(reportId) {
    $("verify-id").value = reportId;
    $("package-report-id").value = reportId;
    const report = await api("/acquisition/reports/" + encodeURIComponent(reportId));
    const verify = await api("/acquisition/reports/" + encodeURIComponent(reportId) + "/verify");
    const findings = (report.findings || [])
      .map(function (f) {
        return (
          "<tr><td class=\"sev-" +
          escapeHtml(f.severity) +
          "\">" +
          escapeHtml(f.severity) +
          "</td><td>" +
          escapeHtml(f.citation) +
          "</td><td>" +
          escapeHtml(f.title) +
          "</td></tr>"
        );
      })
      .join("");
    const chain = ((report.integrity || {}).chain || [])
      .map(function (link) {
        return (
          '<div class="mono">' +
          escapeHtml(String(link.sequence)) +
          " " +
          escapeHtml(link.record_id) +
          " → " +
          escapeHtml(link.chain_digest) +
          "</div>"
        );
      })
      .join("");
    const checks = verify.checks || {};
    const checkHtml = Object.keys(checks)
      .map(function (key) {
        const ok = checks[key];
        return (
          '<div class="' +
          (ok ? "check-ok" : "check-bad") +
          '">' +
          (ok ? "PASS" : "FAIL") +
          " · " +
          escapeHtml(key) +
          "</div>"
        );
      })
      .join("");
    $("report-detail").innerHTML =
      "<p><strong>" +
      escapeHtml(report.report_id) +
      "</strong> verification " +
      (verify.valid ? '<span class="check-ok">VALID</span>' : '<span class="check-bad">INVALID</span>') +
      "</p>" +
      checkHtml +
      "<table><thead><tr><th>Sev</th><th>Citation</th><th>Finding</th></tr></thead><tbody>" +
      findings +
      '</tbody></table><div class="chain">' +
      chain +
      "</div>";
    $("verify-result").innerHTML =
      "<p>valid=" +
      String(verify.valid) +
      "</p><p class=\"mono\">" +
      escapeHtml(verify.merkle_root) +
      "</p>";
  }

  async function runVerify(event) {
    event.preventDefault();
    const id = $("verify-id").value.trim();
    log("GET /acquisition/reports/" + id + "/verify");
    await loadReport(id);
  }

  async function runPackage(event) {
    event.preventDefault();
    const id = $("package-report-id").value.trim();
    log("POST /acquisition/package/" + id);
    const pkg = await api("/acquisition/package/" + encodeURIComponent(id), { method: "POST" });
    rememberLicense(pkg.package_id, pkg.license_key);
    $("unlock-package-id").value = pkg.package_id;
    $("unlock-license").value = pkg.license_key || "";
    $("package-result").innerHTML =
      "<p><strong>" +
      escapeHtml(pkg.package_id) +
      "</strong></p><p>License (session only):</p><p class=\"mono\">" +
      escapeHtml(pkg.license_key || "") +
      "</p><pre>" +
      escapeHtml(pkg.executive_summary || "") +
      "</pre>";
    await refreshPackages();
    await refreshHealth();
  }

  async function refreshPackages() {
    const data = await api("/acquisition/packages?limit=50");
    const rows = (data.packages || []).map(function (p) {
      return {
        onClickId: p.package_id,
        cells: [
          '<span class="mono">' + escapeHtml(p.package_id) + "</span>",
          '<span class="mono">' + escapeHtml(p.report_id) + "</span>",
          escapeHtml(p.tenant_id),
          String((p.pull_request_ids || []).length),
          p.sealed_patch && p.sealed_patch.locked ? "locked" : "open",
        ],
      };
    });
    $("package-list").innerHTML = table(["Package", "Report", "Tenant", "PRs", "Seal"], rows);
    bindRowClicks($("package-list"), function (id) {
      $("unlock-package-id").value = id;
      const remembered = licenses()[id];
      if (remembered) $("unlock-license").value = remembered;
    });
  }

  async function runUnlock(event) {
    event.preventDefault();
    const packageId = $("unlock-package-id").value.trim();
    const licenseKey = $("unlock-license").value.trim();
    log("POST /acquisition/packages/" + packageId + "/unlock");
    const data = await api("/acquisition/packages/" + encodeURIComponent(packageId) + "/unlock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ license_key: licenseKey }),
    });
    const files = (data.files || [])
      .map(function (file) {
        return (
          "<h3 class=\"mono\">" +
          escapeHtml(file.path) +
          "</h3><pre>" +
          escapeHtml(file.content) +
          "</pre>"
        );
      })
      .join("");
    $("unlock-result").innerHTML =
      "<p>unlocked=" +
      String(data.unlocked) +
      " report=" +
      escapeHtml(data.report_id) +
      "</p>" +
      files;
  }

  async function runTick(event) {
    event.preventDefault();
    const size = Number($("tick-size").value || 8);
    log("POST /pipeline/tick?batch_size=" + size);
    const result = await api("/pipeline/tick?batch_size=" + encodeURIComponent(String(size)), {
      method: "POST",
    });
    $("tick-result").innerHTML =
      "<p>events " +
      escapeHtml((result.ingested_events || []).length) +
      " · violations " +
      escapeHtml((result.violations || []).length) +
      " · PRs " +
      escapeHtml((result.pull_requests || []).length) +
      "</p>";
    await refreshOps();
    await refreshHealth();
  }

  async function refreshOps() {
    const stats = await api("/pipeline/stats");
    $("index-snapshot").innerHTML = "<pre>" + escapeHtml(JSON.stringify(stats, null, 2)) + "</pre>";
    const events = await api("/telemetry/events?limit=40");
    $("events-table").innerHTML = table(
      ["Event", "Kind", "Tenant", "Score"],
      (events.events || []).map(function (e) {
        return {
          cells: [
            '<span class="mono">' + escapeHtml(e.event_id) + "</span>",
            escapeHtml(kindOf(e.kind)),
            escapeHtml(e.tenant_id),
            escapeHtml(String((e.risk && e.risk.composite_score) || "")),
          ],
        };
      })
    );
    const violations = await api("/evaluations/violations?limit=40");
    $("violations-table").innerHTML = table(
      ["Violation", "Citation", "Severity"],
      (violations.violations || []).map(function (v) {
        return {
          cells: [
            '<span class="mono">' + escapeHtml(v.violation_id) + "</span>",
            escapeHtml(v.citation),
            '<span class="sev-' + escapeHtml(v.severity) + '">' + escapeHtml(v.severity) + "</span>",
          ],
        };
      })
    );
    const prs = await api("/remediations/pull-requests?limit=40");
    $("prs-table").innerHTML = table(
      ["PR", "Title", "Status"],
      (prs.pull_requests || []).map(function (pr) {
        return {
          cells: [
            '<span class="mono">' + escapeHtml(pr.pr_id) + "</span>",
            escapeHtml(pr.title),
            escapeHtml(pr.status),
          ],
        };
      })
    );
  }

  document.querySelectorAll(".tab").forEach(function (tab) {
    tab.addEventListener("click", function () {
      document.querySelectorAll(".tab").forEach(function (t) {
        t.classList.toggle("on", t === tab);
      });
      document.querySelectorAll(".panel").forEach(function (panel) {
        panel.classList.toggle("on", panel.id === "panel-" + tab.getAttribute("data-tab"));
      });
    });
  });

  $("audit-form").addEventListener("submit", function (event) {
    runAudit(event).catch(function (err) {
      log(err.message);
      $("audit-result").textContent = err.message;
    });
  });
  $("verify-form").addEventListener("submit", function (event) {
    runVerify(event).catch(function (err) {
      log(err.message);
      $("verify-result").textContent = err.message;
    });
  });
  $("package-form").addEventListener("submit", function (event) {
    runPackage(event).catch(function (err) {
      log(err.message);
      $("package-result").textContent = err.message;
    });
  });
  $("unlock-form").addEventListener("submit", function (event) {
    runUnlock(event).catch(function (err) {
      log(err.message);
      $("unlock-result").textContent = err.message;
    });
  });
  $("tick-form").addEventListener("submit", function (event) {
    runTick(event).catch(function (err) {
      log(err.message);
      $("tick-result").textContent = err.message;
    });
  });
  $("refresh-proofs").addEventListener("click", function () {
    refreshProofs().catch(function (err) {
      log(err.message);
    });
  });
  $("refresh-packages").addEventListener("click", function () {
    refreshPackages().catch(function (err) {
      log(err.message);
    });
  });
  $("refresh-ops").addEventListener("click", function () {
    refreshOps().catch(function (err) {
      log(err.message);
    });
  });

  Promise.all([refreshHealth(), refreshProofs(), refreshPackages(), refreshOps()]).catch(function (err) {
    log(err.message);
  });
})();
