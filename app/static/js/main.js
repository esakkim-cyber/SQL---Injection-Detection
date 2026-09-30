async function postJson(url, data) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function text(value) {
  return value === null || value === undefined ? "" : String(value);
}

function byId(id) { return document.getElementById(id); }

const analyzeBtn = byId("analyzeBtn");
if (analyzeBtn) {
  analyzeBtn.addEventListener("click", async () => {
    const payload = byId("payloadInput").value;
    const data = await postJson("/api/analyze", { payload });
    byId("analysisOutput").classList.remove("hidden");
    byId("riskFill").style.width = `${data.risk_score}%`;
    byId("riskText").textContent = `${data.severity} risk (${data.risk_score}/100)`;
    byId("recommendation").textContent = data.recommendation;
    byId("regexStatus").textContent = data.regex_detected ? "Detected" : "Clean";
    byId("mlStatus").textContent = `${data.ml_probability}`;
    byId("anomalyStatus").textContent = data.anomaly_detected ? "Detected" : "Normal";

    const matchesSection = byId("matchesSection");
    const matchesBody = byId("matchesTable").querySelector("tbody");
    matchesBody.innerHTML = "";
    if (data.regex_matches.length) {
      matchesSection.classList.remove("hidden");
      data.regex_matches.forEach(match => {
        const row = document.createElement("tr");
        row.innerHTML = `<td>${text(match.pattern_name)}</td><td>${text(match.description)}</td><td><code>${text(match.matched_text)}</code></td><td>${match.weight}</td>`;
        matchesBody.appendChild(row);
      });
    } else {
      matchesSection.classList.add("hidden");
    }

    const featureGrid = byId("featureGrid");
    featureGrid.innerHTML = "";
    Object.entries(data.features).slice(0, 20).forEach(([key, value]) => {
      const cell = document.createElement("div");
      cell.innerHTML = `<span>${key}</span><strong>${Number(value).toFixed(3)}</strong>`;
      featureGrid.appendChild(cell);
    });
    byId("featuresSection").classList.remove("hidden");
  });
}

const fillSample = byId("fillSample");
if (fillSample) {
  fillSample.addEventListener("click", () => {
    byId("payloadInput").value = "' OR '1'='1' -- ";
  });
}

const clearBtn = byId("clearBtn");
if (clearBtn) {
  clearBtn.addEventListener("click", () => {
    byId("payloadInput").value = "";
    byId("analysisOutput").classList.add("hidden");
    byId("matchesSection").classList.add("hidden");
    byId("featuresSection").classList.add("hidden");
  });
}
