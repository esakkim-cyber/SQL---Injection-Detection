function makeFallbackBars(container, values) {
  container.innerHTML = "";
  const max = Math.max(1, ...Object.values(values));
  Object.entries(values).forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "fallback-bar";
    row.innerHTML = `<span>${label}</span><div style="width:${(value / max) * 100}%"></div><strong>${value}</strong>`;
    container.appendChild(row);
  });
  container.style.display = "grid";
}

function drawCharts() {
  const stats = window.DASHBOARD_STATS || {};
  const severity = stats.severity_counts || {};
  const methods = stats.method_counts || {};

  if (window.Chart) {
    const sevCanvas = document.getElementById("severityChart");
    const methodCanvas = document.getElementById("methodChart");
    if (sevCanvas) {
      new Chart(sevCanvas, {
        type: "doughnut",
        data: { labels: Object.keys(severity), datasets: [{ data: Object.values(severity) }] },
        options: { plugins: { legend: { labels: { color: "#e9eefc" } } } }
      });
    }
    if (methodCanvas) {
      new Chart(methodCanvas, {
        type: "bar",
        data: { labels: Object.keys(methods), datasets: [{ label: "Events", data: Object.values(methods) }] },
        options: {
          scales: {
            x: { ticks: { color: "#e9eefc" }, grid: { color: "rgba(255,255,255,.08)" } },
            y: { ticks: { color: "#e9eefc" }, grid: { color: "rgba(255,255,255,.08)" } }
          },
          plugins: { legend: { labels: { color: "#e9eefc" } } }
        }
      });
    }
  } else {
    document.querySelectorAll("canvas").forEach(c => c.style.display = "none");
    makeFallbackBars(document.querySelector('[data-kind="severity"]'), severity);
    makeFallbackBars(document.querySelector('[data-kind="methods"]'), methods);
  }
}

drawCharts();

const seedEventsBtn = document.getElementById("seedEventsBtn");
if (seedEventsBtn) {
  seedEventsBtn.addEventListener("click", async () => {
    seedEventsBtn.disabled = true;
    seedEventsBtn.textContent = "Creating...";
    await postJson("/api/seed-demo-events", {});
    window.location.reload();
  });
}
