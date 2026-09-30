const runLabBtn = document.getElementById("runLabBtn");
const labResults = document.getElementById("labResults");
const labTable = document.getElementById("labTable");
const labStatus = document.getElementById("labStatus");

function statusBadge(success, blocked) {
  if (blocked) return `<span class="severity high">Blocked</span>`;
  if (success) return `<span class="severity low">Success</span>`;
  return `<span class="severity medium">Failed</span>`;
}

if (runLabBtn) {
  runLabBtn.addEventListener("click", async () => {
    runLabBtn.disabled = true;
    runLabBtn.textContent = "Running...";
    const results = await postJson("/api/attack-simulation", {});
    const body = labTable.querySelector("tbody");
    body.innerHTML = "";
    results.forEach(item => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td><strong>${item.name}</strong><br><code>${item.payload}</code></td>
        <td><span class="severity ${item.detection.severity.toLowerCase()}">${item.detection.risk_score} ${item.detection.severity}</span></td>
        <td>${statusBadge(item.vulnerable.success, item.vulnerable.blocked)}<br><small>${item.vulnerable.message}</small></td>
        <td>${statusBadge(item.secure.success, item.secure.blocked)}<br><small>${item.secure.message}</small></td>
        <td>${statusBadge(item.parameterized_only.success, item.parameterized_only.blocked)}<br><small>${item.parameterized_only.message}</small></td>
      `;
      body.appendChild(row);
    });
    labResults.classList.remove("hidden");
    labStatus.textContent = `${results.length} use cases complete`;
    runLabBtn.disabled = false;
    runLabBtn.textContent = "Run Full Attack Lab Again";
  });
}
