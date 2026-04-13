let gaugeChart = null;
let barChart = null;
let pieChart = null;

function showLoading() {
  document.getElementById("loadingOverlay").classList.remove("d-none");
  document.getElementById("scanBtn").disabled = true;
}

function hideLoading() {
  document.getElementById("loadingOverlay").classList.add("d-none");
  document.getElementById("scanBtn").disabled = false;
}

function getScoreLabel(score) {
  if (score >= 85) return "SECURE";
  if (score >= 60) return "MEDIUM";
  return "HIGH";
}

function buildGauge(score) {
  const ctx = document.getElementById("gaugeChart");

  if (gaugeChart) {
    gaugeChart.destroy();
  }

  gaugeChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      datasets: [
        {
          data: [20, 20, 20, 20, 20],
          backgroundColor: ["#1f95d0", "#67bf3a", "#f2c52b", "#ff9728", "#e53935"],
          borderWidth: 0,
          circumference: 180,
          rotation: 270,
          cutout: "68%"
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: {
        animateRotate: true,
        duration: 900
      },
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false }
      }
    }
  });
}

function buildBarChart(breakdown) {
  const ctx = document.getElementById("barChart");

  if (barChart) {
    barChart.destroy();
  }

  barChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: Object.keys(breakdown),
      datasets: [
        {
          label: "Score",
          data: Object.values(breakdown),
          backgroundColor: [
            "#5aa6f5",
            "#1f73ea",
            "#24b5a9",
            "#f25c3a",
            "#f2a530",
            "#a7dbc4",
            "#9bcaf5"
          ],
          borderRadius: 8,
          maxBarThickness: 48
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: "#e9edf3" },
          ticks: { stepSize: 1 }
        },
        x: {
          grid: { display: false },
          ticks: {
            color: "#4b5a74",
            font: { weight: 600 }
          }
        }
      }
    }
  });
}

function buildRiskDistribution(score) {
  const ctx = document.getElementById("pieChart");

  if (pieChart) {
    pieChart.destroy();
  }

  let low = 0;
  let medium = 0;
  let high = 0;

  if (score >= 85) low = 1;
  else if (score >= 60) medium = 1;
  else high = 1;

  pieChart = new Chart(ctx, {
    type: "pie",
    data: {
      labels: ["Low", "Medium", "High"],
      datasets: [
        {
          data: [low, medium, high],
          backgroundColor: ["#f2c52b", "#ff7a2f", "#e53935"],
          borderColor: "#ffffff",
          borderWidth: 3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "top",
          labels: {
            color: "#4b5a74",
            font: { weight: 600 }
          }
        }
      }
    }
  });
}

function updateRiskUI(risk) {
  const riskBanner = document.getElementById("riskBanner");
  const riskText = document.getElementById("riskText");

  riskText.innerText = risk;
  riskBanner.classList.remove("risk-secure", "risk-medium", "risk-high");

  if (risk === "SECURE") {
    riskBanner.classList.add("risk-secure");
  } else if (risk === "MEDIUM") {
    riskBanner.classList.add("risk-medium");
  } else {
    riskBanner.classList.add("risk-high");
  }
}

function updateHeaders(headers) {
  const container = document.getElementById("headersList");
  container.innerHTML = "";

  Object.entries(headers).forEach(([key, value]) => {
    if (key === "error") {
      const row = document.createElement("div");
      row.className = "header-item";
      row.innerHTML = `
        <div class="header-item-left">
          <span>${value}</span>
        </div>
      `;
      container.appendChild(row);
      return;
    }

    const ok = value === "Present" || value === "Protected (CDN)";
    const partial = value === "Partial";

    const row = document.createElement("div");
    row.className = "header-item";

    row.innerHTML = `
      <div class="header-item-left">
        <i class="fa-solid fa-shield-halved header-check"></i>
        <span>${key}</span>
      </div>
      <div>
        ${
          ok
            ? '<i class="fa-solid fa-check header-check"></i>'
            : partial
            ? '<span style="color:#f0a53c;font-weight:700;">Partial</span>'
            : '<i class="fa-solid fa-xmark header-cross"></i>'
        }
      </div>
    `;

    container.appendChild(row);
  });
}

function updatePorts(ports) {
  const tbody = document.getElementById("portTable");
  tbody.innerHTML = "";

  ports.forEach((portObj) => {
    const tr = document.createElement("tr");
    const statusClass = portObj.status === "Open" ? "status-open" : "status-closed";
    const riskClass = portObj.risk === "High" ? "risk-high-text" : "risk-safe";

    tr.innerHTML = `
      <td>${portObj.port}</td>
      <td><span class="status-pill ${statusClass}">${portObj.status}</span></td>
      <td><span class="${riskClass}">${portObj.risk}</span></td>
    `;

    tbody.appendChild(tr);
  });
}

function resetUIOnError() {
  document.getElementById("scoreNumber").innerText = "0";
  document.getElementById("scoreLabel").innerText = "ERROR";
  document.getElementById("riskText").innerText = "ERROR";
  document.getElementById("sslStatusBadge").innerText = "Not Available";
  document.getElementById("sslIssuer").innerText = "-";
  document.getElementById("sslTls").innerText = "-";
  document.getElementById("sslExpires").innerText = "-";
  document.getElementById("portTable").innerHTML = "";
  document.getElementById("headersList").innerHTML = "";
  updateRiskUI("HIGH");
  buildGauge(0);
  buildBarChart({});
  buildRiskDistribution(0);
}

async function startScan() {
  const domain = document.getElementById("domain").value.trim();

  if (!domain) {
    alert("Please enter a domain");
    return;
  }

  try {
    showLoading();

    const response = await fetch("/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ domain })
    });

    const data = await response.json();

    if (!response.ok || data.error) {
      resetUIOnError();
      alert(data.error || "Scan failed");
      return;
    }

    document.getElementById("scoreNumber").innerText = Math.round(data.score || 0);
    document.getElementById("scoreLabel").innerText = getScoreLabel(data.score || 0);

    updateRiskUI(data.risk || getScoreLabel(data.score || 0));

    document.getElementById("sslStatusBadge").innerText = data.ssl?.status || "Not Available";
    document.getElementById("sslIssuer").innerText = data.ssl?.issuer || "-";
    document.getElementById("sslTls").innerText = data.ssl?.tls || "-";
    document.getElementById("sslExpires").innerText = data.ssl?.expires || "-";

    updatePorts(data.ports || []);
    updateHeaders(data.headers || {});

    buildGauge(data.score || 0);
    buildBarChart(data.breakdown || {});
    buildRiskDistribution(data.score || 0);

  } catch (error) {
    console.error(error);
    resetUIOnError();
    alert("Something went wrong while scanning.");
  } finally {
    hideLoading();
  }
}