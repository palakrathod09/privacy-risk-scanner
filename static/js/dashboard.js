(function () {
  if (typeof overall === "undefined" || typeof Chart === "undefined") return;

  const colors = {
    critical: "#ff4d6d",
    high: "#ff9f40",
    medium: "#ffd166",
    low: "#4ade80",
    grid: "#2a3450",
    text: "#93a0bd",
  };

  // ---- Gauge (half-doughnut) ----------------------------------------
  const gaugeCtx = document.getElementById("gaugeChart");
  if (gaugeCtx) {
    const score = overall.score;
    let scoreColor = colors.low;
    if (score >= 75) scoreColor = colors.critical;
    else if (score >= 50) scoreColor = colors.high;
    else if (score >= 25) scoreColor = colors.medium;

    new Chart(gaugeCtx, {
      type: "doughnut",
      data: {
        datasets: [{
          data: [score, 100 - score],
          backgroundColor: [scoreColor, "#232c44"],
          borderWidth: 0,
        }],
      },
      options: {
        rotation: -90,
        circumference: 180,
        cutout: "75%",
        responsive: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
      },
    });
  }

  // ---- Severity bar chart --------------------------------------------
  const sevCtx = document.getElementById("severityChart");
  if (sevCtx) {
    const sev = overall.by_severity;
    new Chart(sevCtx, {
      type: "bar",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data: [sev.critical, sev.high, sev.medium, sev.low],
          backgroundColor: [colors.critical, colors.high, colors.medium, colors.low],
          borderRadius: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: colors.text }, grid: { display: false } },
          y: { ticks: { color: colors.text, precision: 0 }, grid: { color: colors.grid } },
        },
      },
    });
  }

  // ---- Category doughnut ----------------------------------------------
  const catCtx = document.getElementById("categoryChart");
  if (catCtx) {
    const entries = Object.entries(overall.by_category);
    const palette = ["#5b8cff", "#7c5bff", "#ff4d6d", "#ff9f40", "#ffd166", "#4ade80", "#38bdf8", "#f472b6", "#a78bfa", "#facc15"];
    new Chart(catCtx, {
      type: "doughnut",
      data: {
        labels: entries.map((e) => e[0]),
        datasets: [{
          data: entries.map((e) => e[1]),
          backgroundColor: entries.map((_, i) => palette[i % palette.length]),
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "right",
            labels: { color: colors.text, boxWidth: 12, font: { size: 11 } },
          },
        },
      },
    });
  }
})();
