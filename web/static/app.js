"use strict";

const STRATEGY_COLORS = {
    serial: "#35c6d0",
    batch: "#e3a35a",
    sliding_window: "#9d8cff",
};
const STRATEGY_ORDER = ["serial", "batch", "sliding_window"];

/* ------------------------------------------------------------------ *
 * Live console panes
 * ------------------------------------------------------------------ */
const MAX_LINES = 200;
const panes = {};
document.querySelectorAll(".console").forEach((el) => {
    panes[el.dataset.key] = {
        root: el,
        log: el.querySelector("[data-log]"),
        countEl: el.querySelector("[data-count]"),
        count: 0,
    };
});

// rolling events/sec counter across all streams
let windowCount = 0;
const rateEl = document.getElementById("eventRate");
setInterval(() => {
    rateEl.textContent = windowCount.toString();
    windowCount = 0;
}, 1000);

function paneKey(ev) {
    const src = ev.source_type || "?";
    const attack = (ev.metadata && ev.metadata.attack_type) || "?";
    const key = `${src}:${attack}`;
    return panes[key] ? key : "__other__";
}

function formatLine(ev) {
    let ts = "--:--:--";
    if (ev.timestamp) {
        const d = new Date(ev.timestamp);
        if (!isNaN(d)) ts = d.toLocaleTimeString([], { hour12: false });
    }
    const dest = `${ev.dest_ip || "?"}:${ev.dest_port || "?"}`;
    const success = ev.metadata && ev.metadata.success === true;

    const line = document.createElement("div");
    line.className = "line enter " + (success ? "ok" : "fail");

    let detail;
    let statusText;
    if (ev.source_type === "http") {
        statusText = `status=${ev.exit_code}`;
        detail = (ev.raw_stdout || "").replace(/\s+/g, " ").trim().slice(0, 90);
    } else {
        statusText = success ? "CONNECTED" : `exit=${ev.exit_code}`;
        detail = (ev.raw_stderr || "").replace(/\s+/g, " ").trim().slice(0, 90);
    }

    line.innerHTML =
        `<span class="t">${ts}</span> ` +
        `<span class="meta">→ ${escapeHtml(dest)}</span> ` +
        `<span class="status">${escapeHtml(statusText)}</span>` +
        (detail ? ` <span class="meta">${escapeHtml(detail)}</span>` : "");
    return line;
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => (
        { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
    ));
}

function pushEvent(ev) {
    const pane = panes[paneKey(ev)];
    if (!pane) return;

    const emptyMsg = pane.log.querySelector(".log-empty");
    if (emptyMsg) emptyMsg.remove();

    const atBottom = pane.log.scrollHeight - pane.log.scrollTop - pane.log.clientHeight < 40;
    pane.log.appendChild(formatLine(ev));

    while (pane.log.childElementCount > MAX_LINES) {
        pane.log.removeChild(pane.log.firstElementChild);
    }
    if (atBottom) pane.log.scrollTop = pane.log.scrollHeight;

    pane.count += 1;
    pane.countEl.textContent = pane.count;
    pane.root.setAttribute("data-active", "");
    windowCount += 1;
}

/* ------------------------------------------------------------------ *
 * Benchmark + charts
 * ------------------------------------------------------------------ */
let benchmarkResults = [];
let charts = {};

const chartFont = { family: "'IBM Plex Mono', monospace", size: 11 };
Chart.defaults.color = "#7f95ab";
Chart.defaults.font.family = "'IBM Plex Sans', sans-serif";

function baseOptions(yLabel) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: "#0e151d",
                borderColor: "#26364a",
                borderWidth: 1,
                titleFont: chartFont,
                bodyFont: chartFont,
                padding: 10,
            },
        },
        scales: {
            x: {
                title: { display: true, text: "event volume", font: chartFont },
                grid: { color: "#1f2d3d" },
                ticks: { font: chartFont },
            },
            y: {
                title: { display: true, text: yLabel, font: chartFont },
                grid: { color: "#1f2d3d" },
                ticks: { font: chartFont },
                beginAtZero: true,
            },
        },
    };
}

function makeLineChart(id, yLabel) {
    return new Chart(document.getElementById(id), {
        type: "line",
        data: { labels: [], datasets: [] },
        options: baseOptions(yLabel),
    });
}

function makeBarChart(id, yLabel) {
    return new Chart(document.getElementById(id), {
        type: "bar",
        data: { labels: [], datasets: [] },
        options: baseOptions(yLabel),
    });
}

function initCharts() {
    charts.throughput = makeLineChart("throughputChart", "events / sec");
    charts.latency = makeLineChart("latencyChart", "seconds");
    charts.alerts = makeBarChart("alertsChart", "alerts");
}

function volumesSorted() {
    return [...new Set(benchmarkResults.map((r) => r.volume))].sort((a, b) => a - b);
}

function datasetFor(strategy, field, type) {
    const byVolume = {};
    benchmarkResults
        .filter((r) => r.strategy === strategy)
        .forEach((r) => { byVolume[r.volume] = r[field]; });
    const color = STRATEGY_COLORS[strategy];
    const data = volumesSorted().map((v) => (v in byVolume ? byVolume[v] : null));
    if (type === "bar") {
        return { label: strategy, data, backgroundColor: color, borderRadius: 3, borderWidth: 0 };
    }
    return {
        label: strategy,
        data,
        borderColor: color,
        backgroundColor: color,
        borderWidth: 2,
        tension: 0.25,
        pointRadius: 3,
        pointHoverRadius: 5,
        spanGaps: true,
    };
}

function renderCharts() {
    const labels = volumesSorted().map((v) => v.toLocaleString());
    const present = STRATEGY_ORDER.filter((s) => benchmarkResults.some((r) => r.strategy === s));

    charts.throughput.data.labels = labels;
    charts.throughput.data.datasets = present.map((s) => datasetFor(s, "events_per_second", "line"));
    charts.throughput.update();

    charts.latency.data.labels = labels;
    charts.latency.data.datasets = present.map((s) => datasetFor(s, "elapsed_seconds", "line"));
    charts.latency.update();

    charts.alerts.data.labels = labels;
    charts.alerts.data.datasets = present.map((s) => datasetFor(s, "alert_count", "bar"));
    charts.alerts.update();
}

function renderTable() {
    const body = document.getElementById("resultsBody");
    if (!benchmarkResults.length) {
        body.innerHTML = '<tr class="empty-row"><td colspan="5">No runs yet — start a benchmark to populate.</td></tr>';
        return;
    }
    const rows = benchmarkResults.map((r) => {
        const tp = r.events_per_second ? Math.round(r.events_per_second).toLocaleString() : "—";
        return `<tr>
      <td data-strat="${r.strategy}">${r.strategy}</td>
      <td>${r.volume.toLocaleString()}</td>
      <td>${r.elapsed_seconds.toFixed(4)}</td>
      <td>${tp}</td>
      <td>${r.alert_count.toLocaleString()}</td>
    </tr>`;
    });
    body.innerHTML = rows.join("");
}

/* benchmark control */
const runBtn = document.getElementById("runBenchmark");
const runStatus = document.getElementById("benchmarkStatus");

runBtn.addEventListener("click", async () => {
    runBtn.disabled = true;
    setRunStatus("starting…", "running");
    try {
        const resp = await fetch("/benchmark/start", { method: "POST" });
        const data = await resp.json();
        if (!data.started) {
            setRunStatus("already running…", "running");
        }
    } catch (err) {
        setRunStatus("request failed", "error");
        runBtn.disabled = false;
    }
});

function setRunStatus(text, cls) {
    runStatus.textContent = text;
    runStatus.className = "run-status" + (cls ? " " + cls : "");
}

function handleBenchmark(msg) {
    if (msg.event === "start") {
        benchmarkResults = [];
        renderTable();
        renderCharts();
        runBtn.disabled = true;
        setRunStatus("running…", "running");
    } else if (msg.event === "result") {
        benchmarkResults.push(msg.result);
        renderTable();
        renderCharts();
        const done = benchmarkResults.length;
        setRunStatus(`running… (${done} measured)`, "running");
    } else if (msg.event === "done") {
        runBtn.disabled = false;
        setRunStatus("complete", "done");
    } else if (msg.event === "error") {
        runBtn.disabled = false;
        setRunStatus("error: " + (msg.message || "unknown"), "error");
    }
}

/* ------------------------------------------------------------------ *
 * SSE connection
 * ------------------------------------------------------------------ */
const linkEl = document.getElementById("link");
const linkText = document.getElementById("linkText");

function setLink(up, text) {
    linkEl.className = "link " + (up ? "link-up" : "link-down");
    linkText.textContent = text;
}

function connect() {
    const es = new EventSource("/stream");

    es.onopen = () => setLink(true, "live");
    es.onerror = () => setLink(false, "reconnecting");

    es.onmessage = (e) => {
        let msg;
        try { msg = JSON.parse(e.data); } catch (_) { return; }

        if (msg.channel === "event") {
            pushEvent(msg.data);
        } else if (msg.channel === "benchmark") {
            handleBenchmark(msg.data);
        } else if (msg.channel === "system") {
            if (msg.data && msg.data.kafka) {
                const k = msg.data.kafka;
                setLink(k === "connected", k === "connected" ? "live" : "kafka: " + k);
            }
        }
    };
}

function seedEmpty() {
    Object.values(panes).forEach((p) => {
        p.log.innerHTML = '<div class="log-empty">waiting for traffic…</div>';
    });
}

document.addEventListener("DOMContentLoaded", () => {
    seedEmpty();
    initCharts();
    connect();
});