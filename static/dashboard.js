let techniqueChart = null;
let tacticChart = null;
let riskChart = null;

async function loadDashboard() {

    try {

        const response = await fetch("/api/live");

        const data = await response.json();

        updateSummary(data.summary);

        updateHeatmap(data.mitre);

        updateTimeline(data.timeline);

        updateBeacon(data.beacon);

        updateHardening(data.mitre);

        drawTechniqueChart(data.techniques);

        drawTacticChart(data.tactics);

        drawRiskChart(data.risk_scores);

        document.getElementById("loading").style.display = "none";

        document.getElementById("app").style.display = "block";

        document.getElementById("lastRefresh").innerHTML =
            "Updated " + new Date().toLocaleTimeString();

    }

    catch(err){

        console.error(err);

    }

}

function updateSummary(summary){

    document.getElementById("riskScore").innerHTML =
        summary.overall_risk_score;

    document.getElementById("riskLabel").innerHTML =
        summary.overall_risk_label;

    document.getElementById("tasksSent").innerHTML =
        summary.total_tasks;

    document.getElementById("resultsReceived").innerHTML =
        summary.total_results;

    document.getElementById("checkins").innerHTML =
        summary.total_checkins;

    document.getElementById("anomalies").innerHTML =
        summary.anomalies;

    document.getElementById("yara").innerHTML =
        summary.yara_hits_total;

}

function updateHeatmap(items){

    const div = document.getElementById("heatmap");

    div.innerHTML = "";

    items.forEach(item=>{

        const card = document.createElement("div");

        card.className = "heat-card";

        card.innerHTML = `

            <h4>${item.tid}</h4>

            <strong>${item.name}</strong>

            <small>${item.tactic}</small>

            <div class="count">${item.count}</div>

        `;

        card.style.borderLeft =
            "6px solid " + heatColor(item.heat);

        div.appendChild(card);

    });

}

function heatColor(level){

    switch(level){

        case 5:return "#ff1744";
        case 4:return "#ff5722";
        case 3:return "#ff9800";
        case 2:return "#ffc107";
        case 1:return "#8bc34a";

        default:return "#444";

    }

}

function updateTimeline(items){

    const body =
        document.querySelector("#timelineTable tbody");

    body.innerHTML = "";

    items.reverse().forEach(item=>{

        const row=document.createElement("tr");

        row.innerHTML=`

        <td>${item.task_time}</td>

        <td>${item.task}</td>

        <td>${item.technique}</td>

        <td>${item.duration_ms} ms</td>

        <td>${item.anomaly ? "⚠️":"-"}</td>

        `;

        body.appendChild(row);

    });

}

function updateBeacon(beacon){

    if(!beacon) return;

    document.getElementById("meanInterval").innerHTML =
        beacon.mean_interval_s + " s";

    document.getElementById("jitter").innerHTML =
        beacon.jitter_pct + "%";

    document.getElementById("stdev").innerHTML =
        beacon.stdev_s + " s";

    document.getElementById("minInterval").innerHTML =
        beacon.min_s + " s";

    document.getElementById("maxInterval").innerHTML =
        beacon.max_s + " s";

}

function updateHardening(items){

    const div =
        document.getElementById("hardeningList");

    div.innerHTML="";

    items.filter(x=>x.count>0).forEach(item=>{

        const card=document.createElement("div");

        card.className="recommendation";

        card.innerHTML=`

        <h4>${item.tid}</h4>

        <strong>${item.name}</strong>

        <p>${item.hardening}</p>

        `;

        div.appendChild(card);

    });

}