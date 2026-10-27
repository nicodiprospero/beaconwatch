// -----------------------------------------------------
// Charts
// -----------------------------------------------------

function drawTechniqueChart(techniques){

    const labels = Object.keys(techniques);
    const values = Object.values(techniques);

    const ctx = document
        .getElementById("techniqueChart")
        .getContext("2d");

    if(techniqueChart)
        techniqueChart.destroy();

    techniqueChart = new Chart(ctx,{

        type:"bar",

        data:{

            labels:labels,

            datasets:[{

                label:"Executions",

                data:values,

                backgroundColor:"#4caf50",

                borderRadius:5

            }]

        },

        options:{

            responsive:true,

            maintainAspectRatio:false,

            plugins:{

                legend:{display:false}

            },

            scales:{

                y:{
                    beginAtZero:true
                }

            }

        }

    });

}

function drawTacticChart(tactics){

    const labels = Object.keys(tactics);

    const values = Object.values(tactics);

    const ctx=document
        .getElementById("tacticChart")
        .getContext("2d");

    if(tacticChart)
        tacticChart.destroy();

    tacticChart=new Chart(ctx,{

        type:"doughnut",

        data:{

            labels:labels,

            datasets:[{

                data:values,

                backgroundColor:[

                    "#00BCD4",
                    "#FF9800",
                    "#F44336",
                    "#4CAF50",
                    "#9C27B0",
                    "#607D8B"

                ]

            }]

        },

        options:{

            responsive:true,

            maintainAspectRatio:false

        }

    });

}

function drawRiskChart(risk){

    const labels = Object.keys(risk);

    const values = Object.values(risk);

    const ctx=document
        .getElementById("riskChart")
        .getContext("2d");

    if(riskChart)
        riskChart.destroy();

    riskChart=new Chart(ctx,{

        type:"polarArea",

        data:{

            labels:labels,

            datasets:[{

                data:values,

                backgroundColor:[

                    "#43A047",
                    "#FDD835",
                    "#FB8C00",
                    "#E53935",
                    "#8E24AA",
                    "#1E88E5"

                ]

            }]

        },

        options:{

            responsive:true,

            maintainAspectRatio:false

        }

    });

}

// -----------------------------------------------------
// Live Events
// -----------------------------------------------------

async function loadEvents(){

    try{

        const res = await fetch("/api/events");

        const events = await res.json();

        const container =
            document.getElementById("events");

        container.innerHTML="";

        events.slice(0,30).forEach(event=>{

            const div=document.createElement("div");

            div.className="event";

            let yara="";

            if(event.yara_hits.length){

                yara=
                    "<span class='tag yara'>YARA</span>";

            }

            let anomaly="";

            if(event.anomaly){

                anomaly=
                    "<span class='tag danger'>ANOMALY</span>";

            }

            div.innerHTML=`

                <div class="event-time">

                    ${event.time}

                </div>

                <div class="event-type">

                    ${event.type}

                </div>

                <div class="event-command">

                    ${event.task || ""}

                </div>

                <div>

                    ${yara}

                    ${anomaly}

                </div>

            `;

            container.appendChild(div);

        });

    }

    catch(err){

        console.log(err);

    }

}

// -----------------------------------------------------
// Refresh Loop
// -----------------------------------------------------

async function refresh(){

    await loadDashboard();

    await loadEvents();

}

// -----------------------------------------------------
// Init
// -----------------------------------------------------

window.onload = async function(){

    await refresh();

    setInterval(refresh,2000);

};

// -----------------------------------------------------
// Utility
// -----------------------------------------------------

function riskColor(score){

    if(score<20) return "#4CAF50";

    if(score<50) return "#FFC107";

    if(score<80) return "#FF9800";

    return "#F44336";

}

function formatDate(date){

    return new Date(date)
        .toLocaleString();

}

function clearChildren(node){

    while(node.firstChild)

        node.removeChild(node.firstChild);

}