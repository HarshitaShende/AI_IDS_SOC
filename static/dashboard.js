let live = false;
let packetCount = 0;
let streamTimer = null;

/* IDs from your HTML */
const terminal = document.getElementById("terminal");
const pkt = document.getElementById("pkt");
const status = document.getElementById("status");
const radar = document.getElementById("radar");
const normal = document.getElementById("normal");
const dos = document.getElementById("dos");
const probe = document.getElementById("probe");
const other = document.getElementById("other");
const alarm = document.getElementById("alertSound");

const fakePackets = [
    "TLS packet verified",
    "ACK handshake complete",
    "UDP stream active",
    "ICMP ping",
    "Secure session validated",
    "HTTP payload received",
    "Packet checksum OK"
];

/* START LIVE */
function startLive(){
    if(live) return;
    live = true;
    status.innerText = "Status: Monitoring...";
    radar.classList.remove("pause");

    streamTimer = setInterval(streamTraffic, 800);
}

/* STOP LIVE */
function stopLive(){
    live = false;
    status.innerText = "Status: Stopped";
    radar.classList.add("pause");
    clearInterval(streamTimer);
}

/* STREAM ENGINE */
function streamTraffic(){
    packetCount++;
    pkt.innerText = packetCount;

    const msg = fakePackets[Math.floor(Math.random()*fakePackets.length)];
    terminal.innerHTML += msg + "<br>";
    terminal.scrollTop = terminal.scrollHeight;

    /* baseline normal traffic counter */
    normal.innerText = parseInt(normal.innerText) + 1;
}

/* ATTACK INJECTION */
function injectAttack(){
    if(!live) startLive();

    terminal.innerHTML += "<span style='color:red'>!!! DoS ATTACK DETECTED !!!</span><br>";
    terminal.scrollTop = terminal.scrollHeight;

    dos.innerText = parseInt(dos.innerText) + 1;

    alarm.currentTime = 0;
    alarm.play();
}
