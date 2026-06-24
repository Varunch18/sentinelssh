/* SocketIO client — wires live server events to dashboard handlers. */
const Live = (() => {
  let socket;

  function connect(handlers) {
    socket = io({ transports: ['websocket', 'polling'], withCredentials: true });

    socket.on('connect', () => setLive(true));
    socket.on('disconnect', () => setLive(false));
    socket.on('connect_error', () => setLive(false));

    socket.on('new_attack', (data) => handlers.onAttack && handlers.onAttack(data));
    socket.on('stats_update', (data) => handlers.onStats && handlers.onStats(data));
    socket.on('incident_update', (data) => handlers.onIncident && handlers.onIncident(data));
  }

  function setLive(on) {
    const pill = document.getElementById('livePill');
    if (!pill) return;
    pill.classList.toggle('off', !on);
    pill.lastChild.textContent = on ? ' LIVE' : ' OFFLINE';
  }

  return { connect };
})();
