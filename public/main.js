(function () {
  const root = document.getElementById("root");
  const who = document.getElementById("who");

  fetch("/api/public/me", { credentials: "same-origin" })
    .then(r => r.json())
    .then(me => {
      if (!me || !me.member) {
        location.href = "/subscribe";
        return;
      }
      who.textContent = me.name || "friend";
      root.hidden = false;
    })
    .catch(() => { location.href = "/subscribe"; });
})();
