(function () {
  const btn = document.getElementById("check");
  const status = document.getElementById("status");

  async function check() {
    status.textContent = "";
    btn.disabled = true;
    try {
      const r = await fetch("/api/public/gate-check", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "same-origin",
        body: "{}",
      }).then(x => x.json());
      if (r && r.member) {
        location.href = "/main";
      } else {
        status.textContent = "not a member yet — taking you to subscribe";
        setTimeout(() => { location.href = "/subscribe"; }, 500);
      }
    } catch {
      status.textContent = "network error";
    } finally {
      btn.disabled = false;
    }
  }

  btn.addEventListener("click", check);
})();
