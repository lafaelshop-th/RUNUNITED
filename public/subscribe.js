(function () {
  const form = document.getElementById("form");
  const msg = document.getElementById("msg");
  const q = document.getElementById("q");
  const hp = document.getElementById("hp");

  let challenge = null;

  async function loadChallenge() {
    try {
      const r = await fetch("/api/public/challenge", { method: "POST" }).then(x => x.json());
      challenge = r;
      q.textContent = r.question;
    } catch {
      q.textContent = "?";
    }
  }

  const preset = new URLSearchParams(location.search).get("email");
  if (preset) document.getElementById("email").value = preset;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    msg.textContent = "";

    // honeypot: filled = bot. silently do nothing.
    if (hp.value.trim().length > 0) return;

    const name = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim().toLowerCase();
    const password = document.getElementById("password").value;
    const answer = document.getElementById("answer").value.trim();

    if (!name) { msg.textContent = "first name required"; return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { msg.textContent = "invalid email"; return; }
    if (password.length < 8) { msg.textContent = "password must be 8+ characters"; return; }
    if (!challenge) { msg.textContent = "reload the page"; return; }
    if (!answer) { msg.textContent = "answer the human check"; return; }

    try {
      const r = await fetch("/api/public/subscribe", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({
          name, email, password,
          challenge: challenge.id, answer,
          _hp: "",
        }),
      }).then(x => x.json());

      if (r && r.ok) {
        location.href = "/main";
        return;
      }
      msg.textContent = (r && r.error) || "no";
      loadChallenge();
      document.getElementById("answer").value = "";
    } catch {
      msg.textContent = "network error";
    }
  });

  loadChallenge();
})();
