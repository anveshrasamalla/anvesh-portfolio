/**
 * Handles SFMC form submission with reCAPTCHA v3 + JSON feedback
 */
(function () {
  const form = document.getElementById("sfmcForm");
  const statusEl = document.getElementById("sfmcStatus");
  if (!form) return;

  const servletPath = document
    .querySelector("[data-component='sfmc-form']")
    .getAttribute("data-servlet");

  async function handleSubmit(e) {
    e.preventDefault();
    statusEl.textContent = "Submitting…";

    // Fetch reCAPTCHA token (v3)
    let token = "";
    if (typeof grecaptcha !== "undefined") {
      try {
        token = await grecaptcha.execute(
          form.querySelector(".g-recaptcha").dataset.sitekey,
          { action: "submit" }
        );
        const hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "g-recaptcha-response";
        hidden.value = token;
        form.appendChild(hidden);
      } catch (err) {
        console.warn("⚠️ reCAPTCHA failed", err);
      }
    }

    const data = new URLSearchParams(new FormData(form));

    try {
      const res = await fetch(servletPath, {
        method: "POST",
        headers: { Accept: "application/json" },
        body: data,
      });

      const json = await res.json();
      console.debug("SFMC Response:", json);

      if (json.error) {
        statusEl.className = "sfmc-status error";
        statusEl.textContent = `⚠️ ${json.message}`;
      } else {
        statusEl.className = "sfmc-status success";
        statusEl.textContent = `✅ ${json.message}`;
        form.reset();
      }
    } catch (err) {
      console.error("❌ Submission failed:", err);
      statusEl.className = "sfmc-status error";
      statusEl.textContent = "Submission failed. Try again later.";
    }
  }

  form.addEventListener("submit", handleSubmit);
})();
