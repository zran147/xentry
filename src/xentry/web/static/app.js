const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    "X-Xentry-CSRF": csrf,
    ...(options.headers || {}),
  };
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || data.error?.message || response.statusText);
  }
  return data;
}

function setMessage(text, isError = false) {
  const element = document.getElementById("message");
  if (!element) return;
  element.textContent = text;
  element.classList.toggle("error", isError);
}

function wireHelp() {
  const button = document.getElementById("help-button");
  const dialog = document.getElementById("help-dialog");
  const close = document.getElementById("help-close");
  if (!button || !dialog || !close) return;
  button.addEventListener("click", () => dialog.showModal());
  close.addEventListener("click", () => dialog.close());
}

function wireSubmitPage() {
  const form = document.getElementById("submit-form");
  if (!form) return;
  const cve = document.getElementById("cve-url");
  const poc = document.getElementById("poc-url");
  const checkButton = document.getElementById("check-button");
  const submitButton = document.getElementById("submit-button");
  const preflightButton = document.getElementById("preflight-button");
  const plan = document.getElementById("plan");
  let checkId = "";

  checkButton.addEventListener("click", async () => {
    setMessage("Checking links...");
    plan.hidden = true;
    submitButton.disabled = true;
    try {
      const result = await api("/api/links/check", {
        method: "POST",
        body: JSON.stringify({ cve_url: cve.value, poc_url: poc.value }),
      });
      checkId = result.check_id;
      plan.textContent = JSON.stringify(result.plan, null, 2);
      plan.hidden = false;
      submitButton.disabled = false;
      setMessage(`Target: ${result.target_id}; CVE: ${result.cve_id}`);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!checkId) {
      setMessage("Check the links first.", true);
      return;
    }
    setMessage("Starting job...");
    try {
      const result = await api("/api/jobs", {
        method: "POST",
        body: JSON.stringify({
          cve_url: cve.value,
          poc_url: poc.value,
          check_id: checkId,
        }),
      });
      window.location.href = `/jobs/${result.job_id}`;
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  preflightButton.addEventListener("click", async () => {
    try {
      const result = await api("/api/preflight", { method: "POST", body: "{}" });
      setMessage(result.ok ? "Preflight checks pass." : `Preflight: ${JSON.stringify(result.checks)}`, !result.ok);
    } catch (error) {
      setMessage(error.message, true);
    }
  });
}

function wireJobPage() {
  const data = document.getElementById("job-data");
  if (!data) return;
  const jobId = data.dataset.jobId;
  const outcome = data.dataset.outcome;
  const cancel = document.getElementById("cancel-button");
  if (cancel) {
    cancel.addEventListener("click", async () => {
      try {
        await api(`/api/jobs/${jobId}/cancel`, { method: "POST", body: "{}" });
        setMessage("Cancellation requested.");
      } catch (error) {
        setMessage(error.message, true);
      }
    });
  }
  if (outcome) return;
  const events = new EventSource(`/api/jobs/${jobId}/events`);
  events.addEventListener("state", (event) => {
    const payload = JSON.parse(event.data);
    if (payload.job && payload.job.outcome) {
      events.close();
      window.location.reload();
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  wireHelp();
  wireSubmitPage();
  wireJobPage();
});
