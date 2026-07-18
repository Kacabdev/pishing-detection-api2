// script.js
// Renders the feature form from metadata, calls the /predict API on the same origin,
// and displays the verdict. Value directions (-1 = phishing signal, 0 = suspicious,
// 1 = legitimate signal) follow the documented encoding of the UCI Phishing Websites dataset.

const FEATURE_GROUPS = [
  {
    title: "Address Bar Features",
    fields: [
      { key: "having_ip_address", label: "IP address instead of domain", help: "Does the URL use a raw IP address rather than a domain name?", options: [[1, "No — uses a domain name"], [-1, "Yes — raw IP address"]] },
      { key: "url_length", label: "URL length", help: "How long is the full URL?", options: [[1, "Short (< 54 characters)"], [0, "Medium (54–75 characters)"], [-1, "Long (> 75 characters)"]] },
      { key: "shortining_service", label: "URL shortening service", help: "Was a shortener like bit.ly or tinyurl used?", options: [[1, "No"], [-1, "Yes"]] },
      { key: "having_at_symbol", label: "@ symbol in URL", help: "Does the URL contain an '@' symbol?", options: [[1, "No"], [-1, "Yes"]] },
      { key: "double_slash_redirecting", label: "// after the domain", help: "Does '//' appear again after the domain (path redirect trick)?", options: [[1, "No"], [-1, "Yes"]] },
      { key: "prefix_suffix", label: "Dash in domain", help: "Does the domain contain a '-' (e.g. paypal-secure.com)?", options: [[1, "No"], [-1, "Yes"]] },
      { key: "having_sub_domain", label: "Number of subdomains", help: "How many subdomain levels does the URL have?", options: [[1, "None or one"], [0, "Two"], [-1, "Three or more"]] },
      { key: "sslfinal_state", label: "SSL certificate state", help: "What is the state of the site's HTTPS certificate?", options: [[1, "Trusted HTTPS certificate"], [0, "HTTPS but untrusted/self-signed"], [-1, "No HTTPS / invalid certificate"]] },
      { key: "domain_registration_length", label: "Domain registration length", help: "How far out is the domain registered?", options: [[1, "More than 1 year"], [-1, "1 year or less"]] },
      { key: "favicon", label: "Favicon source", help: "Where is the favicon loaded from?", options: [[1, "Same domain"], [-1, "External domain"]] },
      { key: "port", label: "Open ports", help: "Are only standard ports open?", options: [[1, "Standard ports only"], [-1, "Suspicious port open"]] },
      { key: "https_token", label: "'https' token in domain text", help: "Is the word 'https' embedded in the domain name itself (not the protocol)?", options: [[1, "No"], [-1, "Yes"]] },
    ],
  },
  {
    title: "Abnormal-Based Features",
    fields: [
      { key: "request_url", label: "External request URLs", help: "Are most images/scripts loaded from the same domain?", options: [[1, "Mostly same domain"], [-1, "Mostly external domains"]] },
      { key: "url_of_anchor", label: "Anchor tag URLs", help: "Where do most <a> links on the page point?", options: [[1, "Mostly same domain"], [0, "Mixed"], [-1, "Mostly unrelated/external"]] },
      { key: "links_in_tags", label: "Links in <meta>/<script>/<link>", help: "Where do meta/script/link tag URLs point?", options: [[1, "Mostly same domain"], [0, "Mixed"], [-1, "Mostly external"]] },
      { key: "sfh", label: "Server Form Handler (SFH)", help: "Where does the login/data form submit to?", options: [[1, "Same domain"], [0, "A different domain"], [-1, "Blank / about:blank"]] },
      { key: "submitting_to_email", label: "Form submits via email", help: "Does the form use mailto:/mail() instead of a server request?", options: [[1, "No"], [-1, "Yes"]] },
      { key: "abnormal_url", label: "Abnormal URL", help: "Does the host identity match the site's WHOIS record?", options: [[1, "Matches WHOIS record"], [-1, "Host not in URL / mismatch"]] },
    ],
  },
  {
    title: "HTML & JavaScript Features",
    fields: [
      { key: "redirect", label: "Page redirect count", help: "How many times does the page redirect before loading?", options: [[0, "0–1 redirects (normal)"], [1, "2 or more redirects"]] },
      { key: "on_mouseover", label: "Status bar changes on mouseover", help: "Does JavaScript alter the status bar on mouseover?", options: [[1, "No"], [-1, "Yes"]] },
      { key: "rightclick", label: "Right-click disabled", help: "Is right-click disabled on the page?", options: [[1, "No"], [-1, "Yes"]] },
      { key: "popupwindow", label: "Popup with text fields", help: "Does the site show popup windows asking for input?", options: [[1, "No"], [-1, "Yes"]] },
      { key: "iframe", label: "Invisible iframe", help: "Does the page use a hidden/invisible iframe?", options: [[1, "No"], [-1, "Yes"]] },
    ],
  },
  {
    title: "Domain-Based Features",
    fields: [
      { key: "age_of_domain", label: "Domain age", help: "How old is the domain?", options: [[1, "6 months or older"], [-1, "Younger than 6 months"]] },
      { key: "dnsrecord", label: "DNS record", help: "Does the domain have a valid DNS record?", options: [[1, "Yes"], [-1, "No"]] },
      { key: "web_traffic", label: "Web traffic rank", help: "How does the site rank on traffic (e.g. Alexa)?", options: [[1, "Top 100,000 sites"], [0, "Ranked, outside top 100,000"], [-1, "No recognizable traffic"]] },
      { key: "page_rank", label: "Google PageRank", help: "Is the site's PageRank above the typical threshold?", options: [[1, "Above threshold"], [-1, "Below threshold / none"]] },
      { key: "google_index", label: "Indexed by Google", help: "Is the page indexed by Google?", options: [[1, "Yes"], [-1, "No"]] },
      { key: "links_pointing_to_page", label: "Inbound links", help: "How many external sites link to this page?", options: [[1, "More than 2"], [0, "1–2"], [-1, "0 (none)"]] },
      { key: "statistical_report", label: "Blacklist / statistical report", help: "Is the host flagged in known phishing statistical reports?", options: [[1, "Not flagged"], [-1, "Flagged"]] },
    ],
  },
];

const EXAMPLES = {
  phishing: { having_ip_address: -1, url_length: 1, shortining_service: 1, having_at_symbol: 1, double_slash_redirecting: -1, prefix_suffix: -1, having_sub_domain: -1, sslfinal_state: -1, domain_registration_length: -1, favicon: 1, port: 1, https_token: -1, request_url: 1, url_of_anchor: -1, links_in_tags: 1, sfh: -1, submitting_to_email: -1, abnormal_url: -1, redirect: 0, on_mouseover: 1, rightclick: 1, popupwindow: 1, iframe: 1, age_of_domain: -1, dnsrecord: -1, web_traffic: -1, page_rank: -1, google_index: 1, links_pointing_to_page: 1, statistical_report: -1 },
  legit: { having_ip_address: 1, url_length: 0, shortining_service: -1, having_at_symbol: 1, double_slash_redirecting: 1, prefix_suffix: -1, having_sub_domain: 1, sslfinal_state: 1, domain_registration_length: -1, favicon: 1, port: 1, https_token: 1, request_url: 1, url_of_anchor: 0, links_in_tags: 0, sfh: -1, submitting_to_email: 1, abnormal_url: 1, redirect: 0, on_mouseover: -1, rightclick: 1, popupwindow: -1, iframe: 1, age_of_domain: -1, dnsrecord: -1, web_traffic: 0, page_rank: -1, google_index: 1, links_pointing_to_page: 1, statistical_report: 1 },
};

const groupsContainer = document.getElementById("feature-groups");
const form = document.getElementById("predict-form");

function renderForm() {
  FEATURE_GROUPS.forEach((group, idx) => {
    const details = document.createElement("details");
    details.className = "feature-group";
    if (idx === 0) details.open = true;

    const summary = document.createElement("summary");
    summary.textContent = group.title;
    details.appendChild(summary);

    const grid = document.createElement("div");
    grid.className = "field-grid";

    group.fields.forEach((field) => {
      const wrap = document.createElement("div");
      wrap.className = "field";

      const label = document.createElement("label");
      label.setAttribute("for", field.key);
      label.textContent = field.label;

      const help = document.createElement("p");
      help.className = "field-help";
      help.textContent = field.help;

      const select = document.createElement("select");
      select.id = field.key;
      select.name = field.key;
      field.options.forEach(([value, text]) => {
        const option = document.createElement("option");
        option.value = String(value);
        option.textContent = text;
        select.appendChild(option);
      });

      wrap.append(label, help, select);
      grid.appendChild(wrap);
    });

    details.appendChild(grid);
    groupsContainer.appendChild(details);
  });
}

function applyValues(values) {
  Object.entries(values).forEach(([key, value]) => {
    const select = document.getElementById(key);
    if (select) select.value = String(value);
  });
}

function getFormValues() {
  const values = {};
  FEATURE_GROUPS.forEach((group) => {
    group.fields.forEach((field) => {
      values[field.key] = parseInt(document.getElementById(field.key).value, 10);
    });
  });
  return values;
}

const resultIdle = document.getElementById("result-idle");
const resultLoading = document.getElementById("result-loading");
const resultError = document.getElementById("result-error");
const resultContent = document.getElementById("result-content");

function showState(state) {
  [resultIdle, resultLoading, resultError, resultContent].forEach((el) => el.classList.add("hidden"));
  state.classList.remove("hidden");
}

async function runPrediction(values) {
  showState(resultLoading);
  try {
    const response = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(values),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail ? JSON.stringify(body.detail) : `Request failed (${response.status})`);
    }

    const data = await response.json();
    renderResult(data);
  } catch (err) {
    document.querySelector("#result-error .error-text").textContent =
      "Could not reach the prediction API: " + err.message;
    showState(resultError);
  }
}

function renderResult(data) {
  const badge = document.getElementById("verdict-badge");
  const icon = document.getElementById("verdict-icon");
  const text = document.getElementById("verdict-text");

  badge.className = "verdict-badge " + data.prediction;
  icon.textContent = data.prediction === "phishing" ? "⚠️" : "✅";
  text.textContent = data.prediction === "phishing" ? "Likely Phishing" : "Likely Legitimate";

  const phishingPct = Math.round(data.phishing_probability * 100);
  document.getElementById("phishing-prob-value").textContent = phishingPct + "%";
  document.getElementById("phishing-prob-fill").style.width = phishingPct + "%";
  document.getElementById("legit-prob-value").textContent = Math.round(data.legitimate_probability * 100) + "%";
  document.getElementById("model-name").textContent = data.model;

  showState(resultContent);
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  runPrediction(getFormValues());
});

document.getElementById("clear-btn").addEventListener("click", () => {
  form.reset();
  showState(resultIdle);
});

document.querySelectorAll("[data-example]").forEach((btn) => {
  btn.addEventListener("click", () => {
    applyValues(EXAMPLES[btn.dataset.example]);
  });
});

const themeToggle = document.getElementById("theme-toggle");
const themeIcon = document.getElementById("theme-icon");

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  themeIcon.textContent = theme === "dark" ? "☀" : "☾";
  localStorage.setItem("phishguard-theme", theme);
}

themeToggle.addEventListener("click", () => {
  const current = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
  setTheme(current === "dark" ? "light" : "dark");
});

const savedTheme = localStorage.getItem("phishguard-theme");
if (savedTheme) {
  setTheme(savedTheme);
} else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
  setTheme("dark");
}

renderForm();
