
const SUSPICIOUS_TLDS = [
  "xyz", "top", "pw", "loan", "win",
  "bid", "vip", "click", "cfd", "icu"
];

const SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl",
  "rebrand.ly", "is.gd", "buff.ly"
];

const SCAM_KEYWORDS = [
  "login", "verify", "account", "prize", "gift",
  "win", "claim", "update", "secure", "bank"
];

const MIN_WARNING_SCORE = 25;

function isDomainOrSubdomain(hostname, domain) {
  return hostname === domain || hostname.endsWith("." + domain);
}

function isIpAddress(hostname) {
  const parts = hostname.split(".");

  if (parts.length !== 4) return false;

  return parts.every(part =>
    /^\d{1,3}$/.test(part) &&
    Number(part) >= 0 &&
    Number(part) <= 255
  );
}

function isHomograph(hostname) {
  // URL.hostname converts internationalized domain names to ASCII.
  // Punycode labels can indicate a domain needing closer inspection.
  return hostname
    .split(".")
    .some(label => label.startsWith("xn--"));
}

function analyzeLink(urlString) {
  let url;

  try {
    url = new URL(urlString);
  } catch {
    return {
      score: 0,
      level: "safe",
      reasons: []
    };
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    return {
      score: 0,
      level: "safe",
      reasons: []
    };
  }

  const hostname = url.hostname.toLowerCase();
  const reasons = [];
  let score = 0;

  function addRisk(points, reason) {
    score += points;
    reasons.push(reason);
  }

  // 1. Internationalized / punycode hostname
  if (isHomograph(hostname)) {
    addRisk(
      30,
      "Hostname contains a punycode label; check for impersonation."
    );
  }

  // 2. Known URL shorteners
  if (
    SHORTENERS.some(shortener =>
      isDomainOrSubdomain(hostname, shortener)
    )
  ) {
    addRisk(
      15,
      "Uses a URL shortener, so the final destination may be hidden."
    );
  }

  // 3. Suspicious top-level domain
  const tld = hostname.split(".").pop();

  if (SUSPICIOUS_TLDS.includes(tld)) {
    addRisk(
      20,
      `Uses a TLD sometimes associated with abusive websites: .${tld}`
    );
  }

  // 4. Suspicious words in the hostname
  const matchedKeywords = SCAM_KEYWORDS.filter(word =>
    hostname.includes(word)
  );

  if (matchedKeywords.length > 0) {
    addRisk(
      15,
      "Hostname contains suspicious keywords: " +
        matchedKeywords.join(", ")
    );
  }

  // 5. IPv4 address used directly as the hostname
  if (isIpAddress(hostname)) {
    addRisk(30, "Hostname is a raw IPv4 address.");
  }

  // 6. Username or password embedded in the URL
  if (url.username || url.password) {
    addRisk(
      25,
      "URL contains embedded username or password information."
    );
  }

  // 7. Excessively nested subdomains
  const labels = hostname.split(".");

  if (labels.length >= 5) {
    addRisk(
      10,
      "Hostname has many subdomain levels; inspect it carefully."
    );
  }

  // Cap the score at 100
  score = Math.min(score, 100);

  let level = "safe";

  if (score >= 60) {
    level = "high";
  } else if (score >= 35) {
    level = "medium";
  } else if (score >= MIN_WARNING_SCORE) {
    level = "low";
  }

  return { score, level, reasons };
}

function removePreviousWarning(link) {
  link.parentNode
    ?.querySelectorAll(
      `[data-fraud-warning-for="${CSS.escape(link.dataset.fraudId || "")}"]`
    )
    .forEach(icon => icon.remove());

  link.classList.remove("fraud-warning");
  link.removeAttribute("data-fraud-id");
}

let nextLinkId = 0;

function processLink(link) {
  if (!(link instanceof HTMLAnchorElement)) return;

  const url = link.href;

  // Skip links that have not changed since the previous scan.
  if (link.dataset.fraudCheckedUrl === url) return;

  removePreviousWarning(link);

  link.dataset.fraudCheckedUrl = url;

  const result = analyzeLink(url);

  if (result.score < MIN_WARNING_SCORE) return;

  const linkId = String(++nextLinkId);
  link.dataset.fraudId = linkId;
  link.classList.add("fraud-warning");

  const warningText = [
    `PhishGuard warning: ${result.level.toUpperCase()} risk`,
    `Risk score: ${result.score}/100`,
    ...result.reasons.map(reason => `- ${reason}`),
    "This is a heuristic warning, not a confirmed verdict."
  ].join("\n");

  link.title = warningText;

  const icon = document.createElement("span");
  icon.dataset.fraudWarningFor = linkId;
  icon.textContent = " ⚠";
  icon.title = warningText;
  icon.setAttribute("role", "img");
  icon.setAttribute("aria-label", "Potentially suspicious link");

  icon.style.color = "#c62828";
  icon.style.fontWeight = "bold";
  icon.style.cursor = "help";
  icon.style.marginInlineStart = "4px";

  link.insertAdjacentElement("afterend", icon);

  console.warn("[PhishGuard] Suspicious link detected", {
    url,
    score: result.score,
    level: result.level,
    reasons: result.reasons
  });
}

function scanNode(node) {
  if (!(node instanceof Element)) return;

  if (node.matches("a[href]")) {
    processLink(node);
  }

  node.querySelectorAll("a[href]").forEach(processLink);
}

function scanForLinks() {
  document.querySelectorAll("a[href]").forEach(processLink);
}

// Initial scan
scanForLinks();

// Scan newly added or changed page content.
const observer = new MutationObserver(mutations => {
  for (const mutation of mutations) {
    if (mutation.type === "childList") {
      mutation.addedNodes.forEach(scanNode);
    }

    if (
      mutation.type === "attributes" &&
      mutation.target instanceof HTMLAnchorElement
    ) {
      processLink(mutation.target);
    }
  }
});

observer.observe(document.body, {
  childList: true,
  subtree: true,
  attributes: true,
  attributeFilter: ["href"]
});

console.log("[PhishGuard] Link detector active.");
