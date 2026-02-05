export type ValidationResult = {
  status:
    | "safe"
    | "suspicious"
    | "dangerous"
    | "not_meeting_link"
    | "unverifiable";
  platform?: string;
  message: string;
  details?: string;
  originalUrl: string;
  hostname?: string;
};

// Legitimate meeting platform domains
// Format: base domain -> { displayName, validSubdomainPattern }
const LEGITIMATE_PLATFORMS: Record<
  string,
  { name: string; subdomainPattern?: RegExp }
> = {
  // Zoom - allows any subdomain (vanity URLs like tesla.zoom.us, company.zoom.us)
  // Also allows nested subdomains like a.b.zoom.us for enterprise setups
  // This is safe because only Zoom can create subdomains on zoom.us
  "zoom.us": { name: "Zoom", subdomainPattern: /^[a-z0-9-]+(\.[a-z0-9-]+)*$/ },
  "zoomgov.com": { name: "Zoom (Government)" },

  // Google Meet
  "meet.google.com": { name: "Google Meet" },

  // Microsoft Teams
  "teams.microsoft.com": { name: "Microsoft Teams" },
  "teams.live.com": { name: "Microsoft Teams" },

  // Webex
  "webex.com": { name: "Webex", subdomainPattern: /^[a-z0-9-]+$/ },

  // Calendly
  "calendly.com": { name: "Calendly" },

  // Cal.com
  "cal.com": { name: "Cal.com" },

  // Discord
  "discord.com": { name: "Discord" },
  "discord.gg": { name: "Discord" },

  // Telegram
  "t.me": { name: "Telegram" },
  "telegram.me": { name: "Telegram" },
  "telegram.org": { name: "Telegram" },

  // Twitter/X
  "twitter.com": { name: "Twitter/X" },
  "x.com": { name: "Twitter/X" },

  // Slack
  "slack.com": { name: "Slack", subdomainPattern: /^[a-z0-9-]+$/ },

  // GoTo Meeting
  "gotomeeting.com": { name: "GoTo Meeting" },
  "goto.com": { name: "GoTo", subdomainPattern: /^[a-z0-9-]+$/ },

  // Jitsi Meet
  "meet.jit.si": { name: "Jitsi Meet" },

  // Amazon Chime
  "chime.aws": { name: "Amazon Chime" },

  // Loom
  "loom.com": { name: "Loom", subdomainPattern: /^[a-z0-9-]+$/ },

  // Riverside
  "riverside.fm": { name: "Riverside" },

  // Skype
  "join.skype.com": { name: "Skype" },
  "skype.com": { name: "Skype", subdomainPattern: /^[a-z0-9-]+$/ },

  // Signal
  "signal.group": { name: "Signal" },
  "signal.me": { name: "Signal" },

  // Additional platforms
  "whereby.com": { name: "Whereby" },
};

// Keywords that suggest a URL is trying to be a meeting link
const MEETING_KEYWORDS = [
  "zoom",
  "meet",
  "teams",
  "webex",
  "call",
  "calendly",
  "discord",
  "telegram",
  "conference",
  "video",
  "meeting",
  "slack",
  "goto",
  "gotomeeting",
  "jitsi",
  "chime",
  "loom",
  "skype",
];

// Cyrillic and other homoglyph characters that look like Latin letters
// These are commonly used in phishing attacks
const HOMOGLYPH_MAP: Record<string, string> = {
  а: "a", // Cyrillic
  е: "e", // Cyrillic
  о: "o", // Cyrillic
  р: "p", // Cyrillic
  с: "c", // Cyrillic
  у: "y", // Cyrillic
  х: "x", // Cyrillic
  і: "i", // Cyrillic
  ј: "j", // Cyrillic
  ѕ: "s", // Cyrillic
  ԁ: "d", // Cyrillic
  ɡ: "g", // Latin small letter script g
  ո: "n", // Armenian
  օ: "o", // Armenian
  ս: "s", // Armenian
  ա: "a", // Armenian
  ß: "ss", // German
  ı: "i", // Turkish dotless i
};

// URL shorteners and redirect services that we cannot verify
// These hide the true destination and could redirect to phishing sites
const URL_SHORTENERS = [
  // Popular shorteners
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "adf.ly",
  "bit.do",
  "mcaf.ee",
  "su.pr",
  "tiny.cc",
  "yourls.org",
  "v.gd",
  "tr.im",
  "cli.gs",
  "short.to",
  "budurl.com",
  "ping.fm",
  "post.ly",
  "just.as",
  "bkite.com",
  "snipr.com",
  "fic.kr",
  "loopt.us",
  "doiop.com",
  "twitthis.com",
  "htxt.it",
  "ak.ent",
  "yep.it",
  "posted.at",
  "xrl.us",
  "metamark.net",
  "sn.im",
  "hurl.ws",
  "eepurl.com",
  "idek.net",
  "urlpire.com",
  "chilp.it",
  "moourl.com",
  "snipurl.com",
  "linkbee.com",
  "x.co",
  "lnkd.in",
  "db.tt",
  "qr.ae",
  "cur.lv",
  "ity.im",
  "q.gs",
  "po.st",
  "bc.vc",
  "twit.ac",
  "j.mp",
  "buzurl.com",
  "cutt.us",
  "u.bb",
  "crisco.com",
  "prettylinkpro.com",
  "viralurl.com",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
  "s.id",
  "rotf.lol",
  "rebrand.ly",
  "bl.ink",
  "short.io",
  "hypr.ink",
  "linktr.ee",
  // More shorteners
  "dub.sh",
  "dub.co",
  "short.cm",
  "shrtco.de",
  "shor.by",
  "qr.io",
  "clck.ru",
  "clk.sh",
  "shortcm.li",
  // Open redirect services (Google, Facebook, etc.)
  // Note: We check for specific redirect patterns below
];

// Domains that have open redirect vulnerabilities commonly exploited
const OPEN_REDIRECT_PATTERNS = [
  /^(www\.)?google\.[a-z.]+\/url\?/i,
  /^(www\.)?facebook\.com\/l\.php\?/i,
  /^(www\.)?youtube\.com\/redirect\?/i,
  /^(www\.)?linkedin\.com\/redir\//i,
  /^t\.umblr\.com\/redirect\?/i,
];

/**
 * Check if a URL is a shortener or redirect service
 */
function isUrlShortener(hostname: string, fullUrl: string): boolean {
  // Normalize hostname (remove trailing dots)
  const normalizedHostname = normalizeTrailingDot(hostname);

  // Check against known shorteners
  if (URL_SHORTENERS.includes(normalizedHostname)) {
    return true;
  }

  // Check for open redirect patterns
  for (const pattern of OPEN_REDIRECT_PATTERNS) {
    if (pattern.test(fullUrl.replace(/^https?:\/\//, ""))) {
      return true;
    }
  }

  return false;
}

/**
 * Normalize a string by replacing homoglyphs with their ASCII equivalents
 */
function normalizeHomoglyphs(str: string): string {
  let normalized = str;
  for (const [homoglyph, ascii] of Object.entries(HOMOGLYPH_MAP)) {
    normalized = normalized.split(homoglyph).join(ascii);
  }
  return normalized;
}

/**
 * Check if a string contains non-ASCII characters that could be homoglyphs
 */
function containsHomoglyphs(str: string): boolean {
  // Check for any non-ASCII characters in what should be a domain
  // eslint-disable-next-line no-control-regex
  return /[^\x00-\x7F]/.test(str);
}

/**
 * Check if a hostname is punycode (internationalized domain that was converted)
 * Punycode domains start with "xn--" which indicates IDN encoding
 */
function isPunycode(hostname: string): boolean {
  // Check if any part of the domain starts with xn--
  return hostname.split(".").some((part) => part.startsWith("xn--"));
}

// Common phishing patterns - these are checked AFTER legitimate platform check
const PHISHING_PATTERNS = [
  // Subdomain tricks: zoom.something.com instead of something.zoom.us
  // This catches zoom.webus05.us (the scam from the tweet)
  // Uses [a-z]{2,} to match ANY TLD (not just com/us/net/org/io)
  {
    pattern: /^zoom\.[a-z0-9-]+\.[a-z]{2,}$/i,
    description:
      "Subdomain trick - 'zoom' should be the main domain, not a subdomain",
  },
  {
    pattern: /^meet\.[a-z0-9-]+\.[a-z]{2,}$/i,
    description: "Subdomain trick - suspicious 'meet' subdomain",
  },
  {
    pattern: /^teams\.[a-z0-9-]+\.[a-z]{2,}$/i,
    description: "Subdomain trick - suspicious 'teams' subdomain",
  },
  {
    pattern: /^slack\.[a-z0-9-]+\.[a-z]{2,}$/i,
    description: "Subdomain trick - suspicious 'slack' subdomain",
  },
  {
    pattern: /^skype\.[a-z0-9-]+\.[a-z]{2,}$/i,
    description: "Subdomain trick - suspicious 'skype' subdomain",
  },

  // Lookalike characters - must contain at least one 0 (zero) instead of o
  {
    pattern: /z[o0]*0[o0]*m/i,
    description:
      "Lookalike characters detected - '0' (zero) used instead of 'o'",
  },
  {
    pattern: /2oom/i,
    description: "Lookalike characters detected - '2' used instead of 'z'",
  },

  // Extra words added to zoom (in any position with hyphen or underscore)
  {
    pattern: /zoom[-_](meeting|call|video|conference)/i,
    description: "Suspicious extra words in domain",
  },
  {
    pattern: /(meeting|call|video|conference)[-_]zoom/i,
    description: "Suspicious extra words in domain",
  },

  // Wrong TLD patterns - legitimate domain appears as subdomain of malicious domain
  // Catches: zoom.us.malicious.com, zoom.us.attacker.com, etc.
  {
    pattern: /zoom\.us\.[a-z0-9-]+\.[a-z]+$/i,
    description:
      "Fake domain - 'zoom.us' is being used as a subdomain of another site",
  },
  {
    pattern: /google\.com\.[a-z0-9-]+\.[a-z]+$/i,
    description:
      "Fake domain - 'google.com' is being used as a subdomain of another site",
  },
  {
    pattern: /microsoft\.com\.[a-z0-9-]+\.[a-z]+$/i,
    description:
      "Fake domain - 'microsoft.com' is being used as a subdomain of another site",
  },

  // Also catch simpler wrong TLD: zoom.us.com, meet.google.org, etc
  {
    pattern: /^zoom\.us\.[a-z]{2,}$/i,
    description: "Wrong TLD - legitimate Zoom uses zoom.us, not zoom.us.com",
  },

  // Typosquatting
  { pattern: /zooom/i, description: "Typosquatting detected (extra 'o')" },
  {
    pattern: /zomm\./i,
    description: "Typosquatting detected (swapped letters)",
  },
  { pattern: /zoim/i, description: "Typosquatting detected (typo)" },
  { pattern: /zoomus\./i, description: "Typosquatting detected (missing dot)" },

  // Catch "secure-" or other prefixes with zoom.us pattern
  {
    pattern: /[a-z]+-zoom\.us\./i,
    description: "Suspicious prefix added to zoom domain",
  },
];

/**
 * Check for fragment/hash trick where meeting platform name appears after #
 * Example: evil.com/#zoom.us - user sees "zoom.us" but real domain is evil.com
 */
function checkFragmentTrick(input: string): {
  hasTrick: boolean;
  realDomain?: string;
  fakePart?: string;
} {
  const meetingKeywords = [
    "zoom",
    "meet",
    "teams",
    "webex",
    "calendly",
    "discord",
    "telegram",
  ];

  // Check for hash/fragment containing meeting keywords
  const hashIndex = input.indexOf("#");
  if (hashIndex > -1) {
    const fragment = input.slice(hashIndex + 1).toLowerCase();
    const hasKeyword = meetingKeywords.some((kw) => fragment.includes(kw));

    if (hasKeyword) {
      // Extract the real domain
      try {
        let url = input.slice(0, hashIndex);
        if (!url.match(/^https?:\/\//i)) url = "https://" + url;
        const parsed = new URL(url);
        const realDomain = parsed.hostname;

        // Check if real domain is NOT a legitimate meeting platform
        if (
          !Object.keys(LEGITIMATE_PLATFORMS).some((d) => realDomain.endsWith(d))
        ) {
          return { hasTrick: true, realDomain, fakePart: fragment };
        }
      } catch {
        // URL parse failed, still suspicious
        return { hasTrick: true, fakePart: fragment };
      }
    }
  }

  return { hasTrick: false };
}

/**
 * Check for query parameter trick where redirect params contain meeting keywords
 * Example: auth.com/?redirect=zoom.us - looks legitimate but goes to auth.com
 */
function checkQueryParamTrick(input: string): {
  hasTrick: boolean;
  realDomain?: string;
  suspiciousParam?: string;
} {
  const meetingKeywords = [
    "zoom.us",
    "meet.google",
    "teams.microsoft",
    "webex.com",
    "calendly.com",
    "discord.com",
  ];
  const redirectParams = [
    "redirect",
    "url",
    "next",
    "continue",
    "return",
    "goto",
    "dest",
    "destination",
    "redir",
    "target",
  ];

  try {
    let url = input;
    if (!url.match(/^https?:\/\//i)) url = "https://" + url;
    const parsed = new URL(url);
    const params = parsed.searchParams;

    // Check if any redirect-like param contains meeting platform keywords
    for (const [key, value] of params) {
      const isRedirectParam = redirectParams.some((p) =>
        key.toLowerCase().includes(p),
      );
      const hasMeetingKeyword = meetingKeywords.some((kw) =>
        value.toLowerCase().includes(kw),
      );

      if (isRedirectParam && hasMeetingKeyword) {
        // Check if the main domain is NOT a legitimate meeting platform
        const realDomain = parsed.hostname;
        if (
          !Object.keys(LEGITIMATE_PLATFORMS).some((d) => realDomain.endsWith(d))
        ) {
          return {
            hasTrick: true,
            realDomain,
            suspiciousParam: `${key}=${value}`,
          };
        }
      }
    }
  } catch {
    // URL parse failed
  }

  return { hasTrick: false };
}

/**
 * Check if hostname is an IP address (legitimate meetings never use raw IPs)
 */
function isIpAddress(hostname: string): boolean {
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return true;
  }
  // IPv6 (simplified check)
  if (hostname.includes(":") && /^[0-9a-f:]+$/i.test(hostname)) {
    return true;
  }
  // Localhost
  if (hostname === "localhost") {
    return true;
  }
  return false;
}

/**
 * Check for file:// protocol or local file paths
 */
function isLocalFilePath(input: string): boolean {
  const lower = input.toLowerCase().trim();
  return (
    lower.startsWith("file://") ||
    lower.startsWith("file:///") ||
    /^[a-z]:\\/i.test(input) || // Windows path like C:\
    lower.startsWith("/users/") ||
    lower.startsWith("/home/") ||
    lower.startsWith("~/") ||
    lower.startsWith("./")
  );
}

/**
 * Check if URL contains @ symbol trick (userinfo attack)
 * Example: https://zoom.us@evil.com/j/123 - the actual domain is evil.com, not zoom.us
 * This is a common phishing technique to make URLs look legitimate
 */
function containsAtTrick(input: string): {
  hasTrick: boolean;
  fakeDomain?: string;
  realDomain?: string;
} {
  // Look for @ in the URL after the protocol
  const withoutProtocol = input.replace(/^https?:\/\//i, "");

  // Check if there's an @ before the first /
  const pathStart = withoutProtocol.indexOf("/");
  const hostPart =
    pathStart > -1 ? withoutProtocol.slice(0, pathStart) : withoutProtocol;

  if (hostPart.includes("@")) {
    const parts = hostPart.split("@");
    const fakeDomain = parts[0].split(":")[0]; // Remove port if present
    const realDomain = parts[parts.length - 1].split(":")[0];

    // Check if the fake domain looks like a meeting platform
    const meetingKeywords = [
      "zoom",
      "meet",
      "teams",
      "webex",
      "calendly",
      "discord",
    ];
    const looksSuspicious = meetingKeywords.some((kw) =>
      fakeDomain.toLowerCase().includes(kw),
    );

    if (looksSuspicious && fakeDomain !== realDomain) {
      return { hasTrick: true, fakeDomain, realDomain };
    }
  }

  return { hasTrick: false };
}

/**
 * Normalize hostname by removing trailing dots
 * In DNS, "example.com." (absolute) is equivalent to "example.com" (relative)
 * Attackers use this to bypass string matching checks
 * e.g., "zoom.us." != "zoom.us" in string comparison, but DNS resolves them the same
 */
function normalizeTrailingDot(hostname: string): string {
  // Remove trailing dot(s) - technically only one is valid, but be thorough
  return hostname.replace(/\.+$/, "");
}

/**
 * Check if URL has a trailing dot in the hostname (suspicious pattern)
 * While technically valid in DNS, trailing dots in URLs are extremely rare
 * and often indicate an attempt to bypass security checks
 */
function hasTrailingDot(input: string): boolean {
  // Check for patterns like "zoom.us." or "zoom.webus05.us."
  // The trailing dot appears before the path, query, or end of string
  const hostnameMatch = input.match(/^(?:https?:\/\/)?([^\/\?\#]+)/i);
  if (hostnameMatch) {
    const hostPart = hostnameMatch[1];
    // Remove port if present
    const hostWithoutPort = hostPart.split(":")[0];
    return hostWithoutPort.endsWith(".");
  }
  return false;
}

/**
 * Extract and validate hostname from a URL string
 */
function parseUrl(
  input: string,
): { hostname: string; pathname: string } | null {
  let url = input.trim();

  // Add protocol if missing
  if (!url.match(/^https?:\/\//i)) {
    url = "https://" + url;
  }

  try {
    const parsed = new URL(url);
    // Normalize the hostname by removing trailing dots
    // This ensures "zoom.us." is treated the same as "zoom.us"
    const hostname = normalizeTrailingDot(parsed.hostname.toLowerCase());
    return {
      hostname,
      pathname: parsed.pathname,
    };
  } catch {
    return null;
  }
}

/**
 * Check if hostname matches a legitimate platform
 */
function checkLegitimatePlatform(hostname: string): {
  isLegit: boolean;
  platform?: string;
} {
  // Normalize hostname (remove trailing dots) - ensures "zoom.us." matches "zoom.us"
  const normalizedHostname = normalizeTrailingDot(hostname);

  // Direct match
  if (LEGITIMATE_PLATFORMS[normalizedHostname]) {
    return {
      isLegit: true,
      platform: LEGITIMATE_PLATFORMS[normalizedHostname].name,
    };
  }

  // Check if it's a valid subdomain of a legitimate platform
  for (const [domain, config] of Object.entries(LEGITIMATE_PLATFORMS)) {
    if (normalizedHostname.endsWith("." + domain)) {
      const subdomain = normalizedHostname.slice(0, -(domain.length + 1));

      // If there's a subdomain pattern, validate it
      if (config.subdomainPattern) {
        if (config.subdomainPattern.test(subdomain)) {
          return { isLegit: true, platform: config.name };
        }
        // Has subdomain but doesn't match expected pattern - could be suspicious
        // but we'll let the phishing check handle it
        return { isLegit: false };
      }

      // No specific pattern required, accept any subdomain
      return { isLegit: true, platform: config.name };
    }
  }

  return { isLegit: false };
}

/**
 * Check for known phishing patterns
 */
function checkPhishingPatterns(hostname: string): {
  isPhishing: boolean;
  reason?: string;
} {
  // Normalize hostname (remove trailing dots) - ensures "zoom.webus05.us." matches patterns
  const normalizedHostname = normalizeTrailingDot(hostname);

  for (const { pattern, description } of PHISHING_PATTERNS) {
    if (pattern.test(normalizedHostname)) {
      return { isPhishing: true, reason: description };
    }
  }
  return { isPhishing: false };
}

/**
 * Check if the URL looks like it's trying to be a meeting link
 */
function looksLikeMeetingLink(hostname: string, pathname: string): boolean {
  const combined = (hostname + pathname).toLowerCase();
  return MEETING_KEYWORDS.some((keyword) => combined.includes(keyword));
}

/**
 * Main validation function
 */
export function validateMeetingLink(input: string): ValidationResult {
  const trimmedInput = input.trim();

  if (!trimmedInput) {
    return {
      status: "not_meeting_link",
      message: "Please enter a URL to check",
      originalUrl: input,
    };
  }

  // CRITICAL: Block dangerous URI schemes before any parsing
  const lowerInput = trimmedInput.toLowerCase();
  const dangerousSchemes = ["javascript:", "data:", "blob:", "vbscript:"];
  if (dangerousSchemes.some((scheme) => lowerInput.startsWith(scheme))) {
    return {
      status: "dangerous",
      message: "Dangerous URI scheme detected!",
      details: `This is not a web URL. It uses a "${lowerInput.split(":")[0]}:" scheme which can execute code or load arbitrary content. Legitimate meeting links always use https:// URLs.`,
      originalUrl: input,
    };
  }

  // CRITICAL: Check for local file paths FIRST
  // file:///C:/Users/zoom.html is NOT a legitimate meeting link
  if (isLocalFilePath(trimmedInput)) {
    return {
      status: "dangerous",
      message: "Local file path detected!",
      details: `This is a local file path, not a web URL. Legitimate meeting links are always web URLs (starting with https://). Local file paths can be used to execute malicious scripts on your computer. Do NOT open this.`,
      originalUrl: input,
    };
  }

  // CRITICAL: Check for fragment/hash trick
  // evil.com/#zoom.us makes users think they see "zoom.us" in the URL
  const fragmentCheck = checkFragmentTrick(trimmedInput);
  if (fragmentCheck.hasTrick) {
    return {
      status: "dangerous",
      message: "URL fragment deception detected!",
      details: `This URL uses a deceptive technique: it contains "${fragmentCheck.fakePart}" after a # symbol to make it look legitimate, but the actual domain is "${fragmentCheck.realDomain}". The # fragment is never sent to the server - it's purely visual deception. Do NOT click this link.`,
      originalUrl: input,
      hostname: fragmentCheck.realDomain,
    };
  }

  // CRITICAL: Check for query parameter redirect trick
  // auth.com/?redirect=zoom.us tries to look like it relates to zoom
  const queryCheck = checkQueryParamTrick(trimmedInput);
  if (queryCheck.hasTrick) {
    return {
      status: "dangerous",
      message: "Suspicious redirect parameter detected!",
      details: `This URL contains a redirect parameter (${queryCheck.suspiciousParam}) that mentions a meeting platform, but the actual domain is "${queryCheck.realDomain}". This could be a phishing attempt using an open redirect vulnerability. Do NOT click this link.`,
      originalUrl: input,
      hostname: queryCheck.realDomain,
    };
  }

  // CRITICAL: Check for @ symbol trick FIRST (before URL parsing)
  // https://zoom.us@evil.com looks like zoom.us but actually goes to evil.com
  const atTrickCheck = containsAtTrick(trimmedInput);
  if (atTrickCheck.hasTrick) {
    return {
      status: "dangerous",
      message: "URL deception detected!",
      details: `This URL uses a deceptive technique: it appears to be "${atTrickCheck.fakeDomain}" but actually goes to "${atTrickCheck.realDomain}". The @ symbol in URLs can be used to trick you into thinking you're visiting a legitimate site. Do NOT click this link.`,
      originalUrl: input,
      hostname: atTrickCheck.realDomain,
    };
  }

  const parsed = parseUrl(trimmedInput);

  if (!parsed) {
    return {
      status: "not_meeting_link",
      message: "Invalid URL format",
      details: "The text you entered doesn't appear to be a valid URL.",
      originalUrl: input,
    };
  }

  const { hostname, pathname } = parsed;

  // CRITICAL: Check for IP address hosting
  // Legitimate meeting platforms never use raw IP addresses
  if (isIpAddress(hostname)) {
    return {
      status: "dangerous",
      message: "IP address detected - not a legitimate meeting link!",
      details: `This URL points to a raw IP address (${hostname}) instead of a domain name. Legitimate meeting platforms like Zoom, Google Meet, and Teams always use their official domain names, never IP addresses. This is highly suspicious and could be a phishing attempt or malware host. Do NOT visit this link.`,
      originalUrl: input,
      hostname,
    };
  }

  // Check for URL shorteners FIRST - we cannot verify where they redirect
  if (isUrlShortener(hostname, trimmedInput)) {
    return {
      status: "unverifiable",
      message: "Cannot verify shortened/redirect URL",
      details: `This is a URL shortener or redirect service (${hostname}). We cannot verify where it leads without following the redirect, which could be dangerous. Ask the sender for the full, direct meeting link instead.`,
      originalUrl: input,
      hostname,
    };
  }

  // CRITICAL: Check for homoglyph/Unicode attacks FIRST
  // These are ALWAYS suspicious because legitimate platforms use ASCII only
  if (containsHomoglyphs(hostname)) {
    const normalized = normalizeHomoglyphs(hostname);
    // Check if it's trying to look like a legitimate platform
    const looksLikeKnownPlatform = Object.keys(LEGITIMATE_PLATFORMS).some(
      (domain) =>
        normalized.includes(domain.replace(".", "")) ||
        normalized.endsWith(domain) ||
        MEETING_KEYWORDS.some((kw) => normalized.includes(kw)),
    );

    if (looksLikeKnownPlatform) {
      return {
        status: "dangerous",
        message: "Homoglyph attack detected!",
        details: `This URL contains deceptive characters that look like legitimate letters but are actually different (e.g., Cyrillic letters that look like Latin). This is a common phishing technique. The domain "${hostname}" is NOT the same as it appears.`,
        originalUrl: input,
        hostname,
      };
    }

    return {
      status: "suspicious",
      message: "Suspicious characters detected",
      details: `This URL contains non-standard characters that could be an attempt to deceive. Proceed with extreme caution.`,
      originalUrl: input,
      hostname,
    };
  }

  // Check for punycode domains (IDN homograph attacks)
  // The URL parser converts Unicode to punycode (e.g., zооm.us -> xn--zm-fmca.us)
  if (isPunycode(hostname)) {
    return {
      status: "dangerous",
      message: "Internationalized domain attack detected!",
      details: `This URL uses special Unicode characters that have been encoded as "${hostname}". This is a common phishing technique where attackers use look-alike characters from other alphabets (like Cyrillic) to impersonate legitimate sites. Do NOT trust this link.`,
      originalUrl: input,
      hostname,
    };
  }

  // SECOND: Check if it's a legitimate platform (this takes priority for clean domains)
  const legitCheck = checkLegitimatePlatform(hostname);
  if (legitCheck.isLegit) {
    return {
      status: "safe",
      platform: legitCheck.platform,
      message: `Verified ${legitCheck.platform} link`,
      details: `This link is from the official ${legitCheck.platform} domain.`,
      originalUrl: input,
      hostname,
    };
  }

  // THIRD: Check for known phishing patterns
  const phishingCheck = checkPhishingPatterns(hostname);
  if (phishingCheck.isPhishing) {
    return {
      status: "dangerous",
      message: "Potential phishing link detected!",
      details: phishingCheck.reason,
      originalUrl: input,
      hostname,
    };
  }

  // FOURTH: Check if it looks like it's trying to be a meeting link (suspicious)
  if (looksLikeMeetingLink(hostname, pathname)) {
    return {
      status: "suspicious",
      message: "Unverified meeting link",
      details: `This URL contains meeting-related keywords but is not from a recognized platform. The domain "${hostname}" is not in our verified list. Proceed with caution.`,
      originalUrl: input,
      hostname,
    };
  }

  // Doesn't appear to be a meeting link at all
  return {
    status: "not_meeting_link",
    message: "Not a recognized meeting link",
    details: `This doesn't appear to be a meeting or video call link. If you believe this is a legitimate meeting platform we should recognize, please let us know.`,
    originalUrl: input,
    hostname,
  };
}

/**
 * Get list of supported platforms for display
 */
export function getSupportedPlatforms(): string[] {
  const platforms = new Set<string>();
  for (const config of Object.values(LEGITIMATE_PLATFORMS)) {
    platforms.add(config.name);
  }
  return Array.from(platforms).sort();
}
