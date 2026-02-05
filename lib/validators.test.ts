import { describe, it, expect } from "vitest";
import { validateMeetingLink, getSupportedPlatforms } from "./validators";

// Helper to assert status
function expectStatus(url: string, status: string) {
  const result = validateMeetingLink(url);
  expect(result.status).toBe(status);
  return result;
}

// ─── Empty / whitespace input ────────────────────────────────────────────────

describe("empty and whitespace input", () => {
  it("returns not_meeting_link for empty string", () => {
    expectStatus("", "not_meeting_link");
  });

  it("returns not_meeting_link for whitespace only", () => {
    expectStatus("   ", "not_meeting_link");
  });
});

// ─── Legitimate platforms ────────────────────────────────────────────────────

describe("legitimate platforms — Zoom", () => {
  it("recognizes zoom.us", () => {
    const r = expectStatus("https://zoom.us/j/123456", "safe");
    expect(r.platform).toBe("Zoom");
  });

  it("recognizes vanity subdomain us05web.zoom.us", () => {
    const r = expectStatus("https://us05web.zoom.us/j/123456", "safe");
    expect(r.platform).toBe("Zoom");
  });

  it("recognizes company vanity e.g. tesla.zoom.us", () => {
    expectStatus("https://tesla.zoom.us/j/9999", "safe");
  });

  it("recognizes nested subdomain a.b.zoom.us", () => {
    expectStatus("https://a.b.zoom.us/j/123", "safe");
  });

  it("works without protocol", () => {
    expectStatus("zoom.us/j/123456", "safe");
  });

  it("recognizes zoomgov.com", () => {
    const r = expectStatus("https://zoomgov.com/j/123", "safe");
    expect(r.platform).toBe("Zoom (Government)");
  });
});

describe("legitimate platforms — Google Meet", () => {
  it("recognizes meet.google.com", () => {
    const r = expectStatus("https://meet.google.com/abc-defg-hij", "safe");
    expect(r.platform).toBe("Google Meet");
  });
});

describe("legitimate platforms — Microsoft Teams", () => {
  it("recognizes teams.microsoft.com", () => {
    const r = expectStatus(
      "https://teams.microsoft.com/l/meetup-join/123",
      "safe",
    );
    expect(r.platform).toBe("Microsoft Teams");
  });

  it("recognizes teams.live.com", () => {
    expectStatus("https://teams.live.com/meet/123", "safe");
  });
});

describe("legitimate platforms — Webex", () => {
  it("recognizes company.webex.com", () => {
    const r = expectStatus("https://company.webex.com/meet/user", "safe");
    expect(r.platform).toBe("Webex");
  });
});

describe("legitimate platforms — Calendly", () => {
  it("recognizes calendly.com", () => {
    expectStatus("https://calendly.com/user/meeting", "safe");
  });
});

describe("legitimate platforms — Discord", () => {
  it("recognizes discord.com", () => {
    expectStatus("https://discord.com/invite/abc", "safe");
  });

  it("recognizes discord.gg", () => {
    expectStatus("https://discord.gg/abc", "safe");
  });
});

describe("legitimate platforms — Telegram", () => {
  it("recognizes t.me", () => {
    expectStatus("https://t.me/username", "safe");
  });

  it("recognizes telegram.org", () => {
    expectStatus("https://telegram.org/group", "safe");
  });
});

describe("legitimate platforms — Twitter/X", () => {
  it("recognizes twitter.com", () => {
    expectStatus("https://twitter.com/user", "safe");
  });

  it("recognizes x.com", () => {
    expectStatus("https://x.com/user", "safe");
  });
});

describe("legitimate platforms — newly added", () => {
  it("recognizes slack.com", () => {
    const r = expectStatus("https://slack.com/huddle/123", "safe");
    expect(r.platform).toBe("Slack");
  });

  it("recognizes app.slack.com", () => {
    expectStatus("https://app.slack.com/huddle/123", "safe");
  });

  it("recognizes gotomeeting.com", () => {
    const r = expectStatus("https://gotomeeting.com/join/123", "safe");
    expect(r.platform).toBe("GoTo Meeting");
  });

  it("recognizes app.goto.com", () => {
    expectStatus("https://app.goto.com/meeting/123", "safe");
  });

  it("recognizes meet.jit.si", () => {
    const r = expectStatus("https://meet.jit.si/MyRoom", "safe");
    expect(r.platform).toBe("Jitsi Meet");
  });

  it("recognizes chime.aws", () => {
    expectStatus("https://chime.aws/123", "safe");
  });

  it("recognizes loom.com", () => {
    expectStatus("https://loom.com/share/abc", "safe");
  });

  it("recognizes riverside.fm", () => {
    expectStatus("https://riverside.fm/studio/abc", "safe");
  });

  it("recognizes join.skype.com", () => {
    expectStatus("https://join.skype.com/abc123", "safe");
  });

  it("recognizes skype.com", () => {
    expectStatus("https://skype.com/call/abc", "safe");
  });

  it("recognizes signal.group", () => {
    expectStatus("https://signal.group/#abc", "safe");
  });

  it("recognizes signal.me", () => {
    expectStatus("https://signal.me/#p/abc", "safe");
  });

  it("recognizes whereby.com", () => {
    expectStatus("https://whereby.com/myroom", "safe");
  });

  it("recognizes cal.com", () => {
    expectStatus("https://cal.com/user/meeting", "safe");
  });
});

// ─── Dangerous URI schemes ───────────────────────────────────────────────────

describe("dangerous URI schemes", () => {
  it("flags javascript: URIs", () => {
    const r = expectStatus("javascript:alert(1)//zoom.us", "dangerous");
    expect(r.message).toMatch(/Dangerous URI scheme/i);
  });

  it("flags data: URIs", () => {
    expectStatus("data:text/html,<script>alert(1)</script>", "dangerous");
  });

  it("flags blob: URIs", () => {
    expectStatus("blob:https://evil.com/abc", "dangerous");
  });

  it("flags vbscript: URIs", () => {
    expectStatus("vbscript:MsgBox('hi')", "dangerous");
  });
});

// ─── Local file paths ────────────────────────────────────────────────────────

describe("local file paths", () => {
  it("flags file:// protocol", () => {
    expectStatus("file:///C:/Users/zoom.html", "dangerous");
  });

  it("flags Windows paths", () => {
    expectStatus("C:\\Users\\zoom.html", "dangerous");
  });

  it("flags Unix home paths", () => {
    expectStatus("/home/user/zoom.html", "dangerous");
  });

  it("flags macOS user paths", () => {
    expectStatus("/Users/user/zoom.html", "dangerous");
  });

  it("flags tilde paths", () => {
    expectStatus("~/zoom.html", "dangerous");
  });

  it("flags relative paths", () => {
    expectStatus("./zoom.html", "dangerous");
  });
});

// ─── Fragment / hash trick ───────────────────────────────────────────────────

describe("fragment trick", () => {
  it("detects evil.com/#zoom.us", () => {
    const r = expectStatus("evil.com/#zoom.us", "dangerous");
    expect(r.message).toMatch(/fragment/i);
  });

  it("detects evil.com/#meet.google.com", () => {
    expectStatus("evil.com/#meet.google.com", "dangerous");
  });

  it("does NOT flag legitimate zoom.us with fragment", () => {
    // zoom.us is a legitimate platform, fragment with meeting keywords shouldn't trigger
    expectStatus("https://zoom.us/j/123#teams", "safe");
  });

  it("detects evil.com/#slack.com (newly synced keyword)", () => {
    expectStatus("evil.com/#slack.com", "dangerous");
  });

  it("detects evil.com/#skype (newly synced keyword)", () => {
    expectStatus("evil.com/#skype", "dangerous");
  });
});

// ─── Query parameter redirect trick ─────────────────────────────────────────

describe("query param redirect trick", () => {
  it("detects redirect=zoom.us on non-meeting domain", () => {
    const r = expectStatus(
      "https://auth.evil.com/?redirect=https://zoom.us/j/123",
      "dangerous",
    );
    expect(r.message).toMatch(/redirect/i);
  });

  it("detects url=meet.google.com on non-meeting domain", () => {
    expectStatus("https://evil.com/?url=meet.google.com/abc", "dangerous");
  });

  it("detects redirect=slack.com on non-meeting domain (newly synced)", () => {
    expectStatus(
      "https://evil.com/?redirect=https://slack.com/huddle",
      "dangerous",
    );
  });

  it("detects redirect=signal.group on non-meeting domain (newly synced)", () => {
    expectStatus(
      "https://evil.com/?redirect=https://signal.group/abc",
      "dangerous",
    );
  });
});

// ─── @ symbol (userinfo) trick ───────────────────────────────────────────────

describe("@ symbol trick", () => {
  it("detects https://zoom.us@evil.com", () => {
    const r = expectStatus("https://zoom.us@evil.com/j/123", "dangerous");
    expect(r.message).toMatch(/deception/i);
  });

  it("detects meet.google.com@evil.com", () => {
    expectStatus("https://meet.google.com@evil.com/abc", "dangerous");
  });

  it("detects slack.com@evil.com (newly synced keyword)", () => {
    expectStatus("https://slack.com@evil.com/huddle", "dangerous");
  });
});

// ─── IP address hosting ─────────────────────────────────────────────────────

describe("IP address detection", () => {
  it("flags IPv4 address", () => {
    const r = expectStatus("https://192.168.1.1/zoom/j/123", "dangerous");
    expect(r.message).toMatch(/IP address/i);
  });

  it("flags localhost", () => {
    expectStatus("https://localhost/zoom", "dangerous");
  });
});

// ─── URL shorteners ─────────────────────────────────────────────────────────

describe("URL shorteners", () => {
  it("flags bit.ly links as unverifiable", () => {
    const r = expectStatus("https://bit.ly/abc123", "unverifiable");
    expect(r.message).toMatch(/shortened/i);
  });

  it("flags tinyurl.com", () => {
    expectStatus("https://tinyurl.com/abc", "unverifiable");
  });

  it("flags t.co", () => {
    expectStatus("https://t.co/abc", "unverifiable");
  });

  it("flags cutt.ly", () => {
    expectStatus("https://cutt.ly/abc", "unverifiable");
  });

  it("flags rb.gy", () => {
    expectStatus("https://rb.gy/abc", "unverifiable");
  });
});

// ─── Open redirect patterns ─────────────────────────────────────────────────

describe("open redirect patterns", () => {
  it("flags google.com/url redirect", () => {
    expectStatus(
      "https://www.google.com/url?q=https://evil.com",
      "unverifiable",
    );
  });

  it("flags facebook.com/l.php redirect", () => {
    expectStatus(
      "https://facebook.com/l.php?u=https://evil.com",
      "unverifiable",
    );
  });

  it("flags youtube.com/redirect", () => {
    expectStatus(
      "https://youtube.com/redirect?q=https://evil.com",
      "unverifiable",
    );
  });
});

// ─── Homoglyph / Unicode attacks ─────────────────────────────────────────────

describe("homoglyph attacks", () => {
  it("flags Cyrillic characters in domain (URL parser converts to punycode)", () => {
    // Build a domain with Cyrillic 'о' (U+043E) instead of Latin 'o'
    // The URL constructor converts this to punycode (xn--...), so
    // the punycode check fires before the homoglyph check — both are dangerous
    const cyrillicO = String.fromCodePoint(0x043e);
    const phishingUrl = `https://z${cyrillicO}${cyrillicO}m.us/j/123`;
    const r = expectStatus(phishingUrl, "dangerous");
    expect(r.message).toMatch(/Internationalized domain/i);
  });
});

// ─── Punycode (IDN) attacks ──────────────────────────────────────────────────

describe("punycode domain attacks", () => {
  it("flags xn-- encoded domains", () => {
    const r = expectStatus("https://xn--zm-fmca.us/j/123", "dangerous");
    expect(r.message).toMatch(/Internationalized domain/i);
  });
});

// ─── Phishing patterns — subdomain tricks ────────────────────────────────────

describe("subdomain tricks", () => {
  it("flags zoom.evil.com (zoom as subdomain)", () => {
    const r = expectStatus("https://zoom.evil.com/j/123", "dangerous");
    expect(r.details).toMatch(/subdomain/i);
  });

  it("flags zoom.webus05.us (the original scam)", () => {
    expectStatus("https://zoom.webus05.us/j/123", "dangerous");
  });

  it("flags meet.evil.org", () => {
    expectStatus("https://meet.evil.org/abc", "dangerous");
  });

  it("flags teams.evil.net", () => {
    expectStatus("https://teams.evil.net/meet", "dangerous");
  });

  // NEW: catches TLDs that were previously missed
  it("flags zoom.evil.xyz (previously missed TLD)", () => {
    expectStatus("https://zoom.evil.xyz/j/123", "dangerous");
  });

  it("flags zoom.evil.app (previously missed TLD)", () => {
    expectStatus("https://zoom.evil.app/j/123", "dangerous");
  });

  it("flags zoom.evil.dev (previously missed TLD)", () => {
    expectStatus("https://zoom.evil.dev/j/123", "dangerous");
  });

  it("flags zoom.evil.site", () => {
    expectStatus("https://zoom.evil.site/j/123", "dangerous");
  });

  it("flags zoom.evil.co", () => {
    expectStatus("https://zoom.evil.co/j/123", "dangerous");
  });

  it("flags slack.evil.com (newly added pattern)", () => {
    expectStatus("https://slack.evil.com/huddle/123", "dangerous");
  });

  it("flags skype.evil.xyz (newly added pattern)", () => {
    expectStatus("https://skype.evil.xyz/call/123", "dangerous");
  });
});

// ─── Digit lookalike attacks (0→o, 1→l) ─────────────────────────────────────

describe("digit lookalike attacks", () => {
  it("flags z00m.us (0 for o in zoom)", () => {
    const r = expectStatus("https://z00m.us/j/123", "dangerous");
    expect(r.message).toMatch(/Digit lookalike/i);
  });

  it("flags zo0m.us (single 0 for o)", () => {
    expectStatus("https://zo0m.us/j/123", "dangerous");
  });

  it("flags s1ack.com (1 for l in slack)", () => {
    const r = expectStatus("https://s1ack.com/huddle", "dangerous");
    expect(r.message).toMatch(/Digit lookalike/i);
  });

  it("flags l00m.com (0 for o in loom)", () => {
    expectStatus("https://l00m.com/share/abc", "dangerous");
  });

  it("flags g0t0.com (0 for o in goto)", () => {
    expectStatus("https://g0t0.com/meeting", "dangerous");
  });

  it("does NOT flag legitimate domains with digits", () => {
    // web01.example.com normalizes to webo1.example.com — no meeting keyword
    expectStatus("https://web01.example.com", "not_meeting_link");
  });
});

// ─── Phishing patterns — lookalike characters ────────────────────────────────

describe("lookalike character phishing", () => {
  it("flags 2oom (2 instead of z)", () => {
    expectStatus("https://2oom.us/j/123", "dangerous");
  });
});

// ─── Phishing patterns — extra words ─────────────────────────────────────────

describe("extra words in domain", () => {
  it("flags zoom-meeting.com", () => {
    expectStatus("https://zoom-meeting.com/j/123", "dangerous");
  });

  it("flags zoom_call.com", () => {
    expectStatus("https://zoom_call.com/j/123", "dangerous");
  });

  it("flags meeting-zoom.com", () => {
    expectStatus("https://meeting-zoom.com/j/123", "dangerous");
  });
});

// ─── Phishing patterns — wrong TLD ──────────────────────────────────────────

describe("wrong TLD patterns", () => {
  it("flags zoom.us.malicious.com", () => {
    expectStatus("https://zoom.us.malicious.com/j/123", "dangerous");
  });

  it("flags zoom.us.com", () => {
    expectStatus("https://zoom.us.com/j/123", "dangerous");
  });

  it("flags zoom.us.net", () => {
    expectStatus("https://zoom.us.net/j/123", "dangerous");
  });

  it("flags google.com.evil.com", () => {
    expectStatus("https://google.com.evil.com/meet", "dangerous");
  });

  it("flags microsoft.com.evil.com", () => {
    expectStatus("https://microsoft.com.evil.com/teams", "dangerous");
  });
});

// ─── Phishing patterns — typosquatting ───────────────────────────────────────

describe("typosquatting", () => {
  it("flags zooom.us (extra o)", () => {
    expectStatus("https://zooom.us/j/123", "dangerous");
  });

  it("flags zomm.us (swapped letters)", () => {
    expectStatus("https://zomm.us/j/123", "dangerous");
  });

  it("flags zoomus.com (missing dot)", () => {
    expectStatus("https://zoomus.com/j/123", "dangerous");
  });
});

// ─── Suspicious (unverified meeting-like) links ──────────────────────────────

describe("suspicious / unverified meeting links", () => {
  it("flags unknown domain with zoom in path", () => {
    expectStatus("https://example.com/zoom/j/123", "suspicious");
  });

  it("flags unknown domain with meeting keyword", () => {
    expectStatus("https://myfakesite.com/video-conference", "suspicious");
  });

  it("flags unknown domain with call keyword", () => {
    expectStatus("https://random.io/call/join", "suspicious");
  });
});

// ─── Not a meeting link ─────────────────────────────────────────────────────

describe("not a meeting link", () => {
  it("returns not_meeting_link for generic URLs", () => {
    expectStatus("https://example.com", "not_meeting_link");
  });

  it("returns not_meeting_link for random domains", () => {
    expectStatus("https://shopping.amazon.com/deals", "not_meeting_link");
  });

  it("returns not_meeting_link for invalid URL text", () => {
    expectStatus("not a url at all!!!!", "not_meeting_link");
  });
});

// ─── Edge cases ──────────────────────────────────────────────────────────────

describe("edge cases", () => {
  it("handles trailing dot in hostname (zoom.us.)", () => {
    // Trailing dots are normalized; zoom.us. should still match zoom.us
    expectStatus("https://zoom.us./j/123", "safe");
  });

  it("handles mixed case (ZOOM.US)", () => {
    expectStatus("https://ZOOM.US/j/123", "safe");
  });

  it("handles URLs with port numbers", () => {
    expectStatus("https://zoom.us:443/j/123", "safe");
  });

  it("handles URLs with query params", () => {
    expectStatus("https://zoom.us/j/123?pwd=abc", "safe");
  });

  it("handles URLs without path", () => {
    expectStatus("https://zoom.us", "safe");
  });

  it("strips leading/trailing whitespace", () => {
    expectStatus("  zoom.us/j/123  ", "safe");
  });
});

// ─── getSupportedPlatforms ───────────────────────────────────────────────────

describe("getSupportedPlatforms", () => {
  it("returns a sorted array of unique platform names", () => {
    const platforms = getSupportedPlatforms();
    expect(Array.isArray(platforms)).toBe(true);
    expect(platforms.length).toBeGreaterThan(0);

    // Check it's sorted
    const sorted = [...platforms].sort();
    expect(platforms).toEqual(sorted);

    // Check uniqueness
    const unique = [...new Set(platforms)];
    expect(platforms).toEqual(unique);
  });

  it("includes key platforms", () => {
    const platforms = getSupportedPlatforms();
    expect(platforms).toContain("Zoom");
    expect(platforms).toContain("Google Meet");
    expect(platforms).toContain("Microsoft Teams");
    expect(platforms).toContain("Slack");
    expect(platforms).toContain("Skype");
    expect(platforms).toContain("Jitsi Meet");
    expect(platforms).toContain("Signal");
  });
});
