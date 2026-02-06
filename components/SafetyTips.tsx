"use client";

import { useState } from "react";
import { getSupportedPlatforms } from "@/lib/validators";

export function SafetyTips() {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set());
  const platforms = getSupportedPlatforms();

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(section)) {
        next.delete(section);
      } else {
        next.add(section);
      }
      return next;
    });
  };

  return (
    <div className="w-full max-w-2xl mx-auto mt-12">
      {/* The Scam Explained */}
      <div className="bg-white border border-[#e0d8e8] rounded-2xl p-6 mb-6 shadow-sm">
        <button
          onClick={() => toggleSection("scam")}
          aria-expanded={expandedSections.has("scam")}
          className="w-full flex items-center justify-between text-left"
        >
          <h2 className="text-lg font-semibold text-[#110320] flex items-center gap-2">
            <svg className="w-5 h-5 text-[#CC192E]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            How the Ongoing Fake Zoom Scam Works
          </h2>
          <svg
            className={`w-5 h-5 text-[#110320]/40 transition-transform ${expandedSections.has("scam") ? "rotate-180" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {expandedSections.has("scam") && (
          <div className="mt-4 space-y-4 text-[#110320]/70 text-sm leading-relaxed">
            <p>
              <span className="text-[#110320] font-semibold">1. Initial Contact:</span> You receive a meeting link from what appears to be a trusted source. The link looks almost identical to a real Zoom URL.
            </p>
            <p>
              <span className="text-[#110320] font-semibold">2. The Trick:</span> The hostname and subdomain are swapped. Instead of{" "}
              <code className="bg-[#3BA035]/15 text-[#3BA035] px-1.5 py-0.5 rounded font-medium">us05web.zoom.us</code>, you see{" "}
              <code className="bg-[#CC192E]/15 text-[#CC192E] px-1.5 py-0.5 rounded font-medium">zoom.[fake domain].us</code>
            </p>
            <p>
              <span className="text-[#110320] font-semibold">3. Fake App:</span> The phishing site shows a perfect copy of Zoom&apos;s UI, even sometimes displaying a recording of a trusted party.
            </p>
            <p>
              <span className="text-[#110320] font-semibold">4. The Trap:</span> A fake popup about a technical issue appears, prompting you to copy and run a &quot;fix&quot; command in your terminal. This command installs malware, giving attackers full access to your computer.
            </p>
            <p>
              <span className="text-[#110320] font-semibold">5. The Theft:</span> The malware steals credentials, crypto wallets, and browser session cookies, bypassing 2FA completely.
            </p>
          </div>
        )}
      </div>

      {/* Warning: Even Legit Links Can Be Dangerous */}
      <div className="bg-white border border-[#e0d8e8] rounded-2xl p-6 mb-6 shadow-sm">
        <button
          onClick={() => toggleSection("legitWarning")}
          aria-expanded={expandedSections.has("legitWarning")}
          className="w-full flex items-center justify-between text-left"
        >
          <h2 className="text-lg font-semibold text-[#110320] flex items-center gap-2">
            <svg className="w-5 h-5 text-[#FC5217]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Even Legitimate Links Can Be Dangerous
          </h2>
          <svg
            className={`w-5 h-5 text-[#110320]/40 transition-transform ${expandedSections.has("legitWarning") ? "rotate-180" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {expandedSections.has("legitWarning") && (
          <div className="mt-4 space-y-4 text-[#110320]/70 text-sm leading-relaxed">
            <p className="text-[#110320] font-medium">
              A &quot;Safe&quot; result only means the link goes to a real platform. Sophisticated attackers use legitimate meeting links for social engineering attacks:
            </p>
            <p>
              <span className="text-[#110320] font-semibold">Compromised Account Attacks:</span> Your friend&apos;s or colleague&apos;s account may have been hacked. You join a real Zoom call and see what appears to be someone you know, but the attacker is controlling the session using pre-recorded footage or deepfake video. Always verify identity through a separate channel if something feels off.
            </p>
            <p>
              <span className="text-[#110320] font-semibold">Zoom Remote Control Hijacking:</span> Zoom has a legitimate &quot;Remote Control&quot; feature that lets participants control your screen. Attackers trigger real Zoom permission popups that look completely authentic. Even if you know the caller, be extremely cautious—once granted, they can install malware or access sensitive data in seconds. <strong>Deny all remote control requests unless absolutely necessary.</strong>
            </p>
            <p>
              <span className="text-[#110320] font-semibold">Screenshare Exploitation:</span> Attackers may ask you to share your screen to &quot;help troubleshoot&quot; an issue, then observe sensitive information like passwords, seed phrases, or private keys.
            </p>
            <p>
              <span className="text-[#110320] font-semibold">In-Meeting Malware Links:</span> Once in a legitimate meeting, attackers may share malicious links or files in the chat. The trust built from being in a &quot;real&quot; meeting makes victims more likely to click.
            </p>
            <p>
              <span className="text-[#110320] font-semibold">Calendar Invite Spoofing:</span> Attackers compromise accounts and send calendar invites from trusted contacts. The meeting itself is real, but the person on the other end may not be who you expect.
            </p>
            <p>
              <span className="text-[#110320] font-semibold">Long-Con Social Engineering:</span> Some attackers invest months or even years building genuine relationships before striking. They may pose as helpful developers, crypto contacts, or industry peers. Trust built over time does not guarantee safety.
            </p>
            <p className="bg-[#FC5217]/10 border border-[#FC5217]/20 rounded-lg p-3 text-[#110320]">
              <strong>Bottom line:</strong> This tool verifies the link is authentic, but cannot verify the intentions of the person on the other end. Stay vigilant during calls, especially if asked to share screens, grant remote access, run commands, or download files.
            </p>
          </div>
        )}
      </div>

      {/* Safety Tips */}
      <div className="bg-white border border-[#e0d8e8] rounded-2xl p-6 mb-6 shadow-sm">
        <button
          onClick={() => toggleSection("safety")}
          aria-expanded={expandedSections.has("safety")}
          className="w-full flex items-center justify-between text-left"
        >
          <h2 className="text-lg font-semibold text-[#110320] flex items-center gap-2">
            <svg className="w-5 h-5 text-[#3BA035]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            How to Stay Safe
          </h2>
          <svg
            className={`w-5 h-5 text-[#110320]/40 transition-transform ${expandedSections.has("safety") ? "rotate-180" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {expandedSections.has("safety") && (
          <ul className="mt-4 space-y-3">
            {[
              "Verify unexpected meeting requests through a different channel (call, text, DM on another platform)",
              "Check that the main domain matches the platform (zoom.us, not zoom.something.us)",
              "Never run terminal commands from a meeting app or \"troubleshooting\" guide. This is always malware.",
              "If something feels off mid-call (audio issues, strange UI), leave and rejoin through zoom.us directly",
              "Scammers may use AI-generated video or real recordings of people you know. A familiar face on screen doesn't mean it's actually them.",
              "Use a hardware wallet for crypto and keep it disconnected when not in use",
              "Scammers rely on urgency, fear, and FOMO to override your judgment. If you feel rushed, slow down.",
            ].map((tip, index) => (
              <li key={index} className="flex items-start gap-3 text-[#110320]/70 text-sm">
                <svg className="w-5 h-5 text-[#3BA035] flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                {tip}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Supported Platforms */}
      <div className="bg-white border border-[#e0d8e8] rounded-2xl p-6 mb-6 shadow-sm">
        <button
          onClick={() => toggleSection("platforms")}
          aria-expanded={expandedSections.has("platforms")}
          className="w-full flex items-center justify-between text-left"
        >
          <h2 className="text-lg font-semibold text-[#110320] flex items-center gap-2">
            <svg className="w-5 h-5 text-[#8750FF]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            Supported Platforms ({platforms.length})
          </h2>
          <svg
            className={`w-5 h-5 text-[#110320]/40 transition-transform ${expandedSections.has("platforms") ? "rotate-180" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {expandedSections.has("platforms") && (
          <div className="mt-4 flex flex-wrap gap-2">
            {platforms.map((platform) => (
              <span
                key={platform}
                className="px-3 py-1.5 bg-[#8750FF]/10 border border-[#8750FF]/20 rounded-full text-[#8750FF] text-sm font-medium"
              >
                {platform}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Disclaimer */}
      <div className="bg-white border border-[#e0d8e8] rounded-2xl p-6 shadow-sm">
        <button
          onClick={() => toggleSection("disclaimer")}
          aria-expanded={expandedSections.has("disclaimer")}
          className="w-full flex items-center justify-between text-left"
        >
          <h2 className="text-lg font-semibold text-[#110320] flex items-center gap-2">
            <svg className="w-5 h-5 text-[#110320]/50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Disclaimer
          </h2>
          <svg
            className={`w-5 h-5 text-[#110320]/40 transition-transform ${expandedSections.has("disclaimer") ? "rotate-180" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {expandedSections.has("disclaimer") && (
          <div className="mt-4 space-y-3 text-[#110320]/60 text-xs leading-relaxed">
            <p>
              <strong className="text-[#110320]/80">No Guarantee of Security:</strong> This tool is provided &quot;as is&quot; for educational and informational purposes only. While we strive to detect known phishing patterns, no automated tool can guarantee 100% protection against all threats. New attack vectors emerge constantly, and sophisticated attackers may use techniques not yet covered by this tool.
            </p>
            <p>
              <strong className="text-[#110320]/80">Not Professional Advice:</strong> The results provided by this tool do not constitute professional security, legal, or financial advice. Users should exercise their own judgment and consult with qualified professionals when dealing with suspicious links or potential security threats.
            </p>
            <p>
              <strong className="text-[#110320]/80">Limitation of Liability:</strong> Fairside and its affiliates shall not be held liable for any damages, losses, or security breaches that may occur as a result of using or relying on this tool. Users assume all risks associated with clicking on any links, whether marked as safe or otherwise.
            </p>
            <p>
              <strong className="text-[#110320]/80">Third-Party Platforms:</strong> This tool checks URLs against known legitimate domains but has no affiliation with Zoom, Google, Microsoft, or any other platform mentioned. The legitimacy of a domain does not guarantee the safety of any meeting or the intentions of participants.
            </p>
            <p>
              <strong className="text-[#110320]/80">Data Privacy:</strong> URLs entered into this tool are processed locally in your browser. We do not store, log, or transmit the links you check.
            </p>
            <p className="pt-2 border-t border-[#e0d8e8]">
              By using this tool, you acknowledge that you have read and understood this disclaimer and agree to use the tool at your own risk.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
