"use client";

import { ValidationResult } from "@/lib/validators";

interface ResultDisplayProps {
  result: ValidationResult;
}

export function ResultDisplay({ result }: ResultDisplayProps) {
  const statusConfig = {
    safe: {
      icon: (
        <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
      bgColor: "bg-[#3BA035]/5",
      borderColor: "border-[#3BA035]/30",
      accentColor: "border-l-[#3BA035]",
      textColor: "text-[#3BA035]",
      label: "VERIFIED DOMAIN",
    },
    suspicious: {
      icon: (
        <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      ),
      bgColor: "bg-[#FC5217]/5",
      borderColor: "border-[#FC5217]/30",
      accentColor: "border-l-[#FC5217]",
      textColor: "text-[#FC5217]",
      label: "SUSPICIOUS",
    },
    dangerous: {
      icon: (
        <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
      bgColor: "bg-[#CC192E]/5",
      borderColor: "border-[#CC192E]/30",
      accentColor: "border-l-[#CC192E]",
      textColor: "text-[#CC192E]",
      label: "DANGER - LIKELY PHISHING",
    },
    not_meeting_link: {
      icon: (
        <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
      bgColor: "bg-[#3C95E5]/5",
      borderColor: "border-[#3C95E5]/30",
      accentColor: "border-l-[#3C95E5]",
      textColor: "text-[#3C95E5]",
      label: "NOT A MEETING LINK",
    },
    unverifiable: {
      icon: (
        <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
      bgColor: "bg-[#8750FF]/5",
      borderColor: "border-[#8750FF]/30",
      accentColor: "border-l-[#8750FF]",
      textColor: "text-[#8750FF]",
      label: "CANNOT VERIFY",
    },
  };

  const config = statusConfig[result.status];

  return (
    <div
      className={`mt-6 p-6 rounded-2xl border ${config.borderColor} ${config.bgColor} border-l-4 ${config.accentColor} bg-white shadow-sm transition-all duration-300`}
    >
      <div className="flex items-start gap-4">
        <div className={`${config.textColor} flex-shrink-0`}>{config.icon}</div>
        <div className="flex-1 min-w-0">
          <div className={`text-xs font-bold tracking-wider ${config.textColor} mb-1`}>
            {config.label}
          </div>
          <h3 className="text-lg font-semibold text-[#110320] mb-2">{result.message}</h3>
          {result.details && (
            <p className="text-[#110320]/70 text-sm leading-relaxed">{result.details}</p>
          )}
          {result.hostname && (
            <div className="mt-3 p-3 bg-[#f8f6fa] rounded-xl border border-[#e0d8e8]">
              <span className="text-[#110320]/50 text-xs">Domain: </span>
              <code className={`text-sm ${config.textColor} font-medium`}>{result.hostname}</code>
            </div>
          )}
          {result.platform && (
            <div className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 bg-[#3BA035]/10 rounded-full">
              <span className="w-2 h-2 bg-[#3BA035] rounded-full"></span>
              <span className="text-[#3BA035] text-sm font-medium">{result.platform}</span>
            </div>
          )}
        </div>
      </div>

      {result.status === "safe" && (
        <div className="mt-4 p-4 bg-[#FC5217]/5 border border-[#FC5217]/20 rounded-xl">
          <p className="text-[#FC5217] text-sm font-medium">
            Verified domain does not mean verified safe.
          </p>
          <p className="text-[#110320]/60 text-xs mt-1">
            Attackers use legitimate links for social engineering—watch for screenshare requests, remote control popups, or prompts to run commands.
          </p>
        </div>
      )}

      {result.status === "dangerous" && (
        <div className="mt-4 p-4 bg-[#CC192E]/5 border border-[#CC192E]/20 rounded-xl">
          <p className="text-[#CC192E] text-sm font-medium">
            Do NOT click this link or enter any information on this site.
          </p>
          <p className="text-[#CC192E]/70 text-xs mt-1">
            This appears to be a phishing attempt designed to steal your credentials or install malware.
          </p>
        </div>
      )}

      {result.status === "suspicious" && (
        <div className="mt-4 p-4 bg-[#FC5217]/5 border border-[#FC5217]/20 rounded-xl">
          <p className="text-[#FC5217] text-sm font-medium">
            Verify this link with the sender through a different channel.
          </p>
          <p className="text-[#FC5217]/70 text-xs mt-1">
            Contact them via phone, a different messaging app, or in person to confirm they sent this link.
          </p>
        </div>
      )}

      {result.status === "unverifiable" && (
        <div className="mt-4 p-4 bg-[#8750FF]/5 border border-[#8750FF]/20 rounded-xl">
          <p className="text-[#8750FF] text-sm font-medium">
            Ask for the direct link instead of a shortened URL.
          </p>
          <p className="text-[#110320]/60 text-xs mt-1">
            URL shorteners hide the true destination. Request the full meeting link (e.g., zoom.us/j/...) from the sender so we can verify it.
          </p>
        </div>
      )}
    </div>
  );
}
