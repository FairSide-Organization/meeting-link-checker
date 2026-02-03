"use client";

import { useState, useCallback } from "react";
import { validateMeetingLink, ValidationResult } from "@/lib/validators";
import { ResultDisplay } from "./ResultDisplay";

export function LinkChecker() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [isChecking, setIsChecking] = useState(false);

  const handleCheck = useCallback(() => {
    if (!url.trim()) return;

    setIsChecking(true);
    // Small delay for visual feedback
    setTimeout(() => {
      const validationResult = validateMeetingLink(url);
      setResult(validationResult);
      setIsChecking(false);
    }, 300);
  }, [url]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      handleCheck();
    }
  };

  const handlePaste = useCallback((e: React.ClipboardEvent<HTMLInputElement>) => {
    const pastedText = e.clipboardData.getData("text");
    // Auto-check on paste if it looks like a URL
    if (pastedText && (pastedText.includes(".") || pastedText.includes("/"))) {
      setTimeout(() => {
        const validationResult = validateMeetingLink(pastedText);
        setResult(validationResult);
      }, 100);
    }
  }, []);

  const handleClear = () => {
    setUrl("");
    setResult(null);
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="relative">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={handleKeyDown}
              onPaste={handlePaste}
              placeholder="Paste a meeting link to check (e.g., zoom.us/j/123456)"
              className="w-full px-5 py-4 bg-white border border-[#e0d8e8] rounded-2xl text-[#110320] placeholder-[#110320]/40 focus:outline-none focus:border-[#8750FF] focus:ring-4 focus:ring-[#8750FF]/10 transition-all text-base shadow-sm"
              autoComplete="off"
              spellCheck="false"
            />
            {url && (
              <button
                onClick={handleClear}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-[#110320]/30 hover:text-[#110320] transition-colors"
                aria-label="Clear input"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>
          <button
            onClick={handleCheck}
            disabled={!url.trim() || isChecking}
            className="px-8 py-4 bg-[#8750FF] hover:bg-[#7040EE] disabled:bg-[#d0c0e0] disabled:text-[#110320]/40 disabled:cursor-not-allowed rounded-2xl font-semibold text-white transition-all flex items-center gap-2 min-w-[160px] justify-center shadow-sm"
          >
            {isChecking ? (
              <>
                <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Checking...
              </>
            ) : (
              <>
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Check Link
              </>
            )}
          </button>
        </div>
      </div>

      {result && <ResultDisplay result={result} />}

      <p className="mt-6 text-center text-[#110320]/50 text-sm">
        Paste any meeting link and we&apos;ll verify if it&apos;s from a legitimate platform
      </p>
    </div>
  );
}
