import dynamic from "next/dynamic";
import Image from "next/image";
import { LinkChecker } from "@/components/LinkChecker";

const EXTENSION_URL =
  "https://chromewebstore.google.com/detail/meeting-guard/okloggikocjdmoimalohkkmjhhamdmlj";

const SafetyTips = dynamic(() => import("@/components/SafetyTips").then((m) => ({ default: m.SafetyTips })), {
  loading: () => (
    <div className="w-full max-w-2xl mx-auto mt-12 min-h-[200px] flex items-center justify-center text-[#110320]/50 text-sm">
      Loading safety tips…
    </div>
  ),
  ssr: true,
});

export default function Home() {
  return (
    <main className="min-h-screen bg-grid relative">
      {/* Top Banner: Extension Launch */}
      <div className="bg-[#8750FF] text-white relative z-10">
        <div className="max-w-6xl mx-auto px-4 py-2.5 flex items-center justify-center gap-x-3 gap-y-1.5 flex-wrap text-sm text-center">
          <span className="inline-flex items-center gap-2">
            <span className="relative inline-flex w-1.5 h-1.5">
              <span className="absolute inset-0 rounded-full bg-white animate-ping opacity-75" />
              <span className="relative inline-flex w-1.5 h-1.5 rounded-full bg-white" />
            </span>
            <span>
              <span className="font-semibold">New:</span> Meeting Guard, our free Chrome extension, is live
            </span>
          </span>
          <a
            href={EXTENSION_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-semibold underline underline-offset-2 decoration-white/60 hover:decoration-white"
          >
            Install free
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.2} className="w-3.5 h-3.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="5" y1="12" x2="19" y2="12" />
              <polyline points="12 5 19 12 12 19" />
            </svg>
          </a>
        </div>
      </div>

      {/* Powered by Fairside Badge */}
      <div className="pt-6 px-6">
        <a
          href="https://fairside.io"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 text-[#110320]/50 hover:text-[#110320]/80 text-sm transition-colors"
        >
          <Image
            src="/fairside-logo-purple.png"
            alt="Fairside"
            width={20}
            height={20}
            className="h-5 w-5"
          />
          <span className="font-medium">Fairside</span>
        </a>
      </div>

      {/* Hero Section */}
      <section className="pt-16 pb-4 px-4">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold text-[#110320] mb-6 leading-tight">
            Is my meeting link{" "}
            <span className="text-[#8750FF]">
              safe?
            </span>
          </h1>
          <p className="text-[#110320]/60 text-lg md:text-xl max-w-2xl mx-auto mb-6">
            Fake meeting links are used to steal credentials and install malware.
            Verify any suspicious link before clicking.
          </p>
        </div>
      </section>

      {/* Main Checker */}
      <section className="px-4 pb-10">
        <LinkChecker />
      </section>

      {/* Extension Promo */}
      <section className="px-4 pb-14">
        <div className="max-w-2xl mx-auto">
          <div
            className="rounded-2xl p-6 md:p-7 flex items-center gap-5 flex-wrap"
            style={{
              background:
                "linear-gradient(135deg, rgba(135, 80, 255, 0.08), rgba(135, 80, 255, 0.02))",
              border: "1px solid rgba(135, 80, 255, 0.2)",
            }}
          >
            <div
              className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0"
              style={{ background: "rgba(135, 80, 255, 0.12)", color: "#8750FF" }}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-[22px] h-[22px]" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div className="flex-1 min-w-[220px]">
              <div className="text-[10px] font-semibold uppercase tracking-[0.5px] text-[#8750FF] mb-1">
                Free Chrome Extension
              </div>
              <div className="text-base md:text-lg font-semibold text-[#110320]">
                Stay protected as you browse
              </div>
              <div className="text-sm text-[#110320]/60 mt-1">
                Meeting Guard warns you when unknown sites request your camera or mic and flags suspicious meeting links — automatically.
              </div>
            </div>
            <a
              href={EXTENSION_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="px-5 py-2.5 rounded-xl text-sm font-semibold text-white inline-flex items-center gap-1.5 transition-all hover:brightness-[0.92]"
              style={{ background: "#8750FF" }}
            >
              Get the free extension
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-3.5 h-3.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="7" y1="17" x2="17" y2="7" />
                <polyline points="7 7 17 7 17 17" />
              </svg>
            </a>
          </div>
        </div>
      </section>

      {/* Safety Tips */}
      <section className="px-4 pb-20">
        <SafetyTips />
      </section>

      {/* Footer */}
      <footer className="border-t border-[#d0c0e0] py-8 bg-white/30">
        <div className="max-w-4xl mx-auto px-4 text-center">
          <p className="text-[#110320]/60 text-sm">
            Built by{" "}
            <a href="https://fairside.io" target="_blank" rel="noopener noreferrer" className="text-[#8750FF] hover:underline transition-colors">
              Fairside
            </a>{" "}
            to help keep you safe online.
          </p>
          <p className="text-[#110320]/40 text-xs mt-2">
            This tool checks against known legitimate domains. Always exercise caution with any link.
          </p>
        </div>
      </footer>
    </main>
  );
}
