import Image from "next/image";
import { LinkChecker } from "@/components/LinkChecker";
import { SafetyTips } from "@/components/SafetyTips";

export default function Home() {
  return (
    <main className="min-h-screen bg-grid relative">
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
      <section className="px-4 pb-12">
        <LinkChecker />
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
