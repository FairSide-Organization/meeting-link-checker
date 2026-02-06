import type { NextConfig } from "next";

const withBundleAnalyzer = require("@next/bundle-analyzer")({
  enabled: process.env.ANALYZE === "true",
});

const nextConfig: NextConfig = {
  output: "export",
  images: {
    unoptimized: true,
  },
  compiler: {
    // Strip console.* in production (keep error/warn) for smaller bundle
    removeConsole:
      process.env.NODE_ENV === "production"
        ? { exclude: ["error", "warn"] }
        : false,
  },
};

export default withBundleAnalyzer(nextConfig);
