import type { Metadata } from "next";
import Script from "next/script";
import "./globals.css";

const GA_MEASUREMENT_ID = "G-3VPK83VLZZ";

export const metadata: Metadata = {
  title: "Meeting Link Checker | Fairside Security",
  description: "Verify meeting links are legitimate before clicking. Protect yourself from phishing scams targeting crypto users.",
  keywords: ["meeting link checker", "zoom phishing", "crypto security", "fairside", "link verification"],
  icons: {
    icon: "/fairside-logo-purple.png",
  },
  openGraph: {
    title: "Meeting Link Checker | Fairside Security",
    description: "Verify meeting links are legitimate before clicking. Protect yourself from phishing scams.",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Meeting Link Checker | Fairside Security",
    description: "Verify meeting links are legitimate before clicking. Protect yourself from phishing scams.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">
        {children}
        <Script
          strategy="afterInteractive"
          src={`https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}`}
        />
        <Script id="google-analytics" strategy="afterInteractive">
          {`
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
            gtag('config', '${GA_MEASUREMENT_ID}');
          `}
        </Script>
      </body>
    </html>
  );
}
