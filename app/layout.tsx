import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Meeting Link Checker | Fairside Security",
  description: "Verify meeting links are legitimate before clicking. Protect yourself from phishing scams targeting crypto users.",
  keywords: ["meeting link checker", "zoom phishing", "crypto security", "fairside", "link verification"],
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
      </body>
    </html>
  );
}
