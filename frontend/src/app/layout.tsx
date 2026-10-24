import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Alert Triage Console",
  description: "AI security-alert triage agent dashboard",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="h-full">{children}</body>
    </html>
  );
}
