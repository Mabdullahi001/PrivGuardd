import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PrivGuard",
  description: "Email privacy and security analysis",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
