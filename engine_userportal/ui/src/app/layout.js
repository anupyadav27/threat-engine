import { Geist, Geist_Mono } from "next/font/google";
import "@/css/globals.css";
import { AppProvider } from "@/context/appContext";
import "@/scss/index.scss";

export const metadata = {
    title: "CSPM Platform",
    description: "Cloud Security Posture Management",
};

export default function RootLayout({ children }) {
    return (
        <html lang={`en`}>
            <body className={`antialiased`}>
                <AppProvider>{children}</AppProvider>
            </body>
        </html>
    );
}
