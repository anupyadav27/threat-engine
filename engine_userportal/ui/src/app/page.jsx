"use client";

import { useAppContext } from "@/context/appContext";
import { useEffect } from "react";
import PreLoader from "@/components/preLoader";
import { useRouter } from "next/navigation";

export default function Home() {
    const { state } = useAppContext();
    const router = useRouter();

    useEffect(() => {
        const timer = setTimeout(() => {
            if (state.isAuthenticated) {
                router.push(`/dashboard`);
            } else {
                router.push(`/auth/login`);
            }
        }, 500);
        return () => clearTimeout(timer);
    }, []);

    return (
        <div className={`homepage-wrapper`}>
            <PreLoader isLoading={true} />
        </div>
    );
}
