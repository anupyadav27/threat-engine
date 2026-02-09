"use client";

import React from "react";
import { SpinnerLoader } from "@/components/loaders";

export default function SpinnerLoaderOverlay({ isLoading = false, text = "Loading..." }) {
    if (!isLoading) return null;

    return (
        <div className="spinner__loader-overlay">
            <SpinnerLoader size="lg" color="primary" text={text} />
        </div>
    );
}
