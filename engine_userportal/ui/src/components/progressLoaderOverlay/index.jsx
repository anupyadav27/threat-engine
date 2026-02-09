"use client";

import React from "react";
import { ProgressLoader } from "@/components/loaders";

export default function ProgressLoaderOverlay(
    downloadProgress = { isDownLoading: false, progress: 0 }
) {
    if (!downloadProgress.isDownLoading) return null;

    return (
        <div className="progress__loader-overlay">
            <div className={"progress__loader-container"}>
                <ProgressLoader
                    value={downloadProgress.progress}
                    max={100}
                    color={`success`}
                    showLabel={true}
                />
            </div>
        </div>
    );
}
