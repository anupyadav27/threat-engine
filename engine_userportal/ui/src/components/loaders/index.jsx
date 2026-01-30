"use client";

import React, { useEffect, useState } from "react";

export function SpinnerLoader({ size = "md", color = "primary", text = "", fullScreen = false }) {
    const spinner = (
        <div className={`spinner-loader spinner-loader--${size} spinner-loader--${color}`}>
            <span className="spinner-loader__circle" />
            {text && <p className="spinner-loader__text">{text}</p>}
        </div>
    );

    return fullScreen ? <div className="spinner-loader__fullscreen">{spinner}</div> : spinner;
}

export function SkeletonLoader({ variant = "text", width = "100%", height, className = "" }) {
    return (
        <div
            className={`skeleton-loader skeleton-loader--${variant} ${className}`}
            style={{ width, height }}
        />
    );
}

export function ProgressLoader({
    value = 0,
    max = 100,
    color = "primary",
    showLabel = true,
    onComplete,
}) {
    const [progress, setProgress] = useState(value);
    const percentage = Math.min((progress / max) * 100, 100);

    useEffect(() => {
        setProgress(value);
        if (value >= max && typeof onComplete === "function") onComplete();
    }, [value, max, onComplete]);

    return (
        <div className={`progress-loader progress-loader--${color}`}>
            <div className="progress-loader__bar" style={{ width: `${percentage}%` }} />
            {showLabel && <span className="progress-loader__label">{Math.round(percentage)}%</span>}
        </div>
    );
}

export function DotsLoader({ size = "md", color = "primary", text = "" }) {
    return (
        <div className={`dots-loader dots-loader--${size} dots-loader--${color}`}>
            <span className="dots-loader__dot"></span>
            <span className="dots-loader__dot"></span>
            <span className="dots-loader__dot"></span>
            {text && <span className="dots-loader__text">{text}</span>}
        </div>
    );
}

export default {
    SpinnerLoader,
    SkeletonLoader,
    ProgressLoader,
    DotsLoader,
};
