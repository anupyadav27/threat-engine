"use client";

import { Bar } from "react-chartjs-2";
import { Chart as ChartJS, LinearScale, CategoryScale, BarElement, Title, Tooltip } from "chart.js";

ChartJS.register(LinearScale, CategoryScale, BarElement, Title, Tooltip);

export default function Histogram({
    data = [],
    bins = 10,
    color = "#EF4444",
    title,
    height = 300,
    className = "",
    options = {},
}) {
    if (!Array.isArray(data) || data.length === 0) {
        return (
            <div className={`histogram ${className}`}>
                {title && <h3 className="histogram__title">{title}</h3>}
                <div className="histogram__container" style={{ height: `${height}px` }}>
                    <p className="text-gray-500">No data</p>
                </div>
            </div>
        );
    }

    const min = Math.min(...data);
    const max = Math.max(...data);
    const range = max - min;
    const binWidth = range / bins || 1;

    const labels = [];
    const counts = new Array(bins).fill(0);

    for (let i = 0; i < bins; i++) {
        const start = min + i * binWidth;
        const end = i === bins - 1 ? max : min + (i + 1) * binWidth;
        labels.push(`${start.toFixed(1)}–${end.toFixed(1)}`);
    }

    data.forEach((value) => {
        let binIndex = Math.floor((value - min) / binWidth);
        binIndex = Math.min(binIndex, bins - 1);
        counts[binIndex]++;
    });

    const chartData = {
        labels,
        datasets: [
            {
                label: "Frequency",
                data: counts,
                backgroundColor: color,
                borderRadius: 4,
                borderSkipped: false,
            },
        ],
    };

    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: false },
            tooltip: {
                callbacks: {
                    title: () => "Score Range",
                    label: (context) => `${context.label}: ${context.raw} assets`,
                },
            },
        },
        scales: {
            x: {
                grid: { display: false },
            },
            y: {
                beginAtZero: true,
                ticks: { precision: 0 },
                grid: { color: "rgba(0,0,0,0.05)" },
            },
        },
    };

    const mergedOptions = { ...defaultOptions, ...options };

    return (
        <div className={`histogram ${className}`}>
            {title && <h3 className="histogram__title">{title}</h3>}
            <div className="histogram__container" style={{ height: `${height}px` }}>
                <Bar data={chartData} options={mergedOptions} />
            </div>
        </div>
    );
}
