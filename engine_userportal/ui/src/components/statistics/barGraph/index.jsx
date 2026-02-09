"use client";

import { Bar } from "react-chartjs-2";
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    BarElement,
    Title,
    Tooltip,
    Legend,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

export default function BarGraph({
    data = { labels: [], datasets: [] },
    title,
    height = 300,
    className = "",
    options = {},
}) {
    const processedDatasets = data.datasets.map((ds) => ({
        label: ds.label,
        data: ds.data,
        backgroundColor: ds.color || "#8B5CF6",
        borderRadius: 6,
        borderSkipped: false,
        barPercentage: 0.8,
    }));

    const chartData = {
        labels: data.labels,
        datasets: processedDatasets,
    };

    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: "top",
                labels: { padding: 15 },
            },
        },
        scales: {
            x: {
                grid: { display: false },
            },
            y: {
                beginAtZero: true,
                grid: { color: "rgba(0,0,0,0.05)" },
            },
        },
    };

    const mergedOptions = { ...defaultOptions, ...options };

    return (
        <div className={`bar-graph ${className}`}>
            {title && <h3 className="bar-graph__title">{title}</h3>}
            <div className="bar-graph__container" style={{ height: `${height}px` }}>
                <Bar data={chartData} options={mergedOptions} />
            </div>
        </div>
    );
}
