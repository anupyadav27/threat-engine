"use client";

import { Line } from "react-chartjs-2";
import {
    CategoryScale,
    Chart as ChartJS,
    Legend,
    LinearScale,
    LineElement,
    PointElement,
    Title,
    Tooltip,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend);

export default function LineGraph({
    data = { labels: [], datasets: [] },
    title,
    height = 300,
    className = "",
    options = {},
}) {
    const processedDatasets = data.datasets.map((ds) => ({
        label: ds.label,
        data: ds.data,
        borderColor: ds.color || "#3B82F6",
        backgroundColor: (ds.color || "#3B82F6") + "20",
        tension: 0.4,
        fill: true,
        pointRadius: 3,
        pointHoverRadius: 6,
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
            tooltip: {
                mode: "index",
                intersect: false,
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
        <div className={`line-graph ${className}`}>
            {title && <h3 className="line-graph__title">{title}</h3>}
            <div className="line-graph__container" style={{ height: `${height}px` }}>
                <Line data={chartData} options={mergedOptions} />
            </div>
        </div>
    );
}
