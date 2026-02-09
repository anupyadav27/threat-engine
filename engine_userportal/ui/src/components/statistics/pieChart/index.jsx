"use client";

import { Pie } from "react-chartjs-2";
import { ArcElement, Chart as ChartJS, Legend, Tooltip } from "chart.js";

ChartJS.register(ArcElement, Tooltip, Legend);

export default function PieChart({ data = [], title, height = 300, className = "", options = {} }) {
    const chartData = {
        labels: data.map((item) => item.label),
        datasets: [
            {
                data: data.map((item) => item.value),
                backgroundColor: data.map((item) => item.color || "#6B7280"),
                borderWidth: 0,
            },
        ],
    };

    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: "bottom",
                labels: {
                    padding: 20,
                    usePointStyle: true,
                    pointStyle: "circle",
                },
            },
            tooltip: {
                backgroundColor: "rgba(0, 0, 0, 0.75)",
                padding: 12,
                titleFont: { size: 14 },
                bodyFont: { size: 13 },
            },
        },
    };

    const mergedOptions = { ...defaultOptions, ...options };

    return (
        <div className={`pie-chart ${className}`}>
            {title && <h3 className="pie-chart__title">{title}</h3>}
            <div className="pie-chart__container" style={{ height: `${height}px` }}>
                <Pie data={chartData} options={mergedOptions} />
            </div>
        </div>
    );
}
