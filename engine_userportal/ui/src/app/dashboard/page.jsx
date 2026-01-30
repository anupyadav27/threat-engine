"use client";

import Layout from "@/components/layout";
import { useAppContext } from "@/context/appContext";
import { useEffect } from "react";
import PieChart from "@/components/statistics/pieChart";
import LineGraph from "@/components/statistics/lineGraph";
import BarGraph from "@/components/statistics/barGraph";
import Histogram from "@/components/statistics/histogram";

export default function Dashboard() {
    const { dispatch } = useAppContext();

    useEffect(() => {
        dispatch({ type: "SET_LOADING", payload: false });
    }, []);

    const complianceData = [
        { label: "Compliant", value: 78, color: "#10B981" },
        { label: "Non-Compliant", value: 14, color: "#EF4444" },
        { label: "Exempt", value: 8, color: "#9CA3AF" },
    ];

    const riskTrendData = {
        labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
        datasets: [
            {
                label: "High-Risk Assets",
                data: [42, 38, 45, 32, 28, 20],
                color: "#F59E0B",
            },
        ],
    };

    const cloudUsageData = {
        labels: ["AWS", "Azure", "GCP", "OCI"],
        datasets: [
            {
                label: "Active Resources",
                data: [120, 85, 65, 30],
                color: "#8B5CF6",
            },
        ],
    };

    const vulnScores = Array.from({ length: 200 }, () => Math.floor(Math.random() * 100));
    return (
        <Layout>
            <div className="dashboard">
                {}
                <div className="dashboard__row">
                    <div className="dashboard__card">
                        <PieChart title="Compliance Status" data={complianceData} height={260} />
                    </div>
                    <div className="dashboard__card">
                        <LineGraph
                            title="Risk Trend (Last 6 Months)"
                            data={riskTrendData}
                            height={260}
                        />
                    </div>
                    <div className="dashboard__card">
                        <BarGraph
                            title="Cloud Resource Distribution"
                            data={cloudUsageData}
                            height={260}
                        />
                    </div>
                </div>

                <div className="dashboard__row">
                    <div className="dashboard__card">
                        <Histogram
                            title="Vulnerability Score Distribution"
                            data={vulnScores}
                            bins={10}
                            color="#EF4444"
                            height={260}
                        />
                    </div>
                </div>
            </div>
        </Layout>
    );
}
