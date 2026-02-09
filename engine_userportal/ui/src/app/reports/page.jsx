"use client";

import Layout from "@/components/layout";
import TableGrid from "@/components/tableGrid";
import React, { useEffect, useRef, useState } from "react";
import { useAppContext } from "@/context/appContext";
import { fetchData } from "@/utils/fetchData";
import Button from "@/components/button/index.jsx";
import { FaDownload, FaChartBar, FaFileAlt, FaSearch, FaCheck, FaTimes } from "react-icons/fa";
import { ProgressLoader } from "@/components/loaders/index.jsx";

export default function Reports() {
    const { dispatch } = useAppContext();

    const [reports, setReports] = useState([]);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(10);
    const [searchFilters, setSearchFilters] = useState({});
    const [filterValues, setFilterValues] = useState({});
    const [sortConfig, setSortConfig] = useState({ sortBy: null, order: null });
    const [paginationData, setPaginationData] = useState(null);
    const [downloadProgress, setDownloadProgress] = useState({ isDownloading: false, progress: 0 });
    const [docType, setDocType] = useState("xlsx");

    const searchFiltersRef = useRef(searchFilters);
    const filterValuesRef = useRef(filterValues);
    useEffect(() => {
        searchFiltersRef.current = searchFilters;
        filterValuesRef.current = filterValues;
    }, [searchFilters, filterValues]);

    const buildExportUrl = (doctype) => {
        setDocType(doctype);
        const queryParams = new URLSearchParams();

        for (const [key, value] of Object.entries(searchFiltersRef.current)) {
            if (value?.trim()) {
                queryParams.append(`${key}_search`, value.trim());
            }
        }

        for (const [key, value] of Object.entries(filterValuesRef.current)) {
            if (value !== undefined && value !== null && value !== "") {
                queryParams.append(key, String(value));
            }
        }
        if (sortConfig.sortBy) {
            queryParams.append("sort_by", sortConfig.sortBy);
            queryParams.append("order", sortConfig.order?.toLowerCase() || "asc");
        }

        queryParams.append("doctype", doctype);
        return `${process.env.NEXT_PUBLIC_API_URL}/api/reports/export?${queryParams.toString()}`;
    };

    const downloadFile = async (doctype) => {
        setDownloadProgress({ isDownloading: true, progress: 0 });
        try {
            const url = buildExportUrl(doctype);

            const progressInterval = setInterval(() => {
                setDownloadProgress((prev) => {
                    const newProgress = Math.min(prev.progress + 5, 95);
                    return { isDownloading: true, progress: newProgress };
                });
            }, 200);

            const response = await fetch(url, {
                method: "GET",
                credentials: "include",
            });

            clearInterval(progressInterval);

            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                console.info("Export failed:", error);
                alert("Failed to generate export. Please try again.");
                setDownloadProgress({ isDownloading: false, progress: 0 });
                return;
            }

            const contentLength = response.headers.get("Content-Length");
            const total = parseInt(contentLength, 10);
            let loaded = 0;

            const reader = response.body.getReader();
            const chunks = [];
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                chunks.push(value);
                loaded += value.length;
                if (total) {
                    const progress = Math.round((loaded * 100) / total);
                    setDownloadProgress({ isDownloading: true, progress });
                }
            }
            reader.releaseLock();

            const blob = new Blob(chunks);
            const extension = doctype === "pdf" ? "pdf" : "xlsx";
            const fileName = `reports_export_${new Date().toISOString().split("T")[0]}.${extension}`;

            const downloadUrl = window.URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = downloadUrl;
            link.download = fileName;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(downloadUrl);

            setDownloadProgress({ isDownloading: false, progress: 100 });
            setTimeout(() => setDownloadProgress({ isDownloading: false, progress: 0 }), 1000);
        } catch (error) {
            console.info("Download error:", error);
            alert("Download failed. Please try again.");
        } finally {
            if (downloadProgress.isDownloading) {
                setDownloadProgress({ isDownloading: false, progress: 0 });
            }
        }
    };

    const loadReports = async (options = {}) => {
        const { force = false, validate = false } = options;
        try {
            dispatch({ type: "SET_LOADING", payload: true });

            const queryParams = new URLSearchParams();

            queryParams.append("page", page);
            queryParams.append("pageSize", pageSize);

            for (const [key, value] of Object.entries(searchFilters)) {
                if (value?.trim()) {
                    queryParams.append(`${key}_search`, value.trim());
                }
            }

            for (const [key, value] of Object.entries(filterValues)) {
                if (value) {
                    queryParams.append(key, value);
                }
            }

            if (sortConfig.sortBy && sortConfig.order) {
                queryParams.append("sort_by", sortConfig.sortBy);
                queryParams.append("order", sortConfig.order.toLowerCase());
            }

            const url = `${process.env.NEXT_PUBLIC_API_URL}/api/reports?${queryParams.toString()}`;
            const result = await fetchData(url, { force, validate });

            if (result?.data) {
                setReports(result.data);
            }
            if (result?.pagination) {
                setPaginationData(result.pagination);
            }
        } catch (error) {
            console.info("Error fetching reports:", error);
        } finally {
            dispatch({ type: "SET_LOADING", payload: false });
        }
    };

    useEffect(() => {
        loadReports({ validate: true });
    }, [page, pageSize, searchFilters, filterValues, sortConfig]);

    const handleColumnSearch = ({ key, value }) => {
        setSearchFilters((prev) => ({ ...prev, [key]: value }));
    };

    const handleFilterChange = ({ key, value }) => {
        setFilterValues((prev) => ({ ...prev, [key]: value }));
    };

    const handleSort = ({ sortBy, order }) => {
        setSortConfig({ sortBy, order });
    };

    const handleEdit = (report) => {
        alert(`Editing report: ${report.title}`);
    };

    const handleDelete = (report) => {
        if (window.confirm(`Are you sure you want to delete report ${report.title}?`)) {
            setReports((prev) => prev.filter((r) => r.id !== report.id));
        }
    };

    const columns = [
        {
            key: "id",
            title: "ID",
            width: 70,
            stick: true,
            sortable: true,
            render: (value) => value?.slice(-6) || "-",
        },
        {
            key: "title",
            title: "Report Title",
            searchable: true,
            sortable: true,
            width: 250,
            stick: true,
            render: (value) => (
                <span className="report-title" style={{ color: "#1d4ed8", fontWeight: 600 }}>
                    {value || "-"}
                </span>
            ),
        },
        {
            key: "tenant_id",
            title: "Tenant ID",
            searchable: true,
            sortable: true,
            width: 180,
            render: (value) => value?.slice(-6) || "-",
        },
        {
            key: "tenants__name",
            title: "Tenant Name",
            searchable: true,
            sortable: true,
            width: 180,
        },
        {
            key: "type",
            title: "Report Type",
            filterable: true,
            sortable: true,
            filterOptions: [
                { label: "Vulnerability", value: "vulnerability" },
                { label: "Compliance", value: "compliance" },
                { label: "Security", value: "security" },
                { label: "Audit", value: "audit" },
                { label: "Risk Assessment", value: "risk_assessment" },
            ],
            render: (value) => {
                const typeMap = {
                    vulnerability: { color: "#dc2626", bg: "#fee2e2", icon: <FaChartBar /> },
                    compliance: { color: "#8b5cf6", bg: "#ede9fe", icon: <FaFileAlt /> },
                    security: { color: "#3b82f6", bg: "#dbeafe", icon: <FaChartBar /> },
                    audit: { color: "#f59e0b", bg: "#ffedd5", icon: <FaFileAlt /> },
                    risk_assessment: { color: "#ec4899", bg: "#fce7f3", icon: <FaChartBar /> },
                };
                const style = typeMap[value] || { color: "#6b7280", bg: "#f3f4f6" };

                return (
                    <div
                        style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                            backgroundColor: style.bg,
                            color: style.color,
                            padding: "4px 8px",
                            borderRadius: "6px",
                            fontSize: "12px",
                            fontWeight: 600,
                        }}
                    >
                        {style.icon}
                        {value?.replace(/_/g, " ")?.toUpperCase() || "-"}
                    </div>
                );
            },
        },
        {
            key: "status",
            title: "Status",
            filterable: true,
            sortable: true,
            filterOptions: [
                { label: "Pending", value: "pending" },
                { label: "Completed", value: "completed" },
                { label: "Failed", value: "failed" },
            ],
            render: (value) => {
                const statusMap = {
                    pending: { color: "#f59e0b", bg: "#ffedd5", icon: <FaSearch /> },
                    completed: { color: "#10b981", bg: "#d1fae5", icon: <FaCheck /> },
                    failed: { color: "#dc2626", bg: "#fee2e2", icon: <FaTimes /> },
                };
                const style = statusMap[value] || { color: "#6b7280", bg: "#f3f4f6" };

                return (
                    <div
                        style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                            backgroundColor: style.bg,
                            color: style.color,
                            padding: "4px 8px",
                            borderRadius: "6px",
                            fontSize: "12px",
                            fontWeight: 600,
                        }}
                    >
                        {style.icon}
                        {value?.toUpperCase() || "-"}
                    </div>
                );
            },
        },
        {
            key: "description",
            title: "Description",
            searchable: true,
            sortable: false,
            width: 300,
            render: (value) => (
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <FaSearch style={{ color: "#9ca3af", fontSize: "12px" }} />
                    <span style={{ fontSize: "13px", color: "#4b5563", lineHeight: "1.4" }}>
                        {value?.substring(0, 80) || "-"}
                        {value?.length > 80 ? "..." : ""}
                    </span>
                </div>
            ),
        },
        {
            key: "generated_by",
            title: "Generated By",
            searchable: true,
            sortable: true,
            width: 150,
            render: (value) => value || "-",
        },
        {
            key: "generated_at",
            title: "Generated At",
            width: 160,
            sortable: true,
            render: (value) => (value ? new Date(value).toLocaleString() : "-"),
        },
        {
            key: "created_at",
            title: "Created At",
            width: 160,
            sortable: true,
            render: (value) => (value ? new Date(value).toLocaleString() : "-"),
        },
    ];

    return (
        <Layout>
            <TableGrid
                columns={columns}
                data={reports}
                paginationMode="server"
                controlledPage={page}
                controlledPageSize={pageSize}
                onPageChange={setPage}
                onPageSizeChange={setPageSize}
                totalCount={paginationData?.total}
                onSearch={handleColumnSearch}
                onFilter={handleFilterChange}
                onSort={handleSort}
                pageSizeOptions={[10, 20, 50]}
                maxHeight="60vh"
                maxWidth="100%"
                renderNoData={() => (
                    <div style={{ textAlign: "center", padding: "40px", color: "#6b7280" }}>
                        <FaChartBar size={48} style={{ margin: "0 auto 16px", color: "#d1d5db" }} />
                        <h3 style={{ fontSize: "18px", fontWeight: 600, marginBottom: "8px" }}>
                            No Reports Found
                        </h3>
                        <p>There are currently no reports matching your search criteria.</p>
                    </div>
                )}
            />
            <div
                className="reports__main-container"
                style={{
                    padding: "5px",
                    backgroundColor: "#ffffff",
                    borderRadius: "8px",
                    boxShadow: "0 1px 3px 0 rgba(0, 0, 0, 0.1)",
                }}
            >
                <div
                    className="reports__container-exportbtn"
                    style={{
                        display: "flex",
                        gap: "12px",
                        justifyContent: "center",
                    }}
                >
                    <Button
                        onClick={() => downloadFile("pdf")}
                        disabled={downloadProgress.isDownloading}
                        text={
                            downloadProgress.isDownloading && docType === "pdf"
                                ? "Exporting PDF..."
                                : "Download PDF"
                        }
                        danger
                        iconRight={<FaDownload />}
                    />

                    <Button
                        onClick={() => downloadFile("xlsx")}
                        disabled={downloadProgress.isDownloading}
                        text={
                            downloadProgress.isDownloading && docType === "xlsx"
                                ? "Exporting Excel..."
                                : "Download Excel"
                        }
                        success
                        iconRight={<FaDownload />}
                    />
                </div>

                {downloadProgress.isDownloading && (
                    <div className="progress__loader-container">
                        <ProgressLoader
                            value={downloadProgress.progress}
                            max={100}
                            color={`success`}
                            showLabel={true}
                        />
                    </div>
                )}
            </div>
        </Layout>
    );
}
