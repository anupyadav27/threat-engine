"use client";

import Layout from "@/components/layout";
import TableGrid from "@/components/tableGrid";
import React, { useEffect, useRef, useState } from "react";
import { useAppContext } from "@/context/appContext";
import { fetchData } from "@/utils/fetchData";
import Button from "@/components/button/index.jsx";
import {
    FaBug,
    FaShieldAlt,
    FaExclamationTriangle,
    FaDatabase,
    FaNetworkWired,
    FaDownload,
    FaSearch,
} from "react-icons/fa";
import { ProgressLoader } from "@/components/loaders/index.jsx";

export default function Threats() {
    const { dispatch } = useAppContext();

    const [threats, setThreats] = useState([]);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(10);
    const [searchFilters, setSearchFilters] = useState({});
    const [filterValues, setFilterValues] = useState({});
    const [sortConfig, setSortConfig] = useState({ sortBy: null, order: null });
    const [totalCount, setTotalCount] = useState(0);
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
        return `${process.env.NEXT_PUBLIC_API_URL}/api/threats/export?${queryParams.toString()}`;
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
                console.error("Export failed:", error);
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
            const fileName = `threats_export_${new Date().toISOString().split("T")[0]}.${extension}`;

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
            console.error("Download error:", error);
            alert("Download failed. Please try again.");
            setDownloadProgress({ isDownloading: false, progress: 0 });
        }
    };

    const loadThreats = async (options = {}) => {
        const { force = true, validate = true } = options;
        try {
            dispatch({ type: "SET_LOADING", payload: true });

            const queryParams = new URLSearchParams();
            queryParams.append("page", page);
            queryParams.append("pageSize", pageSize);

            // Handle search filters (field_search)
            for (const [key, value] of Object.entries(searchFilters)) {
                if (value?.trim()) {
                    queryParams.append(`${key}_search`, value.trim());
                }
            }

            // Handle exact filters
            for (const [key, value] of Object.entries(filterValues)) {
                if (value !== undefined && value !== null && value !== "") {
                    queryParams.append(key, String(value));
                }
            }

            // Handle sorting
            if (sortConfig.sortBy && sortConfig.order) {
                queryParams.append("sort_by", sortConfig.sortBy);
                queryParams.append("order", sortConfig.order.toLowerCase());
            }

            const url = `${process.env.NEXT_PUBLIC_API_URL}/api/threats/?${queryParams.toString()}`;
            const result = await fetchData(url, { force, validate });

            // Handle logout scenario
            if (result.logOut) {
                dispatch({ type: "LOGOUT" });
                return;
            }

            // Handle errors
            if (!result.success) {
                console.error("Failed to load threats:", result.error || result.message);
                setThreats([]);
                setTotalCount(0);
                return;
            }

            // ✅ Correctly parse the API response
            setThreats(Array.isArray(result.data) ? result.data : []);
            setTotalCount(result.pagination?.total || 0);
        } catch (error) {
            console.error("Error fetching threats:", error);
            setThreats([]);
            setTotalCount(0);
        } finally {
            dispatch({ type: "SET_LOADING", payload: false });
        }
    };

    useEffect(() => {
        loadThreats({ validate: true });
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

    const handleEdit = (threat) => {
        alert(`Editing threat: ${threat.name}`);
    };

    const handleDelete = (threat) => {
        if (window.confirm(`Are you sure you want to delete threat ${threat.name}?`)) {
            setThreats((prev) => prev.filter((t) => t.id !== threat.id));
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
            key: "name",
            title: "Threat Name",
            searchable: true,
            sortable: true,
            width: 220,
            stick: true,
            render: (value, row) => (
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{ fontWeight: 500 }}>{value || "-"}</span>
                </div>
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
            key: "severity",
            title: "Severity",
            filterable: true,
            sortable: true,
            filterOptions: [
                { label: "Critical", value: "critical" },
                { label: "High", value: "high" },
                { label: "Medium", value: "medium" },
                { label: "Low", value: "low" },
            ],
            render: (value) => {
                const severity = value?.toLowerCase() || "";
                let bgColor = "#e5e7eb";
                let color = "#374151";

                switch (severity) {
                    case "critical":
                        bgColor = "#fee2e2";
                        color = "#dc2626";
                        return (
                            <span
                                style={{
                                    backgroundColor: bgColor,
                                    color: color,
                                    padding: "4px 8px",
                                    borderRadius: "6px",
                                    fontSize: "12px",
                                    fontWeight: 600,
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: "4px",
                                }}
                            >
                                <FaExclamationTriangle />
                                {value?.toUpperCase() || "-"}
                            </span>
                        );
                    case "high":
                        bgColor = "#fef3c7";
                        color = "#b45309";
                        return (
                            <span
                                style={{
                                    backgroundColor: bgColor,
                                    color: color,
                                    padding: "4px 8px",
                                    borderRadius: "6px",
                                    fontSize: "12px",
                                    fontWeight: 600,
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: "4px",
                                }}
                            >
                                <FaExclamationTriangle />
                                {value?.toUpperCase() || "-"}
                            </span>
                        );
                    case "medium":
                        bgColor = "#e5e7eb";
                        color = "#374151";
                        return (
                            <span
                                style={{
                                    backgroundColor: bgColor,
                                    color: color,
                                    padding: "4px 8px",
                                    borderRadius: "6px",
                                    fontSize: "12px",
                                    fontWeight: 600,
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: "4px",
                                }}
                            >
                                <FaBug />
                                {value?.toUpperCase() || "-"}
                            </span>
                        );
                    case "low":
                        bgColor = "#dcfce7";
                        color = "#166534";
                        return (
                            <span
                                style={{
                                    backgroundColor: bgColor,
                                    color: color,
                                    padding: "4px 8px",
                                    borderRadius: "6px",
                                    fontSize: "12px",
                                    fontWeight: 600,
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: "4px",
                                }}
                            >
                                <FaShieldAlt />
                                {value?.toUpperCase() || "-"}
                            </span>
                        );
                    default:
                        bgColor = "#e5e7eb";
                        color = "#374151";
                }

                return (
                    <span
                        style={{
                            backgroundColor: bgColor,
                            color: color,
                            padding: "4px 8px",
                            borderRadius: "6px",
                            fontSize: "12px",
                            fontWeight: 600,
                        }}
                    >
                        {value?.toUpperCase() || "-"}
                    </span>
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
            key: "status",
            title: "Status",
            filterable: true,
            sortable: true,
            filterOptions: [
                { label: "Active", value: "active" },
                { label: "Mitigated", value: "mitigated" },
                { label: "Resolved", value: "resolved" },
                { label: "False Positive", value: "false_positive" },
                { label: "Under Investigation", value: "under_investigation" },
            ],
            render: (value) => {
                const status = value?.toLowerCase() || "";
                let bgColor = "#e5e7eb";
                let color = "#374151";

                switch (status) {
                    case "active":
                        bgColor = "#fef3c7";
                        color = "#b45309";
                        break;
                    case "under_investigation":
                        bgColor = "#dbeafe";
                        color = "#1d4ed8";
                        break;
                    case "resolved":
                    case "mitigated":
                        bgColor = "#dcfce7";
                        color = "#166534";
                        break;
                    case "false_positive":
                        bgColor = "#ede9fe";
                        color = "#7e22ce";
                        break;
                    default:
                        bgColor = "#e5e7eb";
                        color = "#374151";
                }

                return (
                    <span
                        style={{
                            backgroundColor: bgColor,
                            color: color,
                            padding: "4px 8px",
                            borderRadius: "6px",
                            fontSize: "12px",
                            fontWeight: 600,
                        }}
                    >
                        {value ? value.charAt(0).toUpperCase() + value.slice(1) : "-"}
                    </span>
                );
            },
        },
        {
            key: "created_at",
            title: "Detected At",
            width: 160,
            sortable: true,
            render: (value) => (value ? new Date(value).toLocaleString() : "-"),
        },
        {
            key: "updated_at",
            title: "Last Updated",
            width: 160,
            sortable: true,
            render: (value) => (value ? new Date(value).toLocaleString() : "-"),
        },
    ];

    return (
        <Layout headerLabel="Threats">
            <TableGrid
                columns={columns}
                data={threats}
                paginationMode="server"
                controlledPage={page}
                controlledPageSize={pageSize}
                onPageChange={setPage}
                onPageSizeChange={setPageSize}
                totalCount={totalCount}
                onSearch={handleColumnSearch}
                onFilter={handleFilterChange}
                onSort={handleSort}
                pageSizeOptions={[10, 20, 50, 100]}
                maxHeight="60vh"
                maxWidth="100%"
                renderNoData={() => (
                    <div style={{ textAlign: "center", padding: "40px", color: "#6b7280" }}>
                        <FaBug size={48} style={{ margin: "0 auto 16px", color: "#d1d5db" }} />
                        <h3 style={{ fontSize: "18px", fontWeight: 600, marginBottom: "8px" }}>
                            No Threats Found
                        </h3>
                        <p>There are currently no threats matching your search criteria.</p>
                    </div>
                )}
            />

            <div className="threats__main-container">
                <div className="threats__container-exportbtn">
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
                    <div
                        className="progress__loader-container"
                        style={{ maxWidth: "500px", margin: "0 auto" }}
                    >
                        <ProgressLoader
                            value={downloadProgress.progress}
                            max={100}
                            color="success"
                            showLabel={true}
                        />
                    </div>
                )}
            </div>
        </Layout>
    );
}
