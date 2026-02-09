"use client";

import Layout from "@/components/layout";
import TableGrid from "@/components/tableGrid";
import React, { useEffect, useRef, useState } from "react";
import { useAppContext } from "@/context/appContext";
import { fetchData } from "@/utils/fetchData";
import Button from "@/components/button/index.jsx";
import { FaBox, FaDownload, FaShieldAlt, FaExclamationTriangle } from "react-icons/fa";
import { ProgressLoader } from "@/components/loaders/index.jsx";

export default function Assets() {
    const { dispatch } = useAppContext();

    const [assets, setAssets] = useState([]);
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
        return `${process.env.NEXT_PUBLIC_API_URL}/api/assets/export?${queryParams.toString()}`;
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
            const fileName = `assets_export_${new Date().toISOString().split("T")[0]}.${extension}`;

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

    const loadAssets = async (options = {}) => {
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

            const url = `${process.env.NEXT_PUBLIC_API_URL}/api/assets/?${queryParams.toString()}`;
            const result = await fetchData(url, { force, validate });

            // Handle logout scenario
            if (result.logOut) {
                dispatch({ type: "LOGOUT" });
                return;
            }

            // Handle errors
            if (!result.success) {
                console.error("Failed to load assets:", result.error || result.message);
                setAssets([]);
                setTotalCount(0);
                return;
            }

            // ✅ Correctly parse the API response
            setAssets(Array.isArray(result.data) ? result.data : []);
            setTotalCount(result.pagination?.total || 0);
        } catch (error) {
            console.error("Error fetching assets:", error);
            setAssets([]);
            setTotalCount(0);
        } finally {
            dispatch({ type: "SET_LOADING", payload: false });
        }
    };

    useEffect(() => {
        loadAssets({ validate: true });
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

    const handleEdit = (asset) => {
        alert(`Editing asset: ${asset.name}`);
    };

    const handleDelete = (asset) => {
        if (window.confirm(`Are you sure you want to delete asset ${asset.name}?`)) {
            setAssets((prev) => prev.filter((a) => a.id !== asset.id));
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
            title: "Asset Name",
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
            key: "resource_type",
            title: "Type",
            filterable: false,
            searchable: true,
            sortable: true,
            filterOptions: [
                { label: "Virtual Machine", value: "vm" },
                { label: "S3 Bucket", value: "s3" },
                { label: "Database", value: "database" },
                { label: "Network", value: "network" },
                { label: "Storage", value: "storage" },
                { label: "Container", value: "container" },
            ],
            render: (value) => {
                const type = value?.toLowerCase() || "";
                let bgColor = "#e5e7eb";
                let color = "#374151";

                switch (type) {
                    case "vm":
                    case "virtual_machine":
                        bgColor = "#dbeafe";
                        color = "#1d4ed8";
                        break;
                    case "s3":
                    case "bucket":
                        bgColor = "#f3e8ff";
                        color = "#7e22ce";
                        break;
                    case "database":
                        bgColor = "#dcfce7";
                        color = "#166534";
                        break;
                    case "network":
                        bgColor = "#fef3c7";
                        color = "#b45309";
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
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "4px",
                        }}
                    >
                        {value?.toUpperCase() || "-"}
                    </span>
                );
            },
        },
        {
            key: "provider",
            title: "Provider",
            width: 120,
            filterable: true,
            sortable: true,
            filterOptions: [
                { label: "AWS", value: "aws" },
                { label: "Azure", value: "azure" },
                { label: "GCP", value: "gcp" },
                { label: "On-Prem", value: "on_prem" },
            ],
            render: (value) => {
                const provider = value?.toLowerCase() || "";
                let bgColor = "#e5e7eb";
                let color = "#374151";

                switch (provider) {
                    case "aws":
                        bgColor = "#feefc3";
                        color = "#9d5c0c";
                        break;
                    case "azure":
                        bgColor = "#d1e7ff";
                        color = "#0d6efd";
                        break;
                    case "gcp":
                        bgColor = "#d4f8e8";
                        color = "#1a7f37";
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
                        {value?.toUpperCase() || "-"}
                    </span>
                );
            },
        },
        {
            key: "region",
            title: "Region",
            width: 120,
            searchable: true,
            sortable: true,
            render: (value) => value?.toUpperCase() || "-",
        },
        {
            key: "environment",
            title: "Environment",
            width: 120,
            filterable: true,
            sortable: true,
            filterOptions: [
                { label: "Development", value: "development" },
                { label: "Staging", value: "staging" },
                { label: "Production", value: "production" },
                { label: "Test", value: "test" },
            ],
            render: (value) => {
                const env = value?.toLowerCase() || "";
                let bgColor = "#e5e7eb";
                let color = "#374151";

                switch (env) {
                    case "production":
                        bgColor = "#dcfce7";
                        color = "#166534";
                        break;
                    case "staging":
                        bgColor = "#fef3c7";
                        color = "#b45309";
                        break;
                    case "development":
                        bgColor = "#dbeafe";
                        color = "#1d4ed8";
                        break;
                    case "test":
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
            key: "lifecycle_state",
            title: "Lifecycle",
            filterable: true,
            sortable: true,
            filterOptions: [
                { label: "Active", value: "active" },
                { label: "Inactive", value: "inactive" },
                { label: "Terminated", value: "terminated" },
                { label: "Decommissioned", value: "decommissioned" },
            ],
            render: (value) => {
                const state = value?.toLowerCase() || "";
                let bgColor = "#e5e7eb";
                let color = "#374151";

                switch (state) {
                    case "active":
                        bgColor = "#dcfce7";
                        color = "#166534";
                        break;
                    case "terminated":
                    case "decommissioned":
                        bgColor = "#fee2e2";
                        color = "#dc2626";
                        break;
                    case "inactive":
                        bgColor = "#fef3c7";
                        color = "#b45309";
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
            key: "health_status",
            title: "Health",
            filterable: true,
            sortable: true,
            filterOptions: [
                { label: "Healthy", value: "healthy" },
                { label: "Warning", value: "warning" },
                { label: "Critical", value: "critical" },
                { label: "Unknown", value: "unknown" },
            ],
            render: (value) => {
                const status = value?.toLowerCase() || "";
                let bgColor = "#e5e7eb";
                let color = "#374151";

                switch (status) {
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
                                {value ? value.charAt(0).toUpperCase() + value.slice(1) : "-"}
                            </span>
                        );
                    case "warning":
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
                                {value ? value.charAt(0).toUpperCase() + value.slice(1) : "-"}
                            </span>
                        );
                    case "healthy":
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
                                {value ? value.charAt(0).toUpperCase() + value.slice(1) : "-"}
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
                        {value ? value.charAt(0).toUpperCase() + value.slice(1) : "-"}
                    </span>
                );
            },
        },
        {
            key: "created_at",
            title: "Created At",
            width: 160,
            sortable: true,
            render: (value) => (value ? new Date(value).toLocaleString() : "-"),
        },
        {
            key: "updated_at",
            title: "Updated At",
            width: 160,
            sortable: true,
            render: (value) => (value ? new Date(value).toLocaleString() : "-"),
        },
    ];

    return (
        <Layout headerLabel="Assets">
            <TableGrid
                columns={columns}
                data={assets}
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
                    <div
                        style={{
                            textAlign: "center",
                            padding: "60px 20px",
                            color: "#6b7280",
                            backgroundColor: "#f9fafb",
                            borderRadius: "8px",
                            border: "1px dashed #d1d5db",
                        }}
                    >
                        <FaBox size={64} style={{ margin: "0 auto 16px", color: "#d1d5db" }} />
                        <h3
                            style={{
                                fontSize: "20px",
                                fontWeight: 600,
                                marginBottom: "8px",
                                color: "#374151",
                            }}
                        >
                            No Assets Found
                        </h3>
                        <p style={{ fontSize: "16px", marginBottom: "16px" }}>
                            There are currently no assets matching your search criteria.
                        </p>
                    </div>
                )}
            />

            <div className="assets__main-container">
                <div className="assets__container-exportbtn">
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
