"use client";

import Layout from "@/components/layout";
import TableGrid from "@/components/tableGrid";
import React, { useEffect, useRef, useState } from "react";
import { useAppContext } from "@/context/appContext";
import { fetchData } from "@/utils/fetchData";
import Button from "@/components/button/index.jsx";
import { FaDownload } from "react-icons/fa";
import { ProgressLoader } from "@/components/loaders/index.jsx";

export default function Tenants() {
    const { dispatch } = useAppContext();

    const [tenants, setTenants] = useState([]);
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
        return `${process.env.NEXT_PUBLIC_API_URL}/api/tenants/export?${queryParams.toString()}`;
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
            const fileName = `tenants_export_${new Date().toISOString().split("T")[0]}.${extension}`;

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

    const loadTenants = async (options = {}) => {
        const { force = true, validate = true } = options;
        try {
            dispatch({ type: "SET_LOADING", payload: true });

            const queryParams = new URLSearchParams();
            queryParams.append("page", page);
            queryParams.append("pageSize", pageSize); // ✅ Matches Django's page_size_query_param

            // Handle search filters (field_search)
            for (const [key, value] of Object.entries(searchFilters)) {
                if (value?.trim()) {
                    queryParams.append(`${key}_search`, value.trim());
                }
            }

            // Handle exact filters (status, plan, region)
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

            const url = `${process.env.NEXT_PUBLIC_API_URL}/api/tenants/?${queryParams.toString()}`;

            const result = await fetchData(url, { force:true, validate:true });
            
            if (result?.success && Array.isArray(result.data)) {
                setTenants(result.data);
                setTotalCount(result.pagination?.total || 0);
            } else {
                setTenants([]);
                setTotalCount(0);
            }
        } catch (error) {
            console.error("Error fetching tenants:", error);
            setTenants([]);
            setTotalCount(0);
        } finally {
            dispatch({ type: "SET_LOADING", payload: false });
        }
    };

    useEffect(() => {
        loadTenants({ validate: true });
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

    const handleEdit = (tenant) => {
        alert(`Editing tenant: ${tenant.name}`);
    };

    const handleDelete = (tenant) => {
        if (window.confirm(`Are you sure you want to delete ${tenant.name}?`)) {
            setTenants((prev) => prev.filter((t) => t.id !== tenant.id));
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
            title: "Tenant Name",
            searchable: true,
            sortable: true,
            width: 200,
            stick: true,
        },
        {
            key: "description",
            title: "Description",
            searchable: true,
            sortable: true,
            maxWidth: 400,
        },
        {
            key: "status",
            title: "Status",
            filterable: true,
            sortable: true,
            filterOptions: [
                { label: "Active", value: "active" },
                { label: "Inactive", value: "inactive" },
                { label: "Suspended", value: "suspended" },
                { label: "Trial", value: "trial" },
            ],
            render: (value) => {
                const color =
                    value === "active"
                        ? "#22c55e"
                        : value === "suspended"
                          ? "#ef4444"
                          : value === "trial"
                            ? "#3b82f6"
                            : "#f59e0b";
                return (
                    <span style={{ color, fontWeight: 600 }}>
                        {value ? value.charAt(0).toUpperCase() + value.slice(1) : "-"}
                    </span>
                );
            },
        },
        {
            key: "plan",
            title: "Plan",
            filterable: true,
            sortable: true,
            filterOptions: [
                { label: "Free", value: "free" },
                { label: "Basic", value: "basic" },
                { label: "Pro", value: "pro" },
                { label: "Enterprise", value: "enterprise" },
            ],
            render: (value) => (
                <span
                    style={{
                        backgroundColor:
                            value === "enterprise"
                                ? "#e6f3ff"
                                : value === "pro"
                                  ? "#f0fdf4"
                                  : value === "basic"
                                    ? "#fef7e6"
                                    : "#f3e8ff",
                        color:
                            value === "enterprise"
                                ? "#0b62a8"
                                : value === "pro"
                                  ? "#16a34a"
                                  : value === "basic"
                                    ? "#9c6b00"
                                    : "#7e22ce",
                        padding: "2px 6px",
                        borderRadius: "6px",
                        fontSize: "12px",
                    }}
                >
                    {value?.charAt(0).toUpperCase() + value?.slice(1)}
                </span>
            ),
        },
        {
            key: "region",
            title: "Region",
            width: 120,
            searchable: true,
            sortable: true,
            filterOptions: [
                { label: "US East", value: "us-east" },
                { label: "US West", value: "us-west" },
                { label: "EU Central", value: "eu-central" },
                { label: "AP South", value: "ap-south" },
            ],
            render: (value) => value?.toUpperCase() || "-",
        },
        {
            key: "contact_email",
            title: "Contact Email",
            searchable: true,
            sortable: true,
            width: 200,
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
        <Layout headerLabel="Tenants">
            <TableGrid
                columns={columns}
                data={tenants}
                paginationMode="server"
                controlledPage={page}
                controlledPageSize={pageSize}
                onPageChange={setPage}
                onPageSizeChange={setPageSize}
                totalCount={totalCount}
                onSearch={handleColumnSearch}
                onFilter={handleFilterChange}
                onSort={handleSort}
                pageSizeOptions={[10, 20, 50]}
                maxHeight="60vh"
                maxWidth="100%"
                renderNoData={() => "No tenants found"}
            />
            <div className="tenants__main-container">
                <div className="tenants__container-exportbtn">
                    <Button
                        onClick={() => downloadFile("pdf")}
                        disabled={downloadProgress.isDownloading}
                        text={
                            downloadProgress.isDownloading && docType === "pdf"
                                ? "Exporting..."
                                : "Download as PDF"
                        }
                        danger
                        iconRight={<FaDownload />}
                    />

                    <Button
                        onClick={() => downloadFile("xlsx")}
                        disabled={downloadProgress.isDownloading}
                        text={
                            downloadProgress.isDownloading && docType === "xlsx"
                                ? "Exporting..."
                                : "Download as Excel"
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
                            color="success"
                            showLabel={true}
                        />
                    </div>
                )}
            </div>
        </Layout>
    );
}
