"use client";

import React, { useEffect, useState } from "react";
import Layout from "@/components/layout";
import { useAppContext } from "@/context/appContext";
import { fetchData } from "@/utils/fetchData";
import TableGrid from "@/components/tableGrid";
import { useAuthActions } from "@/context/appContext/useAuthActions/index.jsx";
import { notFound } from "next/navigation";

export default function SecOps() {
    return notFound();
    //
    // const { state, dispatch } = useAppContext();
    // const { handleLogout } = useAuthActions();
    //
    // const [secops, setSecops] = useState([]);
    // const [page, setPage] = useState(1);
    // const [pageSize, setPageSize] = useState(10);
    // const [searchFilters, setSearchFilters] = useState({});
    // const [filterValues, setFilterValues] = useState({});
    // const [paginationData, setPaginationData] = useState(null);
    //
    //
    //
    // const loadSecOps = async (options = {}) => {
    //     const { force = false, validate = false } = options;
    //     try {
    //         dispatch({ type: "SET_LOADING", payload: true });
    //
    //         const queryParams = new URLSearchParams();
    //
    //         queryParams.append("page", page);
    //         queryParams.append("pageSize", pageSize);
    //
    //         for (const [key, value] of Object.entries(searchFilters)) {
    //             if (value?.trim()) {
    //                 queryParams.append(`${key}_search`, value.trim());
    //             }
    //         }
    //
    //         for (const [key, value] of Object.entries(filterValues)) {
    //             if (value) {
    //                 queryParams.append(key, value);
    //             }
    //         }
    //
    //         const url = `${process.env.NEXT_PUBLIC_API_URL}/api/secops?${queryParams.toString()}`;
    //         const result = await fetchData(url, { force, validate });
    //
    //         if (result?.logOut) {
    //             handleLogout(dispatch);
    //             return;
    //         }
    //
    //         if (result?.data) {
    //             setSecops(result.data);
    //         }
    //         if (result?.pagination) {
    //             setPaginationData(result.pagination);
    //         }
    //     } catch (error) {
    //         console.info("Error fetching SecOps:", error);
    //     } finally {
    //         dispatch({ type: "SET_LOADING", payload: false });
    //     }
    // };
    //
    // useEffect(() => {
    //     loadSecOps({ validate: true });
    // }, [page, pageSize, searchFilters, filterValues]);
    //
    // const handleColumnSearch = ({ key, value }) => {
    //     setSearchFilters((prev) => ({ ...prev, [key]: value }));
    // };
    //
    // const handleFilterChange = ({ key, value }) => {
    //     setFilterValues((prev) => ({ ...prev, [key]: value }));
    // };
    //
    // const columns = [
    //     {
    //         key: "_id",
    //         title: "ID",
    //         width: 90,
    //         stick: true,
    //         render: (value) => value?.slice(-6) || "-",
    //     },
    //     {
    //         key: "tenantId",
    //         title: "Tenant",
    //         width: 180,
    //         render: (value) => value?.name || "-",
    //     },
    //     {
    //         key: "project",
    //         title: "Project",
    //         searchable: true,
    //         width: 160,
    //     },
    //     {
    //         key: "repository",
    //         title: "Repository",
    //         searchable: true,
    //         width: 220,
    //     },
    //     {
    //         key: "branch",
    //         title: "Branch",
    //         searchable: true,
    //         width: 120,
    //     },
    //     {
    //         key: "commitId",
    //         title: "Commit ID",
    //         searchable: true,
    //         width: 120,
    //     },
    //     {
    //         key: "tool",
    //         title: "Tool",
    //         width: 120,
    //         filterable: true,
    //         filterOptions: [
    //             { label: "All", value: "" },
    //             { label: "SonarQube", value: "SonarQube" },
    //             { label: "Snyk", value: "Snyk" },
    //             { label: "Checkmarx", value: "Checkmarx" },
    //         ],
    //     },
    //     {
    //         key: "ruleName",
    //         title: "Rule Name",
    //         searchable: true,
    //         width: 250,
    //     },
    //     {
    //         key: "severity",
    //         title: "Severity",
    //         filterable: true,
    //         width: 130,
    //         filterOptions: [
    //             { label: "All", value: "" },
    //             { label: "Critical", value: "critical" },
    //             { label: "High", value: "high" },
    //             { label: "Medium", value: "medium" },
    //             { label: "Low", value: "low" },
    //         ],
    //         render: (value) => {
    //             const colorMap = {
    //                 critical: "#dc2626",
    //                 high: "#f97316",
    //                 medium: "#eab308",
    //                 low: "#22c55e",
    //             };
    //             const color = colorMap[value] || "#6b7280";
    //             return (
    //                 <span
    //                     style={{
    //                         backgroundColor: color + "20",
    //                         color,
    //                         padding: "2px 6px",
    //                         borderRadius: "6px",
    //                         fontWeight: 600,
    //                         textTransform: "capitalize",
    //                     }}
    //                 >
    //                     {value || "-"}
    //                 </span>
    //             );
    //         },
    //     },
    //     {
    //         key: "status",
    //         title: "Status",
    //         filterable: true,
    //         width: 130,
    //         filterOptions: [
    //             { label: "All", value: "" },
    //             { label: "Open", value: "open" },
    //             { label: "Resolved", value: "resolved" },
    //         ],
    //         render: (value) => (
    //             <span
    //                 style={{
    //                     color: value === "resolved" ? "#22c55e" : "#ef4444",
    //                     fontWeight: 600,
    //                     textTransform: "capitalize",
    //                 }}
    //             >
    //                 {value || "-"}
    //             </span>
    //         ),
    //     },
    //     {
    //         key: "type",
    //         title: "Type",
    //         width: 130,
    //         filterable: true,
    //         filterOptions: [
    //             { label: "All", value: "" },
    //             { label: "Bug", value: "bug" },
    //             { label: "Vulnerability", value: "vulnerability" },
    //             { label: "Code Smell", value: "code_smell" },
    //         ],
    //         render: (value) => (
    //             <span
    //                 style={{
    //                     backgroundColor: "#f3f4f6",
    //                     color: "#111827",
    //                     padding: "2px 6px",
    //                     borderRadius: "6px",
    //                     textTransform: "capitalize",
    //                 }}
    //             >
    //                 {value || "-"}
    //             </span>
    //         ),
    //     },
    //     {
    //         key: "owner",
    //         title: "Owner",
    //         searchable: true,
    //         width: 140,
    //     },
    //     {
    //         key: "filePath",
    //         title: "File Path",
    //         searchable: true,
    //         width: 220,
    //     },
    //     {
    //         key: "line",
    //         title: "Line",
    //         width: 70,
    //     },
    //     {
    //         key: "introducedAt",
    //         title: "Introduced At",
    //         width: 170,
    //         render: (value) => (value ? new Date(value).toLocaleString() : "-"),
    //     },
    //     {
    //         key: "fixedAt",
    //         title: "Fixed At",
    //         width: 170,
    //         render: (value) => (value ? new Date(value).toLocaleString() : "-"),
    //     },
    // ];
    //

    //
    // return (
    //     <Layout>
    //         <TableGrid
    //             columns={columns}
    //             data={secops}
    //             paginationMode="server"
    //             controlledPage={page}
    //             controlledPageSize={pageSize}
    //             onPageChange={setPage}
    //             onPageSizeChange={setPageSize}
    //             totalCount={paginationData?.total}
    //             onSearch={handleColumnSearch}
    //             onFilter={handleFilterChange}
    //             pageSizeOptions={[5, 10, 20, 50]}
    //             maxHeight="60vh"
    //             maxWidth="100%"
    //             renderNoData={() => "No SecOps issues found"}
    //         />
    //     </Layout>
    // );
}
