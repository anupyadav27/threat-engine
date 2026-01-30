"use client";

import React, { useEffect, useState } from "react";
import Layout from "@/components/layout";
import { fetchData } from "@/utils/fetchData";
import {
    FaBell,
    FaCheck,
    FaChevronDown,
    FaChevronRight,
    FaExclamationTriangle,
    FaFilter,
    FaInfoCircle,
    FaTrashAlt,
} from "react-icons/fa";
import { useAppContext } from "@/context/appContext/index.jsx";

export default function NotificationsPage() {
    const [notifications, setNotifications] = useState([]);
    const [expandedId, setExpandedId] = useState(null);
    const [stats, setStats] = useState({ total: 0, unread: 0 });
    const { dispatch } = useAppContext();
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        loadNotifications();
    }, []);

    const loadNotifications = async () => {
        dispatch({ type: "SET_LOADING", payload: false });
        setLoading(true);
        try {
            const url = `${process.env.NEXT_PUBLIC_API_URL}/api/notifications`;
            const result = await fetchData(url);

            if (result?.data) {
                const sorted = result.data.sort(
                    (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
                );
                setNotifications(sorted);

                const unreadCount = sorted.filter((n) => !n.read).length;
                setStats({ total: sorted.length, unread: unreadCount });
            }
        } catch (err) {
            console.info("Error fetching notifications:", err);
        } finally {
            setLoading(false);
        }
    };

    const markAsRead = (id) => {
        setNotifications((prev) => prev.map((n) => (n._id === id ? { ...n, read: true } : n)));
        setStats((prev) => ({
            ...prev,
            unread: prev.unread > 0 ? prev.unread - 1 : 0,
        }));
    };

    const markAsUnread = (id) => {
        setNotifications((prev) => prev.map((n) => (n._id === id ? { ...n, read: false } : n)));
        setStats((prev) => ({
            ...prev,
            unread: prev.unread + 1,
        }));
    };

    const deleteNotification = (id) => {
        setNotifications((prev) => prev.filter((n) => n._id !== id));
        setStats((prev) => ({
            ...prev,
            total: prev.total - 1,
            unread: prev.unread > 0 ? prev.unread - 1 : 0,
        }));
    };

    const getIcon = (type) => {
        switch (type) {
            case "alert":
                return <FaExclamationTriangle />;
            case "update":
                return <FaInfoCircle />;
            default:
                return <FaBell />;
        }
    };

    const getIconClass = (type) => {
        switch (type) {
            case "alert":
                return "notifications__icon notifications__icon--alert";
            case "update":
                return "notifications__icon notifications__icon--update";
            default:
                return "notifications__icon notifications__icon--info";
        }
    };

    const toggleExpand = (id) => {
        setExpandedId(expandedId === id ? null : id);
    };

    const renderSkeleton = () => (
        <div className="notification-skeleton">
            <div className="skeleton-title"></div>
        </div>
    );

    return (
        <Layout headerLabel={`Notifications`}>
            <div className="notifications-page">
                <div className="notifications-header">
                    <div className="header-left">
                        <button className="action-btn primary-btn">
                            <FaFilter /> Filter
                        </button>
                        <div className="filters">
                            <select className="filter-dropdown">
                                <option>All Types</option>
                                <option>Alert</option>
                                <option>System</option>
                                <option>Update</option>
                            </select>
                            <select className="filter-dropdown">
                                <option>All Priorities</option>
                                <option>High</option>
                                <option>Medium</option>
                                <option>Low</option>
                            </select>
                        </div>
                    </div>
                    <div className="header-right">
                        <div className="notification-stats">
                            <span>Total: {stats.total}</span>
                            <span>Unread: {stats.unread}</span>
                        </div>
                    </div>
                </div>

                <div className={`notifications-container`}>
                    {loading ? (
                        Array.from({ length: 5 }).map((_, i) => (
                            <React.Fragment key={i}>{renderSkeleton()}</React.Fragment>
                        ))
                    ) : notifications.length === 0 ? (
                        <div className="no-notifications">
                            <FaBell size={24} /> No notifications found
                        </div>
                    ) : (
                        <div className="notifications-list">
                            {notifications.map((n) => (
                                <div
                                    key={n._id}
                                    className={`notification-item ${n.read ? "read" : "unread"}`}
                                >
                                    <div className="notification-main">
                                        <div className="notification-title">
                                            <div className={getIconClass(n.category)}>
                                                {getIcon(n.category)}
                                            </div>
                                            <span>{n.title}</span>
                                        </div>
                                        <div className="notification-actions">
                                            {!n.read ? (
                                                <button
                                                    className="action-btn mark-read-btn"
                                                    onClick={() => markAsRead(n._id)}
                                                >
                                                    <FaCheck /> Mark as Read
                                                </button>
                                            ) : (
                                                <button
                                                    className="action-btn mark-unread-btn"
                                                    onClick={() => markAsUnread(n._id)}
                                                >
                                                    <FaBell /> Mark as Unread
                                                </button>
                                            )}
                                            <button
                                                className="action-btn delete-btn"
                                                onClick={() => deleteNotification(n._id)}
                                            >
                                                <FaTrashAlt /> Delete
                                            </button>
                                            <button
                                                className="expand-btn"
                                                onClick={() => toggleExpand(n._id)}
                                            >
                                                {expandedId === n._id ? (
                                                    <FaChevronDown />
                                                ) : (
                                                    <FaChevronRight />
                                                )}
                                            </button>
                                        </div>
                                    </div>

                                    {expandedId === n._id && (
                                        <div className="notification-details">
                                            <div>
                                                <strong>Tenant:</strong> {n.tenantId?.name || "N/A"}
                                            </div>
                                            <div>
                                                <strong>User:</strong> {n.userId?.email || "N/A"}
                                            </div>
                                            <div>
                                                <strong>Category:</strong> {n.category}
                                            </div>
                                            <div>
                                                <strong>Priority:</strong>{" "}
                                                <span className={`priority ${n.priority}`}>
                                                    {n.priority}
                                                </span>
                                            </div>
                                            <div>
                                                <strong>Severity Score:</strong> {n.severityScore}
                                            </div>
                                            <div>
                                                <strong>Source:</strong> {n.source}
                                            </div>
                                            <div>
                                                <strong>Body:</strong> {n.body}
                                            </div>
                                            <div>
                                                <strong>Created:</strong>{" "}
                                                {new Date(n.createdAt).toLocaleString()}
                                            </div>
                                            <div className="delivery-info">
                                                <strong>Delivery Status:</strong>
                                                <ul>
                                                    <li>
                                                        Email:{" "}
                                                        {n.delivery.email.delivered
                                                            ? "Delivered"
                                                            : "Pending"}
                                                    </li>
                                                    <li>
                                                        Webhook:{" "}
                                                        {n.delivery.webhook.delivered
                                                            ? "Delivered"
                                                            : "Pending"}
                                                    </li>
                                                    <li>
                                                        SIEM:{" "}
                                                        {n.delivery.siem.delivered
                                                            ? "Delivered"
                                                            : "Pending"}
                                                    </li>
                                                </ul>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </Layout>
    );
}
