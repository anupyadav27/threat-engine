"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import notificationsData from "@/data/samples/notifications.json";
import { useTenantActions } from "@/context/appContext/useTenantActions";
import { useAuthActions } from "@/context/appContext/useAuthActions";
import { useAppContext } from "@/context/appContext";

export default function Header({ title }) {
    const router = useRouter();
    const [showUserMenu, setShowUserMenu] = useState(false);
    const [showTenantMenu, setShowTenantMenu] = useState(false);
    const [currentUser, setCurrentUser] = useState(null);
    const [selectedTenant, setSelectedTenant] = useState(null);
    const [tenants, setTenants] = useState([]);
    const { state, dispatch } = useAppContext();
    const { handleLogout } = useAuthActions();
    const { switchTenant } = useTenantActions();

    const userMenuRef = useRef(null);
    const tenantMenuRef = useRef(null);

    useEffect(() => {
        setCurrentUser(state?.user);
        setTenants(state?.tenants?.data || []);
        setSelectedTenant(state?.selectedTenant || null);
    }, [state]);

    const unreadCount = notificationsData.notifications?.filter((n) => !n.read).length || 0;

    const handleTenantSwitch = (tenantId) => {
        switchTenant(tenantId);
        setShowTenantMenu(false);
    };

    const handleClick = (link) => {
        dispatch({ type: "SET_LOADING", payload: true });
        router.push(link);
    };

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (userMenuRef.current && !userMenuRef.current.contains(event.target)) {
                setShowUserMenu(false);
            }
            if (tenantMenuRef.current && !tenantMenuRef.current.contains(event.target)) {
                setShowTenantMenu(false);
            }
        };

        document.addEventListener("mousedown", handleClickOutside);
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, []);

    return (
        <header className="header">
            <div className="header__content">
                <div className="header__left">
                    <h1 className="header__title">{title}</h1>
                </div>

                <div className="header__actions">
                    <div className="header__tenant" ref={tenantMenuRef}>
                        <button
                            className="header__tenant-btn"
                            onClick={() => {
                                setShowTenantMenu(!showTenantMenu);
                                setShowUserMenu(false);
                            }}
                        >
                            {selectedTenant?.name || "Select Tenant"}
                            <svg
                                className={`header__tenant-icon ${showTenantMenu ? "rotate-180" : ""}`}
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                            >
                                <path
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                    strokeWidth={2}
                                    d="M19 9l-7 7-7-7"
                                />
                            </svg>
                        </button>

                        {showTenantMenu && tenants.length > 1 && (
                            <div className="header__dropdown">
                                {tenants.map((tenant) => (
                                    <button
                                        key={tenant.id}
                                        onClick={() => handleTenantSwitch(tenant.id)}
                                        className={`header__dropdown-item ${
                                            selectedTenant?.id === tenant.id ? "active" : ""
                                        }`}
                                    >
                                        {tenant.name}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>

                    <div className="header__notifications">
                        <button
                            className="header__icon-btn"
                            onClick={() => handleClick(`/notifications`)}
                        >
                            <svg
                                className="header__icon"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                            >
                                <path
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                    strokeWidth={2}
                                    d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
                                />
                            </svg>
                            {unreadCount > 0 && (
                                <span className="header__badge">{unreadCount}</span>
                            )}
                        </button>
                    </div>

                    <div className="header__user" ref={userMenuRef}>
                        <button
                            className="header__user-btn"
                            onClick={() => {
                                setShowUserMenu(!showUserMenu);
                                setShowTenantMenu(false);
                            }}
                        >
                            <div className="header__avatar">
                                {currentUser?.name?.split(" ")[0][0]}
                                {currentUser?.name?.split(" ")[1][0]}
                            </div>
                        </button>

                        {showUserMenu && (
                            <div className="header__dropdown header__dropdown--right">
                                <p
                                    onClick={() => handleClick(`/profile`)}
                                    className="header__dropdown-item"
                                >
                                    Profile
                                </p>
                                <p
                                    onClick={() => handleClick(`/settings`)}
                                    className="header__dropdown-item"
                                >
                                    Settings
                                </p>
                                <button
                                    onClick={handleLogout}
                                    className="header__dropdown-item header__dropdown-item--danger"
                                >
                                    Logout
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </header>
    );
}
