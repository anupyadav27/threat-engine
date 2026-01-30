"use client";

import { createContext, useContext, useEffect, useReducer, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { appReducer, initialState } from "./reducer";
import notificationsData from "@/data/samples/notifications.json";
import { fetchData } from "@/utils/fetchData";
import handleLogout from "@/utils/handleLogout";
import { ensureCsrf } from "@/utils/csrf";

const AppContext = createContext();

export const AppProvider = ({ children }) => {
    const pathname = usePathname();
    const router = useRouter();
    const [loading, setLoading] = useState(true);
    const [retryCount, setRetryCount] = useState(0);

    const savedState =
        typeof window !== "undefined" && sessionStorage.getItem("appState")
            ? JSON.parse(sessionStorage.getItem("appState"))
            : initialState;

    const [state, dispatch] = useReducer(appReducer, {
        ...savedState,
        isInitialized: savedState?.isInitialized || false,
    });

    useEffect(() => {
        if (typeof window !== "undefined") {
            try {
                sessionStorage.setItem("appState", JSON.stringify(state));
            } catch (err) {
                console.info("Failed to persist app state:", err);
            }
        }
    }, [state]);

    useEffect(() => {
        const handleStorage = (e) => {
            if (e.key === "appState") {
                if (e.newValue) {
                    const parsed = JSON.parse(e.newValue);
                    dispatch({ type: "SET_USER", payload: { user: parsed.user } });
                } else {
                    dispatch({ type: "LOGOUT" });
                }
            }
        };
        window.addEventListener("storage", handleStorage);
        return () => window.removeEventListener("storage", handleStorage);
    }, []);

    const initializeApp = async () => {
        setLoading(true);
        try {
            
            await ensureCsrf();
            
            let { user, isAuthenticated } = state;

            if (!isAuthenticated || !user) {
                try {
                    const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/auth/refresh/`, {
                        method: "POST",
                        credentials: "include",
                    });

                    if (res.ok) {
                        const data = await res.json();
                        if (data?.user) {
                            dispatch({
                                type: "LOGIN",
                                payload: { user: data.user, token: data.token },
                            });
                            user = data.user;
                            isAuthenticated = true;
                        }
                    } else {
                        setLoading(false);
                        return;
                    }
                } catch (err) {
                    console.info("Session refresh failed:", err.message);
                    setLoading(false);
                    return;
                }
            }

            if (isAuthenticated && user) {
                const meRes = await fetch(
                    `${process.env.NEXT_PUBLIC_API_URL}/api/auth/me/`,
                    { credentials: "include" }
                );
                if (!meRes.ok) {
                    handleLogout(dispatch);
                    setLoading(false);
                    return;
                }
                const me = await meRes.json();
                dispatch({
                    type: "SET_ME",
                    payload: {
                        user: me.user,
                        roles: me.roles ?? [],
                        scope: {
                            allowed_tenant_ids: me.allowed_tenant_ids,
                            allowed_customer_ids: me.allowed_customer_ids,
                            is_super_landlord: me.is_super_landlord ?? false,
                        },
                        capabilities: me.capabilities ?? [],
                    },
                });

                const tenantData = await fetchData(
                    `${process.env.NEXT_PUBLIC_API_URL}/api/tenants`,
                    { force: false, validate: true }
                );
                if (tenantData.error || ![200, 304].includes(tenantData.status)) {
                    dispatch({ type: "SET_INITIALIZED", payload: false });
                } else {
                    dispatch({ type: "SET_INITIALIZED", payload: true });
                }
                if (tenantData.logOut) {
                    handleLogout(dispatch);
                }

                dispatch({ type: "SET_TENANTS", payload: tenantData });
                const tenants = Array.isArray(tenantData?.data) ? tenantData.data : [];
                const singleId = me.allowed_tenant_ids?.length === 1 ? me.allowed_tenant_ids[0] : null;
                const preferred = singleId
                    ? tenants.find((t) => t.id === singleId)
                    : tenants[0];
                dispatch({ type: "SELECT_TENANT", payload: preferred ?? null });

                dispatch({
                    type: "SET_NOTIFICATIONS",
                    payload: notificationsData.notifications || [],
                });
                dispatch({
                    type: "SET_NOTIFICATION_SETTINGS",
                    payload: notificationsData.notificationSettings || {},
                });
            }
        } catch (err) {
            console.info("App initialization failed:", err);
            dispatch({ type: "SET_INITIALIZED", payload: false });
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (state.isAuthenticated && !state.isInitialized) {
            initializeApp();
        }
    }, [state.isAuthenticated]);

    useEffect(() => {
        initializeApp();
    }, []);

    useEffect(() => {
        if (!loading && state.isAuthenticated && !state.isInitialized) {
            const maxRetries = 5;
            if (retryCount < maxRetries) {
                const retryDelay = 5000;
                console.info(`Retrying initialization... Attempt ${retryCount + 1}`);
                const timer = setTimeout(() => {
                    setRetryCount((prev) => prev + 1);
                    initializeApp();
                }, retryDelay);
                return () => clearTimeout(timer);
            } else {
                console.info("Max retries reached. Initialization failed permanently.");
            }
        }
    }, [state.isInitialized, loading, retryCount, state.isAuthenticated]);

    useEffect(() => {
        if (!loading) {
            const PUBLIC_ROUTES = ["/auth/login", "/auth/forget-password"];
            if (!state.isAuthenticated && !PUBLIC_ROUTES.includes(pathname)) {
                router.replace("/auth/login");
            }
        }
    }, [state.isAuthenticated, pathname, router, loading]);

    return (
        <AppContext.Provider value={{ state, dispatch, loading }}>{children}</AppContext.Provider>
    );
};

export const useAppContext = () => useContext(AppContext);
