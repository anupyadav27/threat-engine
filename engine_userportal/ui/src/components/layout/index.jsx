"use client";

import Sidebar from "@/components/sideBar";
import Header from "@/components/header";
import SubSideBar from "@/components/subSideBar";
import { useEffect, useRef, useState } from "react";
import { menuItems } from "@/data/components/menuItems";
import { usePathname, useRouter } from "next/navigation";
import { useAppContext } from "@/context/appContext";
import { usePermissions } from "@/context/appContext/usePermissions";
import { canAccessRoute } from "@/utils/permissions";
import SpinnerLoaderOverlay from "@/components/spinnerLoaderOverlay";

const PUBLIC_PATHS = ["/auth/login", "/auth/forget-password"];

export default function Layout({ children, headerLabel, isLoading = false }) {
    const { state, dispatch } = useAppContext();
    const { capabilities, isSuperLandlord } = usePermissions();
    const appLoading = state.isLoading;
    const [isClient, setIsClient] = useState(false);
    const [activeItem, setActiveItem] = useState(null);
    const [hoveredItem, setHoveredItem] = useState(null);
    const [isMouseOverSubSidebar, setIsMouseOverSubSidebar] = useState(false);

    const hideTimeoutRef = useRef(null);
    const pathname = usePathname();
    const router = useRouter();

    useEffect(() => {
        setIsClient(true);
        return () => {
            if (hideTimeoutRef.current) clearTimeout(hideTimeoutRef.current);
        };
    }, []);

    useEffect(() => {
        const matched = menuItems.find((item) => pathname.startsWith(item.link));
        setActiveItem(matched || null);
    }, [pathname]);

    useEffect(() => {
        if (!pathname || PUBLIC_PATHS.some((p) => pathname.startsWith(p))) return;
        if (!state.isAuthenticated || !state.isInitialized) return;
        if (canAccessRoute(pathname, capabilities, isSuperLandlord)) return;
        router.replace("/dashboard");
    }, [pathname, state.isAuthenticated, state.isInitialized, capabilities, isSuperLandlord, router]);

    const handleSidebarClick = (item) => {
        if (!pathname.startsWith(item.link)) {
            dispatch({ type: "SET_LOADING", payload: true });
            setActiveItem(item);
            router.push(item.link);
        }
    };

    const isSubSidebarVisible = hoveredItem?.subMenu?.length > 0;

    const scheduleHide = () => {
        if (hideTimeoutRef.current) {
            clearTimeout(hideTimeoutRef.current);
        }
        hideTimeoutRef.current = setTimeout(() => {
            setHoveredItem(null);
            setIsMouseOverSubSidebar(false);
        }, 200);
    };

    const cancelHide = () => {
        if (hideTimeoutRef.current) {
            clearTimeout(hideTimeoutRef.current);
            hideTimeoutRef.current = null;
        }
    };

    return (
        <div className="layout">
            <Sidebar
                activeItem={activeItem}
                onItemClick={handleSidebarClick}
                onItemHover={(item) => {
                    cancelHide();
                    setHoveredItem(item);
                }}
                onItemLeave={scheduleHide}
            />

            <div className="layout__main">
                <Header title={headerLabel || activeItem?.label} />
                <div>
                    <SubSideBar
                        isVisible={isSubSidebarVisible}
                        menuItem={hoveredItem}
                        onMouseEnter={() => {
                            cancelHide();
                            setIsMouseOverSubSidebar(true);
                        }}
                        onMouseLeave={scheduleHide}
                    />
                </div>
                <div className="layout__body">
                    <div className="layout__content">
                        {isClient && <SpinnerLoaderOverlay isLoading={appLoading || isLoading} />}
                        {children}
                    </div>
                </div>
            </div>
        </div>
    );
}
