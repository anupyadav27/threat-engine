"use client";

import { useMemo } from "react";
import { menuItems } from "@/data/components/menuItems";
import { filterMenuByCapabilities } from "@/utils/permissions";
import { usePermissions } from "@/context/appContext/usePermissions";

export default function Sidebar({ activeItem, onItemClick, onItemHover, onItemLeave }) {
    const { capabilities, isSuperLandlord } = usePermissions();
    const filtered = useMemo(
        () => filterMenuByCapabilities(menuItems, capabilities, isSuperLandlord),
        [capabilities, isSuperLandlord]
    );

    return (
        <div className="sidebar">
            <div className="sidebar__main">
                <div className="sidebar__title">CSPM</div>
                {filtered.map((item) => (
                    <div
                        key={item.id}
                        className={`sidebar__item ${activeItem?.id === item.id ? "sidebar__item--active" : ""}`}
                        onClick={() => onItemClick(item)}
                        onMouseEnter={() => onItemHover(item)}
                        onMouseLeave={onItemLeave}
                    >
                        <div className="sidebar__icon">{item.icon}</div>
                        <span className="sidebar__label">{item.label}</span>
                    </div>
                ))}
            </div>
        </div>
    );
}
