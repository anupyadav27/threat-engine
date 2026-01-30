"use client";

import { useRouter } from "next/navigation";

export default function SubSideBar({ isVisible, menuItem, onMouseEnter, onMouseLeave }) {
    const router = useRouter();

    if (!isVisible || !menuItem?.subMenu?.length) return null;

    return (
        <aside
            className={`sub-sidebar ${isVisible ? "open" : ""}`}
            onMouseEnter={onMouseEnter}
            onMouseLeave={onMouseLeave}
        >
            <div className={`sub-sidebar__title`}>{menuItem.label}</div>
            {menuItem.subMenu.map((sub, idx) => (
                <div key={idx} className="sub-sidebar__item" onClick={() => router.push(sub.route)}>
                    {sub.label}
                </div>
            ))}
        </aside>
    );
}
