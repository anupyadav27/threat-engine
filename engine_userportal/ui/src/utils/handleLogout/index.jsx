import { clearClientData } from "@/utils/clearClientData";

const handleLogout = async (dispatch) => {
    try {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/auth/logout/`, {
            method: "POST",
            credentials: "include",
        });

        const data = await res.json();

        await clearClientData();

        if (dispatch) dispatch({ type: "LOGOUT" });

        const currentPath = window.location.pathname;

        if (data?.sso && data?.redirectUrl) {
            if (currentPath !== data.redirectUrl) {
                window.location.href = data.redirectUrl;
            }
            return;
        }

        if (currentPath !== "/auth/login") {
            window.location.href = "/auth/login";
        }
    } catch (error) {
        console.info("Logout error:", error);

        await clearClientData();
        if (dispatch) dispatch({ type: "LOGOUT" });

        const currentPath = window.location.pathname;
        if (currentPath !== "/auth/login") {
            window.location.href = "/auth/login";
        }
    }
};

export default handleLogout;
