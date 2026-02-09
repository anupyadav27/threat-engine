export const fetchData = async (url, { force = false, validate = false } = {}) => {
    const cacheMode = force ? "no-store" : validate ? "no-cache" : "default";
    
    const fetchConfig = {
        method: "GET",
        credentials: "include",
        cache: cacheMode,
        headers: {
            Accept: "application/json",
        },
    };

    const performFetch = async () => {
        const response = await fetch(url, fetchConfig);
        return response;
    };

    try {
        let response = await performFetch();
        
        if (response.status === 401) {
            console.warn("Session expired or unauthorized (401)");
            return {
                success: false,
                message: "Authentication required",
                data: null,
                pagination: null,
                logOut: true,
                error: "Session expired",
                status: 401,
                fromCache: false,
            };
        }
        
        if (!response.ok) {
            let errorMessage = `Request failed (${response.status})`;
            let errorData = null;

            try {
                errorData = await response.json();
                errorMessage = errorData.message || errorData.error || errorMessage;
            } catch {
                const text = await response.text();
                errorMessage = text || errorMessage;
            }

            return {
                success: false,
                message: errorMessage,
                data: null,
                pagination: null,
                logOut: false,
                error: errorMessage,
                status: response.status,
                fromCache: false,
            };
        }
        
        const apiResponse = await response.json();
        
        const isValidStructure =
            typeof apiResponse.success === "boolean" && "data" in apiResponse;
        
        if (!isValidStructure) {
            console.error("Invalid API response structure:", apiResponse);
            return {
                success: false,
                message: "Invalid API response format",
                data: null,
                pagination: null,
                logOut: false,
                error: "Unexpected response from server",
                status: response.status,
                fromCache: false,
            };
        }
        
        const fromCache = response.headers.has("X-Cache")
            ? response.headers.get("X-Cache") === "HIT"
            : false;
        
        return {
            ...apiResponse,
            logOut: false,
            error: null,
            status: response.status,
            fromCache,
        };
    } catch (networkError) {
        console.error("Network error during fetch:", networkError);
        return {
            success: false,
            message: "Network error",
            data: null,
            pagination: null,
            logOut: false,
            error: networkError.message || "Failed to reach server",
            status: null,
            fromCache: false,
        };
    }
};
