export const initialState = {
    user: null,
    role: null,
    roles: [],
    isAuthenticated: false,
    tenants: { data: [], pagination: {} },
    selectedTenant: null,
    notifications: [],
    notificationSettings: null,
    isLoading: true,
    isInitialized: false,
    scope: null,
    capabilities: [],
};

export function appReducer(state, action) {
    let newState = { ...state };

    switch (action.type) {
        case "LOGIN":
            newState = {
                ...state,
                user: action.payload.user || null,
                role: action.payload.user?.roles?.[0] || null,
                isAuthenticated: true,
                isLoading: false,
                isInitialized: false,
            };
            break;

        case "SET_USER":
            newState = {
                ...state,
                user: action.payload.user || null,
                role: action.payload.user?.roles?.[0] || null,
            };
            break;

        case "LOGOUT":
            newState = {
                ...initialState,
                tenants: state.tenants,
                isAuthenticated: false,
                isLoading: false,
                scope: null,
                capabilities: [],
            };
            break;

        case "SET_TENANTS":
            newState = {
                ...state,
                tenants: {
                    data: Array.isArray(action.payload?.data) ? action.payload.data : [],
                    pagination: action.payload?.pagination || {},
                },
            };
            break;

        case "SELECT_TENANT":
            newState = {
                ...state,
                selectedTenant: action.payload,
            };
            break;

        case "SET_NOTIFICATIONS":
            newState = {
                ...state,
                notifications: action.payload || [],
            };
            break;

        case "SET_NOTIFICATION_SETTINGS":
            newState = {
                ...state,
                notificationSettings: action.payload,
            };
            break;

        case "MARK_AS_READ":
            newState = {
                ...state,
                notifications: state.notifications.map((n) =>
                    n.id === action.payload ? { ...n, isRead: true } : n
                ),
            };
            break;

        case "MARK_AS_UNREAD":
            newState = {
                ...state,
                notifications: state.notifications.map((n) =>
                    n.id === action.payload ? { ...n, isRead: false } : n
                ),
            };
            break;

        case "DELETE_NOTIFICATION":
            newState = {
                ...state,
                notifications: state.notifications.filter((n) => n.id !== action.payload),
            };
            break;

        case "SET_LOADING":
            newState = {
                ...state,
                isLoading: !!action.payload,
            };
            break;

        case "SET_INITIALIZED":
            return { ...state, isInitialized: action.payload };

        default:
            return state;
    }

    if (typeof window !== "undefined") {
        sessionStorage.setItem("appState", JSON.stringify(newState));
    }
    return newState;
}
