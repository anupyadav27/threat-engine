import { useAppContext } from "@/context/appContext";

export const useNotificationActions = () => {
    const { state, dispatch } = useAppContext();

    const markAsRead = (id) => dispatch({ type: "MARK_AS_READ", payload: id });
    const markAsUnread = (id) => dispatch({ type: "MARK_AS_UNREAD", payload: id });
    const deleteNotification = (id) => dispatch({ type: "DELETE_NOTIFICATION", payload: id });

    const updateSettings = (newSettings) => {
        const updated = { ...state.notificationSettings, ...newSettings };
        dispatch({ type: "SET_NOTIFICATION_SETTINGS", payload: updated });
        return { success: true, settings: updated };
    };

    const unreadCount = state.notifications.filter((n) => !n.isRead).length;

    return {
        state,
        markAsRead,
        markAsUnread,
        deleteNotification,
        updateSettings,
        unreadCount,
    };
};
