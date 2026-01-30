export const ensureCsrf = async () => {
    await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/auth/csrf/`, {
        method: "GET",
        credentials: "include",
    });
};
