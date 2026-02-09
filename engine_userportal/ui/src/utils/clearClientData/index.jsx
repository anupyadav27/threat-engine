export const clearClientData = async () => {
    if (typeof window !== "undefined") sessionStorage.clear();
    if ("caches" in window) {
        const cacheNames = await caches.keys();
        await Promise.all(cacheNames.map((name) => caches.delete(name)));
    }

    if (typeof document !== "undefined") {
        document.cookie.split(";").forEach((cookie) => {
            const name = cookie.split("=")[0].trim();

            document.cookie = `${name}=; Max-Age=0; path=/;`;

            document.cookie = `${name}=; Max-Age=0; path=/; domain=${window.location.hostname}`;
        });
    }
};
