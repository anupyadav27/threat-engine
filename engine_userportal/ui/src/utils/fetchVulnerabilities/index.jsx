export const fetchVulnerabilities = async (
    url = `${process.env.NEXT_PUBLIC_API_URL}/api/vulnerability/`,
    force = false
) => {
    const cacheKey = `${url}_vulnerabilityData`;
    let vulnerabilityData = null;

    try {
        if (!force && typeof window !== "undefined") {
            const cached = sessionStorage.getItem(cacheKey);
            if (cached) {
                vulnerabilityData = JSON.parse(cached);
                return vulnerabilityData;
            }
        }

        const res = await fetch(url, {
            method: "GET",
            credentials: "include",
        });

        if (!res.ok) throw new Error(`HTTP Error! Status: ${res.status}`);

        const data = await res.json();

        vulnerabilityData = {
            data: data?.data || [],
            pagination: data?.pagination || {},
        };

        if (typeof window !== "undefined") {
            sessionStorage.setItem(cacheKey, JSON.stringify(vulnerabilityData));
        }

        return vulnerabilityData;
    } catch (e) {
        console.info(`Failed to fetch vulnerabilities:`, e);
        alert(`Failed to fetch vulnerabilities: ${e.message}`);
        return null;
    } finally {
    }
};
