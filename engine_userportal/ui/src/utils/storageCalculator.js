(function () {
    function calculateStorage(storage) {
        let total = 0;
        for (let i = 0; i < storage.length; i++) {
            const key = storage.key(i);
            const value = storage.getItem(key);
            total += key.length + value.length;
        }
        return total;
    }

    function calculateCookies() {
        const cookies = document.cookie.split(";");
        let total = 0;
        cookies.forEach((cookie) => {
            total += cookie.length;
        });
        return total;
    }

    const sessionTotal = calculateStorage(sessionStorage);
    const localTotal = calculateStorage(localStorage);
    const cookiesTotal = calculateCookies();

    function formatBytes(bytes) {
        const kb = (bytes / 1024).toFixed(2);
        const mb = (bytes / (1024 * 1024)).toFixed(2);
        return `${bytes} bytes (${kb} KB / ${mb} MB)`;
    }

    console.log("🟢 Storage Usage:");
    console.log("SessionStorage:", formatBytes(sessionTotal));
    console.log("LocalStorage  :", formatBytes(localTotal));
    console.log("Cookies       :", formatBytes(cookiesTotal));
})();
