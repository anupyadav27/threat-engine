"use client";

import React, { useEffect, useState } from "react";
import Layout from "@/components/layout";
import { fetchData } from "@/utils/fetchData";
import { useAppContext } from "@/context/appContext";

export default function Test() {
    const { state, dispatch } = useAppContext();
    const [rawData, setRawData] = useState(null);
    const [loading, setLoading] = useState(false);

    const loadData = async (url = `${process.env.NEXT_PUBLIC_API_URL}/test/`, options = {}) => {
        const { force = false, validate = true } = options;
        try {
            dispatch({ type: "SET_LOADING", payload: true });
            const data = await fetchData(url, { force, validate });
            setRawData(data?.data || []);
        } catch (error) {
            console.info("Error fetching users:", error);
        } finally {
            dispatch({ type: "SET_LOADING", payload: false });
        }
    };

    useEffect(() => {
        loadData();
    }, []);

    return (
        <Layout>
            <div className="m-4">
                <h1 className="text-4xl font-bold mb-4">Test Fetch Data</h1>
                {loading ? (
                    <p>Loading...</p>
                ) : (
                    <pre className="bg-gray-100 p-4 rounded overflow-auto">
                        {JSON.stringify(rawData, null, 2)}
                    </pre>
                )}
            </div>
        </Layout>
    );
}
