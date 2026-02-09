"use client";

import { useFormik } from "formik";
import * as Yup from "yup";
import { useState, useEffect } from "react";
import Layout from "@/components/layout";
import Input from "@/components/input";
import Button from "@/components/button";
import { useRouter } from "next/navigation";
import { useAppContext } from "@/context/appContext";
import { FiEye, FiEyeOff } from "react-icons/fi";

export default function AddUser() {
    const router = useRouter();
    const { dispatch } = useAppContext();
    const [showPassword, setShowPassword] = useState(false);
    const [roles, setRoles] = useState([]);
    const [isSubmitting, setIsSubmitting] = useState(false);

    useEffect(() => {
        const fetchRoles = async () => {
            try {
                const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/roles/`, {
                    credentials: "include",
                });
                if (response.ok) {
                    const data = await response.json();
                    setRoles(data?.data || []);
                }
            } catch (error) {
                console.info("Error fetching roles:", error);
            }
        };
        fetchRoles();
    }, []);

    const formik = useFormik({
        initialValues: {
            name: {
                first: "",
                last: "",
            },
            email: "",
            password: "",
            roles: [],
            status: "active",
            ssoProvider: "",
            ssoId: "",
            preferences: {
                theme: "light",
                notifications: true,
                language: "en",
            },
        },
        validationSchema: Yup.object({
            name: Yup.object({
                first: Yup.string().trim(),
                last: Yup.string().trim(),
            }),
            email: Yup.string()
                .email("Invalid email address")
                .required("Email is required")
                .lowercase(),
            password: Yup.string()
                .min(8, "Password must be at least 8 characters")
                .required("Password is required"),
            roles: Yup.array().min(1, "At least one role is required").required("Role is required"),
            status: Yup.string()
                .oneOf(["active", "inactive", "pending", "suspended"], "Invalid status")
                .required("Status is required"),
            ssoProvider: Yup.string().nullable(),
            ssoId: Yup.string().nullable(),
            preferences: Yup.object({
                theme: Yup.string().oneOf(["light", "dark"], "Invalid theme"),
                notifications: Yup.boolean(),
                language: Yup.string(),
            }),
        }),
        onSubmit: async (values, { setSubmitting, setFieldError }) => {
            setIsSubmitting(true);
            try {
                const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/users/`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    credentials: "include",
                    body: JSON.stringify({
                        ...values,
                        email: values.email.toLowerCase().trim(),
                        name: {
                            first: values.name.first?.trim() || "",
                            last: values.name.last?.trim() || "",
                        },
                        ssoProvider: values.ssoProvider || null,
                        ssoId: values.ssoId || null,
                    }),
                });

                const data = await response.json();

                if (response.ok) {
                    dispatch({ type: "SET_LOADING", payload: false });
                    router.push("/settings/users");
                } else {
                    if (data.errors) {
                        Object.keys(data.errors).forEach((key) => {
                            setFieldError(key, data.errors[key]);
                        });
                    } else {
                        setFieldError("email", data.message || "Failed to create user");
                    }
                }
            } catch (error) {
                console.info("Error creating user:", error);
                setFieldError("email", "Network error. Please try again.");
            } finally {
                setIsSubmitting(false);
                setSubmitting(false);
            }
        },
    });

    const handleRoleChange = (e) => {
        const selectedRoleId = e.target.value;
        if (selectedRoleId && !formik.values.roles.includes(selectedRoleId)) {
            formik.setFieldValue("roles", [...formik.values.roles, selectedRoleId]);
        }
    };

    const removeRole = (roleId) => {
        formik.setFieldValue(
            "roles",
            formik.values.roles.filter((id) => id !== roleId)
        );
    };

    return (
        <Layout headerLabel="Add User">
            <div className="m-4 max-w-4xl">
                <h1 className="text-4xl font-bold mb-6">Add New User</h1>

                <form onSubmit={formik.handleSubmit} className="space-y-6">
                    {}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-medium mb-2">First Name</label>
                            <Input
                                type="text"
                                name="name.first"
                                placeholder="Enter first name"
                                value={formik.values.name.first}
                                onChange={formik.handleChange}
                                onBlur={formik.handleBlur}
                                success={!formik.errors.name?.first && formik.touched.name?.first}
                                danger={formik.errors.name?.first && formik.touched.name?.first}
                            />
                            {formik.errors.name?.first && formik.touched.name?.first && (
                                <p className="text-red-500 text-sm mt-1">
                                    {formik.errors.name.first}
                                </p>
                            )}
                        </div>

                        <div>
                            <label className="block text-sm font-medium mb-2">Last Name</label>
                            <Input
                                type="text"
                                name="name.last"
                                placeholder="Enter last name"
                                value={formik.values.name.last}
                                onChange={formik.handleChange}
                                onBlur={formik.handleBlur}
                                success={!formik.errors.name?.last && formik.touched.name?.last}
                                danger={formik.errors.name?.last && formik.touched.name?.last}
                            />
                            {formik.errors.name?.last && formik.touched.name?.last && (
                                <p className="text-red-500 text-sm mt-1">
                                    {formik.errors.name.last}
                                </p>
                            )}
                        </div>
                    </div>

                    {}
                    <div>
                        <label className="block text-sm font-medium mb-2">Email *</label>
                        <Input
                            type="email"
                            name="email"
                            placeholder="Enter email address"
                            value={formik.values.email}
                            onChange={formik.handleChange}
                            onBlur={formik.handleBlur}
                            success={!formik.errors.email && formik.touched.email}
                            danger={formik.errors.email && formik.touched.email}
                        />
                        {formik.errors.email && formik.touched.email && (
                            <p className="text-red-500 text-sm mt-1">{formik.errors.email}</p>
                        )}
                    </div>

                    {}
                    <div>
                        <label className="block text-sm font-medium mb-2">Password *</label>
                        <Input
                            type={showPassword ? "text" : "password"}
                            name="password"
                            placeholder="Enter password (min 8 characters)"
                            value={formik.values.password}
                            onChange={formik.handleChange}
                            onBlur={formik.handleBlur}
                            iconRight={
                                showPassword ? (
                                    <FiEye
                                        size={20}
                                        onClick={() => setShowPassword(!showPassword)}
                                        className="cursor-pointer"
                                    />
                                ) : (
                                    <FiEyeOff
                                        size={20}
                                        onClick={() => setShowPassword(!showPassword)}
                                        className="cursor-pointer"
                                    />
                                )
                            }
                            success={!formik.errors.password && formik.touched.password}
                            danger={formik.errors.password && formik.touched.password}
                        />
                        {formik.errors.password && formik.touched.password && (
                            <p className="text-red-500 text-sm mt-1">{formik.errors.password}</p>
                        )}
                    </div>

                    {}
                    <div>
                        <label className="block text-sm font-medium mb-2">Roles *</label>
                        <select
                            name="roleSelect"
                            onChange={handleRoleChange}
                            className="w-full px-4 py-2 border-2 border-gray-300 rounded transition-all duration-200 focus:outline-none focus:border-blue-500"
                            defaultValue=""
                        >
                            <option value="">Select a role to add</option>
                            {roles.map((role) => (
                                <option key={role._id} value={role._id}>
                                    {role.name || role._id}
                                </option>
                            ))}
                        </select>
                        {formik.values.roles.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-2">
                                {formik.values.roles.map((roleId) => {
                                    const role = roles.find((r) => r._id === roleId);
                                    return (
                                        <span
                                            key={roleId}
                                            className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-blue-100 text-blue-800"
                                        >
                                            {role?.name || roleId}
                                            <button
                                                type="button"
                                                onClick={() => removeRole(roleId)}
                                                className="ml-2 text-blue-600 hover:text-blue-800"
                                            >
                                                ×
                                            </button>
                                        </span>
                                    );
                                })}
                            </div>
                        )}
                        {formik.errors.roles && formik.touched.roles && (
                            <p className="text-red-500 text-sm mt-1">{formik.errors.roles}</p>
                        )}
                    </div>

                    {}
                    <div>
                        <label className="block text-sm font-medium mb-2">Status *</label>
                        <select
                            name="status"
                            value={formik.values.status}
                            onChange={formik.handleChange}
                            onBlur={formik.handleBlur}
                            className="w-full px-4 py-2 border-2 border-gray-300 rounded transition-all duration-200 focus:outline-none focus:border-blue-500"
                        >
                            <option value="active">Active</option>
                            <option value="inactive">Inactive</option>
                            <option value="pending">Pending</option>
                            <option value="suspended">Suspended</option>
                        </select>
                        {formik.errors.status && formik.touched.status && (
                            <p className="text-red-500 text-sm mt-1">{formik.errors.status}</p>
                        )}
                    </div>

                    {}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-medium mb-2">SSO Provider</label>
                            <Input
                                type="text"
                                name="ssoProvider"
                                placeholder="e.g., okta, azure"
                                value={formik.values.ssoProvider}
                                onChange={formik.handleChange}
                                onBlur={formik.handleBlur}
                            />
                            {formik.errors.ssoProvider && formik.touched.ssoProvider && (
                                <p className="text-red-500 text-sm mt-1">
                                    {formik.errors.ssoProvider}
                                </p>
                            )}
                        </div>

                        <div>
                            <label className="block text-sm font-medium mb-2">SSO ID</label>
                            <Input
                                type="text"
                                name="ssoId"
                                placeholder="Enter SSO ID"
                                value={formik.values.ssoId}
                                onChange={formik.handleChange}
                                onBlur={formik.handleBlur}
                            />
                            {formik.errors.ssoId && formik.touched.ssoId && (
                                <p className="text-red-500 text-sm mt-1">{formik.errors.ssoId}</p>
                            )}
                        </div>
                    </div>

                    {}
                    <div className="border-t pt-4">
                        <h3 className="text-lg font-semibold mb-4">Preferences</h3>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div>
                                <label className="block text-sm font-medium mb-2">Theme</label>
                                <select
                                    name="preferences.theme"
                                    value={formik.values.preferences.theme}
                                    onChange={formik.handleChange}
                                    onBlur={formik.handleBlur}
                                    className="w-full px-4 py-2 border-2 border-gray-300 rounded transition-all duration-200 focus:outline-none focus:border-blue-500"
                                >
                                    <option value="light">Light</option>
                                    <option value="dark">Dark</option>
                                </select>
                            </div>

                            <div>
                                <label className="block text-sm font-medium mb-2">Language</label>
                                <Input
                                    type="text"
                                    name="preferences.language"
                                    placeholder="e.g., en"
                                    value={formik.values.preferences.language}
                                    onChange={formik.handleChange}
                                    onBlur={formik.handleBlur}
                                />
                            </div>

                            <div className="flex items-center">
                                <label className="flex items-center cursor-pointer">
                                    <input
                                        type="checkbox"
                                        name="preferences.notifications"
                                        checked={formik.values.preferences.notifications}
                                        onChange={(e) =>
                                            formik.setFieldValue(
                                                "preferences.notifications",
                                                e.target.checked
                                            )
                                        }
                                        className="mr-2 w-4 h-4"
                                    />
                                    <span className="text-sm font-medium">
                                        Enable Notifications
                                    </span>
                                </label>
                            </div>
                        </div>
                    </div>

                    {}
                    <div className="flex gap-4 pt-4">
                        <Button
                            type="submit"
                            text="Create User"
                            isLoading={isSubmitting}
                            disabled={isSubmitting}
                            success
                        />
                        <Button
                            type="button"
                            text="Cancel"
                            onClick={() => router.push("/settings/users")}
                            secondary
                        />
                    </div>
                </form>
            </div>
        </Layout>
    );
}
