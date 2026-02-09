"use client";

import { useFormik } from "formik";
import * as Yup from "yup";
import { useRouter } from "next/navigation";
import Image from "next/image";
import Button from "@/components/button";
import Input from "@/components/input";
import { useEffect, useState } from "react";
import { FiEye, FiEyeOff } from "react-icons/fi";
import { FaUserCircle } from "react-icons/fa";
import { useAppContext } from "@/context/appContext";

export default function Login() {
    const router = useRouter();
    const [showPassword, setShowPassword] = useState(false);
    const { state, dispatch } = useAppContext();

    useEffect(() => {
        if (state.isAuthenticated) {
            router.push("/dashboard");
        }
    }, [state.isAuthenticated, router]);

    const formik = useFormik({
        initialValues: {
            email: "",
            password: "",
            rememberMe: false,
        },
        validationSchema: Yup.object({
            email: Yup.string().email("Invalid email address").required("Email is required"),
            password: Yup.string()
                .min(8, "Password must be at least 8 characters")
                .required("Password is required"),
        }),
        onSubmit: async (values, { setSubmitting, setFieldError }) => {
            try {
                const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/auth/login/`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    credentials: "include",
                    body: JSON.stringify(values),
                });

                const data = await res.json();

                if (res.ok) {
                    dispatch({
                        type: "LOGIN",
                        payload: {
                            user: data.user,
                            role: data.user.roles || null,
                            rememberMe: values.rememberMe,
                        },
                    });

                    router.push("/dashboard");
                    return;
                }

                switch (res.status) {
                    case 400:
                        setFieldError("email", "Email and password are required");
                        break;
                    case 401:
                        setFieldError("password", "Incorrect password. Please try again.");
                        break;
                    case 404:
                        setFieldError("email", "User not found");
                        break;
                    case 429:
                        alert("Too many login attempts. Please try again later.");
                        break;
                    default:
                        alert(data.message || "An unexpected error occurred.");
                }
            } catch (error) {
                alert("Network error. Please check your connection.");
            } finally {
                setSubmitting(false);
            }
        },
    });

    const handleShowPassword = () => setShowPassword(!showPassword);

    const handleSSOLogin = () => {
        window.location.href = `${process.env.NEXT_PUBLIC_API_URL}/api/auth/saml/login/`;
    };

    return (
        <div className="login">
            <div className="login__container">
                <div className="login__form-section">
                    <div className="login__form">
                        <p className="login__form-subtitle">Log in to admin portal</p>
                        <h1 className="login__form-title">Sign In</h1>

                        <form onSubmit={formik.handleSubmit} className="space-y-4">
                            <Input
                                type="email"
                                name="email"
                                placeholder="Enter your email"
                                value={formik.values.email}
                                onChange={formik.handleChange}
                                onBlur={formik.handleBlur}
                                iconRight={<FaUserCircle size={20} />}
                                secondary
                                success={!formik.errors.email && formik.touched.email}
                                danger={formik.errors.email && formik.touched.email}
                            />
                            {formik.errors.email && formik.touched.email && (
                                <p className="text-error text-sm">{formik.errors.email}</p>
                            )}

                            <Input
                                type={showPassword ? "text" : "password"}
                                name="password"
                                placeholder="Enter your password"
                                value={formik.values.password}
                                onChange={formik.handleChange}
                                onBlur={formik.handleBlur}
                                iconRight={
                                    showPassword ? (
                                        <FiEye
                                            size={20}
                                            onClick={handleShowPassword}
                                            className="cursor-pointer"
                                        />
                                    ) : (
                                        <FiEyeOff
                                            size={20}
                                            onClick={handleShowPassword}
                                            className="cursor-pointer"
                                        />
                                    )
                                }
                                secondary
                                success={!formik.errors.password && formik.touched.password}
                                danger={formik.errors.password && formik.touched.password}
                            />
                            {formik.errors.password && formik.touched.password && (
                                <p className="text-error text-sm">{formik.errors.password}</p>
                            )}

                            <div className="login__form-remember-me">
                                <p>Remember Me</p>
                                <input
                                    type="checkbox"
                                    name="rememberMe"
                                    checked={formik.values.rememberMe}
                                    onChange={formik.handleChange}
                                    onBlur={formik.handleBlur}
                                />
                            </div>

                            <Button
                                type="submit"
                                text="Submit"
                                className="btn-primary !w-full"
                                isLoading={formik.isSubmitting}
                            />
                        </form>

                        <Button
                            type="button"
                            text="SSO Login"
                            className="btn-secondary !w-full mt-2"
                            onClick={handleSSOLogin}
                        />

                        <div
                            className="login__form-forgot-password"
                            onClick={() => router.push("/forget-password")}
                        >
                            <p>Forgot Password</p>
                        </div>
                    </div>
                </div>

                <div className="login__image-section">
                    <Image
                        src="/login-illustration.svg"
                        alt="login-illustration"
                        fill
                        className="login__image"
                        priority={true}
                    />
                </div>
            </div>
        </div>
    );
}
