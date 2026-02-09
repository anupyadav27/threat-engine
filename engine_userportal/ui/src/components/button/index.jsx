import React from "react";
import LoadingIcon from "@/components/icons/loadingIcon";

const Button = ({
    type = "button",
    onClick,
    disabled = false,
    name,
    style,
    icon,
    iconRight,
    text,
    isLoading = false,
    className = "",
    small = false,
    large = false,
    link = false,
    danger = false,
    success = false,
    secondary = false,
}) => {
    const sizeClass = large ? "btn-large" : small ? "btn-small" : "";

    const variantClass = link
        ? "btn-link"
        : success
          ? "btn-success"
          : danger
            ? "btn-danger"
            : secondary
              ? "btn-secondary"
              : "btn-primary";

    const disabledClass = disabled ? "btn-disabled" : "";

    return (
        <button
            type={type}
            onClick={onClick}
            disabled={disabled}
            name={name}
            style={style}
            className={`btn ${sizeClass} ${variantClass} ${disabledClass} ${className}`}
        >
            {icon && <span className="btn-icon">{icon}</span>}
            {text}
            {isLoading && (
                <span className="loading">
                    <LoadingIcon />
                </span>
            )}
            {iconRight && <span className="btn-icon-right">{iconRight}</span>}
        </button>
    );
};

export default Button;
