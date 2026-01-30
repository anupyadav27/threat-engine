import React from "react";

const Input = ({
    type = "text",
    placeholder = "",
    value,
    onChange,
    onBlur,
    disabled = false,
    className = "",
    small = false,
    large = false,
    success = false,
    danger = false,
    secondary = false,
    iconRight,
    name,
}) => {
    const sizeClass = large ? "input-large" : small ? "input-small" : "";
    const variantClass = success
        ? "input-success"
        : danger
          ? "input-danger"
          : secondary
            ? "input-secondary"
            : "input-primary";
    const disabledClass = disabled ? "input-disabled" : "";

    return (
        <div className={`input-wrapper ${sizeClass} ${variantClass} ${disabledClass} ${className}`}>
            <input
                type={type}
                placeholder={placeholder}
                value={value}
                onChange={onChange}
                onBlur={onBlur}
                disabled={disabled}
                name={name}
                className="input-field"
            />
            {iconRight && <span className="input-icon-right">{iconRight}</span>}
        </div>
    );
};

export default Input;
