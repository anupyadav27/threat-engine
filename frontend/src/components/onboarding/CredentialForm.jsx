'use client';

import { useState, useRef } from 'react';
import { Eye, EyeOff, Upload, X } from 'lucide-react';

function TextField({ field, value, onChange }) {
  const [show, setShow] = useState(false);
  const isPassword = field.sensitive || field.type === 'password';

  return (
    <div>
      <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        {field.label}
        {field.required && <span className="ml-1 text-red-400">*</span>}
      </label>
      <div className="relative">
        <input
          type={isPassword && !show ? 'password' : 'text'}
          value={value || ''}
          placeholder={field.placeholder || ''}
          required={field.required}
          onChange={e => onChange(field.name, e.target.value)}
          className="w-full px-3 py-2 text-sm rounded-lg border outline-none transition-colors"
          style={{
            backgroundColor: 'var(--bg-tertiary)',
            borderColor: 'var(--border-primary)',
            color: 'var(--text-primary)',
          }}
        />
        {isPassword && (
          <button
            type="button"
            onClick={() => setShow(s => !s)}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 hover:opacity-70"
            style={{ color: 'var(--text-muted)' }}
          >
            {show ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        )}
      </div>
      {field.help_text && (
        <p className="mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>{field.help_text}</p>
      )}
    </div>
  );
}

function FileField({ field, value, onChange }) {
  const inputRef = useRef(null);

  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    onChange(field.name, file);
  };

  return (
    <div>
      <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        {field.label}
        {field.required && <span className="ml-1 text-red-400">*</span>}
      </label>
      <div
        className="flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer hover:opacity-80 transition-opacity"
        style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}
        onClick={() => inputRef.current?.click()}
      >
        <Upload size={14} style={{ color: 'var(--text-muted)' }} />
        <span className="text-sm" style={{ color: value ? 'var(--text-primary)' : 'var(--text-muted)' }}>
          {value ? value.name : `Click to upload${field.accept ? ` (${field.accept})` : ''}`}
        </span>
        {value && (
          <button
            type="button"
            onClick={e => { e.stopPropagation(); onChange(field.name, null); }}
            className="ml-auto hover:opacity-70"
            style={{ color: 'var(--text-muted)' }}
          >
            <X size={12} />
          </button>
        )}
      </div>
      <input
        ref={inputRef}
        type="file"
        accept={field.accept}
        className="hidden"
        onChange={handleFile}
      />
    </div>
  );
}

export default function CredentialForm({ authModel, onSubmit, loading }) {
  const [values, setValues] = useState({});

  const handleChange = (name, value) => setValues(v => ({ ...v, [name]: value }));

  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit(values);
  };

  if (!authModel?.credential_fields?.length) {
    return null;
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {authModel.credential_fields.map(field => (
        field.type === 'file'
          ? <FileField key={field.name} field={field} value={values[field.name]} onChange={handleChange} />
          : <TextField key={field.name} field={field} value={values[field.name]} onChange={handleChange} />
      ))}

      <button
        type="submit"
        disabled={loading}
        className="w-full py-2.5 rounded-lg text-sm font-medium transition-opacity disabled:opacity-50"
        style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
      >
        {loading ? 'Validating…' : 'Validate Credentials'}
      </button>
    </form>
  );
}
