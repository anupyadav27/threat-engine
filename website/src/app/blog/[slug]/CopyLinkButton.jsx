'use client';
import { Link2 } from 'lucide-react';

export default function CopyLinkButton({ slug }) {
  return (
    <button
      onClick={() => {
        if (typeof navigator !== 'undefined') {
          navigator.clipboard?.writeText(
            `https://threatengine.io/blog/${slug}`
          );
        }
      }}
      className="inline-flex items-center gap-2 transition-all rounded-xl px-4 py-2"
      style={{
        background: '#eff6ff',
        color: '#2563eb',
        border: '1px solid #bfdbfe',
        fontSize: '13px',
        fontWeight: 600,
        cursor: 'pointer',
      }}
    >
      <Link2 size={14} />
      Copy Link
    </button>
  );
}
