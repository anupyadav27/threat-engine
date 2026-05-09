'use client';
export function ConfigPropertiesTable({ properties = {}, emptyMessage = 'No properties available.' }) {
    const entries = Object.entries(properties).filter(([, v]) => v !== null && v !== undefined);
    if (!entries.length) {
        return <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '12px 0' }}>{emptyMessage}</div>;
    }
    return (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <tbody>
                {entries.map(([key, value]) => (
                    <tr key={key} style={{ borderBottom: '1px solid var(--border-primary)' }}>
                        <td style={{ padding: '6px 8px', fontWeight: 600, color: 'var(--text-secondary)', whiteSpace: 'nowrap', width: '40%' }}>{key.replace(/_/g, ' ')}</td>
                        <td style={{ padding: '6px 8px', color: 'var(--text-primary)', wordBreak: 'break-all' }}>{typeof value === 'boolean' ? String(value) : String(value)}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
}
export default ConfigPropertiesTable;
