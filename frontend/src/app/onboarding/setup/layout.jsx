export default function SetupLayout({ children }) {
  return (
    <div style={{ minHeight: '100vh', backgroundColor: 'var(--bg-primary)' }}>
      {children}
    </div>
  );
}
