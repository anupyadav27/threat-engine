import './globals.css';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';

export const metadata = {
  title: 'Threat Engine — Enterprise CSPM Platform for Multi-Cloud Security',
  description: 'Comprehensive Cloud Security Posture Management for AWS, Azure, GCP, OCI, AliCloud, and IBM Cloud. 40+ services, 13+ compliance frameworks, real-time threat detection.',
  keywords: 'CSPM, cloud security, AWS security, Azure security, GCP security, compliance, threat detection, IAM security',
  openGraph: {
    title: 'Threat Engine — Enterprise CSPM Platform',
    description: 'Protect your multi-cloud environment with the most comprehensive CSPM platform.',
    type: 'website',
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <Navbar />
        <main>{children}</main>
        <Footer />
      </body>
    </html>
  );
}
