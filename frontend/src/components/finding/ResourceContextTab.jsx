'use client';

import AssetContextCard from '@/components/shared/AssetContextCard';
import EmptyState from '@/components/shared/EmptyState';

export default function ResourceContextTab({ finding, data }) {
  const header = finding?.header || data?.header;
  const resourceUid = header?.resourceUid;
  const provider = header?.provider;
  const accountId = header?.accountId;

  if (!resourceUid) {
    return (
      <EmptyState
        title="No resource context"
        description="This finding is not associated with a specific cloud resource."
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <AssetContextCard
        resource_uid={resourceUid}
        provider={provider}
        accountId={accountId}
      />
    </div>
  );
}
