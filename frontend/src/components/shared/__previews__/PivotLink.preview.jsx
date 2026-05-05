'use client';

/**
 * Manual preview page for <PivotLink>.
 * Storybook is not used in this project (see JNY-07 §8).
 *
 * Renders every entity type, every severity, and edge cases.
 * Mount via a route or import in a dev page.
 */

import PivotLink from '../PivotLink';
import { ENTITY_REGISTRY } from '../../../lib/pivot-routes';

const REQUIRED_EXTRAS = {
  finding: { engine: 'check' },
  control: { framework: 'cis-aws-1.5' },
  scan:    { kind: 'sast' },
};

const SAMPLE_IDS = {
  asset:     'arn:aws:s3:::very-long-bucket-name-with-suffix-12345',
  threat:    'thr_0a1b2c3d',
  finding:   'fnd_9z8y7x6w',
  technique: 'T1078.004',
  control:   '1.4',
  framework: 'cis-aws-1.5',
  scenario:  'scn_42',
  workload:  'wkl_node-prod-7',
  scan:      'scan_8de23f',
  agent:     'agt_host-007',
  identity:  'arn:aws:iam::588989875114:user/alice',
};

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function Section({ title, children }) {
  return (
    <section className="mb-8">
      <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">{title}</h2>
      <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">{children}</div>
    </section>
  );
}

export default function PivotLinkPreview() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-6">
      <h1 className="text-xl font-bold mb-6">PivotLink — Preview</h1>

      <Section title="Every entity type (default size, with icon)">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {Object.keys(ENTITY_REGISTRY).map((to) => (
            <PivotLink
              key={to}
              to={to}
              id={SAMPLE_IDS[to]}
              {...(REQUIRED_EXTRAS[to] || {})}
            />
          ))}
        </div>
      </Section>

      <Section title="Severities (showSeverity prop)">
        <div className="flex flex-wrap gap-4">
          {SEVERITIES.map((sev) => (
            <PivotLink key={sev} to="finding" id={`fnd_${sev}`} engine="check" showSeverity={sev} />
          ))}
        </div>
      </Section>

      <Section title="Sizes">
        <div className="flex items-end gap-6">
          <PivotLink to="asset" id="i-0a1b2c3d" size="xs" />
          <PivotLink to="asset" id="i-0a1b2c3d" size="sm" />
          <PivotLink to="asset" id="i-0a1b2c3d" size="md" />
        </div>
      </Section>

      <Section title="Provider variants">
        <div className="flex flex-wrap gap-4">
          {['aws', 'azure', 'gcp', 'oci', 'alicloud', 'k8s'].map((p) => (
            <PivotLink key={p} to="asset" id={`asset-${p}-001`} provider={p} />
          ))}
        </div>
      </Section>

      <Section title="Scan kinds">
        <div className="flex flex-wrap gap-4">
          {['sast', 'dast', 'sca', 'project'].map((k) => (
            <PivotLink key={k} to="scan" id={`scan_${k}_42`} kind={k} />
          ))}
        </div>
      </Section>

      <Section title="Long ARN — middle truncation">
        <div className="max-w-md">
          <PivotLink
            to="asset"
            id="arn:aws:iam::588989875114:role/very/deep/path/to/some/long/role/name/that-overflows"
          />
        </div>
      </Section>

      <Section title="Edge cases">
        <ul className="space-y-2">
          <li>
            <span className="text-slate-500 mr-2">empty id →</span>
            <PivotLink to="asset" id="" />
          </li>
          <li>
            <span className="text-slate-500 mr-2">finding without engine →</span>
            <PivotLink to="finding" id="fnd_no_engine" />
          </li>
          <li>
            <span className="text-slate-500 mr-2">control without framework →</span>
            <PivotLink to="control" id="1.4" />
          </li>
          <li>
            <span className="text-slate-500 mr-2">unknown to →</span>
            <PivotLink to="bogus" id="x" />
          </li>
          <li>
            <span className="text-slate-500 mr-2">RTL label →</span>
            <PivotLink to="identity" id="مستخدم/علي" label="مستخدم/علي" />
          </li>
          <li>
            <span className="text-slate-500 mr-2">custom children →</span>
            <PivotLink to="threat" id="thr_xyz">
              <strong>Custom label node</strong>
            </PivotLink>
          </li>
          <li>
            <span className="text-slate-500 mr-2">no icon →</span>
            <PivotLink to="asset" id="i-noIcon" showIcon={false} />
          </li>
        </ul>
      </Section>
    </div>
  );
}
