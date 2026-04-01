'use client';

import { useState } from 'react';
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ScatterChart, Scatter, PieChart, Pie, Cell, Treemap,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, ReferenceLine, ComposedChart, LabelList,
} from 'recharts';

/* ══════════════════════════════════════════════════════════════
   DESIGN TOKENS
══════════════════════════════════════════════════════════════ */
const T = {
  bgPage:  '#0b0f1c', bgCard:  '#111827', bgCard2: '#1a2235', bgInset: '#0d1321',
  border:  '#1e2d45', borderMd:'#2a3d56',
  textPri: '#e8eef8', textSec: '#8899bb', textMut: '#3a4f6e',
  critical:'#fb7185', high:    '#fdba74', medium:  '#fcd34d',
  low:     '#93c5fd', pass:    '#6ee7b7', info:    '#c4b5fd',
  bgCrit:  '#2a0f14', bgHigh:  '#2a1a08', bgMed:   '#241c07',
  bgLow:   '#0a1a30', bgPass:  '#0a2018',
  indigo:  '#818cf8', sky:     '#38bdf8', emerald: '#34d399', violet: '#a78bfa',
  s1:'#818cf8', s2:'#fb7185', s3:'#6ee7b7', s4:'#fcd34d',
  s5:'#38bdf8', s6:'#a78bfa', s7:'#fdba74', s8:'#2dd4bf',
};

const TAG_THEME = {
  C:{ bg:'#1e1b4b', text:T.indigo,  border:'#312e81' },
  K:{ bg:'#0c2240', text:T.sky,     border:'#0c4a6e' },
  P:{ bg:'#052e1c', text:T.emerald, border:'#064e3b' },
  S:{ bg:'#1e1040', text:T.violet,  border:'#2e1065' },
};
const tagTheme = tag => TAG_THEME[String(tag)[0]] || { bg:'#1e293b', text:T.textSec, border:'#334155' };

function scoreColor(v){ return v>=75?T.pass:v>=50?T.high:T.critical; }
function scoreBg(v)   { return v>=75?T.bgPass:v>=50?T.bgHigh:T.bgCrit; }
function grade(v)     { return v>=80?'A':v>=70?'B':v>=60?'C':v>=50?'D':'F'; }
const fmtK = v => v>=1000?`${(v/1000).toFixed(1)}k`:String(v);
const fmtPct = v => `${v}%`;

/* ══════════════════════════════════════════════════════════════
   RICH TOOLTIP — enterprise multi-line with delta + footer
══════════════════════════════════════════════════════════════ */
function RichTooltip({ active, payload, label, title, unit='', footer, totalKey, prevData }) {
  if (!active || !payload?.length) return null;
  const total = totalKey ? payload.find(p=>p.dataKey===totalKey)?.value : payload.reduce((s,p)=>s+p.value,0);
  return (
    <div style={{
      background:'linear-gradient(160deg,#1c2638,#111827)',
      border:`1px solid ${T.borderMd}`,
      borderRadius:12, padding:'10px 14px',
      boxShadow:'0 24px 48px rgba(0,0,0,0.8),0 0 0 1px rgba(129,140,248,0.08)',
      minWidth:200, pointerEvents:'none',
    }}>
      <div style={{ fontSize:10, fontWeight:700, color:T.textMut, textTransform:'uppercase',
        letterSpacing:'0.08em', paddingBottom:7, marginBottom:7, borderBottom:`1px solid ${T.border}` }}>
        {title || label}
      </div>
      <div style={{ display:'flex', flexDirection:'column', gap:5 }}>
        {payload.map((p,i)=>(
          <div key={i} style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:20 }}>
            <div style={{ display:'flex', alignItems:'center', gap:7 }}>
              <span style={{ width:8, height:8, borderRadius:2, backgroundColor:p.color||p.fill, display:'inline-block', flexShrink:0 }}/>
              <span style={{ fontSize:11, color:T.textSec }}>{p.name}</span>
            </div>
            <span style={{ fontSize:13, fontWeight:700, color:p.color||p.fill }}>
              {typeof p.value==='number'&&p.value>=1000?p.value.toLocaleString():p.value}{unit}
            </span>
          </div>
        ))}
      </div>
      {total!==undefined && !totalKey && payload.length>1 && (
        <div style={{ marginTop:7, paddingTop:6, borderTop:`1px solid ${T.border}`,
          display:'flex', justifyContent:'space-between', fontSize:11 }}>
          <span style={{ color:T.textSec }}>Total</span>
          <span style={{ fontWeight:700, color:T.textPri }}>{total.toLocaleString()}{unit}</span>
        </div>
      )}
      {footer && (
        <div style={{ marginTop:6, paddingTop:5, borderTop:`1px solid ${T.border}`, fontSize:10, color:T.textMut }}>
          {footer}
        </div>
      )}
    </div>
  );
}

/* Insight badge shown inside card header area */
function Insight({ children, color }) {
  return (
    <span style={{ fontSize:10, fontWeight:600, padding:'2px 8px', borderRadius:20,
      background:`${color||T.indigo}18`, color:color||T.indigo, border:`1px solid ${color||T.indigo}30`,
      flexShrink:0 }}>
      {children}
    </span>
  );
}

/* Card wrapper */
function Card({ tag, label, description, insight, insightColor, children, recommended, wide }) {
  const th = tag ? tagTheme(tag) : null;
  return (
    <div className={`rounded-2xl overflow-hidden flex flex-col${wide?' col-span-2':''}`}
      style={{
        background:`linear-gradient(160deg,${T.bgCard} 0%,${T.bgInset} 100%)`,
        border:`1px solid ${recommended?T.indigo+'60':T.border}`,
        boxShadow:recommended?`0 0 0 1px ${T.indigo}30,0 8px 32px rgba(0,0,0,0.5)`:'0 4px 24px rgba(0,0,0,0.45)',
      }}>
      {recommended&&<div style={{ height:2, background:`linear-gradient(90deg,${T.indigo},${T.violet})` }}/>}
      <div className="px-5 py-3 flex items-center gap-2.5 flex-wrap" style={{ borderBottom:`1px solid ${T.border}` }}>
        {tag&&<span className="text-[10px] font-black px-2 py-0.5 rounded-md tracking-wider flex-shrink-0"
          style={{ backgroundColor:th.bg, color:th.text, border:`1px solid ${th.border}` }}>{tag}</span>}
        <span className="font-semibold text-sm" style={{ color:T.textPri }}>{label}</span>
        {recommended&&<span className="text-[10px] font-bold px-2 py-0.5 rounded-full flex-shrink-0"
          style={{ background:`linear-gradient(90deg,${T.indigo}25,${T.violet}25)`, color:T.indigo, border:`1px solid ${T.indigo}40` }}>★ Recommended</span>}
        {insight&&<Insight color={insightColor}>{insight}</Insight>}
        {description&&<span className="text-xs ml-auto" style={{ color:T.textMut }}>{description}</span>}
      </div>
      <div className="p-5 flex-1">{children}</div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   SAMPLE DATA  (realistic CSPM numbers)
══════════════════════════════════════════════════════════════ */
const MONTHS = ['Oct','Nov','Dec','Jan','Feb','Mar'];

// 30-day daily findings — realistic downward trend with noise
const DAILY = Array.from({length:30},(_,i)=>({
  day: i+1,
  label: `Mar ${i+1}`,
  critical: Math.max(2, Math.round(28-i*0.55+Math.sin(i*0.8)*3)),
  high:     Math.max(8, Math.round(58-i*0.7 +Math.cos(i*0.5)*5)),
  medium:   Math.max(14,Math.round(94-i*0.4 +Math.sin(i*0.4)*8)),
  resolved: Math.min(60, Math.round(i*2.2+3)),
  total:    Math.max(24,Math.round(180-i*1.5+Math.sin(i*0.3)*10)),
  // Events
  event: i===6?'Policy deployed':i===14?'Scan config updated':i===22?'Credential rotated':null,
}));

const SEVERITY_DIST = [
  { name:'Critical', value:21  },
  { name:'High',     value:35  },
  { name:'Medium',   value:48  },
  { name:'Low',      value:29  },
  { name:'Info',     value:18  },
];
const SEV_TOTAL = SEVERITY_DIST.reduce((s,d)=>s+d.value,0);

const SERVICE_DATA = [
  { service:'IAM',         findings:41, critical:9,  high:18, medium:14 },
  { service:'Sec Groups',  findings:31, critical:5,  high:14, medium:12 },
  { service:'S3',          findings:23, critical:4,  high:10, medium:9  },
  { service:'CloudTrail',  findings:19, critical:3,  high:8,  medium:8  },
  { service:'EC2',         findings:17, critical:2,  high:7,  medium:8  },
  { service:'RDS',         findings:12, critical:1,  high:5,  medium:6  },
  { service:'Lambda',      findings:8,  critical:0,  high:3,  medium:5  },
];

const FRAMEWORK_DATA = [
  { name:'ISO 27001', score:82, passed:93,  total:114, prevScore:78 },
  { name:'CIS AWS',   score:76, passed:107, total:140, prevScore:71 },
  { name:'HIPAA',     score:71, passed:53,  total:75,  prevScore:69 },
  { name:'NIST CSF',  score:68, passed:73,  total:108, prevScore:65 },
  { name:'SOC 2',     score:63, passed:40,  total:64,  prevScore:60 },
  { name:'GDPR',      score:58, passed:57,  total:99,  prevScore:57 },
  { name:'PCI-DSS',   score:54, passed:121, total:224, prevScore:51 },
];

const DOMAINS = [
  { label:'Compliance', score:76, crit:0,  prev:71 },
  { label:'Threats',    score:58, crit:6,  prev:51 },
  { label:'IAM',        score:42, crit:9,  prev:47 },
  { label:'Misconfigs', score:71, crit:5,  prev:68 },
  { label:'Data Sec',   score:63, crit:3,  prev:60 },
  { label:'Network',    score:69, crit:2,  prev:65 },
  { label:'Code Sec',   score:55, crit:4,  prev:52 },
  { label:'Risk',       score:48, crit:7,  prev:53 },
];

const RADAR_DATA = DOMAINS.map(d=>({ subject:d.label, score:d.score, prev:d.prev, fullMark:100 }));

const SCATTER_DATA = [
  { name:'AWS Prod',     resources:240, risk:78, provider:'AWS'   },
  { name:'AWS Staging',  resources:120, risk:44, provider:'AWS'   },
  { name:'Azure Dev',    resources:89,  risk:38, provider:'Azure' },
  { name:'GCP Analytics',resources:160, risk:62, provider:'GCP'   },
  { name:'AWS DR',       resources:55,  risk:22, provider:'AWS'   },
  { name:'Azure Prod',   resources:198, risk:71, provider:'Azure' },
  { name:'GCP ML',       resources:73,  risk:55, provider:'GCP'   },
  { name:'AWS HPC',      resources:310, risk:85, provider:'AWS'   },
  { name:'Azure Dev2',   resources:42,  risk:18, provider:'Azure' },
  { name:'GCP Backup',   resources:95,  risk:33, provider:'GCP'   },
];

const TREEMAP_DATA = [
  { name:'IAM Role',    size:45, crit:9,  findings:41 },
  { name:'S3 Bucket',   size:38, crit:4,  findings:23 },
  { name:'Sec Group',   size:31, crit:5,  findings:31 },
  { name:'EC2',         size:24, crit:2,  findings:17 },
  { name:'CloudTrail',  size:19, crit:3,  findings:19 },
  { name:'RDS',         size:18, crit:1,  findings:12 },
  { name:'EKS',         size:14, crit:2,  findings:11 },
  { name:'Lambda',      size:12, crit:0,  findings:8  },
  { name:'VPC',         size:9,  crit:1,  findings:7  },
];

const MONTHLY_SEV = [
  { month:'Oct', critical:28, high:62, medium:94, low:45 },
  { month:'Nov', critical:24, high:55, medium:98, low:48 },
  { month:'Dec', critical:31, high:51, medium:86, low:52 },
  { month:'Jan', critical:19, high:44, medium:91, low:55 },
  { month:'Feb', critical:14, high:36, medium:79, low:58 },
  { month:'Mar', critical:9,  high:27, medium:66, low:62 },
];

const HMAP_DAYS  = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
const HMAP_HOURS = ['12a','3a','6a','9a','12p','3p','6p','9p'];
const HMAP = HMAP_DAYS.map((day,di)=>({
  day,
  cells: HMAP_HOURS.map((hour,hi)=>({
    hour,
    count: Math.max(0, Math.round((Math.sin(di*1.3+hi*0.9)*0.5+0.5)*26+Math.random()*4)),
  })),
}));

const FUNNEL = [
  { stage:'Assets Scanned',     n:1240,  icon:'◈' },
  { stage:'Rules Evaluated',    n:89200, icon:'⚙' },
  { stage:'Findings Generated', n:423,   icon:'⚑' },
  { stage:'After Suppression',  n:312,   icon:'◎' },
  { stage:'Open Findings',      n:142,   icon:'▲' },
  { stage:'Critical Open',      n:21,    icon:'●' },
];

const TIMELINE = [
  { time:'2m ago',  type:'critical', msg:'IAM root user login — us-east-1',         src:'Threat Engine', id:'T-4421' },
  { time:'14m ago', type:'high',     msg:'S3 bucket ACL set public: prod-data-lake', src:'Discovery',     id:'D-8832' },
  { time:'31m ago', type:'medium',   msg:'MFA disabled on 3 IAM users',              src:'IAM Engine',    id:'I-2291' },
  { time:'1h ago',  type:'low',      msg:'EBS volume unencrypted: vol-0a1b2c',       src:'Discovery',     id:'D-8801' },
  { time:'2h ago',  type:'pass',     msg:'Scan completed — 1,240 assets, 0 new crit',src:'Onboarding',   id:'S-0099' },
  { time:'3h ago',  type:'critical', msg:'Privilege escalation path: Lambda→Admin',  src:'CIEM',          id:'C-3310' },
];

const STATUSES = [
  { name:'Discoveries',   status:'healthy',  latency:'42ms', uptime:'99.9%' },
  { name:'Check Engine',  status:'healthy',  latency:'38ms', uptime:'99.8%' },
  { name:'Threat Engine', status:'healthy',  latency:'65ms', uptime:'99.7%' },
  { name:'IAM Engine',    status:'degraded', latency:'280ms',uptime:'97.2%' },
  { name:'Compliance',    status:'healthy',  latency:'51ms', uptime:'99.9%' },
  { name:'DataSec',       status:'healthy',  latency:'44ms', uptime:'99.6%' },
  { name:'Inventory',     status:'offline',  latency:'—',    uptime:'94.1%' },
  { name:'Rule Engine',   status:'healthy',  latency:'29ms', uptime:'99.9%' },
  { name:'SecOps',        status:'healthy',  latency:'77ms', uptime:'99.5%' },
];

const ACCOUNTS = [
  { name:'AWS Production',   score:41, findings:142, critical:21, provider:'AWS',   region:'us-east-1'    },
  { name:'GCP Analytics',    score:54, findings:89,  critical:8,  provider:'GCP',   region:'us-central1'  },
  { name:'AWS Staging',      score:67, findings:38,  critical:3,  provider:'AWS',   region:'us-west-2'    },
  { name:'Azure Dev',        score:71, findings:24,  critical:1,  provider:'Azure', region:'eastus'       },
  { name:'AWS DR Region',    score:83, findings:11,  critical:0,  provider:'AWS',   region:'ap-southeast-1'},
].sort((a,b)=>a.score-b.score);

const PIPELINE = [
  { label:'Onboarding',   status:'done',    detail:'3 accounts connected', time:'09:00' },
  { label:'Discovery',    status:'done',    detail:'1,240 assets found',   time:'09:12' },
  { label:'Check Scan',   status:'done',    detail:'89.2k rules evaluated',time:'09:31' },
  { label:'Threat Intel', status:'active',  detail:'Correlating…',         time:'09:45' },
  { label:'Compliance',   status:'pending', detail:'Queued',               time:'—'     },
  { label:'Report',       status:'pending', detail:'Not started',          time:'—'     },
];

/* ══════════════════════════════════════════════════════════════
   CUSTOM TOOLTIP VARIANTS
══════════════════════════════════════════════════════════════ */

/* Time series — shows all series + event annotation */
function TimeTooltip({ active, payload, label }) {
  if (!active||!payload?.length) return null;
  const row = DAILY.find(d=>d.day===Number(label)||d.label===label);
  return (
    <div style={{ background:'linear-gradient(160deg,#1c2638,#111827)', border:`1px solid ${T.borderMd}`,
      borderRadius:12, padding:'10px 14px', boxShadow:'0 24px 48px rgba(0,0,0,0.8)', minWidth:210, pointerEvents:'none' }}>
      <div style={{ fontSize:10, fontWeight:700, color:T.textMut, textTransform:'uppercase',
        letterSpacing:'0.08em', paddingBottom:7, marginBottom:7, borderBottom:`1px solid ${T.border}` }}>
        {row?.label||`Day ${label}`}
        {row?.event&&<span style={{ marginLeft:8, color:T.indigo, fontSize:9 }}>★ {row.event}</span>}
      </div>
      {payload.map((p,i)=>(
        <div key={i} style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:20, marginBottom:4 }}>
          <div style={{ display:'flex', alignItems:'center', gap:7 }}>
            <span style={{ width:8, height:8, borderRadius:2, backgroundColor:p.color, display:'inline-block' }}/>
            <span style={{ fontSize:11, color:T.textSec }}>{p.name}</span>
          </div>
          <span style={{ fontSize:13, fontWeight:700, color:p.color }}>{p.value.toLocaleString()}</span>
        </div>
      ))}
      {payload.length>1&&(
        <div style={{ marginTop:6, paddingTop:6, borderTop:`1px solid ${T.border}`,
          display:'flex', justifyContent:'space-between', fontSize:11 }}>
          <span style={{ color:T.textSec }}>Total findings</span>
          <span style={{ fontWeight:700, color:T.textPri }}>
            {payload.filter(p=>['critical','high','medium'].includes(p.dataKey)).reduce((s,p)=>s+p.value,0)}
          </span>
        </div>
      )}
    </div>
  );
}

/* Bar chart tooltip — adds % of total + severity breakdown */
function BarTooltip({ active, payload, label }) {
  if (!active||!payload?.length) return null;
  const row = SERVICE_DATA.find(d=>d.service===label)||{};
  const total = SERVICE_DATA.reduce((s,d)=>s+d.findings,0);
  return (
    <div style={{ background:'linear-gradient(160deg,#1c2638,#111827)', border:`1px solid ${T.borderMd}`,
      borderRadius:12, padding:'10px 14px', boxShadow:'0 24px 48px rgba(0,0,0,0.8)', minWidth:210, pointerEvents:'none' }}>
      <div style={{ fontSize:10, fontWeight:700, color:T.textMut, textTransform:'uppercase',
        letterSpacing:'0.08em', paddingBottom:7, marginBottom:7, borderBottom:`1px solid ${T.border}` }}>
        {label} · {((row.findings/total)*100).toFixed(0)}% of total
      </div>
      {payload.map((p,i)=>(
        <div key={i} style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:20, marginBottom:4 }}>
          <div style={{ display:'flex', alignItems:'center', gap:7 }}>
            <span style={{ width:8, height:8, borderRadius:2, backgroundColor:p.color||p.fill, display:'inline-block' }}/>
            <span style={{ fontSize:11, color:T.textSec }}>{p.name}</span>
          </div>
          <span style={{ fontSize:13, fontWeight:700, color:p.color||p.fill }}>{p.value}</span>
        </div>
      ))}
      {row.findings&&(
        <div style={{ marginTop:6, paddingTop:6, borderTop:`1px solid ${T.border}`, fontSize:10, color:T.textMut }}>
          Critical rate: {((row.critical/row.findings)*100).toFixed(0)}% · Remediate IAM first
        </div>
      )}
    </div>
  );
}

/* Framework bar tooltip */
function FrameworkTooltip({ active, payload, label }) {
  if (!active||!payload?.length) return null;
  const fw = FRAMEWORK_DATA.find(f=>f.name===label)||{};
  const delta = fw.score-(fw.prevScore||fw.score);
  return (
    <div style={{ background:'linear-gradient(160deg,#1c2638,#111827)', border:`1px solid ${T.borderMd}`,
      borderRadius:12, padding:'10px 14px', boxShadow:'0 24px 48px rgba(0,0,0,0.8)', minWidth:220, pointerEvents:'none' }}>
      <div style={{ fontSize:10, fontWeight:700, color:T.textMut, textTransform:'uppercase',
        letterSpacing:'0.08em', paddingBottom:7, marginBottom:7, borderBottom:`1px solid ${T.border}` }}>
        {label}
      </div>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:6 }}>
        <span style={{ fontSize:11, color:T.textSec }}>Compliance Score</span>
        <div style={{ display:'flex', alignItems:'center', gap:6 }}>
          <span style={{ fontSize:15, fontWeight:800, color:scoreColor(fw.score) }}>{fw.score}%</span>
          {delta!==0&&<span style={{ fontSize:10, fontWeight:600, color:delta>0?T.pass:T.critical }}>
            {delta>0?'▲':'▼'}{Math.abs(delta)}pp
          </span>}
        </div>
      </div>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:4 }}>
        <span style={{ fontSize:11, color:T.textSec }}>Controls Passing</span>
        <span style={{ fontSize:12, fontWeight:700, color:T.textPri }}>{fw.passed} / {fw.total}</span>
      </div>
      <div style={{ height:4, borderRadius:4, backgroundColor:T.border, marginTop:8 }}>
        <div style={{ height:'100%', borderRadius:4, width:`${fw.score}%`, backgroundColor:scoreColor(fw.score) }}/>
      </div>
    </div>
  );
}

/* Scatter tooltip */
function ScatterTooltip({ active, payload }) {
  if (!active||!payload?.length) return null;
  const d = payload[0]?.payload||{};
  const level = d.risk>=75?'Critical':d.risk>=55?'High':d.risk>=35?'Medium':'Low';
  const lc = d.risk>=75?T.critical:d.risk>=55?T.high:d.risk>=35?T.medium:T.pass;
  const pc = { AWS:'#ff9900', Azure:'#0078d4', GCP:'#34a853' };
  return (
    <div style={{ background:'linear-gradient(160deg,#1c2638,#111827)', border:`1px solid ${T.borderMd}`,
      borderRadius:12, padding:'10px 14px', boxShadow:'0 24px 48px rgba(0,0,0,0.8)', minWidth:200, pointerEvents:'none' }}>
      <div style={{ fontSize:11, fontWeight:700, color:T.textPri, marginBottom:8, display:'flex', alignItems:'center', gap:8 }}>
        {d.name}
        <span style={{ fontSize:9, fontWeight:700, padding:'1px 6px', borderRadius:4,
          background:`${pc[d.provider]||T.indigo}22`, color:pc[d.provider]||T.indigo }}>{d.provider}</span>
      </div>
      {[
        ['Risk Score', d.risk, lc],
        ['Resources',  d.resources, T.textPri],
      ].map(([k,v,c])=>(
        <div key={k} style={{ display:'flex', justifyContent:'space-between', gap:20, marginBottom:4 }}>
          <span style={{ fontSize:11, color:T.textSec }}>{k}</span>
          <span style={{ fontSize:12, fontWeight:700, color:c }}>{v}</span>
        </div>
      ))}
      <div style={{ marginTop:7, paddingTop:5, borderTop:`1px solid ${T.border}`, display:'flex', alignItems:'center', gap:6 }}>
        <span style={{ width:8, height:8, borderRadius:2, backgroundColor:lc, display:'inline-block' }}/>
        <span style={{ fontSize:10, color:lc, fontWeight:600 }}>{level} risk account</span>
      </div>
    </div>
  );
}

/* Pie/Donut tooltip */
function PieTooltip({ active, payload }) {
  if (!active||!payload?.length) return null;
  const d = payload[0];
  const pct = ((d.value/SEV_TOTAL)*100).toFixed(1);
  return (
    <div style={{ background:'linear-gradient(160deg,#1c2638,#111827)', border:`1px solid ${T.borderMd}`,
      borderRadius:12, padding:'10px 14px', boxShadow:'0 24px 48px rgba(0,0,0,0.8)', minWidth:180, pointerEvents:'none' }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:8 }}>
        <span style={{ width:10, height:10, borderRadius:2, backgroundColor:d.payload.fill||d.color, display:'inline-block' }}/>
        <span style={{ fontSize:11, fontWeight:700, color:T.textPri }}>{d.name}</span>
      </div>
      <div style={{ display:'flex', justifyContent:'space-between', gap:16, marginBottom:4 }}>
        <span style={{ fontSize:11, color:T.textSec }}>Count</span>
        <span style={{ fontSize:14, fontWeight:800, color:d.payload.fill||d.color }}>{d.value}</span>
      </div>
      <div style={{ display:'flex', justifyContent:'space-between', gap:16 }}>
        <span style={{ fontSize:11, color:T.textSec }}>% of total</span>
        <span style={{ fontSize:12, fontWeight:700, color:T.textPri }}>{pct}%</span>
      </div>
      <div style={{ height:3, borderRadius:3, backgroundColor:T.border, marginTop:8 }}>
        <div style={{ height:'100%', borderRadius:3, width:`${pct}%`, backgroundColor:d.payload.fill||d.color }}/>
      </div>
    </div>
  );
}

/* Heatmap tooltip */
function HmapTooltip({ day, hour, count }) {
  const avg = 14;
  const pct = count===0?0:((count/28)*100).toFixed(0);
  const c = count>20?T.critical:count>13?T.high:count>6?T.medium:count>0?T.low:T.textMut;
  return (
    <div style={{ background:'linear-gradient(160deg,#1c2638,#111827)', border:`1px solid ${T.borderMd}`,
      borderRadius:10, padding:'8px 12px', boxShadow:'0 16px 32px rgba(0,0,0,0.8)', minWidth:170, pointerEvents:'none' }}>
      <div style={{ fontSize:10, color:T.textMut, fontWeight:700, marginBottom:6, textTransform:'uppercase', letterSpacing:'0.08em' }}>
        {day} · {hour}
      </div>
      <div style={{ fontSize:18, fontWeight:800, color:c, marginBottom:4 }}>{count}</div>
      <div style={{ fontSize:10, color:T.textSec }}>findings this hour</div>
      <div style={{ fontSize:10, color:count>avg?T.high:T.pass, marginTop:4 }}>
        {count===0?'No activity':count>avg?`▲ ${count-avg} above avg`:`▼ ${avg-count} below avg`}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   SHARED AXIS / GRID PROPS
══════════════════════════════════════════════════════════════ */
const ax   = { tick:{ fill:T.textSec, fontSize:10 }, tickLine:false };
const axL  = { tick:{ fill:T.textSec, fontSize:10 }, tickLine:false, axisLine:false };
const grid = { stroke:T.border, strokeDasharray:'3 3' };

/* Custom event dot on line chart */
function EventDot(props) {
  const { cx, cy, payload } = props;
  if (!payload?.event) return null;
  return (
    <g>
      <circle cx={cx} cy={cy} r={5} fill={T.indigo} stroke={T.bgCard} strokeWidth={2}/>
      <circle cx={cx} cy={cy} r={9} fill="none" stroke={T.indigo} strokeWidth={1} opacity={0.4}/>
    </g>
  );
}

/* ══════════════════════════════════════════════════════════════
   CHART COMPONENTS
══════════════════════════════════════════════════════════════ */

function ChartLine() {
  const last = DAILY[DAILY.length-1];
  const first = DAILY[0];
  const drop = first.critical - last.critical;
  return (
    <Card tag="C1" label="Line Chart — Multi-Series Trend"
      insight={`↓ ${drop} critical in 30d`} insightColor={T.pass}
      description="Findings over time · event markers">
      <ResponsiveContainer width="100%" height={210}>
        <LineChart data={DAILY} margin={{ top:8, right:12, bottom:0, left:-18 }}>
          <CartesianGrid {...grid}/>
          <XAxis dataKey="day" {...ax} tickFormatter={v=>v%5===0?`Mar ${v}`:''} interval={0}/>
          <YAxis {...axL}/>
          <Tooltip content={<TimeTooltip/>}/>
          <Legend wrapperStyle={{ fontSize:11, color:T.textSec, paddingTop:8 }}/>
          <ReferenceLine x={7}  stroke={T.indigo} strokeDasharray="4 2" strokeWidth={1} label={{ value:'Policy', fill:T.indigo, fontSize:9, position:'top' }}/>
          <ReferenceLine x={15} stroke={T.violet} strokeDasharray="4 2" strokeWidth={1} label={{ value:'Config update', fill:T.violet, fontSize:9, position:'top' }}/>
          <Line type="monotone" dataKey="critical" stroke={T.s2} strokeWidth={2} dot={<EventDot/>} activeDot={{ r:5, strokeWidth:2, stroke:T.bgCard }} name="Critical"/>
          <Line type="monotone" dataKey="high"     stroke={T.s4} strokeWidth={2} dot={false} activeDot={{ r:5 }} name="High"/>
          <Line type="monotone" dataKey="medium"   stroke={T.s1} strokeWidth={2} dot={false} activeDot={{ r:5 }} name="Medium"/>
        </LineChart>
      </ResponsiveContainer>
      <div className="flex gap-4 mt-2" style={{ fontSize:10, color:T.textMut }}>
        <span style={{ color:T.indigo }}>◆ = annotation event (policy / config change)</span>
        <span>Hover any point for full breakdown</span>
      </div>
    </Card>
  );
}

function ChartArea() {
  return (
    <Card tag="C2" label="Area Chart — Volume + Trend"
      insight="↑ 44 resolved this month" insightColor={T.pass}
      description="Total open vs resolved · gradient fill">
      <ResponsiveContainer width="100%" height={210}>
        <AreaChart data={DAILY} margin={{ top:8, right:12, bottom:0, left:-18 }}>
          <defs>
            <linearGradient id="ag1" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor={T.s1} stopOpacity={0.4}/>
              <stop offset="95%" stopColor={T.s1} stopOpacity={0}/>
            </linearGradient>
            <linearGradient id="ag2" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor={T.s3} stopOpacity={0.4}/>
              <stop offset="95%" stopColor={T.s3} stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid {...grid}/>
          <XAxis dataKey="day" {...ax} tickFormatter={v=>v%5===0?`Mar ${v}`:''} interval={0}/>
          <YAxis {...axL}/>
          <Tooltip content={<TimeTooltip/>}/>
          <Legend wrapperStyle={{ fontSize:11, color:T.textSec, paddingTop:8 }}/>
          <Area type="monotone" dataKey="total"    stroke={T.s1} fill="url(#ag1)" strokeWidth={2} dot={false} activeDot={{ r:4 }} name="Total Open"/>
          <Area type="monotone" dataKey="resolved" stroke={T.s3} fill="url(#ag2)" strokeWidth={2} dot={false} activeDot={{ r:4 }} name="Resolved"/>
        </AreaChart>
      </ResponsiveContainer>
    </Card>
  );
}

function ChartStackedArea() {
  return (
    <Card tag="C3" label="Stacked Area — Severity Composition Over Time"
      insight="Critical ↓ 68% · 30-day window" insightColor={T.pass}
      description="All severity tiers stacked · reduction story at a glance" wide>
      <ResponsiveContainer width="100%" height={210}>
        <AreaChart data={DAILY} margin={{ top:8, right:12, bottom:0, left:-18 }}>
          <defs>
            {[[T.s2,'sa1'],[T.s4,'sa2'],[T.s1,'sa3'],[T.s3,'sa4']].map(([c,id])=>(
              <linearGradient key={id} id={id} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={c} stopOpacity={0.6}/>
                <stop offset="95%" stopColor={c} stopOpacity={0.05}/>
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid {...grid}/>
          <XAxis dataKey="day" {...ax} tickFormatter={v=>v%5===0?`Mar ${v}`:''} interval={0}/>
          <YAxis {...axL}/>
          <Tooltip content={<TimeTooltip/>}/>
          <Legend wrapperStyle={{ fontSize:11, color:T.textSec, paddingTop:8 }}/>
          <Area type="monotone" dataKey="critical" stackId="a" stroke={T.s2} fill="url(#sa1)" strokeWidth={1.5} dot={false} name="Critical"/>
          <Area type="monotone" dataKey="high"     stackId="a" stroke={T.s4} fill="url(#sa2)" strokeWidth={1.5} dot={false} name="High"/>
          <Area type="monotone" dataKey="medium"   stackId="a" stroke={T.s1} fill="url(#sa3)" strokeWidth={1.5} dot={false} name="Medium"/>
        </AreaChart>
      </ResponsiveContainer>
    </Card>
  );
}

function ChartVertBar() {
  return (
    <Card tag="C4" label="Vertical Bar — Findings by Cloud Service"
      insight="IAM = 27% of all findings" insightColor={T.high}
      description="Grouped by severity · value labels on top">
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={SERVICE_DATA} margin={{ top:18, right:8, bottom:0, left:-18 }}>
          <CartesianGrid {...grid} vertical={false}/>
          <XAxis dataKey="service" {...ax}/>
          <YAxis {...axL}/>
          <Tooltip content={<BarTooltip/>}/>
          <Legend wrapperStyle={{ fontSize:11, color:T.textSec, paddingTop:8 }}/>
          <Bar dataKey="findings" fill={T.s1}      name="All Findings" radius={[4,4,0,0]} maxBarSize={26}>
            <LabelList dataKey="findings" position="top" style={{ fontSize:9, fill:T.textSec, fontWeight:600 }}/>
          </Bar>
          <Bar dataKey="critical" fill={T.critical} name="Critical"     radius={[4,4,0,0]} maxBarSize={26}/>
        </BarChart>
      </ResponsiveContainer>
    </Card>
  );
}

function ChartHorizBar() {
  return (
    <Card tag="C5" label="Horizontal Bar — Framework Compliance"
      insight="ISO 27001 leading · PCI lagging" insightColor={T.medium}
      description="Score per framework · target reference · delta vs prev scan">
      <ResponsiveContainer width="100%" height={250}>
        <BarChart data={FRAMEWORK_DATA} layout="vertical" margin={{ top:0, right:40, bottom:0, left:62 }}>
          <CartesianGrid {...grid} horizontal={false}/>
          <XAxis type="number" domain={[0,100]} {...ax} axisLine={false} tickFormatter={fmtPct}/>
          <YAxis type="category" dataKey="name" tick={{ fill:T.textSec, fontSize:10 }} tickLine={false} width={62}/>
          <Tooltip content={<FrameworkTooltip/>}/>
          <ReferenceLine x={75} stroke={T.pass} strokeDasharray="4 2" strokeWidth={1.5}
            label={{ value:'Target 75%', fill:T.pass, fontSize:9, position:'insideTopRight' }}/>
          <Bar dataKey="score" name="Score" radius={[0,6,6,0]} maxBarSize={20}>
            <LabelList dataKey="score" position="right" style={{ fontSize:10, fontWeight:700 }}
              formatter={v=>`${v}%`}
              fill={T.textSec}/>
            {FRAMEWORK_DATA.map((d,i)=><Cell key={i} fill={scoreColor(d.score)} opacity={0.85}/>)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Card>
  );
}

function ChartStackedBar() {
  return (
    <Card tag="C6" label="Stacked Bar — Monthly Severity Trend"
      insight="Critical ↓ 68% since Oct" insightColor={T.pass}
      description="6-month severity breakdown · remediation progress visible" wide>
      <ResponsiveContainer width="100%" height={210}>
        <BarChart data={MONTHLY_SEV} margin={{ top:8, right:8, bottom:0, left:-18 }}>
          <CartesianGrid {...grid} vertical={false}/>
          <XAxis dataKey="month" {...ax}/>
          <YAxis {...axL}/>
          <Tooltip content={<RichTooltip footer="Hover segments for breakdown"/>}/>
          <Legend wrapperStyle={{ fontSize:11, color:T.textSec, paddingTop:8 }}/>
          <Bar dataKey="critical" stackId="a" fill={T.critical} name="Critical"/>
          <Bar dataKey="high"     stackId="a" fill={T.high}     name="High"/>
          <Bar dataKey="medium"   stackId="a" fill={T.medium}   name="Medium"/>
          <Bar dataKey="low"      stackId="a" fill={T.low}      name="Low"  radius={[4,4,0,0]}>
            <LabelList dataKey="low" position="top" style={{ fontSize:9, fill:T.textMut }}
              formatter={(_,entry)=>{
                const row=MONTHLY_SEV.find(m=>m.month===entry?.month);
                if(!row) return '';
                return `${row.critical+row.high+row.medium+row.low}`;
              }}/>
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Card>
  );
}

const PIE_COLORS = [T.critical, T.high, T.medium, T.low, T.info];
const RADIAN = Math.PI/180;
function PieLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent }) {
  if (percent<0.07) return null;
  const r = innerRadius+(outerRadius-innerRadius)*0.52;
  return <text x={cx+r*Math.cos(-midAngle*RADIAN)} y={cy+r*Math.sin(-midAngle*RADIAN)}
    fill="#fff" textAnchor="middle" dominantBaseline="central" fontSize={11} fontWeight={700}>
    {`${(percent*100).toFixed(0)}%`}
  </text>;
}

function ChartDonut() {
  return (
    <Card tag="C7" label="Donut Chart — Finding Distribution"
      insight={`${SEV_TOTAL} total findings`} insightColor={T.indigo}
      description="Hover slice for count + % breakdown">
      <ResponsiveContainer width="100%" height={210}>
        <PieChart>
          <Pie data={SEVERITY_DIST} cx="50%" cy="50%" innerRadius={52} outerRadius={86}
            dataKey="value" labelLine={false} label={<PieLabel/>} paddingAngle={2}>
            {SEVERITY_DIST.map((_,i)=><Cell key={i} fill={PIE_COLORS[i]} opacity={0.9}/>)}
          </Pie>
          <Tooltip content={<PieTooltip/>}/>
          <Legend wrapperStyle={{ fontSize:11, color:T.textSec }}/>
        </PieChart>
      </ResponsiveContainer>
    </Card>
  );
}

function ChartPie() {
  return (
    <Card tag="C8" label="Pie Chart — Full Circle Distribution"
      insight={`${SEV_TOTAL} findings`} insightColor={T.indigo}
      description="Simple proportion · no center hole">
      <ResponsiveContainer width="100%" height={210}>
        <PieChart>
          <Pie data={SEVERITY_DIST} cx="50%" cy="50%" outerRadius={86}
            dataKey="value" labelLine={false} label={<PieLabel/>} paddingAngle={2}>
            {SEVERITY_DIST.map((_,i)=><Cell key={i} fill={PIE_COLORS[i]} opacity={0.9}/>)}
          </Pie>
          <Tooltip content={<PieTooltip/>}/>
          <Legend wrapperStyle={{ fontSize:11, color:T.textSec }}/>
        </PieChart>
      </ResponsiveContainer>
    </Card>
  );
}

function ChartRadar() {
  return (
    <Card tag="C9" label="Radar / Spider — Multi-Domain Posture"
      insight="IAM + Risk = weakest axes" insightColor={T.critical}
      description="Current vs previous scan · shape change = progress" recommended>
      <ResponsiveContainer width="100%" height={240}>
        <RadarChart data={RADAR_DATA}>
          <PolarGrid stroke={T.border}/>
          <PolarAngleAxis dataKey="subject" tick={{ fill:T.textSec, fontSize:10 }}/>
          <PolarRadiusAxis angle={30} domain={[0,100]} tick={{ fill:T.textMut, fontSize:9 }} tickCount={4}/>
          <Radar name="Current" dataKey="score" stroke={T.indigo} fill={T.indigo} fillOpacity={0.2} strokeWidth={2} dot={{ fill:T.indigo, r:3 }}/>
          <Radar name="Prev Scan" dataKey="prev" stroke={T.violet} fill={T.violet} fillOpacity={0.08} strokeWidth={1.5} strokeDasharray="4 2" dot={false}/>
          <Tooltip content={<RichTooltip footer="vs previous scan shown dashed"/>}/>
          <Legend wrapperStyle={{ fontSize:11, color:T.textSec }}/>
        </RadarChart>
      </ResponsiveContainer>
    </Card>
  );
}

function ChartScatter() {
  const pc = { AWS:'#ff9900', Azure:'#0078d4', GCP:'#34a853' };
  const riskColor = r => r>=75?T.critical:r>=55?T.high:r>=35?T.medium:T.pass;
  return (
    <Card tag="C10" label="Scatter Plot — Risk vs Resource Count"
      insight="2 critical-risk accounts" insightColor={T.critical}
      description="Each dot = cloud account · colour = risk level · hover for detail">
      <ResponsiveContainer width="100%" height={220}>
        <ScatterChart margin={{ top:8, right:16, bottom:24, left:-10 }}>
          <CartesianGrid {...grid}/>
          <XAxis dataKey="resources" name="Resources" type="number" {...ax}
            label={{ value:'← Resource Count →', position:'insideBottom', offset:-14, fill:T.textMut, fontSize:10 }}/>
          <YAxis dataKey="risk" name="Risk Score" type="number" {...axL}
            label={{ value:'Risk', angle:-90, position:'insideLeft', fill:T.textMut, fontSize:10, dy:20 }}/>
          <Tooltip content={<ScatterTooltip/>}/>
          <ReferenceLine y={55} stroke={T.high}     strokeDasharray="4 2" label={{ value:'High', fill:T.high,     fontSize:9, position:'right' }}/>
          <ReferenceLine y={75} stroke={T.critical} strokeDasharray="4 2" label={{ value:'Critical', fill:T.critical, fontSize:9, position:'right' }}/>
          <Scatter data={SCATTER_DATA} shape={props=>{
            const { cx, cy, payload } = props;
            const c = riskColor(payload.risk);
            return <circle cx={cx} cy={cy} r={6} fill={c} fillOpacity={0.8} stroke={c} strokeWidth={1.5} strokeOpacity={0.5}/>;
          }}/>
        </ScatterChart>
      </ResponsiveContainer>
    </Card>
  );
}

function ChartComposed() {
  return (
    <Card tag="C11" label="Composed Chart — Total / Resolved / Critical"
      insight="44 resolved this month" insightColor={T.pass}
      description="Bar + Area + Line combined · shows remediation progress against total" wide>
      <ResponsiveContainer width="100%" height={210}>
        <ComposedChart data={DAILY} margin={{ top:8, right:12, bottom:0, left:-18 }}>
          <defs>
            <linearGradient id="cg1" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%"  stopColor={T.s1} stopOpacity={0.25}/>
              <stop offset="95%" stopColor={T.s1} stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid {...grid}/>
          <XAxis dataKey="day" {...ax} tickFormatter={v=>v%5===0?`Mar ${v}`:''} interval={0}/>
          <YAxis {...axL}/>
          <Tooltip content={<TimeTooltip/>}/>
          <Legend wrapperStyle={{ fontSize:11, color:T.textSec, paddingTop:8 }}/>
          <Area  type="monotone" dataKey="total"    stroke={T.s1}  fill="url(#cg1)" strokeWidth={2}   dot={false} activeDot={{ r:4 }} name="Total Open"/>
          <Bar                   dataKey="resolved" fill={T.pass}  name="Resolved"  radius={[3,3,0,0]} maxBarSize={10} opacity={0.85}/>
          <Line  type="monotone" dataKey="critical" stroke={T.s2}  strokeWidth={2}  dot={false} activeDot={{ r:5 }} name="Critical"/>
        </ComposedChart>
      </ResponsiveContainer>
    </Card>
  );
}

function ChartTreemap() {
  const Content = ({ x, y, width, height, name, crit, findings }) => {
    if (width<28||height<18) return null;
    const c = crit>5?T.critical:crit>2?T.high:crit>0?T.medium:T.pass;
    return (
      <g>
        <rect x={x+1} y={y+1} width={width-2} height={height-2} rx={6}
          style={{ fill:`${c}18`, stroke:c, strokeWidth:1.5, strokeOpacity:0.5 }}/>
        {height>26&&width>55&&<text x={x+9} y={y+16} fill={T.textPri} fontSize={11} fontWeight={600}>{name}</text>}
        {height>38&&<text x={x+9} y={y+30} fill={T.textSec} fontSize={9}>{findings} findings{crit>0?` · ${crit} crit`:''}</text>}
      </g>
    );
  };
  return (
    <Card tag="C12" label="Treemap — Findings by Resource Type"
      insight="IAM has highest crit density" insightColor={T.critical}
      description="Size = finding count · colour border = severity · hover to drill">
      <ResponsiveContainer width="100%" height={230}>
        <Treemap data={TREEMAP_DATA} dataKey="size" aspectRatio={4/3} content={<Content/>}/>
      </ResponsiveContainer>
    </Card>
  );
}

function ChartHeatmap() {
  const [hovered, setHovered] = useState(null); // {day,hour,count,x,y}
  return (
    <Card tag="C13" label="Heatmap — Findings by Day × Hour"
      insight="Mon 3p is hotspot" insightColor={T.high}
      description="Intensity = finding count · hover cell for exact value + vs-average">
      <div className="overflow-x-auto" style={{ position:'relative' }}>
        <div className="min-w-max">
          <div className="flex gap-1 mb-1 ml-10">
            {HMAP_HOURS.map(h=>(
              <div key={h} className="w-9 text-center" style={{ fontSize:9, color:T.textSec, fontWeight:600 }}>{h}</div>
            ))}
          </div>
          {HMAP.map(row=>(
            <div key={row.day} className="flex gap-1 mb-1 items-center">
              <div className="w-9 text-right pr-2 flex-shrink-0" style={{ fontSize:9, color:T.textSec, fontWeight:600 }}>{row.day}</div>
              {row.cells.map(cell=>{
                const pct = cell.count/26;
                let bg=T.bgInset, borderC='transparent';
                if      (pct>0.75){ bg=`${T.critical}30`; borderC=`${T.critical}60`; }
                else if (pct>0.5) { bg=`${T.high}28`;     borderC=`${T.high}50`; }
                else if (pct>0.25){ bg=`${T.medium}22`;   borderC=`${T.medium}40`; }
                else if (pct>0.04){ bg=`${T.low}1a`;      borderC=`${T.low}35`; }
                return (
                  <div key={cell.hour}
                    className="w-9 h-7 rounded-lg flex items-center justify-center transition-all cursor-pointer"
                    style={{ backgroundColor:bg, border:`1px solid ${borderC}`,
                      transform:hovered?.day===row.day&&hovered?.hour===cell.hour?'scale(1.15)':'scale(1)',
                      boxShadow:hovered?.day===row.day&&hovered?.hour===cell.hour?`0 0 10px ${borderC}`:'none',
                      zIndex:hovered?.day===row.day&&hovered?.hour===cell.hour?10:1, position:'relative' }}
                    onMouseEnter={()=>setHovered({day:row.day, hour:cell.hour, count:cell.count})}
                    onMouseLeave={()=>setHovered(null)}>
                    <span style={{ fontSize:cell.count>15?9:8, fontWeight:700,
                      color:pct>0.5?T.critical:pct>0.25?T.high:T.textMut, opacity:cell.count>0?1:0.3 }}>
                      {cell.count||'·'}
                    </span>
                  </div>
                );
              })}
            </div>
          ))}
          {/* Legend */}
          <div className="flex items-center gap-3 mt-2 ml-10">
            <span style={{ fontSize:9, color:T.textMut }}>Fewer</span>
            {[[T.low,0.15],[T.medium,0.35],[T.high,0.6],[T.critical,0.85]].map(([c,o])=>(
              <div key={o} className="w-5 h-4 rounded-md" style={{ backgroundColor:c, opacity:o }}/>
            ))}
            <span style={{ fontSize:9, color:T.textMut }}>More findings</span>
          </div>
        </div>
        {/* Tooltip portal */}
        {hovered&&(
          <div style={{ position:'fixed', bottom:24, right:24, zIndex:1000 }}>
            <HmapTooltip {...hovered}/>
          </div>
        )}
      </div>
    </Card>
  );
}

function ChartGauge({ value=64 }) {
  const cx=100, cy=92, r=72;
  const toRad = d=>(d*Math.PI)/180;
  const arc = (from,to)=>{
    const x1=cx+r*Math.cos(toRad(from)),y1=cy+r*Math.sin(toRad(from));
    const x2=cx+r*Math.cos(toRad(to)),  y2=cy+r*Math.sin(toRad(to));
    return `M ${x1} ${y1} A ${r} ${r} 0 ${to-from>180?1:0} 1 ${x2} ${y2}`;
  };
  const va = -215+(value/100)*(35-(-215));
  const nx = cx+(r-16)*Math.cos(toRad(va)), ny = cy+(r-16)*Math.sin(toRad(va));
  const c = scoreColor(value);
  return (
    <Card tag="C14" label="Gauge / Speedometer — Posture Score"
      insight={`Grade: ${grade(value)} · ${value>=75?'Good':'Needs attention'}`}
      insightColor={c}
      description="Zone bands: red 0–49 · amber 50–74 · green 75–100" recommended>
      <div className="flex flex-col items-center gap-3">
        <svg width={200} height={118}>
          <path d={arc(-215,-120)} stroke={T.critical} strokeWidth={10} fill="none" strokeLinecap="round" opacity={0.2}/>
          <path d={arc(-120,-45)}  stroke={T.high}     strokeWidth={10} fill="none" strokeLinecap="round" opacity={0.2}/>
          <path d={arc(-45,  35)}  stroke={T.pass}     strokeWidth={10} fill="none" strokeLinecap="round" opacity={0.2}/>
          <path d={arc(-215, va)}  stroke={c}          strokeWidth={10} fill="none" strokeLinecap="round"/>
          <line x1={cx} y1={cy} x2={nx} y2={ny} stroke={T.textPri} strokeWidth={2.5} strokeLinecap="round"/>
          <circle cx={cx} cy={cy} r={5} fill={T.textPri}/>
          <text x={cx} y={cy+22} textAnchor="middle" fill={c} fontSize={26} fontWeight={800}>{value}</text>
          <text x={cx} y={cy+37} textAnchor="middle" fill={T.textSec} fontSize={11}>Overall Posture Score</text>
          <text x={36}  y={cy+14} fill={T.critical} fontSize={9} textAnchor="middle">Poor</text>
          <text x={164} y={cy+14} fill={T.pass}     fontSize={9} textAnchor="middle">Good</text>
        </svg>
        <div className="flex gap-5" style={{ fontSize:10 }}>
          <span style={{ color:T.critical }}>● 0–49 Poor</span>
          <span style={{ color:T.high }}>● 50–74 Fair</span>
          <span style={{ color:T.pass }}>● 75–100 Good</span>
        </div>
        <div className="w-full grid grid-cols-3 gap-2 mt-1">
          {[['Critical Open','21',T.critical],['High Open','35',T.high],['MTTR','4.2d',T.sky]].map(([l,v,c])=>(
            <div key={l} className="text-center py-2 rounded-lg" style={{ background:T.bgInset, border:`1px solid ${T.border}` }}>
              <div style={{ fontSize:16, fontWeight:800, color:c }}>{v}</div>
              <div style={{ fontSize:9, color:T.textMut, marginTop:2 }}>{l}</div>
            </div>
          ))}
        </div>
      </div>
    </Card>
  );
}

function Sparkline({ data, color, height=44, width=110, showArea=true, ticks=null, period=null }) {
  const PAD_B = ticks ? 18 : 4;
  const chartH = height - PAD_B;
  const mn = Math.min(...data), mx = Math.max(...data), rng = mx - mn || 1;
  const px = i => (i / (data.length - 1)) * width;
  const py = v => chartH - ((v - mn) / rng) * (chartH - 8) - 3;
  const pts = data.map((v,i) => `${px(i)},${py(v)}`).join(' ');
  const lx = px(data.length - 1), ly = py(data[data.length - 1]);
  const gradId = `sg${color.replace(/[^a-z0-9]/gi,'')}`;
  const areaD = `M0,${chartH} ${data.map((v,i)=>`L${px(i)},${py(v)}`).join(' ')} L${lx},${chartH} Z`;
  return (
    <svg width={width} height={height} style={{ overflow:'visible', display:'block', flexShrink:0 }}>
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.28}/>
          <stop offset="100%" stopColor={color} stopOpacity={0.01}/>
        </linearGradient>
      </defs>
      {/* baseline */}
      <line x1={0} y1={chartH} x2={width} y2={chartH} stroke={T.borderMd} strokeWidth={1} strokeDasharray="2,3"/>
      {/* area fill */}
      {showArea && <path d={areaD} fill={`url(#${gradId})`}/>}
      {/* line */}
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.8} strokeLinejoin="round" strokeLinecap="round"/>
      {/* end-point dot */}
      <circle cx={lx} cy={ly} r={2.5} fill={color} stroke={T.bgCard} strokeWidth={1.5}/>
      {/* tick labels */}
      {ticks?.map(({idx, label}, ti) => (
        <text key={idx} x={px(idx)} y={height - 3}
          textAnchor={ti === 0 ? 'start' : ti === ticks.length - 1 ? 'end' : 'middle'}
          style={{ fontSize:8, fill:T.textMut, fontFamily:'monospace' }}>{label}</text>
      ))}
      {/* period badge */}
      {period && (
        <text x={width} y={9} textAnchor="end"
          style={{ fontSize:8, fill:color, opacity:0.65, fontFamily:'inherit', fontWeight:700 }}>{period}</text>
      )}
    </svg>
  );
}

const SPARK14_TICKS = [
  { idx:0,  label:'14d' },
  { idx:6,  label:'7d'  },
  { idx:13, label:'Today' },
];

function ChartSparklines() {
  const metrics = [
    { label:'Critical Findings', color:T.critical, data:[28,25,23,21,20,18,16,15,13,12,10,8,6,4],                             delta:'-86%', note:'↓ 24 in 14d' },
    { label:'High Findings',     color:T.high,     data:[58,55,52,49,46,43,40,37,35,32,29,27,24,22],                          delta:'-62%', note:'↓ 36 in 14d' },
    { label:'Assets Scanned',    color:T.sky,      data:[1100,1130,1155,1170,1185,1195,1205,1215,1220,1225,1230,1235,1238,1240],delta:'+13%', note:'↑ 140 new assets' },
    { label:'Rules Passing',     color:T.pass,     data:[790,800,812,820,826,834,839,844,847,851,855,858,861,864],             delta:'+9%', note:'↑ 74 controls' },
  ];
  return (
    <Card tag="C15" label="Sparklines — Inline Trend Indicators"
      insight="All KPIs trending positive" insightColor={T.pass}
      description="Mini trend lines inside metric cards · 14-day window" wide>
      <div className="grid grid-cols-4 gap-3">
        {metrics.map(m=>(
          <div key={m.label} className="p-4 rounded-xl flex flex-col gap-2"
            style={{ background:T.bgInset, border:`1px solid ${T.border}` }}>
            <div className="flex items-start justify-between gap-2">
              <div className="text-xs" style={{ color:T.textSec }}>{m.label}</div>
              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full flex-shrink-0"
                style={{ background:`${m.color}18`, color:m.color }}>{m.delta}</span>
            </div>
            <div className="text-2xl font-black" style={{ color:m.color }}>{m.data[m.data.length-1].toLocaleString()}</div>
            <div style={{ marginTop:4 }}>
              <Sparkline data={m.data} color={m.color} height={52} width={120}
                ticks={SPARK14_TICKS} period="14d" showArea={true}/>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

/* ══════════════════════════════════════════════════════════════
   KPI CARDS
══════════════════════════════════════════════════════════════ */

function KpiSimple() {
  const kpis=[
    { label:'Total Assets',    value:'1,240', delta:'+3.2%',  up:true,  color:T.sky,      icon:'◈', sub:'vs last scan' },
    { label:'Open Findings',   value:'312',   delta:'↓17.5%', up:false, color:T.high,     icon:'⚑', sub:'378 previously' },
    { label:'Critical Issues', value:'21',    delta:'▲16.7%', up:true,  color:T.critical, icon:'◉', sub:'18 previously' },
    { label:'Compliance',      value:'74%',   delta:'+2.1pp', up:false, color:T.pass,     icon:'◎', sub:'vs 71.9% prior' },
  ];
  return (
    <div className="grid grid-cols-4 gap-3">
      {kpis.map(k=>(
        <div key={k.label} className="rounded-xl p-4 flex flex-col gap-3"
          style={{ background:`linear-gradient(145deg,${T.bgCard2},${T.bgInset})`, border:`1px solid ${T.border}`, boxShadow:'0 4px 16px rgba(0,0,0,0.4)' }}>
          <div className="flex items-center justify-between">
            <span style={{ fontSize:18, color:k.color }}>{k.icon}</span>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full"
              style={{ background:`${k.color}18`, color:k.color }}>{k.delta}</span>
          </div>
          <div>
            <div className="text-2xl font-black tracking-tight" style={{ color:k.color }}>{k.value}</div>
            <div className="text-xs mt-0.5" style={{ color:T.textSec }}>{k.label}</div>
            <div className="text-[10px] mt-0.5" style={{ color:T.textMut }}>{k.sub}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function KpiTrend() {
  const kpis=[
    { label:'Open Findings',  value:312, prev:378, unit:'',  flip:true,  color:T.high     },
    { label:'Critical',       value:21,  prev:18,  unit:'',  flip:true,  color:T.critical },
    { label:'MTTR (days)',    value:4.2, prev:5.1, unit:'d', flip:true,  color:T.sky      },
    { label:'Asset Coverage', value:94,  prev:88,  unit:'%', flip:false, color:T.pass     },
  ];
  return (
    <div className="grid grid-cols-4 gap-3">
      {kpis.map(k=>{
        const delta=((k.value-k.prev)/k.prev*100).toFixed(1);
        const good = k.flip?Number(delta)<0:Number(delta)>0;
        const tc   = good?T.pass:T.critical;
        return (
          <div key={k.label} className="rounded-xl p-4"
            style={{ background:`linear-gradient(145deg,${T.bgCard2},${T.bgInset})`, border:`1px solid ${T.border}` }}>
            <div className="text-xs mb-2" style={{ color:T.textSec }}>{k.label}</div>
            <div className="text-2xl font-black mb-1" style={{ color:k.color }}>{k.value}{k.unit}</div>
            <div className="flex items-center gap-1.5">
              <span style={{ fontSize:12, color:tc }}>{Number(delta)>0?'▲':'▼'}</span>
              <span className="text-xs font-semibold" style={{ color:tc }}>{Math.abs(delta)}%</span>
              <span style={{ fontSize:9, color:T.textMut }}>prev: {k.prev}{k.unit}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

const WEEK_TICKS = [
  { idx:0, label:'Mon' },
  { idx:2, label:'Wed' },
  { idx:4, label:'Fri' },
  { idx:6, label:'Sun' },
];
const MONTH_TICKS = [
  { idx:0,  label:'Wk 1' },
  { idx:6,  label:'Wk 2' },
  { idx:13, label:'Wk 3' },
  { idx:20, label:'Wk 4' },
  { idx:27, label:'Today' },
];

function KpiSparkline() {
  const kpis = [
    {
      label:'Critical Findings', value:21, color:T.critical,
      data:[28,26,23,20,18,16,21],
      delta:'-25%', deltaColor:T.pass,
      note:'↓ 7 since Mon · peak: 28',
      ticks:WEEK_TICKS, period:'This week',
    },
    {
      label:'High Findings', value:35, color:T.high,
      data:[52,48,45,42,40,38,35],
      delta:'-33%', deltaColor:T.pass,
      note:'↓ 17 since Mon · target: <30',
      ticks:WEEK_TICKS, period:'This week',
    },
    {
      label:'Assets Scanned', value:1240, color:T.sky,
      data:[1080,1110,1140,1158,1172,1188,1200,1210,1218,1226,1232,1236,1238,1239,1240,1240,1240,1240,1240,1240,1240,1240,1240,1240,1240,1240,1240,1240],
      delta:'+15%', deltaColor:T.sky,
      note:'+160 new assets · 98.3% coverage',
      ticks:MONTH_TICKS, period:'Last 28d',
    },
    {
      label:'Rules Passing', value:847, color:T.pass,
      data:[790,795,801,809,814,819,824,828,831,834,837,839,841,843,844,845,846,846,847,847,847,847,847,847,847,847,847,847],
      delta:'+7%', deltaColor:T.pass,
      note:'+57 controls · 68.5% pass rate',
      ticks:MONTH_TICKS, period:'Last 28d',
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-3">
      {kpis.map(k => (
        <div key={k.label} className="flex flex-col p-4 rounded-xl"
          style={{ background:`linear-gradient(160deg,${T.bgCard2},${T.bgInset})`,
            border:`1px solid ${T.border}`, boxShadow:'0 4px 20px rgba(0,0,0,0.4)' }}>
          {/* header row */}
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium" style={{ color:T.textSec }}>{k.label}</span>
            <div className="flex items-center gap-1.5">
              <span style={{ fontSize:9, color:T.textMut, fontFamily:'monospace' }}>{k.period}</span>
              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full"
                style={{ background:`${k.deltaColor}18`, color:k.deltaColor }}>{k.delta}</span>
            </div>
          </div>
          {/* big value */}
          <div className="text-3xl font-black tracking-tight mb-0.5" style={{ color:k.color }}>
            {k.value.toLocaleString()}
          </div>
          {/* context note */}
          <div style={{ fontSize:10, color:T.textMut, marginBottom:10 }}>{k.note}</div>
          {/* full-width sparkline */}
          <Sparkline data={k.data} color={k.color} height={58} width={220}
            ticks={k.ticks} period={null} showArea={true}/>
        </div>
      ))}
    </div>
  );
}

function KpiRing() {
  const Ring=({score,size=54})=>{
    const r=(size-10)/2,circ=2*Math.PI*r,fill=circ*(score/100),c=scoreColor(score);
    return(
      <svg width={size} height={size} style={{ transform:'rotate(-90deg)', flexShrink:0 }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={T.border} strokeWidth={6}/>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={c} strokeWidth={6}
          strokeDasharray={`${fill} ${circ}`} strokeLinecap="round"/>
      </svg>
    );
  };
  return (
    <div className="grid grid-cols-4 gap-3">
      {DOMAINS.slice(0,4).map(d=>{
        const delta=d.score-d.prev;
        return (
          <div key={d.label} className="rounded-xl p-4 flex items-center gap-3"
            style={{ background:`linear-gradient(145deg,${T.bgCard2},${T.bgInset})`, border:`1px solid ${T.border}` }}>
            <div className="relative flex-shrink-0">
              <Ring score={d.score}/>
              <span className="absolute inset-0 flex items-center justify-center text-xs font-black"
                style={{ color:scoreColor(d.score) }}>{d.score}</span>
            </div>
            <div>
              <div className="text-xs font-medium" style={{ color:T.textPri }}>{d.label}</div>
              <div style={{ fontSize:10, color:delta>=0?T.pass:T.critical, marginTop:2 }}>
                {delta>=0?'▲':'▼'} {Math.abs(delta)}pp vs prev
              </div>
              {d.crit>0&&<div style={{ fontSize:10, color:T.critical, marginTop:1 }}>▲ {d.crit} critical</div>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function KpiProgress() {
  return (
    <div className="space-y-2.5">
      {FRAMEWORK_DATA.map(it=>{
        const delta=it.score-(it.prevScore||it.score);
        return (
          <div key={it.name} className="flex items-center gap-4 px-4 py-3 rounded-xl"
            style={{ background:T.bgInset, border:`1px solid ${T.border}` }}>
            <div className="w-28 flex-shrink-0">
              <div className="text-xs font-semibold" style={{ color:T.textPri }}>{it.name}</div>
              <div style={{ fontSize:10, color:T.textSec, marginTop:1 }}>{it.passed}/{it.total} controls</div>
            </div>
            <div className="flex-1 h-2 rounded-full" style={{ backgroundColor:T.border }}>
              <div className="h-full rounded-full" style={{ width:`${it.score}%`, backgroundColor:scoreColor(it.score) }}/>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <span className="text-sm font-black w-9 text-right" style={{ color:scoreColor(it.score) }}>{it.score}%</span>
              {delta!==0&&<span style={{ fontSize:9, fontWeight:700, color:delta>0?T.pass:T.critical }}>
                {delta>0?'▲':'▼'}{Math.abs(delta)}
              </span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function KpiColorTint() {
  const kpis=[
    { label:'Critical',  value:21,  sub:'▲16.7% vs prev', color:T.critical, bg:T.bgCrit },
    { label:'High',      value:35,  sub:'↓14.6% vs prev', color:T.high,     bg:T.bgHigh },
    { label:'Medium',    value:48,  sub:'↓8.3% vs prev',  color:T.medium,   bg:T.bgMed  },
    { label:'Low',       value:29,  sub:'↓6.5% vs prev',  color:T.low,      bg:T.bgLow  },
    { label:'Resolved',  value:142, sub:'↑42 this scan',  color:T.pass,     bg:T.bgPass },
    { label:'Suppressed',value:56,  sub:'manual override', color:T.textSec,  bg:T.bgInset},
  ];
  return (
    <div className="grid grid-cols-6 gap-2">
      {kpis.map(k=>(
        <div key={k.label} className="rounded-xl p-3 flex flex-col gap-1 cursor-pointer hover:opacity-90 transition-opacity"
          style={{ background:`linear-gradient(145deg,${k.bg},${k.bg}bb)`, border:`1px solid ${k.color}28` }}>
          <div style={{ fontSize:22, fontWeight:800, color:k.color, lineHeight:1.1 }}>{k.value}</div>
          <div style={{ fontSize:10, fontWeight:600, color:`${k.color}cc` }}>{k.label}</div>
          <div style={{ fontSize:9, color:`${k.color}88`, marginTop:1 }}>{k.sub}</div>
        </div>
      ))}
    </div>
  );
}

function KpiSplit() {
  const items=[
    { label:'Scan Coverage',  a:{val:'94%', sub:'1,164 scanned',  color:T.pass}, b:{val:'6%',  sub:'76 unscanned',  color:T.textMut} },
    { label:'Finding Rate',   a:{val:'34%', sub:'rules failing',  color:T.high}, b:{val:'66%', sub:'rules passing', color:T.pass} },
    { label:'Risk Split',     a:{val:'56',  sub:'Critical+High',  color:T.critical}, b:{val:'77', sub:'Medium+Low', color:T.medium} },
  ];
  return (
    <div className="grid grid-cols-3 gap-3">
      {items.map(k=>(
        <div key={k.label} className="rounded-xl p-4"
          style={{ background:`linear-gradient(145deg,${T.bgCard2},${T.bgInset})`, border:`1px solid ${T.border}` }}>
          <div style={{ fontSize:10, fontWeight:700, textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:12, color:T.textMut }}>{k.label}</div>
          <div className="flex items-end gap-4">
            <div>
              <div style={{ fontSize:24, fontWeight:800, color:k.a.color, lineHeight:1 }}>{k.a.val}</div>
              <div style={{ fontSize:10, color:T.textSec, marginTop:3 }}>{k.a.sub}</div>
            </div>
            <div className="w-px h-10 self-center" style={{ backgroundColor:T.border }}/>
            <div>
              <div style={{ fontSize:20, fontWeight:700, color:k.b.color, lineHeight:1 }}>{k.b.val}</div>
              <div style={{ fontSize:10, color:T.textSec, marginTop:3 }}>{k.b.sub}</div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function KpiComparison() {
  const items=[
    { label:'Open Findings', cur:312, prev:378, flip:true  },
    { label:'Critical',      cur:21,  prev:18,  flip:true  },
    { label:'MTTR (days)',   cur:4.2, prev:5.1, flip:true  },
  ];
  return (
    <div className="grid grid-cols-3 gap-3">
      {items.map(it=>{
        const delta=it.cur-it.prev;
        const pct=Math.abs((delta/it.prev)*100).toFixed(0);
        const good=it.flip?delta<0:delta>0;
        const tc=good?T.pass:T.critical;
        return (
          <div key={it.label} className="rounded-xl p-4"
            style={{ background:`linear-gradient(145deg,${T.bgCard2},${T.bgInset})`, border:`1px solid ${T.border}` }}>
            <div style={{ fontSize:10, color:T.textSec, marginBottom:8 }}>{it.label}</div>
            <div className="flex items-baseline gap-3 mb-3">
              <span style={{ fontSize:30, fontWeight:800, color:tc, lineHeight:1 }}>{it.cur}</span>
              <div>
                <div style={{ fontSize:10, color:T.textSec }}>was {it.prev}</div>
                <div style={{ fontSize:10, fontWeight:600, color:tc }}>{delta>0?'+':''}{delta} ({pct}%)</div>
              </div>
            </div>
            <div style={{ height:4, borderRadius:4, backgroundColor:T.border }}>
              <div style={{ height:'100%', borderRadius:4, width:`${(it.cur/Math.max(it.cur,it.prev))*100}%`, backgroundColor:tc }}/>
            </div>
            <div style={{ fontSize:9, color:T.textMut, marginTop:5 }}>
              {good?'Improving trend ↓':'Needs attention ↑'} — vs previous scan
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   DATA PATTERNS
══════════════════════════════════════════════════════════════ */

function PatternFunnel() {
  const palette=[T.sky,T.s1,T.medium,T.high,T.critical,T.critical];
  const max=FUNNEL[0].n;
  return (
    <div className="space-y-1.5 max-w-md mx-auto">
      {FUNNEL.map((s,i)=>{
        const w=40+(s.n/max)*60, c=palette[i];
        const drop=i>0?Math.round((1-(s.n/FUNNEL[i-1].n))*100):0;
        return (
          <div key={s.stage} className="flex flex-col items-center">
            <div className="flex items-center justify-between px-4 py-2.5 rounded-xl w-full"
              style={{ maxWidth:`${w}%`, minWidth:200, background:`${c}18`, border:`1px solid ${c}40` }}>
              <div className="flex items-center gap-2">
                <span style={{ fontSize:12, color:c }}>{s.icon}</span>
                <span style={{ fontSize:11, fontWeight:600, color:T.textPri }}>{s.stage}</span>
              </div>
              <div className="flex items-center gap-3">
                {i>0&&<span style={{ fontSize:9, color:T.textMut }}>-{drop}%</span>}
                <span style={{ fontSize:13, fontWeight:700, color:c }}>{s.n.toLocaleString()}</span>
              </div>
            </div>
            {i<FUNNEL.length-1&&<div style={{ width:1, height:6, backgroundColor:T.border }}/>}
          </div>
        );
      })}
      <div style={{ fontSize:10, color:T.textMut, textAlign:'center', marginTop:8 }}>
        Drop-off: 1,240 assets → 21 critical open findings (1.7% critical rate)
      </div>
    </div>
  );
}

function PatternRiskMatrix() {
  const cells=[
    [{ sev:'info', n:8 },   { sev:'low',      n:3 }, { sev:'medium',   n:1 }],
    [{ sev:'low',  n:12 },  { sev:'medium',   n:7 }, { sev:'high',     n:4 }],
    [{ sev:'medium',n:5 },  { sev:'high',     n:9 }, { sev:'critical', n:21}],
  ];
  const sc={ critical:T.critical, high:T.high, medium:T.medium, low:T.low, info:T.textSec };
  const sb={ critical:T.bgCrit,   high:T.bgHigh,   medium:T.bgMed,  low:T.bgLow,  info:T.bgInset };
  const [tip, setTip]=useState(null);
  return (
    <div>
      <div className="flex gap-2 mb-2 ml-20">
        {['Low Impact','Medium Impact','High Impact'].map(l=>(
          <div key={l} className="flex-1 text-center"
            style={{ fontSize:10, color:T.textSec, fontWeight:600 }}>{l}</div>
        ))}
      </div>
      <div className="flex gap-2">
        <div className="flex flex-col gap-2 justify-between" style={{ width:76 }}>
          {['Likely','Possible','Rare'].map(l=>(
            <div key={l} className="flex items-center justify-end pr-2"
              style={{ fontSize:10, color:T.textSec, fontWeight:600, height:68 }}>{l}</div>
          ))}
        </div>
        <div className="flex-1 flex flex-col gap-2">
          {cells.slice().reverse().map((row,ri)=>(
            <div key={ri} className="flex gap-2">
              {row.map((cell,ci)=>{
                const c=sc[cell.sev], bg=sb[cell.sev];
                return (
                  <div key={ci}
                    className="flex-1 rounded-xl flex flex-col items-center justify-center gap-1 cursor-pointer transition-all"
                    style={{ height:68, background:`linear-gradient(145deg,${bg},${bg}aa)`,
                      border:`1.5px solid ${c}40`,
                      boxShadow:tip?.r===ri&&tip?.c===ci?`0 0 16px ${c}60, inset 0 0 8px ${c}20`:'none',
                      transform:tip?.r===ri&&tip?.c===ci?'scale(1.03)':'scale(1)' }}
                    onMouseEnter={()=>setTip({ r:ri, c:ci, ...cell })}
                    onMouseLeave={()=>setTip(null)}>
                    <span style={{ fontSize:20, fontWeight:800, color:c, lineHeight:1 }}>{cell.n}</span>
                    <span style={{ fontSize:9, textTransform:'capitalize', fontWeight:600, color:`${c}bb` }}>{cell.sev}</span>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>
      {/* Inline tooltip for risk matrix */}
      {tip&&(
        <div className="mt-3 px-4 py-3 rounded-xl" style={{ background:`${sc[tip.sev]||T.indigo}12`, border:`1px solid ${sc[tip.sev]||T.indigo}30` }}>
          <span style={{ fontSize:11, color:sc[tip.sev], fontWeight:700 }}>{tip.n} {tip.sev} findings</span>
          <span style={{ fontSize:10, color:T.textSec, marginLeft:8 }}>
            {{
              critical:'Immediate remediation required · escalate to security lead',
              high:'Address within 24h · assign owner',
              medium:'Schedule for next sprint · track',
              low:'Log and monitor · low urgency',
              info:'Informational · review periodically',
            }[tip.sev]}
          </span>
        </div>
      )}
      <div className="flex gap-4 mt-3 ml-20 flex-wrap">
        {Object.entries(sc).map(([k,v])=>(
          <span key={k} className="flex items-center gap-1.5" style={{ fontSize:10, color:T.textSec }}>
            <span style={{ width:8, height:8, borderRadius:2, backgroundColor:v, display:'inline-block' }}/>
            {k}
          </span>
        ))}
      </div>
    </div>
  );
}

function PatternTimeline() {
  const tc={ critical:T.critical, high:T.high, medium:T.medium, low:T.low, pass:T.pass };
  const tb={ critical:T.bgCrit, high:T.bgHigh, medium:T.bgMed, low:T.bgLow, pass:T.bgPass };
  return (
    <div className="space-y-2">
      {TIMELINE.map((ev,i)=>{
        const c=tc[ev.type]||T.textSec;
        const bg=tb[ev.type]||T.bgInset;
        return (
          <div key={i} className="flex items-start gap-3 p-3 rounded-xl cursor-pointer hover:opacity-90 transition-opacity"
            style={{ background:`linear-gradient(90deg,${bg},${T.bgInset})`, border:`1px solid ${c}22` }}>
            <div style={{ width:6, height:6, borderRadius:'50%', backgroundColor:c, marginTop:5, flexShrink:0, boxShadow:`0 0 6px ${c}80` }}/>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <span style={{ fontSize:9, fontWeight:800, textTransform:'uppercase', padding:'1px 6px', borderRadius:4,
                  background:`${c}20`, color:c, border:`1px solid ${c}30`, flexShrink:0 }}>{ev.type}</span>
                <span style={{ fontSize:11, color:T.textPri }}>{ev.msg}</span>
              </div>
              <div className="flex items-center gap-3 flex-wrap">
                <span style={{ fontSize:9, color:T.textSec }}>{ev.src}</span>
                <span style={{ fontSize:9, color:T.textMut }}>·</span>
                <span style={{ fontSize:9, color:T.textSec, fontFamily:'monospace' }}>{ev.id}</span>
                <span style={{ fontSize:9, color:T.textMut }}>·</span>
                <span style={{ fontSize:9, color:T.textMut }}>{ev.time}</span>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function PatternStatus() {
  const sc={ healthy:T.pass, degraded:T.medium, offline:T.critical };
  const sb={ healthy:T.bgPass, degraded:T.bgMed, offline:T.bgCrit };
  return (
    <div className="grid grid-cols-3 gap-2">
      {STATUSES.map(s=>{
        const c=sc[s.status], bg=sb[s.status];
        return (
          <div key={s.name} className="rounded-xl p-3"
            style={{ background:`linear-gradient(145deg,${bg},${T.bgInset})`, border:`1px solid ${c}25` }}>
            <div className="flex items-center gap-2 mb-2">
              <span style={{ width:7, height:7, borderRadius:'50%', backgroundColor:c, boxShadow:`0 0 6px ${c}80`, display:'inline-block', flexShrink:0 }}/>
              <span style={{ fontSize:11, fontWeight:600, color:T.textPri }}>{s.name}</span>
            </div>
            <div className="flex items-center justify-between">
              <span style={{ fontSize:9, fontWeight:700, textTransform:'capitalize', color:c }}>{s.status}</span>
              <span style={{ fontSize:9, color:T.textSec }}>{s.latency}</span>
            </div>
            <div style={{ fontSize:9, color:T.textMut, marginTop:2 }}>uptime {s.uptime}</div>
          </div>
        );
      })}
    </div>
  );
}

function PatternRanking() {
  const pc={ AWS:'#ff9900', Azure:'#0078d4', GCP:'#34a853' };
  return (
    <div className="space-y-2">
      {ACCOUNTS.map((a,i)=>(
        <div key={a.name} className="flex items-center gap-3 px-4 py-3 rounded-xl"
          style={{ background:`linear-gradient(145deg,${T.bgCard2},${T.bgInset})`, border:`1px solid ${T.border}` }}>
          <div style={{ width:24, textAlign:'center', fontSize:13, fontWeight:800, flexShrink:0,
            color:i===0?T.critical:i===1?T.high:T.textMut }}>{i===0?'⚠':i+1}</div>
          <div className="flex-1 min-w-0">
            <div style={{ fontSize:12, fontWeight:600, color:T.textPri }}>{a.name}</div>
            <div className="flex items-center gap-2 mt-0.5 flex-wrap">
              <span style={{ fontSize:9, fontWeight:700, padding:'1px 5px', borderRadius:4,
                background:`${pc[a.provider]}20`, color:pc[a.provider] }}>{a.provider}</span>
              <span style={{ fontSize:9, color:T.textSec }}>{a.region}</span>
              <span style={{ fontSize:9, color:T.textSec }}>·</span>
              <span style={{ fontSize:9, color:T.textSec }}>{a.findings} findings</span>
              {a.critical>0&&<span style={{ fontSize:9, fontWeight:700, color:T.critical }}>▲ {a.critical} crit</span>}
            </div>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <div style={{ width:88, height:5, borderRadius:5, backgroundColor:T.border }}>
              <div style={{ height:'100%', borderRadius:5, width:`${a.score}%`, backgroundColor:scoreColor(a.score) }}/>
            </div>
            <span style={{ fontSize:14, fontWeight:800, width:28, textAlign:'right', color:scoreColor(a.score) }}>{a.score}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function PatternPipeline() {
  const sc={ done:T.pass, active:T.sky, pending:T.textMut };
  const sb={ done:T.bgPass, active:T.bgLow, pending:T.bgInset };
  return (
    <div>
      <div className="flex items-start gap-0">
        {PIPELINE.map((s,i)=>(
          <div key={s.label} className="flex-1 flex flex-col items-center">
            <div className="flex items-center w-full">
              {i>0&&<div style={{ flex:1, height:2, backgroundColor:s.status!=='pending'?sc.done:T.border }}/>}
              <div style={{ width:28, height:28, borderRadius:'50%', display:'flex', alignItems:'center',
                justifyContent:'center', flexShrink:0, fontSize:10, fontWeight:800,
                background:`linear-gradient(145deg,${sb[s.status]},${T.bgInset})`,
                border:`2px solid ${sc[s.status]}`, color:sc[s.status],
                boxShadow:s.status==='active'?`0 0 10px ${T.sky}60`:'' }}>
                {s.status==='done'?'✓':s.status==='active'?'…':i+1}
              </div>
              {i<PIPELINE.length-1&&<div style={{ flex:1, height:2, backgroundColor:s.status==='done'?sc.done:T.border }}/>}
            </div>
            <div style={{ marginTop:8, textAlign:'center', padding:'0 2px' }}>
              <div style={{ fontSize:10, fontWeight:600, color:sc[s.status] }}>{s.label}</div>
              <div style={{ fontSize:9, color:T.textSec, marginTop:1 }}>{s.detail}</div>
              <div style={{ fontSize:9, color:T.textMut, marginTop:1 }}>{s.time}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   SCORE VISUALIZATIONS
══════════════════════════════════════════════════════════════ */

function ScoreBarList() {
  return (
    <div className="space-y-1.5">
      {DOMAINS.map(d=>{
        const delta=d.score-d.prev;
        return (
          <div key={d.label} className="flex items-center gap-3 px-3 py-2.5 rounded-xl cursor-pointer hover:opacity-80 transition-opacity"
            style={{ background:T.bgInset, border:`1px solid ${T.border}` }}>
            <span style={{ fontSize:12, fontWeight:800, width:24, textAlign:'right', flexShrink:0, color:scoreColor(d.score) }}>{d.score}</span>
            <span style={{ fontSize:11, width:76, flexShrink:0, color:T.textSec }}>{d.label}</span>
            <div style={{ flex:1, height:6, borderRadius:6, backgroundColor:T.border, position:'relative' }}>
              <div style={{ height:'100%', borderRadius:6, width:`${d.score}%`, backgroundColor:scoreColor(d.score) }}/>
              <div style={{ position:'absolute', top:0, height:'100%', width:1, left:'75%', backgroundColor:T.textSec, opacity:0.25 }}/>
            </div>
            <span style={{ fontSize:11, fontWeight:800, width:20, textAlign:'center', flexShrink:0, color:scoreColor(d.score) }}>{grade(d.score)}</span>
            <span style={{ fontSize:9, fontWeight:600, width:36, textAlign:'right', flexShrink:0,
              color:delta>=0?T.pass:T.critical }}>{delta>=0?'+':''}{delta}pp</span>
            {d.crit>0&&<span style={{ fontSize:9, fontWeight:700, padding:'2px 6px', borderRadius:5, flexShrink:0,
              background:`${T.critical}18`, color:T.critical, border:`1px solid ${T.critical}30` }}>{d.crit}</span>}
          </div>
        );
      })}
      <div style={{ fontSize:10, color:T.textMut, marginTop:4 }}>
        ▏75 = target threshold · pp = percentage points vs previous scan
      </div>
    </div>
  );
}

function ScoreBullet() {
  return (
    <div className="space-y-3">
      {DOMAINS.map(d=>(
        <div key={d.label} className="flex items-center gap-3">
          <span style={{ fontSize:10, width:76, flexShrink:0, color:T.textSec }}>{d.label}</span>
          <div style={{ flex:1, height:16, borderRadius:8, overflow:'hidden', position:'relative' }}>
            <div style={{ position:'absolute', inset:0, left:0,    width:'50%', background:`${T.critical}18` }}/>
            <div style={{ position:'absolute', inset:0, left:'50%',width:'25%', background:`${T.high}18` }}/>
            <div style={{ position:'absolute', inset:0, left:'75%',            background:`${T.pass}18` }}/>
            <div style={{ position:'absolute', top:3, bottom:3, left:0, borderRadius:6,
              width:`${d.score}%`, backgroundColor:scoreColor(d.score), opacity:0.85 }}/>
            <div style={{ position:'absolute', inset:0, left:'75%', width:1, backgroundColor:T.textSec, opacity:0.35 }}/>
          </div>
          <span style={{ fontSize:12, fontWeight:800, width:24, textAlign:'right', flexShrink:0, color:scoreColor(d.score) }}>{d.score}</span>
          {d.crit>0&&<span style={{ fontSize:9, fontWeight:700, padding:'1px 6px', borderRadius:4, flexShrink:0,
            background:`${T.critical}18`, color:T.critical }}>{d.crit}</span>}
        </div>
      ))}
    </div>
  );
}

function ScoreDonutGrid() {
  const Ring=({score,size=52})=>{
    const r=(size-10)/2,circ=2*Math.PI*r,fill=circ*(score/100),c=scoreColor(score);
    return(
      <svg width={size} height={size} style={{ transform:'rotate(-90deg)' }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={T.border} strokeWidth={6}/>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={c} strokeWidth={6}
          strokeDasharray={`${fill} ${circ}`} strokeLinecap="round"/>
      </svg>
    );
  };
  return (
    <div className="grid grid-cols-4 gap-3">
      {DOMAINS.map(d=>{
        const delta=d.score-d.prev;
        return (
          <div key={d.label} className="flex flex-col items-center gap-2 rounded-xl p-3 cursor-pointer hover:opacity-85 transition-opacity"
            style={{ background:`linear-gradient(145deg,${T.bgCard2},${T.bgInset})`, border:`1px solid ${T.border}` }}>
            <div style={{ position:'relative' }}>
              <Ring score={d.score}/>
              <span style={{ position:'absolute', inset:0, display:'flex', alignItems:'center', justifyContent:'center',
                fontSize:13, fontWeight:800, color:scoreColor(d.score) }}>{d.score}</span>
            </div>
            <span style={{ fontSize:10, textAlign:'center', color:T.textSec }}>{d.label}</span>
            <span style={{ fontSize:9, fontWeight:600, color:delta>=0?T.pass:T.critical }}>{delta>=0?'+':''}{delta}pp</span>
            {d.crit>0&&<span style={{ fontSize:9, fontWeight:700, padding:'1px 6px', borderRadius:4,
              background:`${T.critical}18`, color:T.critical }}>{d.crit} crit</span>}
          </div>
        );
      })}
    </div>
  );
}

function ScoreLetterGrades() {
  return (
    <div className="grid grid-cols-4 gap-3">
      {DOMAINS.map(d=>{
        const c=scoreColor(d.score), bg=scoreBg(d.score), delta=d.score-d.prev;
        return (
          <div key={d.label} className="flex flex-col items-center gap-1 rounded-xl p-3 cursor-pointer hover:opacity-85 transition-opacity"
            style={{ background:`linear-gradient(145deg,${bg},${T.bgInset})`, border:`1px solid ${c}28` }}>
            <span style={{ fontSize:34, fontWeight:900, lineHeight:1, color:c }}>{grade(d.score)}</span>
            <span style={{ fontSize:14, fontWeight:700, color:c }}>{d.score}</span>
            <span style={{ fontSize:9, fontWeight:600, color:delta>=0?T.pass:T.critical }}>{delta>=0?'+':''}{delta}pp</span>
            <span style={{ fontSize:10, textAlign:'center', color:T.textSec, marginTop:1 }}>{d.label}</span>
            {d.crit>0&&<span style={{ fontSize:9, fontWeight:700, color:T.critical }}>▲ {d.crit} critical</span>}
          </div>
        );
      })}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   PAGE SHELL
══════════════════════════════════════════════════════════════ */
const SECTIONS=[
  { id:'charts',   label:'Charts',         count:15 },
  { id:'kpi',      label:'KPI Cards',       count:8  },
  { id:'patterns', label:'Data Patterns',   count:6  },
  { id:'scores',   label:'Score Patterns',  count:4  },
];

function SectionHeader({ label, sub }) {
  return (
    <div className="mb-7 pb-4" style={{ borderBottom:`1px solid ${T.border}` }}>
      <div className="flex items-baseline gap-3">
        <h2 style={{ fontSize:20, fontWeight:900, color:T.textPri, letterSpacing:'-0.02em' }}>{label}</h2>
        <span style={{ fontSize:13, color:T.textMut }}>— {sub}</span>
      </div>
    </div>
  );
}

export default function DesignPreview() {
  const [active, setActive]=useState('charts');
  const go=id=>{ setActive(id); document.getElementById(id)?.scrollIntoView({ behavior:'smooth', block:'start' }); };

  return (
    <div className="min-h-screen" style={{ backgroundColor:T.bgPage }}>

      {/* Sticky nav */}
      <div className="sticky top-0 z-40"
        style={{ backgroundColor:`${T.bgPage}e8`, borderBottom:`1px solid ${T.border}`, backdropFilter:'blur(16px)' }}>
        <div className="max-w-5xl mx-auto px-8 py-3 flex items-center gap-4">
          <span style={{ fontSize:10, fontWeight:800, padding:'4px 10px', borderRadius:8, letterSpacing:'0.1em',
            background:`${T.indigo}18`, color:T.indigo, border:`1px solid ${T.indigo}30`, flexShrink:0 }}>
            DESIGN LIBRARY
          </span>
          <div className="flex items-center gap-1">
            {SECTIONS.map(s=>(
              <button key={s.id} onClick={()=>go(s.id)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150"
                style={{
                  background:   active===s.id?`linear-gradient(135deg,${T.indigo}30,${T.violet}20)`:'transparent',
                  color:        active===s.id?T.textPri:T.textSec,
                  border:      `1px solid ${active===s.id?T.indigo+'50':'transparent'}`,
                }}>
                {s.label}
                <span style={{ marginLeft:5, fontSize:9, fontWeight:700, padding:'1px 5px', borderRadius:10,
                  background:T.bgInset, color:T.textMut }}>{s.count}</span>
              </button>
            ))}
          </div>
          <span className="ml-auto hidden sm:block" style={{ fontSize:10, color:T.textMut }}>
            Pick a tag → tell Claude to implement it on any engine dashboard
          </span>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-10 space-y-20">

        <section id="charts">
          <SectionHeader label="Chart Types" sub="Recharts · 30-day CSPM data · event annotations · rich tooltips"/>
          <div className="grid grid-cols-2 gap-5">
            <ChartLine/>
            <ChartArea/>
            <ChartStackedArea/>
            <ChartVertBar/>
            <ChartHorizBar/>
            <ChartStackedBar/>
            <ChartDonut/>
            <ChartPie/>
            <ChartRadar/>
            <ChartScatter/>
            <ChartComposed/>
            <ChartTreemap/>
            <ChartHeatmap/>
            <ChartGauge value={64}/>
            <ChartSparklines/>
          </div>
        </section>

        <section id="kpi">
          <SectionHeader label="KPI Card Styles" sub="Top-of-dashboard metric blocks · delta · trend · context"/>
          <div className="space-y-5">
            <Card tag="K1" label="Simple KPI"          insight="4 metrics · icon + delta badge" description="Clean minimal · icon · value · sub-label"><KpiSimple/></Card>
            <Card tag="K2" label="Trend Arrow KPI"     insight="vs previous scan" description="Delta direction · prev value inline"><KpiTrend/></Card>
            <Card tag="K3" label="KPI + Sparkline"     insight="14-day window" description="Inline trend line · delta % · note text" recommended><KpiSparkline/></Card>
            <Card tag="K4" label="KPI + Donut Ring"    insight="pp = points vs prev" description="Arc ring + domain label + delta"><KpiRing/></Card>
            <Card tag="K5" label="KPI + Progress Bar"  insight="7 frameworks" description="Pass/fail bar · controls count · delta vs prev scan"><KpiProgress/></Card>
            <Card tag="K6" label="Severity Tint KPI"   insight="Wiz pattern" description="Background IS the signal · sub-label with delta"><KpiColorTint/></Card>
            <Card tag="K7" label="Split Metric"        insight="Dual-value card" description="Two related numbers · divider · contextual sub-labels"><KpiSplit/></Card>
            <Card tag="K8" label="Comparison KPI"      insight="vs prev scan" description="Before → after · delta abs + % · mini bar · context note" recommended><KpiComparison/></Card>
          </div>
        </section>

        <section id="patterns">
          <SectionHeader label="Data Patterns" sub="Flows · matrices · feeds · status · pipelines"/>
          <div className="space-y-5">
            <Card tag="P1" label="Funnel — Finding Lifecycle"     insight="1.7% critical rate"  description="Drop-off % at each stage · asset → critical"><PatternFunnel/></Card>
            <Card tag="P2" label="Risk Matrix (2D)"               insight="21 critical-likely"  description="Impact × Likelihood · hover for remediation guidance" recommended><PatternRiskMatrix/></Card>
            <Card tag="P3" label="Activity / Alert Feed"          insight="2 critical unread"   description="Finding ID · source · severity badge · time ago"><PatternTimeline/></Card>
            <Card tag="P4" label="Service Status Grid"            insight="1 offline · 1 degraded" description="Engine health · latency · uptime %"><PatternStatus/></Card>
            <Card tag="P5" label="Account Risk Ranking"           insight="AWS Prod = worst"    description="Score + critical count + provider + region"><PatternRanking/></Card>
            <Card tag="P6" label="Pipeline Steps"                 insight="Step 4/6 active"     description="Scan workflow · status · timestamp · detail"><PatternPipeline/></Card>
          </div>
        </section>

        <section id="scores">
          <SectionHeader label="Score Visualization Patterns" sub="0–100 posture scores · delta vs previous scan"/>
          <div className="space-y-5">
            <Card tag="S1" label="Score Bar + Grade"   insight="Compact list + delta" description="Score · bar · letter grade · delta pp · critical badge" recommended><ScoreBarList/></Card>
            <Card tag="S2" label="Bullet Chart"        insight="Zone context"          description="Poor / Fair / Good zone bands · score bar overlay"><ScoreBullet/></Card>
            <Card tag="S3" label="Donut Ring Grid"     insight="4×2 ring grid"         description="Score ring · grade-delta · critical count · Prisma pattern"><ScoreDonutGrid/></Card>
            <Card tag="S4" label="Letter Grade Cards"  insight="A–F · exec-friendly"   description="Large letter · score · delta pp · SecurityScorecard pattern"><ScoreLetterGrades/></Card>
          </div>
        </section>

        <p className="text-center pb-12" style={{ fontSize:11, color:T.textMut }}>
          /design-preview · Enterprise Design Library · v3 · Tell Claude: "use C9 + K3 + P2 for Threat engine dashboard"
        </p>
      </div>
    </div>
  );
}
