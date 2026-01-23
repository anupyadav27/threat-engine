"""
Agentic AI Quality Enhancement System
Using Claude Sonnet 4.5 + LangGraph
Multi-agent orchestration for CSP rule validation and improvement
"""

import os
os.environ['ANTHROPIC_API_KEY'] = os.getenv('ANTHROPIC_API_KEY', 'your-anthropic-api-key-here')

import yaml
import json
from pathlib import Path
from typing import Dict, List, TypedDict, Annotated
from datetime import datetime
import time

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

class RuleMetadata(BaseModel):
    """Schema for rule metadata"""
    rule_id: str
    service: str
    resource: str
    requirement: str
    scope: str
    domain: str
    subcategory: str
    severity: str
    title: str
    description: str
    rationale: str
    references: List[str]
    compliance: List[str] = []

class ValidationResult(BaseModel):
    """Schema for validation results"""
    field: str
    is_valid: bool
    issues: List[str] = []
    confidence_score: float = 0.0
    suggestions: List[str] = []

class ImprovedMetadata(BaseModel):
    """Schema for improved metadata"""
    title: str = Field(description="Professional, specific, actionable title")
    description: str = Field(description="Enterprise-grade description with security context")
    rationale: str = Field(description="Clear explanation of why this control matters")
    references: List[str] = Field(description="Specific, working documentation URLs")

class AgentState(TypedDict):
    """State shared across all agents"""
    rule: Dict
    csp: str
    validation_results: List[ValidationResult]
    improved_metadata: Dict
    final_rule: Dict
    errors: List[str]
    agent_logs: List[str]

class CSPAgenticSystem:
    """
    Multi-agent system for CSP rule quality enhancement
    
    Agents:
    1. Validator Agent - Validates current metadata quality
    2. Title Agent - Improves titles with CSP-specific expertise
    3. Description Agent - Enhances descriptions with security context
    4. Reference Agent - Finds specific, working documentation URLs
    5. Quality Assurance Agent - Final review and scoring
    """
    
    def __init__(self, csp_name: str):
        self.csp = csp_name.upper()
        self.csp_lower = csp_name.lower()
        
        # Initialize Claude Sonnet 4.5 with timeout
        self.llm = ChatAnthropic(
            model="claude-sonnet-4-20250514",
            temperature=0.3,
            max_tokens=4096,
            timeout=60.0,  # 60 second timeout per API call
            max_retries=2   # Retry failed calls twice
        )
        
        # CSP-specific documentation bases
        self.doc_bases = {
            'alicloud': {
                'base': 'https://www.alibabacloud.com/help',
                'security': 'https://www.alibabacloud.com/help/security-center',
                'patterns': {
                    'service_docs': '{base}/{service}',
                    'security_guide': '{base}/{service}/security-best-practices',
                    'user_guide': '{base}/{service}/user-guide'
                }
            },
            'aws': {
                'base': 'https://docs.aws.amazon.com',
                'security': 'https://docs.aws.amazon.com/security',
                'patterns': {
                    'service_docs': '{base}/{service}',
                    'security_guide': '{base}/{service}/latest/userguide/security.html',
                    'best_practices': '{base}/{service}/latest/userguide/best-practices.html'
                }
            },
            'azure': {
                'base': 'https://docs.microsoft.com/azure',
                'security': 'https://docs.microsoft.com/azure/security',
                'patterns': {
                    'service_docs': '{base}/{service}',
                    'security_guide': '{base}/{service}/security-baseline',
                    'best_practices': '{base}/{service}/security-best-practices'
                }
            },
            'gcp': {
                'base': 'https://cloud.google.com',
                'security': 'https://cloud.google.com/security',
                'patterns': {
                    'service_docs': '{base}/{service}/docs',
                    'security_guide': '{base}/{service}/docs/security',
                    'best_practices': '{base}/{service}/docs/best-practices'
                }
            },
            'ibm': {
                'base': 'https://cloud.ibm.com/docs',
                'security': 'https://cloud.ibm.com/docs/security',
                'patterns': {
                    'service_docs': '{base}/{service}',
                    'security_guide': '{base}/{service}?topic={service}-security',
                    'best_practices': '{base}/{service}?topic={service}-best-practices'
                }
            },
            'oci': {
                'base': 'https://docs.oracle.com/iaas',
                'security': 'https://docs.oracle.com/iaas/security',
                'patterns': {
                    'service_docs': '{base}/{service}',
                    'security_guide': '{base}/{service}/security',
                    'best_practices': '{base}/{service}/best-practices'
                }
            },
            'k8s': {
                'base': 'https://kubernetes.io/docs',
                'security': 'https://kubernetes.io/docs/concepts/security',
                'patterns': {
                    'service_docs': '{base}/concepts/{service}',
                    'security_guide': '{base}/concepts/security/{service}',
                    'best_practices': '{base}/tasks/administer-cluster/{service}'
                }
            }
        }
        
        # Build the agent workflow
        self.workflow = self.build_workflow()
        
    def build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow with all agents"""
        workflow = StateGraph(AgentState)
        
        # Add agents as nodes
        workflow.add_node("validator", self.validator_agent)
        workflow.add_node("title_improver", self.title_agent)
        workflow.add_node("description_improver", self.description_agent)
        workflow.add_node("reference_finder", self.reference_agent)
        workflow.add_node("qa_reviewer", self.qa_agent)
        
        # Define the workflow
        workflow.set_entry_point("validator")
        workflow.add_edge("validator", "title_improver")
        workflow.add_edge("title_improver", "description_improver")
        workflow.add_edge("description_improver", "reference_finder")
        workflow.add_edge("reference_finder", "qa_reviewer")
        workflow.add_edge("qa_reviewer", END)
        
        return workflow.compile()
    
    def validator_agent(self, state: AgentState) -> AgentState:
        """Agent 1: Validates current metadata quality"""
        rule = state['rule']
        
        validation_prompt = f"""You are a {self.csp} security expert and metadata validator.

Analyze this security rule's metadata and identify quality issues:

Rule ID: {rule.get('rule_id', '')}
Service: {rule.get('service', '')}
Resource: {rule.get('resource', '')}
Current Title: {rule.get('title', '')}
Current Description: {rule.get('description', '')}
Current References: {rule.get('references', [])}

**Validation Criteria:**

1. **Title Quality:**
   - Is it specific and professional?
   - Does it use proper {self.csp} service names (not codes)?
   - Is it actionable and clear?
   - Max 80 characters?

2. **Description Quality:**
   - Does it explain WHAT is validated?
   - Does it explain WHY it matters?
   - Does it mention specific security risks?
   - Is it enterprise-grade (not generic template language)?
   - Does it mention compliance relevance?

3. **References Quality:**
   - Are URLs specific to this control (not generic)?
   - Do they point to real {self.csp} documentation?
   - Are they relevant to the service and requirement?
   - Do they include security guides and best practices?

Return a JSON array of issues found:
[
  {{
    "field": "title|description|references",
    "issue": "specific problem found",
    "severity": "high|medium|low",
    "suggestion": "how to fix"
  }}
]

If no issues, return empty array: []"""

        try:
            response = self.llm.invoke([
                SystemMessage(content=f"You are a {self.csp} security metadata validator."),
                HumanMessage(content=validation_prompt)
            ])
            
            # Parse validation results
            content = response.content.strip()
            if content.startswith('```json'):
                content = content[7:-3]
            elif content.startswith('```'):
                content = content[3:-3]
            
            issues = json.loads(content)
            
            state['validation_results'] = issues
            state['agent_logs'].append(f"✅ Validator: Found {len(issues)} issues")
            
        except Exception as e:
            state['errors'].append(f"Validator error: {str(e)}")
            state['validation_results'] = []
        
        return state
    
    def title_agent(self, state: AgentState) -> AgentState:
        """Agent 2: Improves title with CSP-specific expertise"""
        rule = state['rule']
        
        title_prompt = f"""You are a {self.csp} security expert specializing in professional documentation.

Create an improved, enterprise-grade title for this security rule:

**Rule Context:**
- Rule ID: {rule.get('rule_id', '')}
- Service: {rule.get('service', '')}
- Resource: {rule.get('resource', '')}
- Requirement: {rule.get('requirement', '')}
- Severity: {rule.get('severity', '')}
- Domain: {rule.get('domain', '')}

**Current Title:** {rule.get('title', '')}

**Requirements for Improved Title:**
1. Use proper {self.csp} service names (not codes or abbreviations)
2. Be specific and actionable
3. Professional and clear
4. Max 80 characters
5. Format: "{self.csp} [Service Name] [Resource]: [Specific Requirement]"

**Examples of Good Titles:**
- "Azure Key Vault: Customer-Managed Keys for Encryption"
- "AWS S3 Buckets: Server-Side Encryption with KMS"
- "GCP Cloud Storage: Uniform Bucket-Level Access Control"

Return ONLY the improved title as plain text (no JSON, no explanation)."""

        try:
            response = self.llm.invoke([
                SystemMessage(content=f"You are a {self.csp} documentation expert."),
                HumanMessage(content=title_prompt)
            ])
            
            improved_title = response.content.strip().strip('"\'')
            
            if 'improved_metadata' not in state:
                state['improved_metadata'] = {}
            state['improved_metadata']['title'] = improved_title
            state['agent_logs'].append(f"✅ Title Agent: Improved title")
            
        except Exception as e:
            state['errors'].append(f"Title agent error: {str(e)}")
        
        return state
    
    def description_agent(self, state: AgentState) -> AgentState:
        """Agent 3: Enhances description with security context"""
        rule = state['rule']
        
        description_prompt = f"""You are a {self.csp} security expert specializing in CSPM and compliance documentation.

Create an enterprise-grade description for this security rule:

**Rule Context:**
- Rule ID: {rule.get('rule_id', '')}
- Service: {rule.get('service', '')}
- Resource: {rule.get('resource', '')}
- Requirement: {rule.get('requirement', '')}
- Severity: {rule.get('severity', '')}
- Domain: {rule.get('domain', '')}
- Subcategory: {rule.get('subcategory', '')}

**Current Description:** {rule.get('description', '')}

**Requirements for Improved Description (3-4 sentences):**

Sentence 1: WHAT this rule validates (be specific with {self.csp} technology/features)
Sentence 2: WHY it matters - specific security risks if not configured properly
Sentence 3: BUSINESS IMPACT - what could happen (data breach, compliance violation, etc.)
Sentence 4: COMPLIANCE - mention relevant frameworks (ISO 27001, PCI-DSS, SOC2, HIPAA, GDPR, etc.)

**Tone:**
- Professional and enterprise-grade
- Specific to {self.csp} (use actual service/feature names)
- Security-focused (explain real risks)
- Avoid generic template language
- Include compliance context

**Example of Good Description:**
"Validates that Azure Key Vault uses customer-managed keys (CMK) for data encryption, ensuring organization control over encryption keys rather than relying on Microsoft-managed keys. Without CMK, organizations cannot meet compliance requirements for key rotation policies, key access auditing, or bring-your-own-key (BYOK) scenarios. This control is mandatory for PCI-DSS, HIPAA, and SOC 2 Type II compliance, as these frameworks require demonstrable control over encryption key lifecycle management."

Return ONLY the improved description as plain text (no JSON, no formatting, no explanation)."""

        try:
            response = self.llm.invoke([
                SystemMessage(content=f"You are a {self.csp} security and compliance expert."),
                HumanMessage(content=description_prompt)
            ])
            
            improved_description = response.content.strip().strip('"\'')
            state['improved_metadata']['description'] = improved_description
            state['agent_logs'].append(f"✅ Description Agent: Enhanced description")
            
        except Exception as e:
            state['errors'].append(f"Description agent error: {str(e)}")
        
        return state
    
    def reference_agent(self, state: AgentState) -> AgentState:
        """Agent 4: Finds specific, working documentation URLs"""
        rule = state['rule']
        doc_config = self.doc_bases.get(self.csp_lower, {})
        
        reference_prompt = f"""You are a {self.csp} documentation expert with deep knowledge of official documentation structure.

Find specific, relevant documentation URLs for this security rule:

**Rule Context:**
- Rule ID: {rule.get('rule_id', '')}
- Service: {rule.get('service', '')}
- Resource: {rule.get('resource', '')}
- Requirement: {rule.get('requirement', '')}
- Domain: {rule.get('domain', '')}

**{self.csp} Documentation Structure:**
- Base URL: {doc_config.get('base', 'N/A')}
- Security Center: {doc_config.get('security', 'N/A')}

**Requirements:**
1. Find 3-5 SPECIFIC documentation URLs (not generic landing pages)
2. URLs must be relevant to the EXACT security control
3. Include at least one security guide URL
4. Include at least one best practices URL
5. URLs should be real and follow {self.csp}'s documentation structure

**URL Priority:**
1. Feature-specific documentation (e.g., encryption, access control, logging)
2. Service security guide
3. Best practices guide
4. Compliance/governance documentation
5. Related API reference or configuration guide

**DO NOT include:**
- Generic landing pages
- URLs without specific paths
- Duplicate or similar URLs

Return ONLY a JSON array of URLs:
["url1", "url2", "url3", "url4", "url5"]

Make sure URLs follow {self.csp}'s actual documentation structure and naming conventions."""

        try:
            response = self.llm.invoke([
                SystemMessage(content=f"You are a {self.csp} documentation structure expert."),
                HumanMessage(content=reference_prompt)
            ])
            
            content = response.content.strip()
            if content.startswith('```json'):
                content = content[7:-3]
            elif content.startswith('```'):
                content = content[3:-3]
            
            references = json.loads(content)
            
            # Validate and clean URLs
            valid_refs = [url for url in references if url.startswith('http')]
            
            state['improved_metadata']['references'] = valid_refs[:5]
            state['agent_logs'].append(f"✅ Reference Agent: Found {len(valid_refs)} URLs")
            
        except Exception as e:
            state['errors'].append(f"Reference agent error: {str(e)}")
            # Fallback to basic URLs
            base = doc_config.get('base', '')
            state['improved_metadata']['references'] = [
                f"{base}/{rule.get('service', '')}",
                doc_config.get('security', '')
            ]
        
        return state
    
    def qa_agent(self, state: AgentState) -> AgentState:
        """Agent 5: Final quality assurance and scoring"""
        rule = state['rule']
        improved = state['improved_metadata']
        
        qa_prompt = f"""You are a senior {self.csp} security architect performing final quality review.

**Original Metadata:**
Title: {rule.get('title', '')}
Description: {rule.get('description', '')}
References: {rule.get('references', [])}

**Improved Metadata:**
Title: {improved.get('title', '')}
Description: {improved.get('description', '')}
References: {improved.get('references', [])}

**Quality Assessment:**

Rate improvements on scale 1-10 for:
1. Title clarity and professionalism
2. Description quality (specificity, security context, compliance)
3. Reference relevance and specificity

Also provide:
- Overall improvement score (1-10)
- Key improvements made
- Any remaining issues

Return JSON:
{{
  "title_score": 0-10,
  "description_score": 0-10,
  "references_score": 0-10,
  "overall_score": 0-10,
  "improvements": ["improvement1", "improvement2"],
  "remaining_issues": ["issue1"] or []
}}"""

        try:
            response = self.llm.invoke([
                SystemMessage(content=f"You are a {self.csp} security QA expert."),
                HumanMessage(content=qa_prompt)
            ])
            
            content = response.content.strip()
            if content.startswith('```json'):
                content = content[7:-3]
            elif content.startswith('```'):
                content = content[3:-3]
            
            qa_results = json.loads(content)
            
            # Build final rule with improvements
            final_rule = rule.copy()
            final_rule.update(improved)
            final_rule['qa_score'] = qa_results.get('overall_score', 0)
            final_rule['quality_grade'] = 'A+' if qa_results['overall_score'] >= 9 else 'A' if qa_results['overall_score'] >= 8 else 'B+'
            
            state['final_rule'] = final_rule
            state['agent_logs'].append(f"✅ QA Agent: Score {qa_results.get('overall_score', 0)}/10")
            
        except Exception as e:
            state['errors'].append(f"QA agent error: {str(e)}")
            state['final_rule'] = {**rule, **improved}
        
        return state
    
    def process_rule(self, rule: Dict) -> Dict:
        """Process a single rule through the agent workflow"""
        initial_state = {
            'rule': rule,
            'csp': self.csp,
            'validation_results': [],
            'improved_metadata': {},
            'final_rule': {},
            'errors': [],
            'agent_logs': []
        }
        
        try:
            # Run the workflow
            result = self.workflow.invoke(initial_state)
            return result['final_rule']
            
        except Exception as e:
            print(f"  ❌ Workflow error: {str(e)}")
            return rule
    
    def process_all_rules(self, rules: List[Dict], batch_size: int = 5) -> List[Dict]:
        """Process all rules with progress tracking"""
        print(f"\n🤖 Processing {len(rules)} {self.csp} rules with multi-agent system...")
        print(f"📦 Batch size: {batch_size}\n")
        
        improved_rules = []
        stats = {'processed': 0, 'improved': 0, 'errors': 0}
        
        for i in range(0, len(rules), batch_size):
            batch = rules[i:i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = (len(rules) + batch_size - 1) // batch_size
            
            for rule in batch:
                improved_rule = self.process_rule(rule)
                improved_rules.append(improved_rule)
                
                stats['processed'] += 1
                if improved_rule.get('qa_score', 0) > 0:
                    stats['improved'] += 1
            
            # Progress update
            print(f"✅ Batch {batch_num}/{total_batches} | "
                  f"Progress: {stats['processed']}/{len(rules)} | "
                  f"Improved: {stats['improved']} | "
                  f"Success: {(stats['improved']/stats['processed']*100):.1f}%")
            
            # Pause between batches
            if i + batch_size < len(rules):
                time.sleep(2)
        
        return improved_rules

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 agentic_quality_system.py <csp_name>")
        print("CSPs: alicloud, aws, azure, gcp, ibm, oci, k8s")
        sys.exit(1)
    
    csp = sys.argv[1].lower()
    
    print("="*80)
    print(f"🤖 Agentic AI Quality Enhancement System")
    print(f"CSP: {csp.upper()}")
    print(f"Model: Claude Sonnet 4.5")
    print(f"Framework: LangGraph Multi-Agent Orchestration")
    print("="*80)
    
    # Initialize system
    system = CSPAgenticSystem(csp)
    
    # Load rules
    # (Implementation continues in CSP-specific scripts)
    
    print("\n✅ System initialized successfully!")
    print("Multi-agent workflow:")
    print("  1️⃣  Validator Agent - Quality assessment")
    print("  2️⃣  Title Agent - Professional title improvement")
    print("  3️⃣  Description Agent - Enterprise-grade descriptions")
    print("  4️⃣  Reference Agent - Specific documentation URLs")
    print("  5️⃣  QA Agent - Final review and scoring")

if __name__ == '__main__':
    main()

