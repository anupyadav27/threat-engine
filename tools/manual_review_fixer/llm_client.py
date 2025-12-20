"""
Optional LLM client for batch fixing unresolved manual review items
"""

import json
from typing import Any, Dict, List, Optional

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    OpenAI = None


class LLMClient:
    """LLM client for proposing fixes to unresolved manual review items"""
    
    def __init__(self, model: str = "gpt-4o-mini", api_key: Optional[str] = None):
        self.model = model
        if not OPENAI_AVAILABLE:
            raise ImportError("openai package not installed. Install with: pip install openai")
        
        # Try to get API key
        if api_key:
            self.client = OpenAI(api_key=api_key)
        else:
            import os
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                self.client = OpenAI(api_key=api_key)
            else:
                raise ValueError("OpenAI API key not provided. Set OPENAI_API_KEY env var or pass api_key parameter")
    
    def batch_fix(self, unresolved_items: List[Dict[str, Any]], 
                  direct_vars: Dict[str, Any],
                  derived_catalog: Dict[str, Any],
                  service_name: str) -> List[Dict[str, Any]]:
        """Batch process unresolved items and return suggested fixes"""
        if not unresolved_items:
            return []
        
        # Prepare context
        direct_vars_list = direct_vars.get("final_union", [])
        derived_keys = list(derived_catalog.keys())
        
        # Build prompt
        prompt = self._build_prompt(unresolved_items, direct_vars_list, derived_keys, service_name)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a code analysis assistant that suggests fixes for manual review items. Return only valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            
            result_text = response.choices[0].message.content
            result_json = json.loads(result_text)
            
            fixes = result_json.get("fixes", [])
            return fixes
            
        except Exception as e:
            print(f"Error calling LLM: {e}")
            return []
    
    def _build_prompt(self, unresolved_items: List[Dict[str, Any]], 
                     direct_vars: List[str],
                     derived_keys: List[str],
                     service_name: str) -> str:
        """Build prompt for LLM"""
        items_text = json.dumps(unresolved_items[:10], indent=2)  # Limit to 10 items per batch
        
        prompt = f"""Analyze these unresolved manual review items for AWS service '{service_name}' and suggest fixes.

Available direct variables: {', '.join(direct_vars[:50])}  # Limit display
Available derived variables: {', '.join(derived_keys)}

Unresolved items:
{items_text}

For each item, suggest a fix if you can determine:
1. A direct variable from the available list that matches
2. A derived variable that matches based on keywords
3. Entity aliases if there's a mismatch

Return JSON in this format:
{{
  "fixes": [
    {{
      "rule_id": "...",
      "suggested_check": {{
        "var": "direct_var_name or derived.var_key",
        "op": "equals",
        "value": "true/false/...",
        "derived": "var_key (if derived)",
        "derive_key": "aws.service_name.topic.var_key"
      }},
      "suggested_aliases": {{
        "entity_aliases": {{"alias": "canonical"}},
        "param_aliases": {{"param": ["candidate_fields"]}}
      }},
      "confidence": 0.0-1.0,
      "reason": "explanation"
    }}
  ]
}}

Only suggest fixes with confidence >= 0.80. If uncertain, omit the item."""
        
        return prompt

