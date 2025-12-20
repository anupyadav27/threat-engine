"""
AI-Assisted Parent Discovery Matcher

Uses AI to match required parameters to parent discoveries and fields.
Provides structured context to prevent hallucination.
"""

import json
from typing import Dict, List, Tuple, Optional
from openai import OpenAI
import os


def get_openai_client():
    """Get OpenAI client"""
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")
    return OpenAI(api_key=api_key)


def build_context_for_ai(
    current_function: str,
    required_params: List[str],
    independent_discoveries: Dict,
    dependent_discoveries: Dict,
    boto3_service_data: Dict
) -> str:
    """
    Build structured context for AI prompt.
    
    Args:
        current_function: Function that needs parent (e.g., 'get_authorizers')
        required_params: Parameters it needs (e.g., ['restApiId'])
        independent_discoveries: Dict of independent discovery_id -> discovery_data
        dependent_discoveries: Dict of dependent discovery_id -> discovery_data
        boto3_service_data: Boto3 operations data for this service
    
    Returns:
        Formatted context string
    """
    context_parts = []
    
    # Current function info
    context_parts.append(f"Current function: {current_function}")
    context_parts.append(f"Required parameters: {', '.join(required_params)}")
    context_parts.append("")
    
    # Independent functions (candidates for parent)
    context_parts.append("Available independent functions (candidates for parent):")
    for discovery_id, discovery_data in independent_discoveries.items():
        func_data = discovery_data.get('_function_data', {})
        python_method = func_data.get('python_method', '')
        item_fields = func_data.get('item_fields', [])[:10]  # Limit to avoid token bloat
        available_fields = func_data.get('available_fields', [])[:10]
        all_fields = list(set(item_fields + available_fields))[:15]
        
        context_parts.append(f"  - {python_method} (discovery_id: {discovery_id})")
        context_parts.append(f"    Emits fields: {', '.join(all_fields[:10])}")
        context_parts.append("")
    
    # Dependent functions (for reference, not candidates)
    if dependent_discoveries:
        context_parts.append("Dependent functions (for reference, not candidates):")
        for discovery_id, discovery_data in list(dependent_discoveries.items())[:5]:
            func_data = discovery_data.get('_function_data', {})
            python_method = func_data.get('python_method', '')
            context_parts.append(f"  - {python_method}")
        context_parts.append("")
    
    return "\n".join(context_parts)


def ai_suggest_parent(
    current_function: str,
    required_params: List[str],
    independent_discoveries: Dict,
    dependent_discoveries: Dict,
    boto3_service_data: Dict
) -> Optional[Tuple[str, str]]:
    """
    Use AI to suggest parent discovery and field.
    
    Args:
        current_function: Function needing parent (e.g., 'get_authorizers')
        required_params: Parameters needed (e.g., ['restApiId'])
        independent_discoveries: Available independent discoveries
        dependent_discoveries: Dependent discoveries (for context)
        boto3_service_data: Boto3 data for verification
    
    Returns:
        (parent_discovery_id, field_name) or None if AI fails
    """
    try:
        client = get_openai_client()
        
        # Build context
        context = build_context_for_ai(
            current_function, required_params,
            independent_discoveries, dependent_discoveries,
            boto3_service_data
        )
        
        # Build prompt
        param_str = ', '.join(required_params)
        prompt = f"""You are helping match AWS boto3 function dependencies.

{context}

Task: For function '{current_function}' which requires parameter(s) '{param_str}', determine:
1. Which independent function should provide this value?
2. Which field from that function should be used?

Consider semantic meaning:
- restApiId → needs REST API ID → likely from get_rest_apis or list_rest_apis
- workGroup → needs Work Group name → likely from list_work_groups
- bucketName → needs bucket name → likely from list_buckets

Respond in JSON format:
{{
    "parent_function": "function_name_from_list",
    "parent_discovery_id": "discovery_id_from_list",
    "field_name": "field_name_from_emitted_fields",
    "reasoning": "brief explanation"
}}

Only suggest functions and fields that are in the provided lists above."""

        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Use cost-effective model
            messages=[
                {"role": "system", "content": "You are an expert at matching AWS API function dependencies. Always respond with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,  # Low temperature for consistency
            max_tokens=500
        )
        
        # Parse response
        response_text = response.choices[0].message.content.strip()
        
        # Extract JSON (handle markdown code blocks)
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()
        
        result = json.loads(response_text)
        
        parent_discovery_id = result.get('parent_discovery_id')
        field_name = result.get('field_name')
        
        # Verify the suggestion is valid
        if parent_discovery_id and parent_discovery_id in independent_discoveries:
            discovery_data = independent_discoveries[parent_discovery_id]
            func_data = discovery_data.get('_function_data', {})
            item_fields = func_data.get('item_fields', [])
            available_fields = func_data.get('available_fields', [])
            all_fields = [f.lower() for f in item_fields + available_fields]
            
            if field_name.lower() in all_fields:
                return (parent_discovery_id, field_name)
        
        return None
        
    except Exception as e:
        print(f"⚠️  AI parent matching failed: {e}")
        return None


def get_all_fields(discovery_data: Dict) -> List[str]:
    """Get all fields emitted by a discovery"""
    func_data = discovery_data.get('_function_data', {})
    item_fields = func_data.get('item_fields', [])
    available_fields = func_data.get('available_fields', [])
    return list(set(item_fields + available_fields))

