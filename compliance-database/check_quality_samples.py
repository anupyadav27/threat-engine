#!/usr/bin/env python3
"""
Extract quality samples from deep search log in real-time
"""

import re
import json

log_file = "alicloud_deep_search.log"

# Parse log
with open(log_file, 'r') as f:
    content = f.read()

# Find all completed rules with their URLs
rule_pattern = r'🔍 Deep search: (alicloud\.[^\n]+)\n.*?(?:✅ Selected TOP 2 URLs:.*?1\. Score: ([\d.]+) \| ([^\n]+)|📚.*Using fallback)'

matches = re.findall(rule_pattern, content, re.DOTALL)

successful = []
fallback_count = 0

for match in content.split('🔍 Deep search: ')[1:]:
    lines = match.split('\n')
    rule_id = lines[0].strip()
    
    if '✅ Selected TOP 2 URLs:' in match:
        # Extract URLs and scores
        url_lines = [l for l in lines if 'Score:' in l and 'http' in l]
        urls = []
        for line in url_lines[:2]:
            try:
                score = float(re.search(r'Score: ([\d.]+)', line).group(1))
                url = re.search(r'(https://[^\s]+)', line).group(1)
                urls.append({'url': url, 'score': score})
            except:
                pass
        
        if urls:
            successful.append({
                'rule_id': rule_id,
                'status': 'FOUND',
                'urls': urls,
                'num_urls': len(urls)
            })
    elif '📚' in match and 'fallback' in match.lower():
        fallback_count += 1

# Print quality samples
print("╔══════════════════════════════════════════════════════════════════════════════╗")
print("║                   📊 QUALITY SAMPLES - DEEP SEARCH 📊                       ║")
print("╚══════════════════════════════════════════════════════════════════════════════╝")
print()

total_processed = len(successful) + fallback_count
print(f"📈 OVERALL STATS:")
print(f"  Total Processed:    {total_processed}")
print(f"  ✅ High-Quality:    {len(successful)} ({len(successful)/max(total_processed,1)*100:.1f}%)")
print(f"  📚 Fallback:        {fallback_count} ({fallback_count/max(total_processed,1)*100:.1f}%)")
print()

if successful:
    print(f"✅ SUCCESSFUL FINDS (Sample of {min(len(successful), 10)}):")
    print("="*80)
    
    for i, result in enumerate(successful[:10], 1):
        print(f"\n{i}. Rule: {result['rule_id']}")
        print(f"   Status: {result['status']}")
        print(f"   Found: {result['num_urls']} URL(s)")
        for j, url_data in enumerate(result['urls'], 1):
            print(f"   [{j}] Score: {url_data['score']:.3f} | {url_data['url'][:70]}...")
    
    print()
    print("="*80)
    print(f"\n📊 QUALITY ANALYSIS:")
    
    # Analyze scores
    all_scores = [url['score'] for r in successful for url in r['urls']]
    if all_scores:
        avg_score = sum(all_scores) / len(all_scores)
        high_quality = sum(1 for s in all_scores if s >= 0.7)
        medium_quality = sum(1 for s in all_scores if 0.4 <= s < 0.7)
        low_quality = sum(1 for s in all_scores if s < 0.4)
        
        print(f"  Average Score:      {avg_score:.3f}")
        print(f"  High (≥0.7):        {high_quality} ({high_quality/len(all_scores)*100:.1f}%)")
        print(f"  Medium (0.4-0.7):   {medium_quality} ({medium_quality/len(all_scores)*100:.1f}%)")
        print(f"  Low (<0.4):         {low_quality} ({low_quality/len(all_scores)*100:.1f}%)")
    
    # Analyze domains
    print(f"\n📍 DOMAIN DISTRIBUTION:")
    domains = {}
    for result in successful:
        for url_data in result['urls']:
            domain = url_data['url'].split('/')[2]
            domains[domain] = domains.get(domain, 0) + 1
    
    for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {domain:40s} {count:3d} URLs")

else:
    print("⚠️  No successful finds yet (all using fallback)")

print()
print("="*80)
print("Monitor: ./check_quality_samples.py")
print("Live:    tail -f alicloud_deep_search.log")
print("="*80)

# Save to file
output = {
    'timestamp': 'in_progress',
    'total_processed': total_processed,
    'successful_finds': len(successful),
    'fallback_used': fallback_count,
    'samples': successful[:20]
}

with open('alicloud/final/DEEP_SEARCH_SAMPLES.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"\n💾 Saved to: alicloud/final/DEEP_SEARCH_SAMPLES.json")

