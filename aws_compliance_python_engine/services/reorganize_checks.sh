#!/bin/bash
# Reorganize checks from checks/ folder to rules/ folder with correct naming

for service_dir in */; do
    service=$(basename "$service_dir")
    
    # Skip non-directory files and special folders
    if [ "$service" == "SERVICE_INDEX.yaml" ] || [ "$service" == "*.md" ] || [ "$service" == "*.py" ]; then
        continue
    fi
    
    # Check if checks folder exists
    if [ -d "$service_dir/checks" ]; then
        # Create rules folder
        mkdir -p "$service_dir/rules"
        
        # Find the checks file
        checks_file="$service_dir/checks/${service}_checks.yaml"
        
        if [ -f "$checks_file" ]; then
            # Check if file has content (more than just empty structure)
            line_count=$(wc -l < "$checks_file")
            if [ "$line_count" -gt 10 ]; then
                # Copy to rules folder with correct name
                cp "$checks_file" "$service_dir/rules/${service}.yaml"
                echo "✓ Copied $service"
            fi
        fi
    fi
done

echo ""
echo "Reorganization complete!"
echo "Files copied from checks/{service}_checks.yaml to rules/{service}.yaml"
