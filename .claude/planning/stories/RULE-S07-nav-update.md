# RULE-S07 — Nav Update: Policies → Rules & Policy

**File**: `frontend/src/lib/constants.js`  
**Status**: Ready for dev

## Goal
Rename the Policies nav section to "Rules & Policy", update the child links to point to /rules and /suppressions.

## Changes
- Parent label: "Policies" → "Rules & Policy"
- Child 1: "All Policies" → href: /suppressions (label: "Suppressions")
- Child 2: "Rule Management" → href: /rules (label: "Rule Library") — unchanged
- Icon: BookOpen → Shield (or keep BookOpen)
