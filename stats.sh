#!/bin/bash
# Quick stats from feedback log

echo "📊 Kasbah Feedback Stats"
echo "========================"
echo ""

# Count total feedback entries
total=$(grep -c "^## Feedback #" FEEDBACK_LOG.md)
echo "Total feedback: $total"

# Count by status
fixed=$(grep -c "Status.*FIXED" FEEDBACK_LOG.md)
open=$(grep -c "Status.*OPEN" FEEDBACK_LOG.md)
in_progress=$(grep -c "Status.*IN PROGRESS" FEEDBACK_LOG.md)

echo "  Fixed: $fixed"
echo "  In progress: $in_progress"  
echo "  Open: $open"
echo ""

# Recent activity
echo "Recent feedback:"
grep "^## Feedback #" FEEDBACK_LOG.md | tail -3
echo ""

echo "📧 Next action: Check GitHub issues and email for new feedback"
