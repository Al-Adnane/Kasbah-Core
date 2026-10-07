#!/bin/bash
# Kasbah-Core - GitHub Issues Setup Script
# Creates all labels, milestones, and issues for Phase 1-4

set -e

echo "=============================================="
echo "  KASBAH-CORE - GITHUB ISSUES SETUP"
echo "=============================================="
echo ""

REPO="Al-Adnane/Kasbah-Core"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check authentication
check_auth() {
    log_info "Checking GitHub authentication..."
    if ! gh auth status &> /dev/null; then
        log_error "Not authenticated with GitHub"
        log_info "Run: gh auth login"
        exit 1
    fi
    log_info "✓ Authenticated as: $(gh api user | jq -r '.login')"
}

# Create labels
create_labels() {
    log_info "Creating labels..."
    
    # Priority labels
    gh label create "P0-Critical" --color "B60205" --description "Must fix before launch" --repo $REPO 2>/dev/null || log_warn "Label P0-Critical exists"
    gh label create "P1-High" --color "D93F0B" --description "Fix within 30 days" --repo $REPO 2>/dev/null || log_warn "Label P1-High exists"
    gh label create "P2-Medium" --color "FBCA04" --description "Fix within 90 days" --repo $REPO 2>/dev/null || log_warn "Label P2-Medium exists"
    gh label create "P3-Low" --color "0E8A16" --description "Fix when possible" --repo $REPO 2>/dev/null || log_warn "Label P3-Low exists"
    
    # Phase labels
    gh label create "Phase-1" --color "1D76DB" --description "Critical fixes (4 weeks)" --repo $REPO 2>/dev/null || log_warn "Label Phase-1 exists"
    gh label create "Phase-2" --color "0052CC" --description "Product completion (8 weeks)" --repo $REPO 2>/dev/null || log_warn "Label Phase-2 exists"
    gh label create "Phase-3" --color "6554C0" --description "Production hardening (8 weeks)" --repo $REPO 2>/dev/null || log_warn "Label Phase-3 exists"
    gh label create "Phase-4" --color "403294" --description "Scale & growth (6 weeks)" --repo $REPO 2>/dev/null || log_warn "Label Phase-4 exists"
    
    # Component labels
    for label in ML Mobile Desktop SDK Extensions Enterprise API Security Compliance IDE Communication Marketing; do
        gh label create "$label" --color "5319E7" --description "$label component" --repo $REPO 2>/dev/null || log_warn "Label $label exists"
    done
    
    # Status labels
    gh label create "TODO" --color "D4C5F9" --repo $REPO 2>/dev/null || log_warn "Label TODO exists"
    gh label create "In Progress" --color "FFCC00" --repo $REPO 2>/dev/null || log_warn "Label In Progress exists"
    gh label create "In Review" --color "BFDADC" --repo $REPO 2>/dev/null || log_warn "Label In Review exists"
    gh label create "DONE" --color "008672" --repo $REPO 2>/dev/null || log_warn "Label DONE exists"
    gh label create "BLOCKED" --color "B60205" --repo $REPO 2>/dev/null || log_warn "Label BLOCKED exists"
    
    log_info "✓ Labels created"
}

# Create milestones
create_milestones() {
    log_info "Creating milestones..."
    
    gh milestone create "Phase 1: Critical Fixes" --dueDate "2026-04-04" --description "Make all products buildable and publishable" --repo $REPO 2>/dev/null || log_warn "Milestone Phase 1 exists"
    gh milestone create "Phase 2: Product Completion" --dueDate "2026-05-30" --description "Complete missing core functionality" --repo $REPO 2>/dev/null || log_warn "Milestone Phase 2 exists"
    gh milestone create "Phase 3: Production Hardening" --dueDate "2026-07-25" --description "Enterprise-ready deployment" --repo $REPO 2>/dev/null || log_warn "Milestone Phase 3 exists"
    gh milestone create "Phase 4: Scale & Growth" --dueDate "2026-09-08" --description "Market readiness" --repo $REPO 2>/dev/null || log_warn "Milestone Phase 4 exists"
    
    log_info "✓ Milestones created"
}

# Create P0-Critical issues
create_p0_issues() {
    log_info "Creating P0-Critical issues..."
    
    # ML-001
    gh issue create \
        --title "[P0] ML Models Trained on Synthetic Data Only" \
        --body "All ML models are currently trained on synthetic data only. We need to download real deepfake datasets (FaceForensics++, DFDC, ASVspoof, Celeb-DF) and retrain all models with proper validation.

**Acceptance Criteria:**
- [ ] Download all 4 real datasets
- [ ] Retrain all models on real data
- [ ] Cross-validation performed (5-fold)
- [ ] Test set accuracy >85% for all models
- [ ] Model cards created with accuracy metrics

**Estimated Effort:** 14-20 weeks
**Dependencies:** Budget approval for storage (\$500/month)

See: ENGINEERING_TICKETS.md for full details" \
        --label "P0-Critical,ML,Phase-1" \
        --milestone "Phase 1: Critical Fixes" \
        --repo $REPO 2>/dev/null || log_warn "Issue ML-001 exists"
    
    # MOB-001
    gh issue create \
        --title "[P0] iOS App Not Buildable" \
        --body "iOS application is not buildable. Need to complete Xcode project configuration and implement native detection engine.

**Acceptance Criteria:**
- [ ] iOS app builds successfully
- [ ] Native detection engine implemented (Swift)
- [ ] Code signing configured
- [ ] TestFlight deployment working
- [ ] App Store submission ready

**Estimated Effort:** 4 weeks
**Dependencies:** Apple Developer account (\$99/year)

See: ENGINEERING_TICKETS.md for full details" \
        --label "P0-Critical,Mobile,Phase-1" \
        --milestone "Phase 1: Critical Fixes" \
        --repo $REPO 2>/dev/null || log_warn "Issue MOB-001 exists"
    
    # MOB-002
    gh issue create \
        --title "[P0] Android App Not Buildable" \
        --body "Android application is not buildable. Need to complete Android Studio configuration and implement native detection engine.

**Acceptance Criteria:**
- [ ] Android app builds successfully
- [ ] Native detection engine implemented (Kotlin)
- [ ] Signing configured
- [ ] Internal testing track working
- [ ] Play Store submission ready

**Estimated Effort:** 4 weeks
**Dependencies:** Google Play Developer account (\$25 one-time)

See: ENGINEERING_TICKETS.md for full details" \
        --label "P0-Critical,Mobile,Phase-1" \
        --milestone "Phase 1: Critical Fixes" \
        --repo $REPO 2>/dev/null || log_warn "Issue MOB-002 exists"
    
    # SDK-001 to SDK-004 (combined)
    gh issue create \
        --title "[P0] All SDKs Unpublished (npm, PyPI, pub.dev)" \
        --body "All 4 SDKs (Node.js, Python, Flutter, React Native) are ready but not published to their respective registries.

**Acceptance Criteria:**
- [ ] Node.js SDK published to npm (@kasbah/sdk)
- [ ] Python SDK published to PyPI (kasbah-guard)
- [ ] Flutter SDK published to pub.dev (kasbah_sdk)
- [ ] React Native SDK published to npm (@kasbah/react-native-sdk)
- [ ] All installations verified

**Estimated Effort:** 1 week
**Dependencies:** npm org account, PyPI account, pub.dev account

See: ENGINEERING_TICKETS.md for full details" \
        --label "P0-Critical,SDK,Phase-1" \
        --milestone "Phase 1: Critical Fixes" \
        --repo $REPO 2>/dev/null || log_warn "Issue SDK-Unpublished exists"
    
    log_info "✓ P0-Critical issues created"
}

# Create P1-High issues
create_p1_issues() {
    log_info "Creating P1-High issues..."
    
    # DESK-001
    gh issue create \
        --title "[P1] Windows Desktop Build Missing" \
        --body "Windows binary of Tauri desktop app not implemented.

**Acceptance Criteria:**
- [ ] Windows binary builds successfully
- [ ] MSI installer generated
- [ ] Code signed
- [ ] Tested on Windows 10/11

**Estimated Effort:** 2 weeks

See: ENGINEERING_TICKETS.md for full details" \
        --label "P1-High,Desktop,Phase-1" \
        --milestone "Phase 1: Critical Fixes" \
        --repo $REPO 2>/dev/null || log_warn "Issue DESK-001 exists"
    
    # DESK-002
    gh issue create \
        --title "[P1] Linux Desktop Build Missing" \
        --body "Linux binary of Tauri desktop app not implemented.

**Acceptance Criteria:**
- [ ] Linux binary builds successfully
- [ ] DEB and RPM packages generated
- [ ] Tested on Ubuntu, Fedora

**Estimated Effort:** 1 week

See: ENGINEERING_TICKETS.md for full details" \
        --label "P1-High,Desktop,Phase-1" \
        --milestone "Phase 1: Critical Fixes" \
        --repo $REPO 2>/dev/null || log_warn "Issue DESK-002 exists"
    
    # EXT-001
    gh issue create \
        --title "[P1] No E2E Browser Tests" \
        --body "No automated E2E testing for browser extensions.

**Acceptance Criteria:**
- [ ] Playwright test infrastructure setup
- [ ] 50+ E2E tests written
- [ ] Tests run on CI
- [ ] All browsers covered (Chrome, Firefox, Edge, Opera, Safari)

**Estimated Effort:** 2 weeks

See: ENGINEERING_TICKETS.md for full details" \
        --label "P1-High,Extensions,Phase-1" \
        --milestone "Phase 1: Critical Fixes" \
        --repo $REPO 2>/dev/null || log_warn "Issue EXT-001 exists"
    
    # API-001
    gh issue create \
        --title "[P1] No API Rate Limiting" \
        --body "Cloudflare Worker API lacks rate limiting - DDoS vulnerability.

**Acceptance Criteria:**
- [ ] Cloudflare Rate Limiting configured (100 req/min)
- [ ] 429 responses returned when exceeded
- [ ] Rate limit headers present

**Estimated Effort:** 1 week

See: ENGINEERING_TICKETS.md for full details" \
        --label "P1-High,API,Phase-1" \
        --milestone "Phase 1: Critical Fixes" \
        --repo $REPO 2>/dev/null || log_warn "Issue API-001 exists"
    
    log_info "✓ P1-High issues created (showing 4 of 10)"
}

# Main
main() {
    check_auth
    
    echo ""
    echo "Repository: $REPO"
    echo ""
    read -p "Create all labels? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        create_labels
    fi
    
    read -p "Create all milestones? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        create_milestones
    fi
    
    read -p "Create P0-Critical issues? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        create_p0_issues
    fi
    
    read -p "Create P1-High issues? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        create_p1_issues
    fi
    
    echo ""
    log_info "GitHub setup complete!"
    echo ""
    echo "Next steps:"
    echo "1. Review created issues: https://github.com/$REPO/issues"
    echo "2. Assign team members to issues"
    echo "3. Create GitHub Projects board"
    echo "4. Start sprint"
}

main
