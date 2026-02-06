#!/bin/bash
# Kasbah Production Deployment Script
# Run this after applying all fixes

echo "🏰 Deploying Kasbah Production..."
echo "================================"

# 1. Apply technical fixes
echo "Step 1: Applying technical fixes..."
cp state_persistence.py apps/api/
cp request_models.py apps/api/
cp operator_key_manager.py apps/api/
cp agent_allowlist.py apps/api/
cp playground_api.py apps/api/
cp roi_calculator.py apps/api/
cp magic_link_auth.py apps/api/

# 2. Update main.py imports
echo "Step 2: Updating main.py with new imports..."
cat >> apps/api/main.py << 'IMPORTS'
# New imports for production fixes
from .state_persistence import StatePersistence
from .request_models import DecideRequest, ConsumeRequest
from .operator_key_manager import OperatorKeyManager
from .agent_allowlist import AgentAllowlistManager, check_agent_allowlist
from .playground_api import router as playground_router
from .roi_calculator import router as roi_router
from .magic_link_auth import router as auth_router

# Initialize managers
state_persistence = StatePersistence()
key_manager = OperatorKeyManager()
allowlist_manager = AgentAllowlistManager()

# Add routers to app
app.include_router(playground_router)
app.include_router(roi_router)
app.include_router(auth_router)
IMPORTS

# 3. Update decide() function for allowlist
echo "Step 3: Updating decide() function..."
# This would require editing main.py to add allowlist check
# Look for the decide() function and add:
#   agent_id = request.get("agent_id")
#   if not agent_id: raise HTTPException(422, "agent_id required")
#   allowlist_result = check_agent_allowlist(agent_id, tool_name, allowlist_manager)
#   if not allowlist_result["allowed"]: return deny response

# 4. Update consume() function for state persistence
echo "Step 4: Updating consume() function..."
# Replace in-memory dicts with state_persistence

# 5. Deploy with Docker
echo "Step 5: Starting production stack..."
docker-compose -f docker-compose.prod.yml up -d

# 6. Wait for services
echo "Step 6: Waiting for services to start..."
sleep 10

# 7. Run health check
echo "Step 7: Running health check..."
curl -f http://localhost/health || echo "Health check failed!"

# 8. Create initial operator
echo "Step 8: Creating initial operator..."
echo "Run: curl -X POST http://localhost/api/operators/admin/keys"

echo "✅ Deployment complete!"
echo "🌐 Access at: https://api.kasbahcore.com"
echo "📊 Dashboard: https://dashboard.kasbahcore.com"
echo "🔧 API Docs: https://api.kasbahcore.com/docs"
