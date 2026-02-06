from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

class ROICalculatorInput(BaseModel):
    agent_count: int = 10
    api_calls_per_day: int = 5000
    cost_per_1k: float = 0.50
    incident_cost: int = 50000  # Medium incident cost
    engineer_salary: int = 150000

@app.post("/api/roi/calculate")
async def calculate_roi(input_data: ROICalculatorInput):
    """Calculate ROI for Kasbah deployment"""
    
    # Calculate waste prevention
    total_daily_calls = input_data.agent_count * input_data.api_calls_per_day
    total_annual_calls = total_daily_calls * 365
    waste_reduction = 0.30  # Kasbah stops 30% wasteful calls
    calls_saved = total_annual_calls * waste_reduction
    api_cost_savings = (calls_saved / 1000) * input_data.cost_per_1k
    
    # Calculate incident prevention
    # Industry avg: 2.5 security incidents per year for AI systems
    incidents_per_year = 2.5
    incidents_prevented = incidents_per_year * 0.95  # Kasbah prevents 95%
    incident_savings = incidents_prevented * input_data.incident_cost
    
    # Calculate engineering time saved
    # Kasbah replaces ~60% of manual monitoring work
    engineering_savings = input_data.engineer_salary * 0.60
    
    # Total savings
    total_savings = api_cost_savings + incident_savings + engineering_savings
    
    # Kasbah cost
    kasbah_monthly = 499
    kasbah_annual = kasbah_monthly * 12
    
    # ROI
    roi = total_savings / kasbah_annual if kasbah_annual > 0 else 0
    
    return {
        "savings_breakdown": {
            "api_cost_savings": round(api_cost_savings, 2),
            "incident_savings": round(incident_savings, 2),
            "engineering_savings": round(engineering_savings, 2),
            "total_savings": round(total_savings, 2)
        },
        "costs": {
            "kasbah_monthly": kasbah_monthly,
            "kasbah_annual": kasbah_annual
        },
        "roi": round(roi, 1),
        "payback_months": round(kasbah_annual / (total_savings / 12), 1) if total_savings > 0 else 0,
        "assumptions": {
            "waste_reduction_percent": 30,
            "incidents_prevented_percent": 95,
            "engineering_time_saved_percent": 60,
            "incidents_per_year": 2.5
        }
    }
