"""
Example: Using Kasbah with LangChain
"""

from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_openai import ChatOpenAI
from kasbah import protect_tool

# Protect a dangerous tool
@protect_tool(kasbah_url="http://localhost:5000")
def refund_customer(customer_id: str) -> str:
    """Refund a customer - DANGEROUS operation"""
    # Your actual refund logic here
    print(f"Processing refund for {customer_id}")
    return f"Refunded customer {customer_id}"

@protect_tool(kasbah_url="http://localhost:5000")
def delete_user_data(user_id: str) -> str:
    """Delete user data - DANGEROUS operation"""
    print(f"Deleting data for {user_id}")
    return f"Deleted data for {user_id}"

# Safe tool (no protection needed)
def search_customer(query: str) -> str:
    """Search for customers - READ-ONLY, safe"""
    return f"Found customers matching: {query}"

# Create tools
tools = [
    Tool(
        name="refund_customer",
        func=refund_customer,
        description="Refund a customer. Requires customer_id. DANGEROUS - use with caution."
    ),
    Tool(
        name="delete_user_data",
        func=delete_user_data,
        description="Delete all user data. Requires user_id. DANGEROUS - irreversible."
    ),
    Tool(
        name="search_customer",
        func=search_customer,
        description="Search for customers. READ-ONLY, safe to use."
    ),
]

# Create agent
llm = ChatOpenAI(temperature=0)
agent = create_react_agent(llm, tools, prompt_template)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

# Run agent - Kasbah will gate dangerous operations
result = agent_executor.invoke({
    "input": "Refund customer customer-123"
})

print(result)
