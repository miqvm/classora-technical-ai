import asyncio
from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent

# Load environment variables (pulls OPENAI_API_KEY from .env)
load_dotenv()


async def main():
    # Initialize the MCP Client using HTTP transport to point to our local server
    client = MultiServerMCPClient(
        {
            "ioc_server": {
                "transport": "http",
                "url": "http://localhost:8000/mcp",
            },
        }
    )

    # Fetch the tools dynamically from the local server
    tools = await client.get_tools()

    # Instantiate the LLM (API key is loaded from .env automatically)
    llm = ChatOpenAI(model="gpt-5.5", temperature=0)

    # Create the agent using the LLM object and the fetched tools
    agent = create_agent(llm, tools)

    # Define the IOCs to test, including valid and invalid types
    test_cases = [
        {"name": "IP Test", "prompt": "Please analyze the ip '8.8.8.8'."},
        {"name": "Domain Test", "prompt": "Please analyze the domain 'google.com'."},
        {
            "name": "Hash Test",
            "prompt": "Please analyze the hash '44d88612fea8a8f36de82e1278abb02f'.",
        },
        {
            "name": "Unsupported IOC Test",
            "prompt": "Please try to analyze 'attacker@example.com'.",
        },
    ]

    # Run through each test case sequentially
    for index, test in enumerate(test_cases, start=1):
        print(f"\n--- Starting LLM Analysis {index}: {test['name']} ---")
        print(f"User Prompt: {test['prompt']}")

        analysis_response = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": test["prompt"],
                    }
                ]
            }
        )

        # Print the final AI message
        print(f"\n--- Final LLM Response for {test['name']} ---")
        print(analysis_response["messages"][-1].content)

    # Read the resource URI
    print("\n--- Senior Task: Fetching logs from Resource URI ---")
    # Open a direct session with the server to read the custom MCP resource
    async with client.session("ioc_server") as session:
        resource_response = await session.read_resource("log://analyzed_iocs")
        print(resource_response.contents[0].text)


if __name__ == "__main__":
    asyncio.run(main())
