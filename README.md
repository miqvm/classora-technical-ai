# MCP Server for IOC Analysis

This project implements a Model Context Protocol (MCP) server designed to expose Indicator of Compromise (IOC) analysis tools to Large Language Models (LLMs). It utilizes the `FastMCP` library to standardize communication between the LLM agent and the underlying threat intelligence services. 

The project includes an MCP Server, a LangChain-powered client agent using OpenAI's GPT models, and a concrete integration with the VirusTotal API for real-world threat enrichment.

## Architecture & Design Decisions

To ensure a clean, maintainable, and scalable codebase, this project was designed with the following architectural principles:

1. **Hexagonal Architecture (Ports and Adapters):**
   * **Interfaces (`src/interfaces`):** The `IOCAnalyserInterface` acts as a port. It abstracts the core logic of threat intelligence retrieval, ensuring the server doesn't tightly couple to a single provider.
   * **Adapters (`src/adapters`):** The `VirusTotalIOCAnalyserService` acts as an adapter. It implements the interface to communicate specifically with the VirusTotal API. Even though the exercise allowed simulating API calls, this design allows the application to easily swap between a mock service, VirusTotal, or any other threat intel provider (like CrowdStrike or X-Force) without touching the core MCP server logic.

2. **State Management & Tool Chaining:**
   * The exercise requires a multi-step process: `analyze_ioc` returns an ID, which is then passed to `get_threat_context`. 
   * To support this, the server utilizes lightweight in-memory state mapping (`db_ioc_context`). When an IOC is analyzed, the data is fetched, stored in memory, and bound to a unique UUID. The LLM is forced to use this UUID for subsequent contextual lookups, mirroring real-world asynchronous job polling patterns.

3. **Resource Exposure (Senior Requirement):**
   * Using FastMCP's `@mcp.resource` decorator, the server exposes an internal read-only resource URI (`log://analyzed_iocs`).
   * An in-memory logging array (`session_logs`) is updated every time a tool is invoked. The client can read this URI to gain out-of-band visibility into the server's session history, perfectly fulfilling the senior-level requirement of exposing session logs.

4. **Protocol Standard:**
   * By leveraging `FastMCP` and `langchain-mcp-adapters`, the codebase strictly adheres to the Model Context Protocol standards. It automatically generates the correct OpenAPI schemas and handles JSON-RPC message framing securely.

---

## Getting Started

### Prerequisites

* Python 3.10+ (Referenced via Pipfile)
* [Pipenv](https://pipenv.pypa.io/en/latest/) for virtual environment and dependency management.
* API Keys for **OpenAI** (for the LLM client) and **VirusTotal** (for the IOC Adapter).

### 1. Environment Setup

Clone the repository and navigate to the project directory. Install the dependencies using Pipenv:

```bash
pipenv install

```

Create a `.env` file in the root of the project to store your secret API keys:

```bash
touch .env

```

Add the following variables to your `.env` file:

```env
OPENAI_API_KEY=your_openai_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

```

Activate the virtual environment:

```bash
pipenv shell

```

---

## Execution Instructions

The project is split into two components: the MCP Server that hosts the tools, and the Client Agent that consumes them.

### Step 1: Run the MCP Server

In your first terminal (with the pipenv active), start the MCP server:

```bash
python src/server.py

```

*Note: The server will spin up and listen for connections via the HTTP transport defined in the code, simulating a production-grade external tool provider.*

### Step 2: Run the LLM Client

Open a **second terminal window**, navigate to the project directory, activate the pipenv (`pipenv shell`), and execute the client:

```bash
python src/client.py

```

**What happens during client execution:**

1. The client connects to the local MCP server and dynamically queries its available tools.
2. The LangChain agent (powered by `gpt-4o-mini`) is instructed to analyze the IP `8.8.8.8`.
3. The LLM intelligently calls `analyze_ioc`, receives a UUID, and automatically follows up by calling `get_threat_context` using that UUID.
4. **Senior Task:** The client finally reads from the `log://analyzed_iocs` resource URI to output the backend logs of the current session.

---

## Testing

The project is equipped with an automated test suite built on `pytest` and `pytest-asyncio`. The tests verify the core logic of the server, state management persistence, and resource endpoints using mocked service responses to ensure deterministic results without requiring live API calls.

To run the test suite, execute the following command from the root of the project:

```bash
pytest src/tests/ -v 

```

---

## Project Structure

```text
.
├── .gitignore                  # Git ignore rules
├── Pipfile                     # Pipenv dependencies specification
├── Pipfile.lock                # Locked dependency tree
├── README.md                   # This file
└── src/
    ├── .env-template           # Template for environment variables
    ├── adapters/
    │   └── virustotal_service.py # VT API implementation adapter
    ├── interfaces/
    │   └── ioc_analyser_interface.py # Abstract Base Class for IOC Analysis
    ├── tests/
    │   └── test_server.py  # Pytest suite for server logic and state
    ├── client.py               # LangChain MCP Client and Agent execution
    └── server.py               # FastMCP Server defining tools and resources

```

---

## Author

**Miquel Vives Marcus**

Contact: miquelvm2000@gmail.com
