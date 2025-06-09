# Security Analysis Agent

A LangChain-powered security analysis agent that demonstrates how to build an intelligent security analysis tool using multiple data sources and AI-powered analysis.

## Features

- **Multi-Source Analysis**: Combines data from WHOIS, DNS, SSL certificates, and Shodan
- **AI-Powered Analysis**: Uses Claude 3 Opus for intelligent analysis of security data
- **Conversation Memory**: Maintains context between queries for better analysis
- **Structured Output**: Clean, formatted presentation of security information
- **Extensible Design**: Easy to add new data sources and analysis capabilities

## Architecture

The agent uses a multi-chain approach:

1. **Simple Analysis Chain**: Basic security assessment
2. **Sequential Analysis Chain**: Detailed, step-by-step security analysis
3. **Memory-Enabled Chain**: Contextual analysis with conversation history

### Data Sources

- **WHOIS**: Domain registration and ownership information
- **DNS**: Record analysis and infrastructure mapping
- **SSL**: Certificate validation and security assessment
- **Shodan**: Infrastructure and vulnerability information
- **Geolocation**: IP and domain location data

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/security-analysis-agent.git
cd security-analysis-agent
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
```

Edit `.env` with your API keys:
```
ANTHROPIC_API_KEY=your_anthropic_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here  # Optional
```

## Usage

Run the agent:
```bash
python security_agent.py
```

Example queries:
```
> analyze the security of example.com
> what can you tell me about 8.8.8.8?
> where is example.com located?
```

## Project Structure

```
security-analysis-agent/
├── README.md
├── requirements.txt
├── .env.example
├── security_agent.py
└── utils/
    ├── __init__.py
    ├── analysis.py
    ├── dns_utils.py
    ├── ssl_utils.py
    └── shodan_utils.py
```

## Key Concepts

### 1. LangChain Integration

The agent uses LangChain's powerful features:
- **Chains**: For structured analysis workflows
- **Memory**: For maintaining conversation context
- **Prompts**: For guiding AI analysis
- **Tools**: For integrating external data sources

### 2. Security Analysis

The agent performs multiple types of analysis:
- **Basic Analysis**: Quick security assessment
- **Detailed Analysis**: Comprehensive security review
- **Contextual Analysis**: Analysis with historical context

### 3. Data Collection

The agent gathers data from multiple sources:
- **WHOIS**: Domain registration details
- **DNS**: Infrastructure mapping
- **SSL**: Certificate validation
- **Shodan**: Vulnerability assessment
- **Geolocation**: Location data

### 4. AI Analysis

The agent uses Claude 3 Opus for:
- **Pattern Recognition**: Identifying security patterns
- **Context Understanding**: Understanding security context
- **Recommendation Generation**: Providing security recommendations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [LangChain](https://github.com/langchain-ai/langchain)
- [Anthropic](https://www.anthropic.com/)
- [Shodan](https://www.shodan.io/) 