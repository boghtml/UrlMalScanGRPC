<body>

<h1>URL Checker Project</h1>
<p>A microservice application for checking and filtering malicious URLs.</p>

<h2>Overview</h2>
<p>This project provides a service for checking URLs for potentially malicious content and filtering HTML documents to identify and neutralize harmful links. It consists of two main components:</p>
<ul>
    <li>gRPC Server - Core service for URL checking and HTML filtering with Redis caching</li>
    <li>REST API Client - Web interface for interacting with the gRPC server</li>
</ul>


![image](https://github.com/user-attachments/assets/6eb7b3ed-8910-4df1-88a2-13a4b84f3a9e)


<h2>Project Structure</h2>
<pre>
url-filter-project/
├── proto/
│   └── url_service.proto
├── server/
│   ├── cmd/
│   ├── internal/
│   │   ├── handler/
│   │   ├── service/
│   │   └── cache/
│   └── Dockerfile
├── client/
│   ├── cmd/
│   ├── internal/
│   │   ├── handler/
│   │   └── grpc_client/
│   └── Dockerfile
├── docker-compose.yml
├── go.mod
└── README.html
</pre>

<h2>Features</h2>
<ul>
    <li>URL Checking</li>
    <li>HTML Filtering</li>
    <li>Redis Caching</li>
    <li>REST API</li>
    <li>Docker Containerization</li>
</ul>

<h2>Malicious URL Detection Criteria</h2>
<table border="1">
    <tr>
        <th>Criteria</th>
        <th>Description</th>
    </tr>
    <tr>
        <td>Blacklisted Domains</td>
        <td>Known malicious domains like malware.com, phish.net</td>
    </tr>
    <tr>
        <td>Suspicious Keywords</td>
        <td>Words like "phish", "hack", "malware"</td>
    </tr>
    <tr>
        <td>File Extensions</td>
        <td>.exe, .bat, .dll, etc.</td>
    </tr>
    <tr>
        <td>IP-based URLs</td>
        <td>Raw IP instead of domain</td>
    </tr>
    <tr>
        <td>Long URLs</td>
        <td>Over 250 characters</td>
    </tr>
</table>

<h2>Installation and Setup</h2>
<h3>Prerequisites</h3>
<ul>
    <li>Docker & Docker Compose</li>
    <li>Git</li>
</ul>

<h3>Steps</h3>
<pre>
git clone https://github.com/yourusername/url-filter-project.git
cd url-filter-project
docker-compose up --build
</pre>

<h2>API Documentation</h2>

<h3>POST /api/check-url</h3>
<p>Checks a single URL.</p>
<pre>
Request:
{
  "url": "https://example.com"
}

Response:
{
  "url": "https://example.com",
  "is_malicious": false
}
</pre>

<h3>POST /api/filter-html</h3>
<p>Uploads HTML file and scans it.</p>
<pre>
Form-data key: html_file

Response:
{
  "filtered_html": "...",
  "url_results": [
    {
      "url": "https://example.com",
      "is_malicious": false
    },
    {
      "url": "https://malicious-site.com",
      "is_malicious": true
    }
  ]
}
</pre>

<h2>Testing with gRPCurl</h2>
<pre>
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext -d '{"url":"https://example.com"}' localhost:50051 urlservice.URLService/CheckURL
</pre>

<h2>Architecture</h2>
<ul>
    <li>gRPC Server - core logic</li>
    <li>Redis Cache - for performance</li>
    <li>REST Client - exposes HTTP interface</li>
</ul>

<h2>Error Handling</h2>
<ul>
    <li>Graceful Redis fallbacks</li>
    <li>Invalid URLs are treated as malicious</li>
    <li>Clear status codes and messages</li>
    <li>Logging included</li>
</ul>

<h2>Security Considerations</h2>
<ul>
    <li>Enhance detection logic</li>
    <li>Use authentication and rate limiting</li>
    <li>Enable TLS for all communication</li>
</ul>

<h2>License</h2>
<p>MIT License</p>

</body>
</html>
