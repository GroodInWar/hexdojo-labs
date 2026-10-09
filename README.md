# HexDojo sample labs

Original guided network workshop for a disposable, disconnected Linux VM. Read network-0/README.md first. Containers share a kernel; this template is not a hosted multi-tenant sandbox and has not passed live VM isolation acceptance tests.

`npm test` checks source syntax and risky Compose options without creating containers. No CI workflow executes Docker, accesses cloud credentials, or deploys to production.

Hidden challenges, signing keys, grading services, production infrastructure, and learner evidence are not included. See SECURITY.md and CONTRIBUTING.md.
