# Security policy

Security review is welcome for the code in this repository. Only the current main branch is maintained; old releases may not receive fixes. This policy authorizes local source review and testing in your own disposable environment. It does not authorize scanning, denial of service, account attacks, container escapes, or exploitation against HexDojo's live services, infrastructure, or other students.

## Report privately

When the repository's Security tab offers **Report a vulnerability**, use it for confidential findings. Include the affected file/version, impact, minimal local reproduction, and proposed remediation. Remove credentials, student information, and unnecessary exploit material. Do not file sensitive findings as public issues or discussions. Private reporting must be enabled before this repository is opened for community security reports; until then, do not publish the finding here.

Maintainers will triage reports and coordinate a fix and disclosure. There is no guaranteed response deadline or paid bounty program.

## Trust boundaries

Containers share a kernel; container hardening alone does not establish a safe student execution boundary. Sample labs belong inside disposable VMs disconnected from external networks after setup. Public sample verification is practice evidence and cannot award trusted account mastery. Production secrets, account persistence, orchestration, attestation, and hidden challenges stay outside the public repositories.
