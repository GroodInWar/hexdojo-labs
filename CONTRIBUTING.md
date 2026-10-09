# Contributing to HexDojo

Welcome code reviews, lesson corrections, accessibility improvements, and reproducible bug reports. Start with a small issue or focused pull request. Explain the learner-visible problem, your change, and the checks you ran. Screenshots help with interface changes; remove account details and private notes first.

## Work locally

The website repository contains the public visitor experience, not the production account service. Run `npm test` and follow `network-0/README.md` for guided practice. Sign-in and account study resources require the production platform and are not available from the static preview. The lab repository is a guided exercise for a disposable, disconnected Linux VM. Follow its README before running any commands.

## Review and merge

Use a branch and a pull request. Required CI checks and a maintainer review must pass before merging. Do not add credentials, production URLs for internal services, student records, grading keys, hidden challenge answers, privileged executors, or deployment access. New dependencies need an explanation and license review. Public pull requests never deploy to production or receive production secrets.

## Security findings

Follow SECURITY.md. Test only code in your own disposable environment. The public platform, other students, provider metadata services, and production infrastructure are outside this contribution policy's testing authorization. Do not open public issues containing exploit details or private data.

## Recognition

Merged contributors may opt in to public acknowledgment. Contributions, sponsorship, and student achievement badges are separate. The project does not offer a cash bounty or guarantee rewards.
