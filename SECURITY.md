# Security and Privacy

## Local-first policy

Diagnostics remain on the machine by default. The toolkit must not automatically transmit diagnostic bundles, account information, network metadata, logs, or identifiers to any external service.

## Supported security reports

Please open a GitHub issue for non-sensitive defects. For vulnerabilities that would expose user data or enable unintended system modification, use GitHub's private vulnerability reporting if enabled for this repository.

## Project boundary

This project is a diagnostic and repair utility. Contributions that add device-identity spoofing, hardware-identifier concealment, or mechanisms whose purpose is to evade service-side restrictions are outside scope.

## Destructive operations

Future cleanup functions must:

1. enumerate targets before modification;
2. create a timestamped backup where practical;
3. log each change locally;
4. verify the expected post-condition;
5. surface partial failure clearly;
6. provide rollback when feasible.
