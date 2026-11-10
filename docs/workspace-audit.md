# Workspace audit

Before the Tauri migration, the C++/WPF/React demonstration was copied to a **local-only** \`archive/pre-tauri-source.zip\`. Forty-seven source/documentation files were compared by SHA-256 before the old directories were removed. The archive is intentionally excluded from GitHub. The obsolete \`gui-client/\`, \`core-service/\`, \`kernel-drivers/\`, \`shared-ipc/\`, root CMake file, old GUI plan, and generated \`build/\` were removed. README, CMake-era testing instructions, and the VS Code task were replaced for the native Tauri project. User vault data and regression tests were not deleted.

~~~text
.
├── .vscode/             Tauri development/build tasks
├── docs/                architecture, testing, distribution, audit
├── installer/           NSIS hooks, ACL provisioning, build wrapper
├── service-daemon/      optional SCM service and tests
├── signatures/          integration-test definitions
├── src/                 React UI and six-language translations
├── src-tauri/           Rust backend and Tauri v2 configuration
├── index.html
├── package-lock.json
├── package.json
└── vite.config.js
~~~

\`.tools/\`, \`node_modules/\`, \`dist/\`, \`archive/\`, \`src-tauri/gen/\`, and Cargo \`target/\` trees are ignored local/generated directories. They may remain on a development machine because they support builds and testing.

> [Self-Check] PE parsing, YARA, and scanning remain outside the renderer. The scanner bounds workers and queues; the privileged optional service is not silently installed. Vault entries are never opened or executed by the GUI. Unsupported protections are identified as missing rather than represented by empty modules.
