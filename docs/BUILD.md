# Build

## Prerequisites

- Visual Studio 2022 with MSVC v143
- CMake 3.25 or newer
- Windows SDK 10.0.26100 (or a compatible installed SDK)
- Windows Debugging Tools when using the installed EngExtCpp mode
- Python 3 for the default XED 2026 source build

## Local build

```powershell
cmake --preset vs2022-x64
cmake --build --preset vs2022-x64-relwithdebinfo --parallel 4
ctest --preset vs2022-x64-release-tests --output-on-failure
```

For x86:

```powershell
cmake --preset vs2022-x86
cmake --build --preset vs2022-x86-relwithdebinfo --parallel 4
ctest --preset vs2022-x86-release-tests --output-on-failure
```

The build uses the installed Debugging Tools by default when available. To use the
pinned compatibility copy of `engextcpp`:

```powershell
cmake --preset vs2022-x64 -D0CCHEXT_USE_INSTALLED_ENGEXTCPP=OFF
```

DbgEng and DbgHelp headers and import libraries come from the installed Windows
SDK. Microsoft SDK headers and libraries are not copied into the repository.

The release binaries are written to:

```text
build/x86/bin
build/x64/bin
```

## Current dependencies

- Intel XED v2026.08.23, built from source through Intel mbuild and pinned by SHA256
- Lua 5.4.9, downloaded by CMake FetchContent and pinned by SHA256
- EngExtCpp from the installed Debugging Tools, or `compat/windbg`

The default XED 2026 backend supports AVX-512 EVEX instructions, including the implicit `K0` mask form used by plain ZMM mnemonics. The compatibility fallback is retained for non-AVX-512 code and does not promise AVX-512 encoding.

The old prebuilt XED can be used as a compatibility fallback:

```powershell
cmake --preset vs2022-x64 -D0CCHEXT_USE_XED_2026=OFF
```

## Versioning and CI trigger policy

- `VERSION` is the local default and contains four numeric components.
- CI uses the first three components from `VERSION` plus the GitHub run number as the fourth component.
- Pushes to ordinary branches do not run a workflow.
- Pull requests and manual dispatches run `.github/workflows/ci.yml`.
- Pushing a dotted numeric tag runs `.github/workflows/release.yml`, which builds and tests x86/x64, runs the cdb smoke test, and publishes a GitHub Release.
- A three-component tag such as `v1.20.3` selects the next fourth component from existing tags, for example `1.20.3.5`.
- A four-component tag such as `v1.20.3.6` is treated as an exact version override.
- Re-running the same release tag produces the same computed version when no newer matching tag exists.
