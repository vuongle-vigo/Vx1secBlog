---
title: "Local PE Injection"
pubDatetime: 2024-05-17
slug: local-pe-injection
author: "Vigo"
category: "Malware Analysis"
tags: ["malware development", "process injection", "PE loading", "shellcode", "memory execution"]
description: "Loading and executing PE files directly in process memory"
---

## Local PE Injection

When running an executable file, dll, or generally a PE file, the operating system will load that file into memory and perform a series of necessary processes such as loading the PE, fixing the IAT, fixing the relocation table, and so on. This section will guide writing a PE loader into the current program's memory, then executing that PE from there.

Note: This post contains advanced techniques for manual PE loading and execution without relying on the Windows loader.
