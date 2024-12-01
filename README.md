# CELular: The CEL-powered Linux audit utility

![Celular Banner](./celular.png)

> 🛰️ Lightweight system audit utility for Linux environments 

```
   ___/   \___/   \___/
 _/ ∧ \___/ ∨ \___/ ! \_
  \___/   \___/ . \___/
 _/ = \___/see\___/   \_
  \___/ca.\___/   \___/
  celular @ v0.3.0-beta
```

---

## 📦 Overview

**Celular** is a CEL-powered CLI tool that determines if your Linux system is "in use" — before you reboot, shut down, or automate something you might regret.

- 💡 Declarative expressions via [Common Expression Language (CEL)](https://github.com/google/cel-spec)
- 🧠 Real-time observables from `psutil` and `pwd`
- 🎯 Designed for shell scripts, `systemd`, and cron
- 📈 Exposes `processes`, `mounts`, and `users` as CEL data

---

## 🚀 Quickstart

### 🔹 Basic Usage

```bash
$ ./celular.py
```

- Returns `0` if the system is **idle** (no expressions matched).
- Returns non-zero if the system is **in use** (any expression matched).

---

### 🔹 JSON Output for Debugging

```bash
$ ./celular.py --json-output=processes,mounts
$ ./celular.py --json-output-all
```

Inspect what's visible to expressions (`procs`, `mounts`, etc.).

---

### 🔹 Config File

Celular looks for a `celular.json` file in:

- `./celular.json`
- `/usr/local/etc/celular.json`

Override with:

```bash
$ ./celular.py --config=/path/to/config.json
```

You must define your own expressions. See below for examples.

---

## 🧠 Expression Breakdown (What It Checks)

These are the default expressions included in the sample config. Each returns `true` if the system is **in use**.

---

### 1. Check for active working directories

```cel
vars.current_working_directories.filter(
  cwd,
  procs.filter(proc,
    type(proc['cwd']) == string &&
    proc['cwd'].startsWith(cwd)
  )
) != []
```

**Detects:**  
Any running process whose working directory begins with one of the entries in `vars.current_working_directories`.

---

### 2. Check for monitored processes by user

```cel
vars.process_names.filter(
  name,
  procs.filter(proc,
    type(proc['name']) == string &&
    proc['name'] == name &&
    (proc['username'] == username || proc['username'] in common_users)
  )
) != []
```

**Detects:**  
Processes matching `vars.process_names` (e.g. `code`, `bash`, `chrome`) **run by** either `globals.username` or any human-like user (`UID 1000–1999`).

---

### 3. Check for active mount points

```cel
vars.mount_points.filter(
  mntpt,
  mounts.filter(mount,
    type(mount) == map &&
    type(mount['mountpoint']) == string &&
    mount['mountpoint'].startsWith(mntpt)
  )
) != []
```

**Detects:**  
Mounted volumes that match or begin with any path in `vars.mount_points` (e.g. `/mnt/ebs`).

---

## 🧠 How Celular Maps System State to CEL

Celular exposes system internals as CEL-friendly objects using [`psutil`](https://pypi.org/project/psutil/) and [`celpy`](https://pypi.org/project/celpy/). These are available inside your expressions:

| CEL Object | Description |
|------------|-------------|
| `procs` | A list of running processes (`pid`, `name`, `exe`, `cwd`, `username`, etc.) |
| `mounts` | Mounted volumes (`mountpoint`, `device`, etc.) |
| `users` | All system users from `pwd.getpwall()` |
| `common_users` | UIDs between 1000–1999 (typically humans) |
| `vars` | Custom variables from your config |
| `globals` | Top-level globals like `username` from config |

---

### 🔗 CEL Language Resources

- 📘 [CEL Specification](https://github.com/google/cel-spec)
- 📚 [celpy (Python)](https://github.com/codemix/cel-python)
- 🧪 [CEL Playground](https://github.com/undistro/cel-playground)

---

## 🛠 Utility Integration: `snoozgans`

Example helper utilities are included to integrate Celular into a `systemd` timer or shell-driven loop:

- [`examples/snoozgans/snoozgans.service`](examples/snoozgans/snoozgans.service)
- [`examples/snoozgans/snoozgans.timer`](examples/snoozgans/snoozgans.timer)
- [`examples/snoozgans/snoozgans_install.sh`](examples/snoozgans/snoozgans_install.sh)

**Status:** Experimental  
Use these as a starting point for your own systemd integration or reboot logic.

---

## 📥 Requirements

- Python 3.6+
- [`psutil`](https://pypi.org/project/psutil/)
- [`celpy`](https://pypi.org/project/celpy/)

Install:

```bash
pip install psutil celpy
```

---

## ✍️ Credits

Written and created by [circasee](https://github.com/circasee).  
© 2025 circasee. Licensed under the Apache 2.0 License.  

Documentation and organization support for this project was provided in part by artificial intelligences like 
[Chatty Kat](https://www.openai.com/chatgpt).

---

## 📄 License

This project is licensed under the [Apache License, Version 2.0](LICENSE).

See the [NOTICE](NOTICE) file for important attribution information, 
including third-party materials and assets with different licensing terms.

> **Note:** The `celular.png` image is © 2025 circasee. **All rights reserved.**  
> It is not covered by the Apache License. Redistribution, modification, or reuse of the image is prohibited without prior written permission from the author.
