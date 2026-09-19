# Build Feasibility Report — JVA-bookstore

**Date:** 2026-09-19
**Task:** T00 (source intake feasibility)
**Target:** `https://github.com/Moseyuh333/JVA-bookstore` @ `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`
**Checkout:** `harness/JVA-bookstore/` (disposable overlay; pristine target never modified)

---

## 1. Verification of the pinned revision

```
$ git -C harness/JVA-bookstore log --oneline -1
dd48d12 Merge pull request #24 from Moseyuh333/new-bug-fixing
```

Commit SHA matches the pinned revision in `.planning/PROJECT-PLAN.md`.

## 2. File inventory (reconciled with plan)

| Kind | Count | Location |
|------|-------|----------|
| Main-source Java files | **97** | `src/main/java/**/*.java` |
| JSP files | **38** | `src/main/webapp/**/*.jsp` |
| `src/test` suite | **0** (absent) | — |

Counts match the read-only inspection recorded in the planning package.

## 3. Toolchain

| Component | Version | Status |
|-----------|---------|--------|
| JDK (build) | OpenJDK 17 (`C:/Program Files/Java/jdk-17`) | Working |
| JDK (host default) | Java 22 | Not used for build |
| Maven | 3.9.11 (`C:/apache-maven-3.9.11`) | Working |
| `pom.xml` source/target | 11 | Compiles under JDK 17 |

### Environmental issue found and resolved

The host `JAVA_HOME` pointed to `C:\Program Files\Eclipse Adoptium\jdk-23.0.2.7-hotspot`, which **does not exist** on this machine. Every Maven invocation failed with:

```
The JAVA_HOME environment variable is not defined correctly
```

Resolution: run Maven with an explicit `JAVA_HOME=C:/Program Files/Java/jdk-17`. The Eclipse Adoptium entry is a stale environment variable and must not be relied upon; the pinned toolchain for this project is JDK 17 (compiles `source/target 11`).

### MSYS / git-bash note

Invoking the bash wrapper (`bin/mvn`) failed with a `ClassNotFoundException` in the Plexus launcher. Use `mvn.cmd` from git-bash instead. This is a launcher quirk, not a project defect.

## 4. Build result

Command:

```
JAVA_HOME="C:/Program Files/Java/jdk-17" mvn.cmd -B -DskipTests clean compile
```

Result: **BUILD SUCCESS** (9.6 s)

```
[INFO] Building jva-bookstore 1.0-SNAPSHOT
[INFO] --------------------------------[ war ]---------------------------------
[INFO] --- maven-clean:3.2.0:clean (clean) @ jva-bookstore ---
[INFO] --- maven-resources:3.3.1:resources (default-resources) @ jva-bookstore ---
[INFO] Copying 5 resources from src\main\resources to target\classes
[INFO] --- maven-compiler:3.11.0:compile (default-compile) @ jva-bookstore ---
[INFO] Compiling 97 source files with javac [debug target 11] to target\classes
[WARNING] system modules path not set in conjunction with -source 11
[INFO] BUILD SUCCESS
```

One non-fatal warning: `system modules path not set in conjunction with -source 11`. Harmless for this project (no `--release` flag; JDK 17 bootclasspath handles Java 11 platform APIs), but recorded for reproducibility.

## 5. Coverage implications for the plan

| Check | Result | Implication |
|-------|--------|-------------|
| Java compilation | 97/97 files compiled | Full Java track eligible for SpotBugs/FindSecBugs (compiled-class analysis) |
| JSP precompilation (Jasper) | **Not yet attempted** | Deferred to T02/T03; ACC-04 requires it, and failures must stay visible as incomplete coverage |
| `src/test` | absent | T03 harness must generate its own JUnit tests; none exist to reuse |
| PostgreSQL dependency | present in `pom.xml` | T03 provides synthetic PostgreSQL fixtures; the bundled `backup*.sql` dumps are **never** restored |
| Tunnel scripts (`cloudflared.exe`, `Procfile`) | present | **Never executed** — out of scope, per plan section 3 |

## 6. Prerequisites for downstream tasks

- **T02 (analysis):** compile with the pinned command before any SpotBugs/FindSecBugs run; the adapter must record JDK + Maven versions in the run manifest.
- **T03 (sandbox):** Docker is **not available on this host**. The container-based verification level is a documented unavailable condition for now; ACC-06 structural evidence applies where execution cannot run. Sandboxed execution remains optional by design.
- **T00 conclusion:** source intake is **feasible**. Build works with a pinned JDK 17 toolchain; no project-side repair of the pristine target was needed or performed.

## 7. Open items

1. JSP precompilation feasibility (Jasper) — scheduled with T02/T03.
2. Container availability for the optional sandbox verification level — tracked as an environmental limitation, not a blocker for the deterministic baseline.
3. CodeQL extraction feasibility (ACC-01 experimental) — separate probe; CodeQL remains optional and never gates ACC-01.
