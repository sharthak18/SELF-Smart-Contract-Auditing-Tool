#!/bin/bash
# Run these commands to push SELF to GitHub

# Step 1: Initialize git (if not already a repo)
git init
git add .
git status

# Step 2: Commit
git commit -m "feat: SELF v2.0.0 — Intelligence Layer

- 95+ vulnerability patterns across 5 languages
- Protocol Context Engine: reads README/docs/NatSpec to suppress false positives
- Local LLM analysis via Ollama (deepseek-coder, qwen2.5-coder)
- Protocol packs: AMM, Lending, Bridge, Staking
- Taint tracker: data flow analysis
- Glider-inspired Query DSL for custom rules
- Tested on Damn Vulnerable DeFi: caught all 8 known vulnerability classes

Sources: Rekt.news, Code4rena, Sherlock, Trail of Bits, OpenZeppelin, Pashov"

# Step 3: Create repo on GitHub first at https://github.com/new
# Repo name suggestion: self-auditor
# Description: Intelligent smart contract security auditing tool — 95+ patterns, doc-aware, local LLM

# Step 4: Push
git remote add origin https://github.com/YOUR_USERNAME/self-auditor.git
git branch -M main
git push -u origin main
