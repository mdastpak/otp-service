# Git Workflow Documentation

## 🚨 **CRITICAL WORKFLOW RULES** 🚨

### **❌ NEVER DO THIS:**
- **NEVER commit directly to `main` branch**
- **NEVER push changes without updating MD files**
- **NEVER merge without proper PR process**

### **✅ ALWAYS DO THIS:**

## **1. Branch Creation Strategy**

### **Branch Naming Convention:**
```bash
feature/descriptive-name       # New features
bugfix/issue-description       # Bug fixes  
enhancement/improvement-name   # Improvements
docs/documentation-update      # Documentation only
security/vulnerability-fix     # Security patches
```

### **Examples:**
```bash
feature/admin-logging-enhancements
bugfix/redis-connection-timeout
enhancement/performance-optimization
docs/api-documentation-update
security/jwt-vulnerability-patch
```

## **2. Complete Development Workflow**

### **Step 1: Create Feature Branch**
```bash
# Always start from latest main
git checkout main
git pull origin main

# Create and checkout new feature branch
git checkout -b feature/your-feature-name
```

### **Step 2: Development Process**
1. **Make your code changes**
2. **Run tests to ensure everything works**
   ```bash
   go test ./...
   ```
3. **Update ALL relevant MD files BEFORE committing:**
   - `README.md` - API docs, features, configuration
   - `TESTING.md` - Test updates, new test files
   - `SECURITY.md` - Security features, vulnerabilities
   - `ROADMAP.md` - Progress updates, completed features
   - Create new docs if needed (like this WORKFLOW.md)

### **Step 3: Commit Process**
```bash
# Stage all changes including updated MD files
git add -A

# Check what's being committed
git status

# Commit with descriptive message
git commit -m "$(cat <<'EOF'
Brief description of changes

- Detailed bullet point of change 1
- Detailed bullet point of change 2
- Documentation updates in README.md and TESTING.md

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"
```

### **Step 4: Push and PR Process**
```bash
# Push feature branch to remote
git push origin feature/your-feature-name

# Create Pull Request
gh pr create --title "Brief PR Title" --body "$(cat <<'EOF'
## Summary
Brief description of what this PR does

## Changes Made
- Change 1 with details
- Change 2 with details
- Updated documentation files

## Testing
- [ ] All tests pass
- [ ] New features tested
- [ ] Documentation updated

## Review Notes
Any specific areas that need attention

🤖 Generated with [Claude Code](https://claude.ai/code)
EOF
)"

# After review approval, merge PR
gh pr merge --merge --delete-branch
```

### **Step 5: Cleanup**
```bash
# Switch back to main and pull merged changes
git checkout main
git pull origin main

# Verify the merge was successful
git log --oneline -5
```

## **3. Documentation Update Requirements**

### **Before EVERY commit, check and update:**

#### **README.md Updates Needed When:**
- New features added
- API endpoints changed
- Configuration options modified
- Security features enhanced
- Performance improvements made

#### **TESTING.md Updates Needed When:**
- New test files created
- Test functions added/modified
- Test coverage changes
- New testing categories added

#### **SECURITY.md Updates Needed When:**
- Security features added
- Vulnerabilities fixed
- Security best practices changed
- Compliance requirements updated

#### **ROADMAP.md Updates Needed When:**
- Features completed
- Phase progress made
- Timeline adjustments
- New features planned

## **4. Quality Gates**

### **Before Every Commit:**
- [ ] All tests pass (`go test ./...`)
- [ ] Code builds without errors (`go build`)
- [ ] All relevant MD files updated
- [ ] Commit message is descriptive
- [ ] Changes are in feature branch (not main)

### **Before Every PR:**
- [ ] Feature branch is up to date with main
- [ ] All documentation reflects changes
- [ ] PR description is comprehensive
- [ ] Self-review completed

### **Before Every Merge:**
- [ ] PR has been reviewed
- [ ] All CI checks pass
- [ ] Documentation is complete and accurate
- [ ] Feature branch will be deleted after merge

## **5. Emergency Workflow**

### **For Critical Security Fixes:**
```bash
git checkout -b security/critical-vulnerability-fix
# Make minimal necessary changes
# Update SECURITY.md with patch details
git commit -m "SECURITY: Fix critical vulnerability [details]"
git push origin security/critical-vulnerability-fix
gh pr create --title "SECURITY: Critical vulnerability fix" --body "..."
# Request immediate review and fast-track merge
```

## **6. Common Mistakes to Avoid**

### **❌ Don't:**
- Commit directly to main
- Skip updating documentation
- Use generic commit messages
- Forget to run tests
- Leave debugging files (*.log, *.tmp)
- Push without PR process

### **✅ Do:**
- Always use feature branches
- Update docs with every change
- Write descriptive commit messages
- Run full test suite before committing
- Clean up temporary files
- Follow proper PR workflow

## **7. Workflow Checklist Template**

```markdown
## Pre-Commit Checklist
- [ ] Created feature branch from latest main
- [ ] Made necessary code changes
- [ ] Updated README.md (if applicable)
- [ ] Updated TESTING.md (if applicable)  
- [ ] Updated SECURITY.md (if applicable)
- [ ] Updated ROADMAP.md (if applicable)
- [ ] All tests pass
- [ ] Code builds without errors
- [ ] Removed debug/log files
- [ ] Descriptive commit message ready

## Pre-PR Checklist  
- [ ] Feature branch pushed to remote
- [ ] PR title is descriptive
- [ ] PR description explains changes
- [ ] Documentation changes included
- [ ] Ready for code review

## Pre-Merge Checklist
- [ ] PR reviewed and approved
- [ ] All CI checks passing
- [ ] Documentation is accurate
- [ ] Ready to delete feature branch
```

---

## **🎯 Remember: This Workflow is MANDATORY**

**Every single change, no matter how small, must follow this workflow.**

**📋 Keep this document open during development as a reference.**

**⚡ When in doubt, create a branch and update the docs!**

---

**Last Updated**: December 2024  
**Next Review**: When workflow issues arise  
**Status**: 🔒 **MANDATORY PROCESS** - No exceptions