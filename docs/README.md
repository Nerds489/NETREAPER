# NETREAPER Documentation

This folder contains internal documentation for NETREAPER development and maintenance.

## Files

| Document | Description |
|----------|-------------|
| `NETREAPER-GIT-HOWTO.md` | Git workflow, release pipeline, VERSION sync checklist, gh CLI usage, panic recovery |
| `NETREAPER-FORGOTTEN-FEATURES.md` | Complete specification of 67 features across 17 categories (architecture, wireless, installer, etc.) |

## Quick Links

- **Version bump?** → See VERSION SYNC CHECKLIST in GIT-HOWTO
- **New feature?** → Check if it's already spec'd in FORGOTTEN-FEATURES
- **Release?** → Follow Release Flow in GIT-HOWTO
- **Hotfix?** → Follow Hotfix Flow in GIT-HOWTO
- **Tests failing on version?** → You forgot to sync all VERSION locations

## Installation

Copy these files to your NETREAPER repo:

```bash
cp *.md ~/NETREAPER/docs/
```

---

© 2025 Nerds489
