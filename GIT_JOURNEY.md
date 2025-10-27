# My Git Mastery Challenge Journey

## Student Information
- Name: Pavan Kumar Goli
- Student ID: 23A91A0598
- Repository: https://github.com/GoliPavan888/git-solved-23A91A0598.git 
- Date Started: 2025-10-25
- Date Completed: 2025-10-27

## Task Summary
Cloned instructor's repository with pre-built conflicts and resolved all merge conflicts across multiple branches using professional Git workflows for branching, merging, rebasing, and documentation.

## Commands Used

| Command         | Times Used | Purpose                                                         |
|-----------------|-----------:|-----------------------------------------------------------------|
| git clone       |          1 | Clone instructor's repository                                   |
| git checkout    |        20+ | Switch between branches                                        |
| git branch      |        10+ | View and manage branches                                       |
| git merge       |          2 | Merge dev and conflict-simulator into main                     |
| git add         |        30+ | Stage resolved conflicts and changes                           |
| git commit      |        15+ | Commit resolved changes with context                           |
| git push        |        10+ | Push changes to my repository                                  |
| git fetch       |          2 | Fetch updates from instructor                                  |
| git pull        |        10+ | Pull and integrate remote changes                              |
| git stash       |          2 | Save temporary work                                            |
| git cherry-pick |          1 | Copy specific commit                                           |
| git rebase      |          3 | Rebase feature/main branches, resolve duplicate histories       |
| git reset       |          3 | Practice undo with soft, mixed, and hard resets                |
| git revert      |          1 | Safe undo to maintain history                                  |
| git tag         |          3 | Create annotated release tags                                  |
| git status      |        50+ | Check repository state                                         |
| git log         |        30+ | View and investigate commit history                            |
| git diff        |        20+ | Compare branch and file changes                                |
| git remote      |          2 | Ensure both `origin` and `instructor` are set                  |

## Conflicts Resolved

### Merge 1: main + dev (6 files)

#### Conflict 1: `config/app-config.yaml`
- **Issue**: Production port (8080) vs. Development port (3000)
- **Resolution**: Introduced an environment-specific config section; kept prod default and dev override.
- **Difficulty**: Medium

#### Conflict 2: `config/database-config.json`
- **Issue**: Different DB hosts and SSL settings
- **Resolution**: Structured separate config blocks for both environments, documented rationale.
- **Difficulty**: Medium

#### Conflict 3: `scripts/deploy.sh`
- **Issue**: Production used direct deployment, dev used Docker Compose
- **Resolution**: Conditional script logic for `DEPLOY_ENV`, fallback to manual in dev.
- **Difficulty**: Hard

#### Conflict 4: `scripts/monitor.js`
- **Issue**: Different logging and monitoring intervals
- **Resolution**: `NODE_ENV` based config, merged both logic paths to support both behaviors.
- **Difficulty**: Medium

#### Conflict 5: `docs/architecture.md`
- **Issue**: Separate architecture descriptions for prod/dev
- **Resolution**: Combined as versioned subsections with clear differentiations; included both diagrams and summaries.
- **Difficulty**: Easy

#### Conflict 6: `README.md`
- **Issue**: Feature lists/version numbers mismatched
- **Resolution**: Unified features by category; resolved duplications and clarified version flow.
- **Difficulty**: Easy

### Merge 2: main + conflict-simulator (examples, fill real file names)

#### Conflict 7: `config/experimental.yaml`
- **Issue**: Conflicting AI settings between branches
- **Resolution**: Merged advanced experimental block as opt-in; preserved main's compatibility.
- **Difficulty**: Medium

#### Conflict 8: `scripts/backup.sh`
- **Issue**: One branch had new environment vars, one had error handling improvements
- **Resolution**: Manual merge of error handling into latest version of the script.
- **Difficulty**: Medium

#### Conflict 9: `monitoring/alerts.json`
- **Issue**: Slack/Webhook structures differed
- **Resolution**: Chose extensible structure, merged both alert channels and improved JSON formatting.
- **Difficulty**: Medium

#### Conflict 10: `package.json`
- **Issue**: Competing dependency updates
- **Resolution**: Bumped to upper version range, included missing required packages from both.
- **Difficulty**: Easy

#### Conflict 11: `CHANGELOG.md`
- **Issue**: Out-of-sync documentation between branches
- **Resolution**: Manually merged all entries, resolved duplicate headings and entries.
- **Difficulty**: Easy

#### Conflict 12: `api/config.js`
- **Issue**: Logic structure reordered, new feature additions
- **Resolution**: Manual diff review and integration, with extra tests for correct runtime.
- **Difficulty**: Hard

## Most Challenging Parts

1. **Interpreting conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`)**: Initially unclear which side represented which branch; after several merges, recognized HEAD as current and adjusted accordingly.
2. **Strategic merging**: Particularly hard with big logic differences (e.g. in deploy.sh); had to test both approaches after manual merge.
3. **Ensuring no hidden or missed conflicts**: Repeated use of `git status`, `git diff`, and full file review before continuing each rebase/merge.

## Key Learnings

### Technical Skills
- Mastered manual conflict resolution in multi-branch projects.
- Learned advanced Git commands: rebase, cherry-pick, reflog, stash, reset, revert.
- Improved commit message quality and branch history organization.

### Best Practices
- Always test after resolving conflicts.
- Clearly document every manual resolution in CHANGELOG.md.
- Use annotated tags for milestones.
- Ensure two-way remote setup and syncing with instructor and origin.

### Workflow Insights
- Conflicts are standard in collaboration; clear process and communication are key.
- Versioned, well-formatted documentation makes merges easier.
- A good development workflow saves time and stress during complex merges.

## Reflection

This challenge built real confidence in tackling Git conflicts, not just as obstacles but as opportunities to thoughtfully merge the best of both worlds. The hands-on process, especially with complicated rebase and cherry-pick scenarios, clarified the power of Git history manipulation. Documenting every phase gave depth to my workflow and set a benchmark for future collaboration.

---

