# Components

One folder per component, each with a single `README.md` that follows the template below.

To add a component: create `infrastructure/components/<name>/README.md`, copy the template and fill it in.

## Template

```markdown
# <Component name>

> One sentence for a beginner: what it is and what it is for.

## What it is and what it does

Plain language, no prior knowledge assumed. What problem it solves, what it is
responsible for in a security setup, and what it is NOT responsible for.

## How it works

Diagram (Mermaid renders on GitHub): where the data comes from, what the tool does
with it, where it goes next. A few sentences under the diagram.

## Lab details

Optional. Only non-sensitive information: version, role in the lab, link to the
lab-specific notes. No secrets or public addresses.

## Setup

### Requirements

### Installation

### Configuration

Placeholders only, no secrets (e.g. `<API_KEY>`).

### Verify it works

A check that does not depend on other components.

## Troubleshooting
```
