---
title: Why So Many Informative?
date: 2025-06-09 1:00:00
categories: [Review, BBP]
tags: [BLE]
---

Recently, I’ve noticed that many of my bug reports are being marked as informative. To understand why and improve my submissions, I decided to analyze the factors contributing to this trend and identify ways to enhance my approach.

### Bug Type Matters

The type of bug I focus on significantly influences the outcome of my reports. Unlike vulnerabilities like XSS or SSRF, which often have clear-cut criteria, my reports primarily involve Business Logic Errors (BLE) and Access Control bugs.

Access Control bugs tend to have a higher success rate because they are often well-documented, providing clear references to support a report.

However, BLEs are trickier, with a lower success rate. This makes sense since BLEs vary greatly between programs—what’s critical in one program might be considered informative in another. BLEs demand a deep understanding of the application’s logic and the specific threat model it faces. Based on my experience, I’ve developed a set of questions to guide myself before submitting a BLE report to improve its quality and relevance.

### Is This Behavior Actually Intended?

When exploring an application, you may encounter behaviors that seem unusual or deviate from expected functionality, which might initially appear to be vulnerabilities. Before rushing to submit a report on platforms like HackerOne, take a step back to verify if the behavior is intentional.

Review the application’s documentation, discussion forums, or other resources to check if the behavior is documented. If no documentation exists, investigate past reports or other sources to ensure there’s no evidence suggesting the behavior is intended. This due diligence helps avoid submitting reports for features that are working as designed.

### Are There Separate Access Controls for the Bypass You’re Exploiting?

Sometimes, you might discover a way to bypass an access control using another feature. For instance, if an admin restricts group creation, but you find you can bypass this by importing a group, confirm whether there are separate access controls for the import feature.

If the import feature has its own access controls that the admin can configure, the program is likely to consider the bypass informative. This is because the admin can disable both features (e.g., group creation and importing) to mitigate the issue.

You might wonder, “Why isn’t this considered a bug if there are separate access controls? Shouldn’t the application automatically block group imports when group creation is disabled?” This is a valid question, but from the program’s perspective, separate access controls are often designed to give admins flexibility. If the bypass relies on a feature that the admin explicitly enables, the program may view it as a configuration choice rather than a vulnerability. For example, the application might assume the admin is aware of the interplay between these features and has chosen to enable both, accepting the associated risks.

### Does the Bypass Rely on a Feature That Must Be Enabled and Directly Conflicts with the Access Control?

Consider a scenario where an application allows admins to lock membership to prevent new user creation. However, the admin can also enable SSO and SCIM provisioning. In this case, you might bypass the membership lock using SCIM. However, this is likely to be deemed informative because SCIM’s purpose is to manage user provisioning. Enabling SSO and SCIM typically hands over user registration control to the Identity Provider (IdP), making it expected that features like membership locks may not apply when SCIM is active. Programs often view such conflicts as intentional design trade-offs rather than vulnerabilities.

### What’s the Impact?

Not every BLE constitutes a vulnerability. A logic flaw might exist, but without a meaningful impact, it’s just a bug, not a security issue. Always evaluate the real-world consequences of the flaw. Ask yourself: What can an attacker achieve? Could they access sensitive data, escalate privileges, or disrupt critical functionality? If the impact is negligible or requires unrealistic conditions, the report is likely to be marked informative. Clearly articulating the impact in your report, with a focus on how it affects the application’s security or users, is crucial to demonstrating its severity.
