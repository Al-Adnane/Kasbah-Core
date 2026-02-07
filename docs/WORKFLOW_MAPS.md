# Kasbah — workflow maps (for validation)

## 1) Support refund / account change (mundane failure)
Today: context drift + retries → wrong customer action executes (auth still valid).
Kasbah: tool+target-bound, TTL, single-use ticket → mismatch denied before execution.

## 2) CRM update / enrichment job
Today: batch job retries after timeout → duplicate updates / wrong field writes.
Kasbah: single-use + TTL + audit chain → replay blocked; drift triggers deny/lockdown.

## 3) Infra / ops automation
Today: scripted agent calls “cleanup” against the wrong environment after a prompt change.
Kasbah: environment-bound ticket (prod vs staging) + tool binding → wrong env denied.
