# Kasbah — workflow maps (for validation)

## 1) Support refund / account change
Today: context drift + retries → wrong customer action executes (auth still valid).
Kasbah: tool+target-bound, TTL, single-use ticket → mismatch denied before execution.

## 2) CRM update / enrichment job
Today: batch retries after timeout → duplicate updates / wrong record writes.
Kasbah: single-use + TTL + audit chain → replay blocked; drift triggers deny/lockdown.

## 3) Ops automation / environment mix-up
Today: agent runs “cleanup” against prod after a prompt/tool selection shift.
Kasbah: environment-bound + tool-bound ticket → wrong env/tool denied.
