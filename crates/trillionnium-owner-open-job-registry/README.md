# trillionnium-owner-open-job-registry

Mechanism-only state for owner-open long-running jobs. The registry binds one scoped `job_id` to one exact request, grants at most one spawn generation, tracks live, terminal and restart-uncertain state, bounded observations, attachments, stdin closure and kill requests. It does not classify command meaning, authorize a target, retry an uncertain effect or replace the durable job observation journal.
