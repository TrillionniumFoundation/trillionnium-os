# Code 8: make the completion tool explicit

The runtime SYSTEM text now lists `done(status,summary)` in its tool menu and
states the allowed statuses. It explicitly requires a tool-name string action,
requires both done fields, and distinguishes temporary loading waits from
ending a task or remaining on a completed page.

This is a general protocol clarification. The owner instruction, UI observation,
candidate actions, grammar, parser, dispatch and completion-evidence checks stay
unchanged. Only the SYSTEM string changes within the controller implementation;
IME progress, click freshness and the native engine remain code 7 behavior.
No vision engine is introduced.

The focused host gate extracts the actual Java SYSTEM literal and checks it
against the actual production-generated grammar. Complete done decisions for
success, partial and failure remain valid; null action, missing status, missing
or empty summary and treating wait as a completion action are rejected. This
does not establish that a local model will choose the correct tool or that a
phone task was completed. Device acceptance remains independent and pending.
