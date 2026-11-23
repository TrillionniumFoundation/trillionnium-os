package org.trillionnium.hepta.local;
final class LocalTaskSession {
    boolean journalBlocked;
    void requireModelSettingsJournalIdle(){if(journalBlocked)throw new IllegalStateException("fixture unfinished task journal");}
}

